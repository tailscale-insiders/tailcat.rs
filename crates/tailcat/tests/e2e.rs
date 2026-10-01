//! End-to-end tests: a server and clients in one process, meeting through
//! a local DERP relay.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tailcat::derp::server::DevDerp;
use tailcat::{
    Client, ClientOptions, KeySet, NodePrivate, PortRange, PresharedKey, Server, ServerBuilder, TcpHandler, TcpStream,
    UdpConn, connector, handler, udp_handler,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tracing_subscriber::EnvFilter;

fn init() {
    let _ = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).try_init();
}

/// Awaits `f`, failing the test if it takes more than `secs` seconds.
async fn within<T>(secs: u64, f: impl Future<Output = T>) -> T {
    timeout(Duration::from_secs(secs), f).await.expect("timed out")
}

/// A server builder using the local relay.
fn builder(dev: &DevDerp) -> ServerBuilder {
    Server::builder().region(dev.region.clone())
}

/// A server using the local relay, with no handlers.
async fn bare_server(dev: &DevDerp) -> Server {
    builder(dev).start().await.unwrap()
}

fn client_with_key(server: &Server, key: NodePrivate) -> Client {
    Client::with_options(server.tailcat_addr(), ClientOptions { key: Some(key), ..Default::default() })
}

/// The server's tunnel address, at `port`.
fn server_addr(server: &Server, port: u16) -> SocketAddr {
    SocketAddr::new(server.addr().into(), port)
}

/// The client's tunnel address, at `port`.
fn client_addr(client: &Client, port: u16) -> SocketAddr {
    SocketAddr::new(client.public_key().tailcat_ip().into(), port)
}

/// Sends `msg` on `u` until it's echoed back; the first datagrams can be
/// lost while the tunnel comes up (or back up).
async fn udp_round_trip(u: &UdpConn, msg: &[u8]) {
    let mut buf = [0u8; 64];
    for _ in 0..30 {
        u.send(msg).await.unwrap();
        if let Ok(Ok(n)) = timeout(Duration::from_secs(1), u.recv(&mut buf)).await {
            assert_eq!(&buf[..n], msg);
            return;
        }
    }
    panic!("no UDP echo");
}

/// Sends `req`, half-closes, and returns the whole reply.
async fn request(mut c: TcpStream, req: &[u8]) -> String {
    c.write_all(req).await.unwrap();
    c.shutdown().await.unwrap();
    let mut s = String::new();
    within(20, c.read_to_string(&mut s)).await.unwrap();
    s
}

/// Reads `c` to the end.
async fn read_all(c: &mut TcpStream) -> String {
    let mut s = String::new();
    c.read_to_string(&mut s).await.unwrap();
    s
}

/// Reads from `c` until the connection ends, which it must promptly.
async fn wait_closed(mut c: TcpStream) {
    let mut buf = [0u8; 64];
    let end = async { while c.read(&mut buf).await.is_ok_and(|n| n > 0) {} };
    timeout(Duration::from_secs(5), end).await.expect("connection outlived its peer");
}

async fn echo_server(dev: &DevDerp) -> Server {
    echo(builder(dev)).start().await.unwrap()
}

/// Adds TCP and UDP echo handlers; TCP port 81 refuses connections.
fn echo(b: ServerBuilder) -> ServerBuilder {
    b.on_tcp(|port| (port != 81).then(|| tcp_echo(port))).on_udp(|_port| {
        Some(udp_handler(|c: UdpConn| async move {
            let mut buf = [0u8; 2048];
            while let Ok(n) = c.recv(&mut buf).await {
                let _ = c.send(&buf[..n]).await;
            }
        }))
    })
}

/// Replies `port <port>: ` and then what the client sent.
fn tcp_echo(port: u16) -> TcpHandler {
    handler(move |mut c: TcpStream| async move {
        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.unwrap();
        c.write_all(format!("port {port}: ").as_bytes()).await.unwrap();
        c.write_all(&buf).await.unwrap();
        c.shutdown().await.unwrap();
        c.drain(Duration::from_secs(5)).await;
    })
}

/// Writes `msg` to every connection.
fn say(msg: &'static [u8]) -> Option<TcpHandler> {
    Some(handler(move |mut c: TcpStream| async move {
        let _ = c.write_all(msg).await;
    }))
}

#[tokio::test]
async fn tcp_and_udp_over_local_derp() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = echo_server(&dev).await;
    let addr = server.tailcat_addr();
    assert!(addr.as_str().starts_with("tc"));

    let client = Client::new(addr.clone());
    let pong = within(15, client.ping()).await.unwrap();
    assert!(pong.latency < Duration::from_secs(10));

    let mut c = within(20, client.dial_tcp_port(80)).await.unwrap();
    let payload = vec![7u8; 200_000];
    c.write_all(&payload).await.unwrap();
    c.shutdown().await.unwrap();
    let mut got = Vec::new();
    within(30, c.read_to_end(&mut got)).await.unwrap();
    assert!(got.starts_with(b"port 80: "));
    assert_eq!(got.len(), 9 + payload.len());

    // A port with no handler answers with a RST.
    let err = within(20, client.dial_tcp_port(81)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionRefused);

    let u = client.dial_udp_port(53).await.unwrap();
    udp_round_trip(&u, b"hello udp").await;

    // Relayed only where there's no interface but loopback (a build
    // sandbox), and named as the address names the region: addresses
    // leave out region codes, so the code is the ID.
    let dp = client.disco_ping(Duration::from_secs(5)).await.unwrap();
    if let tailcat::Via::Derp { region_id, region_code } = dp.via {
        let r = addr.parse().unwrap().region.swap_remove(0);
        assert_eq!((region_id, region_code), (r.region_id, r.region_code));
    }

    let st = server.status();
    assert_eq!(st.peers.len(), 1);
    assert_eq!(st.peers[0].key, client.public_key());
    assert_eq!(st.peers[0].tailcat_ip, client.public_key().tailcat_ip());
    assert_eq!(server.peer_key(client_addr(&client, 1)), Some(client.public_key()));
    assert_eq!(server.peer_key(server_addr(&server, 1)), None);
    assert_eq!(server.peer_key("127.0.0.1:1".parse().unwrap()), None);
    assert!(client.drain_tcp(Duration::from_secs(5)).await);
    server.close();
}

#[tokio::test]
async fn allowlist_rejects_strangers() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let allowed = NodePrivate::generate();
    let allow = KeySet::default();
    allow.add(allowed.public());
    let server = builder(&dev).allow_client(allow.checker()).on_tcp(|_| say(b"hi")).start().await.unwrap();

    let stranger = Client::new(server.tailcat_addr());
    assert!(stranger.ping().await.is_err(), "stranger was admitted");

    let friend = client_with_key(&server, allowed.clone());
    friend.ping().await.unwrap();
    let mut c = friend.dial_tcp_port(1).await.unwrap();
    assert_eq!(read_all(&mut c).await, "hi");
    assert_eq!(server.status().peers.len(), 1);

    assert!(server.disconnect_client(&friend.public_key()));

    assert!(!server.disconnect_client(&friend.public_key()));
    assert!(server.status().peers.is_empty());
    assert_eq!(server.peer_key(c.local_addr()), None);

    // A new client with the allowed key gets back in.
    drop((c, friend));
    let again = client_with_key(&server, allowed);
    again.ping().await.unwrap();
    assert_eq!(server.status().peers.len(), 1);
    server.close();
}

#[tokio::test]
async fn client_rejoins_a_restarted_server() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let (key, psk) = (NodePrivate::generate(), PresharedKey::generate());
    let start = || echo(builder(&dev).key(key.clone()).preshared_key(psk)).start();
    let server = start().await.unwrap();
    let client = Client::new(server.tailcat_addr());
    assert_eq!(request(client.dial_tcp_port(80).await.unwrap(), b"before").await, "port 80: before");
    server.close();

    // The same key and pre-shared key make the same address, but the new
    // server has never heard of the client.
    let server = start().await.unwrap();
    assert_eq!(&server.tailcat_addr(), client.server());
    let c = timeout(Duration::from_secs(30), client.dial_tcp_port(80)).await.expect("dial stalled");
    assert_eq!(request(c.unwrap(), b"after").await, "port 80: after");

    // Disconnected, the client joins again when its datagrams go
    // unanswered.
    assert!(server.disconnect_client(&client.public_key()));
    let u = client.dial_udp_port(53).await.unwrap();
    udp_round_trip(&u, b"still here").await;
    assert_eq!(server.status().peers.len(), 1);
    server.close();
}

/// Dials that pile up behind a rejoin the gone server never answers share
/// its failure: each waited its turn and then waited out the server
/// again, so the last of n dials failed after n rejoins.
#[tokio::test]
async fn dials_share_an_unanswered_rejoin() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = echo(builder(&dev)).start().await.unwrap();
    let client = Client::new(server.tailcat_addr());
    assert_eq!(request(client.dial_tcp_port(80).await.unwrap(), b"hi").await, "port 80: hi");
    server.close();

    // A dial waits 5 seconds before rejoining, and a rejoin 10.
    let dials = futures::future::join_all((0..3).map(|_| client.dial_tcp_port(80)));
    let results = within(25, dials).await;

    for r in results {
        assert_eq!(r.unwrap_err().kind(), ErrorKind::TimedOut);
    }
}

#[tokio::test]
async fn ping_needs_a_live_server() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = bare_server(&dev).await;
    let client = Client::new(server.tailcat_addr());
    client.ping().await.unwrap();
    client.ping().await.unwrap();

    server.close();

    assert!(client.ping().await.is_err(), "ping answered by a closed server");
}

#[tokio::test]
async fn listeners_take_precedence() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = bare_server(&dev).await;
    let mut ln = server.listen_tcp(8080).unwrap();
    assert_eq!(ln.local_addr(), server_addr(&server, 8080));
    assert!(server.listen_tcp(8080).is_err(), "port listened on twice");
    let ephemeral = server.listen_tcp(0).unwrap();
    assert!((32768..=60999).contains(&ephemeral.port()));

    let client = Client::new(server.tailcat_addr());
    let accept = tokio::spawn(async move {
        let mut c = ln.accept().await.unwrap();
        c.write_all(b"from listener").await.unwrap();
        c.shutdown().await.unwrap();
        c.drain(Duration::from_secs(5)).await;
    });
    let mut c = client.dial_tcp_port(8080).await.unwrap();
    assert_eq!(read_all(&mut c).await, "from listener");
    accept.await.unwrap();

    // Without a handler or listener, other ports are refused.
    assert!(client.dial_tcp_port(8081).await.is_err());
    // Dropping a listener frees its port.
    server.listen_tcp(8080).unwrap();
    drop(ephemeral);
}

#[tokio::test]
async fn udp_listener_flows_idle_out() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = builder(&dev).udp_idle_timeout(Duration::from_millis(300)).start().await.unwrap();
    let mut ln = server.listen_udp(9).unwrap();
    let client = Client::new(server.tailcat_addr());
    let u = client.dial_udp_port(9).await.unwrap();
    let flow = loop {
        u.send(b"x").await.unwrap();
        if let Ok(Some(f)) = timeout(Duration::from_secs(1), ln.accept()).await {
            break f;
        }
    };
    assert_eq!(flow.local_addr(), server_addr(&server, 9));
    assert_eq!(flow.peer_addr(), client_addr(&client, u.local_addr().port()));
    assert_eq!(server.peer_key(flow.peer_addr()), Some(client.public_key()));

    // With the client quiet, the flow closes after the idle timeout.
    let mut buf = [0u8; 16];
    let err = loop {
        if let Err(e) = within(5, flow.recv(&mut buf)).await {
            break e;
        }
    };
    assert_eq!(err.kind(), ErrorKind::TimedOut);
}

#[tokio::test]
async fn closing_resets_open_connections() {
    init();
    let dev = DevDerp::start_local().await.unwrap();

    // A closed server's connections reset rather than hang.
    let server = bare_server(&dev).await;
    let mut ln = server.listen_tcp(80).unwrap();
    let client = Client::new(server.tailcat_addr());
    let c = client.dial_tcp_port(80).await.unwrap();
    let _accepted = ln.accept().await.unwrap();
    server.close();
    wait_closed(c).await;

    // And so do a dropped client's.
    let server = bare_server(&dev).await;
    let mut ln = server.listen_tcp(80).unwrap();
    let client = Client::new(server.tailcat_addr());
    let c = client.dial_tcp_port(80).await.unwrap();
    let accepted = ln.accept().await.unwrap();
    drop((c, client));
    wait_closed(accepted).await;
    server.close();
}

#[tokio::test]
async fn served_ports_filter_silently() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = builder(&dev).served_tcp_ports([PortRange::single(80)]).on_tcp(|_| say(b"ok")).start().await.unwrap();
    let client = Client::new(server.tailcat_addr());
    assert_eq!(request(client.dial_tcp_port(80).await.unwrap(), b"").await, "ok");

    // A filtered port neither answers nor refuses.
    let filtered = timeout(Duration::from_secs(1), client.dial_tcp_port(81)).await;
    assert!(filtered.is_err(), "filtered port answered: {filtered:?}");
    server.close();
}

/// A connector prepares before the client's handshake completes: what it
/// prepared serves the connection, and its failure refuses the client.
#[tokio::test]
async fn connectors_prepare_before_accepting() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = builder(&dev)
        .on_tcp(|port| {
            Some(connector(move || async move {
                if port == 81 {
                    return Err(io::Error::from(ErrorKind::ConnectionRefused));
                }
                let greeting = format!("prepared for {port}");
                Ok(move |mut c: TcpStream| async move {
                    let _ = c.write_all(greeting.as_bytes()).await;
                })
            }))
        })
        .start()
        .await
        .unwrap();
    let client = Client::new(server.tailcat_addr());
    assert_eq!(request(within(20, client.dial_tcp_port(80)).await.unwrap(), b"").await, "prepared for 80");
    let err = within(20, client.dial_tcp_port(81)).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    server.close();
}

/// A loopback TCP service that answers one connection with what it sent,
/// uppercased.
async fn shouting_service() -> SocketAddr {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = ln.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        s.write_all(&buf.to_ascii_uppercase()).await.unwrap();
    });
    addr
}

/// A loopback UDP echo service.
async fn udp_echo_service() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// Adds handlers that forward TCP and UDP to their destinations.
fn exit_node(b: ServerBuilder) -> ServerBuilder {
    b.on_tcp_forward(|dst| {
        Some(handler(move |c: TcpStream| async move {
            let os = tokio::net::TcpStream::connect(dst).await.unwrap();
            tailcat::proxy_conns(c, os).await;
        }))
    })
    .on_udp_forward(|dst| {
        Some(udp_handler(move |c: UdpConn| async move {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sock.connect(dst).await.unwrap();
            tailcat::proxy_packet_conns(&c, &sock, Duration::from_secs(5)).await;
        }))
    })
}

#[tokio::test]
async fn exit_node_forwards_tcp_and_udp() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    // Services reachable only through the exit node's own network.
    let tcp_addr = shouting_service().await;
    let udp_addr = udp_echo_service().await;
    let server = exit_node(builder(&dev)).start().await.unwrap();
    let client = Client::new(server.tailcat_addr());

    let c = client.dial_tcp(tcp_addr).await.unwrap();
    // IPv4 destinations ride the NAT64 prefix through the tunnel.
    assert!(matches!(c.peer_addr().ip(), IpAddr::V6(v6) if v6.segments()[..2] == [0x64, 0xff9b]));
    assert_eq!(request(c, b"through the exit").await, "THROUGH THE EXIT");

    let u = client.dial_udp(udp_addr).await.unwrap();
    udp_round_trip(&u, b"datagram").await;
    server.close();
}

#[cfg(unix)]
#[tokio::test]
async fn exec_handler_runs_a_command_per_connection() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = bare_server(&dev).await;
    let mut ln = server.listen_tcp(7).unwrap();
    let script = r#"printf '%s %s\n' "$TAILCAT_PEER_KEY" "$TAILCAT_LOCAL_ADDR"; tr a-z A-Z"#;
    let h = server.exec_conn_handler(["sh", "-c", script]);
    tokio::spawn(async move {
        while let Some(c) = ln.accept().await {
            tokio::spawn(h(c));
        }
    });
    let client = Client::new(server.tailcat_addr());

    let got = request(client.dial_tcp_port(7).await.unwrap(), b"shout").await;

    let local = server_addr(&server, 7);
    assert_eq!(got, format!("{} {local}\nSHOUT", client.public_key()));
    server.close();
}
