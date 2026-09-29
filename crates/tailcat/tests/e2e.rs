//! End-to-end tests: a server and clients in one process, meeting through
//! a local DERP relay.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tailcat::derp::server::DevDerp;
use tailcat::{
    Client, ClientOptions, KeySet, NodePrivate, PortRange, Server, TcpStream, UdpConn, handler, udp_handler,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn init() {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).try_init();
}

/// Sends `msg` on `u` until it's echoed back; the first datagrams can be
/// lost while the tunnel comes up.
async fn udp_round_trip(u: &UdpConn, msg: &[u8]) {
    let mut buf = [0u8; 64];
    for _ in 0..10 {
        u.send(msg).await.unwrap();
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(1), u.recv(&mut buf)).await {
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
    tokio::time::timeout(Duration::from_secs(20), c.read_to_string(&mut s)).await.unwrap().unwrap();
    s
}

async fn echo_server(dev: &DevDerp) -> Server {
    Server::builder()
        .region(dev.region.clone())
        .on_tcp(|port| {
            if port == 81 {
                return None;
            }
            Some(handler(move |mut c: TcpStream| async move {
                let mut buf = Vec::new();
                c.read_to_end(&mut buf).await.unwrap();
                c.write_all(format!("port {port}: ").as_bytes()).await.unwrap();
                c.write_all(&buf).await.unwrap();
                c.shutdown().await.unwrap();
                c.drain(Duration::from_secs(5)).await;
            }))
        })
        .on_udp(|_port| {
            Some(udp_handler(|c: UdpConn| async move {
                let mut buf = [0u8; 2048];
                while let Ok(n) = c.recv(&mut buf).await {
                    let _ = c.send(&buf[..n]).await;
                }
            }))
        })
        .start()
        .await
        .unwrap()
}

#[tokio::test]
async fn tcp_and_udp_over_local_derp() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = echo_server(&dev).await;
    let addr = server.tailcat_addr();
    assert!(addr.as_str().starts_with("tc"));

    let client = Client::new(addr.clone());
    let pong = tokio::time::timeout(Duration::from_secs(15), client.ping()).await.unwrap().unwrap();
    assert!(pong.latency < Duration::from_secs(10));

    let mut c = tokio::time::timeout(Duration::from_secs(20), client.dial_tcp_port(80)).await.unwrap().unwrap();
    let payload = vec![7u8; 200_000];
    c.write_all(&payload).await.unwrap();
    c.shutdown().await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), c.read_to_end(&mut got)).await.unwrap().unwrap();
    assert!(got.starts_with(b"port 80: "));
    assert_eq!(got.len(), 9 + payload.len());

    // A port with no handler answers with a RST.
    let err = tokio::time::timeout(Duration::from_secs(20), client.dial_tcp_port(81)).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);

    let u = client.dial_udp_port(53).await.unwrap();
    udp_round_trip(&u, b"hello udp").await;

    let dp = client.disco_ping(Duration::from_secs(5)).await.unwrap();
    if dp.endpoint.is_none() {
        assert_eq!(dp.derp_region_id, dev.region.region_id);
        assert_eq!(dp.derp_region_code, dev.region.region_code);
    }

    let st = server.status();
    assert_eq!(st.peers.len(), 1);
    assert_eq!(st.peers[0].key, client.public_key());
    assert_eq!(st.peers[0].tailcat_ip, client.public_key().tailcat_ip());
    let peer = SocketAddr::new(client.public_key().tailcat_ip().into(), 1);
    assert_eq!(server.peer_key(peer), Some(client.public_key()));
    assert_eq!(server.peer_key(SocketAddr::new(server.addr().into(), 1)), None);
    assert_eq!(server.peer_key("127.0.0.1:1".parse().unwrap()), None);
    assert!(client.drain_tcp(Duration::from_secs(5)).await);
    server.close();
}

#[tokio::test]
async fn allowlist_rejects_strangers() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let allowed = NodePrivate::generate();
    let friend_key = allowed.clone();
    let allow = KeySet::default();
    allow.add(allowed.public());
    let server = Server::builder()
        .region(dev.region.clone())
        .allow_client(allow.checker())
        .on_tcp(|_| {
            Some(handler(|mut c: TcpStream| async move {
                let _ = c.write_all(b"hi").await;
            }))
        })
        .start()
        .await
        .unwrap();
    let addr = server.tailcat_addr();

    let stranger = Client::new(addr.clone());
    assert!(stranger.ping().await.is_err(), "stranger was admitted");

    let friend = Client::with_options(addr, ClientOptions { key: Some(friend_key), ..Default::default() });
    friend.ping().await.unwrap();
    let mut c = friend.dial_tcp_port(1).await.unwrap();
    let mut s = String::new();
    c.read_to_string(&mut s).await.unwrap();
    assert_eq!(s, "hi");
    assert_eq!(server.status().peers.len(), 1);
    assert!(server.disconnect_client(&friend.public_key()));
    assert!(!server.disconnect_client(&friend.public_key()));
    assert!(server.status().peers.is_empty());
    assert_eq!(server.peer_key(c.local_addr()), None);

    // A new client with the allowed key gets back in.
    drop((c, friend));
    let again = Client::with_options(server.tailcat_addr(), ClientOptions { key: Some(allowed), ..Default::default() });
    again.ping().await.unwrap();
    assert_eq!(server.status().peers.len(), 1);
    server.close();
}

#[tokio::test]
async fn listeners_take_precedence() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = Server::builder().region(dev.region.clone()).start().await.unwrap();
    let mut ln = server.listen_tcp(8080).unwrap();
    assert_eq!(ln.local_addr(), SocketAddr::new(server.addr().into(), 8080));
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
    let mut s = String::new();
    c.read_to_string(&mut s).await.unwrap();
    assert_eq!(s, "from listener");
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
    let server = Server::builder()
        .region(dev.region.clone())
        .udp_idle_timeout(Duration::from_millis(300))
        .start()
        .await
        .unwrap();
    let mut ln = server.listen_udp(9).unwrap();
    let client = Client::new(server.tailcat_addr());
    let u = client.dial_udp_port(9).await.unwrap();
    let flow = loop {
        u.send(b"x").await.unwrap();
        if let Ok(Some(f)) = tokio::time::timeout(Duration::from_secs(1), ln.accept()).await {
            break f;
        }
    };
    assert_eq!(flow.local_addr(), SocketAddr::new(server.addr().into(), 9));
    assert_eq!(flow.peer_addr(), SocketAddr::new(client.public_key().tailcat_ip().into(), u.local_addr().port()));
    assert_eq!(server.peer_key(flow.peer_addr()), Some(client.public_key()));

    // With the client quiet, the flow closes after the idle timeout.
    let mut buf = [0u8; 16];
    let err = loop {
        match tokio::time::timeout(Duration::from_secs(5), flow.recv(&mut buf)).await.unwrap() {
            Ok(_) => continue,
            Err(e) => break e,
        }
    };
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn served_ports_filter_silently() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = Server::builder()
        .region(dev.region.clone())
        .served_tcp_ports(vec![PortRange::single(80)])
        .on_tcp(|_| {
            Some(handler(|mut c: TcpStream| async move {
                let _ = c.write_all(b"ok").await;
            }))
        })
        .start()
        .await
        .unwrap();
    let client = Client::new(server.tailcat_addr());
    assert_eq!(request(client.dial_tcp_port(80).await.unwrap(), b"").await, "ok");
    // A filtered port neither answers nor refuses.
    let filtered = tokio::time::timeout(Duration::from_secs(1), client.dial_tcp_port(81)).await;
    assert!(filtered.is_err(), "filtered port answered: {filtered:?}");
    server.close();
}

#[tokio::test]
async fn exit_node_forwards_tcp_and_udp() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    // Services reachable only through the exit node's own network.
    let tcp_svc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_svc.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = tcp_svc.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        s.write_all(&buf.to_ascii_uppercase()).await.unwrap();
    });
    let udp_svc = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp_svc.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = udp_svc.recv_from(&mut buf).await {
            let _ = udp_svc.send_to(&buf[..n], from).await;
        }
    });

    let server = Server::builder()
        .region(dev.region.clone())
        .on_tcp_forward(|dst| {
            Some(handler(move |c: TcpStream| async move {
                let os = tokio::net::TcpStream::connect(dst).await.unwrap();
                tailcat::proxy_conns(c, os).await;
            }))
        })
        .on_udp_forward(|dst| {
            Some(udp_handler(move |c: UdpConn| async move {
                let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                sock.connect(dst).await.unwrap();
                tailcat::proxy_packet_conns(&c, &sock, Duration::from_secs(5)).await;
            }))
        })
        .start()
        .await
        .unwrap();
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
    let server = Server::builder().region(dev.region.clone()).start().await.unwrap();
    let mut ln = server.listen_tcp(7).unwrap();
    let h = server.exec_conn_handler(
        ["sh", "-c", r#"printf '%s %s\n' "$TAILCAT_PEER_KEY" "$TAILCAT_LOCAL_ADDR"; tr a-z A-Z"#]
            .map(String::from)
            .to_vec(),
    );
    tokio::spawn(async move {
        while let Some(c) = ln.accept().await {
            tokio::spawn(h(c));
        }
    });
    let client = Client::new(server.tailcat_addr());
    let got = request(client.dial_tcp_port(7).await.unwrap(), b"shout").await;
    let local = SocketAddr::new(server.addr().into(), 7);
    assert_eq!(got, format!("{} {local}\nSHOUT", client.public_key()));
    server.close();
}
