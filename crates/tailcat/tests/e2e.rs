//! End-to-end tests: a server and clients in one process, meeting through
//! a local DERP relay.

use std::time::Duration;

use tailcat::derp::server::DevDerp;
use tailcat::{Client, ClientOptions, KeySet, NodePrivate, Server, TcpStream, UdpConn, handler, udp_handler};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn init() {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).try_init();
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
    let mut buf = [0u8; 64];
    let mut ok = false;
    for _ in 0..10 {
        u.send(b"hello udp").await.unwrap();
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(1), u.recv(&mut buf)).await {
            assert_eq!(&buf[..n], b"hello udp");
            ok = true;
            break;
        }
    }
    assert!(ok, "no UDP echo");

    let st = server.status();
    assert_eq!(st.peers.len(), 1);
    assert_eq!(st.peers[0].key, client.public_key());
    assert_eq!(server.peer_key(std::net::SocketAddr::new(client.public_key().tailcat_ip().into(), 1)), Some(client.public_key()));
    server.close();
}

#[tokio::test]
async fn allowlist_rejects_strangers() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let allowed = NodePrivate::generate();
    let allow = KeySet::default();
    allow.add(allowed.public());
    let server = Server::builder()
        .region(dev.region.clone())
        .allow_client(allow.checker())
        .on_tcp(|_| Some(handler(|mut c: TcpStream| async move {
            let _ = c.write_all(b"hi").await;
        })))
        .start()
        .await
        .unwrap();
    let addr = server.tailcat_addr();

    let stranger = Client::new(addr.clone());
    assert!(stranger.ping().await.is_err(), "stranger was admitted");

    let friend = Client::with_options(addr, ClientOptions { key: Some(allowed), ..Default::default() });
    friend.ping().await.unwrap();
    let mut c = friend.dial_tcp_port(1).await.unwrap();
    let mut s = String::new();
    c.read_to_string(&mut s).await.unwrap();
    assert_eq!(s, "hi");
    assert!(server.disconnect_client(&friend.public_key()));
    assert!(!server.disconnect_client(&friend.public_key()));
    server.close();
}

#[tokio::test]
async fn listeners_take_precedence() {
    init();
    let dev = DevDerp::start_local().await.unwrap();
    let server = Server::builder().region(dev.region.clone()).start().await.unwrap();
    let mut ln = server.listen_tcp(8080).unwrap();
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
}
