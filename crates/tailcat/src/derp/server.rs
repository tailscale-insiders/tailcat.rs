//! A small DERP relay server with a STUN responder, wire-compatible with
//! Tailscale's clients. It's used by the local development relay mode
//! (`TS_DEBUG_TAILCAT_LOCAL_DERP`), by tests, and by `tailcat dev-derp`.
//! It relays within one process only (no meshing) and applies no rate
//! limits, so it's not meant as a public relay.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, trace};

use super::{
    ClientInfo, FrameType, MAGIC, MAX_FRAME_SIZE, PEER_GONE_NOT_HERE, PROTOCOL_VERSION, ServerInfo, frame, split_key,
};
use crate::derpmap::{DerpNode, DerpRegion, NodeIp};
use crate::key::{NodePrivate, NodePublic};
use crate::{Error, Result};

const CLIENT_QUEUE: usize = 1024;
const KEEPALIVE: Duration = Duration::from_secs(60);
/// How long a client may take to send its HTTP request line and headers.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 10 });
/// The most bytes of request line and headers we read.
const MAX_REQUEST_SIZE: u64 = 16 << 10;

/// A connected client.
struct Client {
    /// Its send queue.
    tx: mpsc::Sender<Vec<u8>>,
    /// Closes its connection, when a newer one replaces it.
    close: Arc<Notify>,
}

/// The relay's state: its key and the connected clients.
pub struct Server {
    key: NodePrivate,
    clients: Mutex<HashMap<NodePublic, Client>>,
}

impl Server {
    /// Creates a relay with a fresh key.
    pub fn new() -> Arc<Self> {
        Arc::new(Server { key: NodePrivate::generate(), clients: Mutex::default() })
    }

    /// The relay's public key.
    pub fn public_key(&self) -> NodePublic {
        self.key.public()
    }

    /// Reports whether a client with key `k` is connected.
    pub fn is_client_connected(&self, k: &NodePublic) -> bool {
        self.clients.lock().unwrap().contains_key(k)
    }

    /// Serves TLS connections from `ln` until it fails.
    pub async fn serve_tls(self: Arc<Self>, ln: TcpListener, tls: Arc<rustls::ServerConfig>) {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        while let Ok((tcp, remote)) = ln.accept().await {
            let _ = tcp.set_nodelay(true);
            let s = self.clone();
            let accept = acceptor.accept(tcp);
            tokio::spawn(async move {
                match tokio::time::timeout(Duration::from_secs(10), accept).await {
                    Ok(Ok(tls)) => {
                        if let Err(e) = s.handle_http(tls, remote).await {
                            trace!("derp server: {remote}: {e}");
                        }
                    }
                    _ => trace!("derp server: {remote}: TLS handshake failed"),
                }
            });
        }
    }

    async fn handle_http<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: S, remote: SocketAddr) -> Result<()> {
        let mut br = BufReader::new(stream);
        let (path, upgrade, fast_start) = tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut br))
            .await
            .map_err(|_| Error::Derp("timeout reading HTTP request".into()))??;
        let canned: &[u8] = match path.as_str() {
            "/derp/probe" | "/derp/latency-check" => {
                b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            "/generate_204" => b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
            _ if !upgrade => {
                b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 32\r\nConnection: close\r\n\r\nDERP requires connection upgrade"
            }
            _ if !fast_start => {
                let resp = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: {PROTOCOL_VERSION}\r\nDerp-Public-Key: {}\r\n\r\n",
                    hex::encode(self.key.public().as_bytes())
                );
                // The server key frame that follows flushes this.
                br.get_mut().write_all(resp.as_bytes()).await?;
                return self.accept(br, remote).await;
            }
            _ => return self.accept(br, remote).await,
        };
        br.get_mut().write_all(canned).await?;
        Ok(br.get_mut().flush().await?)
    }

    async fn accept<S: AsyncRead + AsyncWrite + Unpin>(&self, mut br: BufReader<S>, remote: SocketAddr) -> Result<()> {
        super::write_frame(br.get_mut(), FrameType::ServerKey, &[MAGIC, self.key.public().as_bytes()]).await?;

        let (t, payload) = tokio::time::timeout(Duration::from_secs(10), super::read_frame(&mut br, 256 << 10))
            .await
            .map_err(|_| Error::Derp("timeout waiting for client info".into()))??;
        let (client, sealed) = split_key(&payload)
            .filter(|_| t == FrameType::ClientInfo as u8)
            .ok_or_else(|| Error::Derp("bad client info frame".into()))?;
        let msg =
            self.key.open_from(&client, sealed).ok_or_else(|| Error::Derp("cannot open client info box".into()))?;
        let info: ClientInfo = serde_json::from_slice(&msg).map_err(|error| Error::BadClientInfo { error })?;
        if !info.app_name.is_valid() {
            return Err(Error::Derp("invalid app name".into()));
        }

        let si = serde_json::to_vec(&ServerInfo { version: PROTOCOL_VERSION, ..Default::default() }).unwrap();
        super::write_frame(br.get_mut(), FrameType::ServerInfo, &[&self.key.seal_to(&client, &si)]).await?;

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CLIENT_QUEUE);
        let close = Arc::new(Notify::new());
        let old = self.clients.lock().unwrap().insert(client, Client { tx: tx.clone(), close: close.clone() });
        debug!("derp server: {remote} connected as {}", client.short_string());
        if let Some(old) = old {
            debug!("derp server: closing {}'s older connection", client.short_string());
            old.close.notify_one();
        }

        let (mut rd, wr) = tokio::io::split(br);
        let mut wr = BufWriter::new(wr);
        let reader = async {
            loop {
                let (t, payload) = super::read_frame(&mut rd, MAX_FRAME_SIZE).await?;
                match FrameType::from_u8(t) {
                    Some(FrameType::SendPacket) => {
                        let Some((dst, pkt)) = split_key(&payload) else { continue };
                        let to = self.clients.lock().unwrap().get(&dst).map(|d| d.tx.clone());
                        // Frames are dropped if the recipient is slow.
                        let _ = match to {
                            Some(to) => to.try_send(frame(FrameType::RecvPacket, &[client.as_bytes(), pkt])),
                            None => tx.try_send(frame(FrameType::PeerGone, &[dst.as_bytes(), &[PEER_GONE_NOT_HERE]])),
                        };
                    }
                    Some(FrameType::Ping) => {
                        if let Some(d) = payload.get(..8) {
                            let _ = tx.try_send(frame(FrameType::Pong, &[d]));
                        }
                    }
                    _ => {}
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        };
        let writer = async {
            let mut ka = tokio::time::interval_at(tokio::time::Instant::now() + KEEPALIVE, KEEPALIVE);
            loop {
                tokio::select! {
                    f = rx.recv() => {
                        let Some(f) = f else { return Ok::<(), Error>(()) };
                        super::write_queued(&mut wr, f, &mut rx).await?;
                    }
                    _ = ka.tick() => super::write_frame(&mut wr, FrameType::KeepAlive, &[]).await?,
                }
            }
        };
        let res = tokio::select! {
            r = reader => r,
            r = writer => r,
            _ = close.notified() => Err(Error::Derp("replaced by a newer connection".into())),
        };
        self.forget(&client, &tx);
        debug!("derp server: {} disconnected", client.short_string());
        res
    }

    /// Removes `client`, unless a newer connection with its key, which
    /// has another queue than `tx`, replaced it.
    fn forget(&self, client: &NodePublic, tx: &mpsc::Sender<Vec<u8>>) {
        let mut clients = self.clients.lock().unwrap();
        if clients.get(client).is_some_and(|c| c.tx.same_channel(tx)) {
            clients.remove(client);
        }
        drop(clients);
    }
}

/// Reads an HTTP request line and headers, returning the request's path
/// and whether it asks to upgrade to DERP, and to skip the upgrade
/// response.
async fn read_request<R: AsyncBufRead + Unpin>(r: R) -> Result<(String, bool, bool)> {
    let mut r = r.take(MAX_REQUEST_SIZE);
    let (mut path, mut upgrade, mut fast_start) = (None, false, false);
    let mut line = String::new();
    loop {
        line.clear();
        // A line cut short by EOF or the size limit is an error.
        if r.read_line(&mut line).await? == 0 || !line.ends_with('\n') {
            return Err(Error::Derp("bad HTTP request".into()));
        }
        let line = line.trim_end();
        if path.is_none() {
            path = Some(line.split_whitespace().nth(1).unwrap_or("").to_string());
        } else if line.is_empty() {
            return Ok((path.unwrap_or_default(), upgrade, fast_start));
        } else if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("upgrade") {
                upgrade = v.eq_ignore_ascii_case("derp");
            } else if k.eq_ignore_ascii_case(super::FAST_START_HEADER) {
                fast_start = v == "1";
            }
        }
    }
}

/// Answers STUN binding requests on `sock` forever.
pub async fn serve_stun(sock: UdpSocket) {
    let mut buf = [0u8; 1500];
    while let Ok((n, src)) = sock.recv_from(&mut buf).await {
        if let Some(tx) = crate::stun::parse_binding_request(&buf[..n]) {
            let _ = sock.send_to(&crate::stun::response(tx, src), src).await;
        }
    }
}

/// A running development relay: a DERP server and STUN responder on
/// local ports, with a region describing how to reach them.
pub struct DevDerp {
    pub server: Arc<Server>,
    /// A region naming this relay, with `InsecureForTests` set because
    /// its certificate is self-signed.
    pub region: DerpRegion,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for DevDerp {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl DevDerp {
    /// Starts a relay on `127.0.0.1` with OS-chosen ports.
    pub async fn start_local() -> Result<DevDerp> {
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        Self::start(local, local, None).await
    }

    /// Starts a relay listening for DERP (TLS) on `derp_addr` and STUN on
    /// `stun_addr`. The region advertises `advertise` (or the DERP
    /// listener's address) as the node's IP address.
    pub async fn start(derp_addr: SocketAddr, stun_addr: SocketAddr, advertise: Option<IpAddr>) -> Result<DevDerp> {
        let server = Server::new();
        let ln = TcpListener::bind(derp_addr).await?;
        let derp = ln.local_addr()?;
        let udp = UdpSocket::bind(stun_addr).await?;
        let stun_port = udp.local_addr()?.port();
        let tls = Arc::new(crate::tls::self_signed_server_config(&["T", "localhost"])?);
        let tasks = vec![tokio::spawn(server.clone().serve_tls(ln, tls)), tokio::spawn(serve_stun(udp))];
        // Clients aren't to try the other family.
        let (ipv4, ipv6) = match advertise.unwrap_or(derp.ip()) {
            ip @ IpAddr::V4(_) => (NodeIp::Addr(ip), NodeIp::Disabled),
            ip @ IpAddr::V6(_) => (NodeIp::Disabled, NodeIp::Addr(ip)),
        };
        let region = DerpRegion {
            region_id: 1,
            region_code: "D".into(),
            region_name: "Local dev relay".into(),
            nodes: vec![DerpNode {
                name: "t1".into(),
                region_id: 1,
                host_name: "T".into(),
                ipv4,
                ipv6,
                stun_port: stun_port as i32,
                derp_port: derp.port() as i32,
                insecure_for_tests: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        Ok(DevDerp { server, region, tasks })
    }

    /// Waits until a client with key `k` is connected, or `timeout` passes.
    pub async fn wait_for_client(&self, k: &NodePublic, timeout: Duration) -> bool {
        let connected = async {
            while !self.server.is_client_connected(k) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(timeout, connected).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{DuplexStream, duplex};
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::derp::client::{DerpClient, login};
    use crate::derp::{MAX_PACKET_SIZE, read_frame};

    const T: Duration = Duration::from_secs(5);
    const FAST_START: &str = "GET /derp HTTP/1.1\r\nUpgrade: DERP\r\nDerp-Fast-Start: 1\r\n\r\n";
    const PING: &[u8] = b"12345678";

    type Conn = BufReader<DuplexStream>;

    /// Waits for the next packet `rx` gets.
    async fn recv_within<P>(rx: &mut mpsc::Receiver<P>) -> P {
        timeout(T, rx.recv()).await.expect("nothing arrived").expect("channel closed")
    }

    /// Waits for `server` to unregister `key`.
    async fn wait_until_gone(server: &Server, key: &NodePublic) {
        let gone = async {
            while server.is_client_connected(key) {
                sleep(Duration::from_millis(10)).await;
            }
        };
        timeout(T, gone).await.expect("the client is still connected");
    }

    #[tokio::test]
    async fn relays_between_two_clients() {
        let dev = DevDerp::start_local().await.unwrap();
        let (a_tx, mut a_rx) = mpsc::channel(16);
        let (b_tx, mut b_rx) = mpsc::channel(16);
        let (ka, kb) = (NodePrivate::generate(), NodePrivate::generate());
        let a = DerpClient::spawn(dev.region.clone(), ka.clone(), &"test-a".into(), true, a_tx);
        // Nothing is queued before the connection is up.
        assert!(!a.send(&kb.public(), b"too early"));
        let b = DerpClient::spawn(dev.region.clone(), kb.clone(), &"test-b".into(), true, b_tx);
        assert!(a.wait_connected(T).await);
        assert!(b.wait_connected(T).await);
        assert!(dev.wait_for_client(&kb.public(), T).await);

        assert!(a.send(&kb.public(), b"hello b"));
        let got = recv_within(&mut b_rx).await;
        assert_eq!(got.src, ka.public());
        assert_eq!(got.region_id, 1);
        assert_eq!(got.data, b"hello b");

        assert!(b.send(&ka.public(), b"hi a"));
        let got = recv_within(&mut a_rx).await;
        assert_eq!(got.data, b"hi a");

        // Oversized packets are refused rather than truncated.
        let oversized = vec![0; MAX_PACKET_SIZE + 1];
        assert!(!a.send(&kb.public(), &oversized));

        // Dropping a client disconnects it from the relay.
        drop(b);
        wait_until_gone(&dev.server, &kb.public()).await;
    }

    /// Runs [`Server::handle_http`] on one end of an in-memory pipe and
    /// returns the other end, with `request` already written.
    async fn http(request: &str) -> (Arc<Server>, Conn) {
        let server = Server::new();
        let c = connect(&server, request).await;
        (server, c)
    }

    /// Like [`http`], on an existing server.
    async fn connect(server: &Arc<Server>, request: &str) -> Conn {
        let (near, far) = duplex(1 << 20);
        let s = server.clone();
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        tokio::spawn(async move { s.handle_http(far, peer).await });
        let mut near = BufReader::new(near);
        write(&mut near, request.as_bytes()).await;
        near
    }

    async fn write(c: &mut Conn, data: &[u8]) {
        c.get_mut().write_all(data).await.unwrap();
    }

    async fn next_frame(c: &mut Conn) -> (u8, Vec<u8>) {
        read_frame(c, 1 << 10).await.unwrap()
    }

    /// Reads until the server closes the connection.
    async fn read_until_closed(c: &mut Conn) -> Vec<u8> {
        let mut rest = Vec::new();
        timeout(T, c.read_to_end(&mut rest)).await.expect("the connection is still open").unwrap();
        rest
    }

    async fn response(request: &str) -> String {
        let (_server, mut c) = http(request).await;
        String::from_utf8(read_until_closed(&mut c).await).unwrap()
    }

    #[tokio::test]
    async fn answers_plain_http() {
        let probe = response("GET /derp/probe HTTP/1.1\r\n\r\n").await;
        let generate_204 = response("GET /generate_204 HTTP/1.1\r\n\r\n").await;
        let websocket = response("GET /derp HTTP/1.1\r\nUpgrade: websocket\r\n\r\n").await;

        assert!(probe.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(generate_204.starts_with("HTTP/1.1 204 "));
        assert!(websocket.starts_with("HTTP/1.1 426 "));
        assert!(websocket.ends_with("DERP requires connection upgrade"));
    }

    /// A request line or header that never ends, or headers that never
    /// finish, get the connection closed instead of held open.
    #[tokio::test]
    async fn gives_up_on_unfinished_requests() {
        let endless = "x".repeat(64 << 10);
        assert_eq!(response(&endless).await, "");
        assert_eq!(response(&format!("GET /derp HTTP/1.1\r\nX: {endless}")).await, "");
        assert_eq!(response("GET /derp HTTP/1.1\r\nUpgrade: DERP\r\n").await, "");
    }

    #[tokio::test]
    async fn fast_start_skips_the_upgrade_response() {
        let (server, mut c) = http(FAST_START).await;

        let (t, payload) = next_frame(&mut c).await;

        assert_eq!(t, FrameType::ServerKey as u8);
        assert_eq!(&payload[..8], MAGIC);
        assert_eq!(&payload[8..], server.public_key().as_bytes());
    }

    #[tokio::test]
    async fn answers_pings_and_reports_absent_peers() {
        let (server, mut c) = http("").await;
        let key = NodePrivate::generate();
        assert_eq!(login(&mut c, "T", &key, &"test".into()).await.unwrap(), server.public_key());
        let (t, sealed) = next_frame(&mut c).await;
        assert_eq!(t, FrameType::ServerInfo as u8);
        let opened = key.open_from(&server.public_key(), &sealed).unwrap();
        let info: ServerInfo = serde_json::from_slice(&opened).unwrap();
        assert_eq!(info.version, PROTOCOL_VERSION);
        assert!(server.is_client_connected(&key.public()));

        let stranger = NodePrivate::generate().public();
        write(&mut c, &frame(FrameType::SendPacket, &[stranger.as_bytes(), b"hello?"])).await;
        write(&mut c, &frame(FrameType::Ping, &[PING])).await;

        let (t, payload) = next_frame(&mut c).await;
        assert_eq!(t, FrameType::PeerGone as u8);
        assert_eq!(payload, [stranger.as_bytes().as_slice(), &[PEER_GONE_NOT_HERE]].concat());
        let (t, payload) = next_frame(&mut c).await;
        assert_eq!((t, payload.as_slice()), (FrameType::Pong as u8, PING));

        // Hanging up unregisters the client.
        drop(c);
        wait_until_gone(&server, &key.public()).await;
    }

    /// Connects to `server` and logs in as `key`.
    async fn logged_in(server: &Arc<Server>, key: &NodePrivate) -> Conn {
        let mut c = connect(server, "").await;
        login(&mut c, "T", key, &"test".into()).await.unwrap();
        let (t, _) = next_frame(&mut c).await;
        assert_eq!(t, FrameType::ServerInfo as u8);
        c
    }

    /// A client that connects again with the same key replaces its older
    /// connection, which the relay closes.
    #[tokio::test]
    async fn a_new_connection_replaces_the_old_one() {
        let server = Server::new();
        let key = NodePrivate::generate();
        let mut old = logged_in(&server, &key).await;
        let mut new = logged_in(&server, &key).await;

        read_until_closed(&mut old).await;

        assert!(server.is_client_connected(&key.public()));
        write(&mut new, &frame(FrameType::Ping, &[PING])).await;
        let (t, payload) = next_frame(&mut new).await;
        assert_eq!((t, payload.as_slice()), (FrameType::Pong as u8, PING));
    }

    #[tokio::test]
    async fn rejects_a_bad_client_info_box() {
        let (server, mut c) = http(FAST_START).await;
        next_frame(&mut c).await;
        let key = NodePrivate::generate();
        // Sealed to the wrong key, so the server can't open it.
        let sealed = key.seal_to(&key.public(), b"{}");

        write(&mut c, &frame(FrameType::ClientInfo, &[key.public().as_bytes(), &sealed])).await;

        assert!(read_until_closed(&mut c).await.is_empty());
        assert!(!server.is_client_connected(&key.public()));
    }
}
