//! A small DERP relay server with a STUN responder, wire-compatible with
//! Tailscale's clients. It's used by the local development relay mode
//! (`TS_DEBUG_TAILCAT_LOCAL_DERP`), by tests, and by `tailcat dev-derp`.
//! It relays within one process only (no meshing) and applies no rate
//! limits, so it's not meant as a public relay.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::{ClientInfo, FrameType, MAGIC, MAX_FRAME_SIZE, PEER_GONE_NOT_HERE, PROTOCOL_VERSION, ServerInfo};
use crate::derpmap::{DerpNode, DerpRegion};
use crate::key::{NodePrivate, NodePublic};
use crate::{Error, Result};

const CLIENT_QUEUE: usize = 1024;
const KEEPALIVE: Duration = Duration::from_secs(60);

struct Slot {
    id: u64,
    tx: mpsc::Sender<Vec<u8>>,
}

/// The relay's state: its key and the connected clients.
pub struct Server {
    key: NodePrivate,
    clients: Mutex<HashMap<NodePublic, Slot>>,
    next_id: AtomicU64,
}

impl Server {
    /// Creates a relay with a fresh key.
    pub fn new() -> Arc<Self> {
        Arc::new(Server { key: NodePrivate::generate(), clients: Mutex::default(), next_id: AtomicU64::new(1) })
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
        loop {
            let Ok((tcp, remote)) = ln.accept().await else { return };
            let _ = tcp.set_nodelay(true);
            let s = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
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
        let mut request_line = String::new();
        br.read_line(&mut request_line).await?;
        let path = request_line.split_whitespace().nth(1).unwrap_or("").to_string();
        let mut upgrade = String::new();
        let mut fast_start = false;
        let mut total = 0;
        loop {
            let mut line = String::new();
            let n = br.read_line(&mut line).await?;
            total += n;
            if n == 0 || total > 16 << 10 {
                return Err(Error::Derp("bad HTTP request".into()));
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim();
                if k.eq_ignore_ascii_case("upgrade") {
                    upgrade = v.to_ascii_lowercase();
                } else if k.eq_ignore_ascii_case(super::FAST_START_HEADER) {
                    fast_start = v == "1";
                }
            }
        }
        let w = br.get_mut();
        match path.as_str() {
            "/derp/probe" | "/derp/latency-check" => {
                w.write_all(
                    b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
                w.flush().await?;
                return Ok(());
            }
            "/generate_204" => {
                w.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
                w.flush().await?;
                return Ok(());
            }
            _ => {}
        }
        if upgrade != "derp" {
            w.write_all(
                b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 32\r\nConnection: close\r\n\r\nDERP requires connection upgrade",
            )
            .await?;
            w.flush().await?;
            return Ok(());
        }
        if !fast_start {
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: {PROTOCOL_VERSION}\r\nDerp-Public-Key: {}\r\n\r\n",
                hex::encode(self.key.public().as_bytes())
            );
            w.write_all(resp.as_bytes()).await?;
            w.flush().await?;
        }
        self.accept(br, remote).await
    }

    async fn accept<S: AsyncRead + AsyncWrite + Unpin>(&self, mut br: BufReader<S>, remote: SocketAddr) -> Result<()> {
        let mut greeting = MAGIC.to_vec();
        greeting.extend_from_slice(self.key.public().as_bytes());
        super::write_frame(br.get_mut(), FrameType::ServerKey, &[&greeting]).await?;

        let (t, payload) = tokio::time::timeout(Duration::from_secs(10), super::read_frame(&mut br, 256 << 10))
            .await
            .map_err(|_| Error::Derp("timeout waiting for client info".into()))??;
        if t != FrameType::ClientInfo as u8 || payload.len() < 32 + 24 {
            return Err(Error::Derp("bad client info frame".into()));
        }
        let client = NodePublic::from_slice(&payload[..32]).expect("32 bytes");
        let msg = self
            .key
            .open_from(&client, &payload[32..])
            .ok_or_else(|| Error::Derp("cannot open client info box".into()))?;
        let info: ClientInfo = serde_json::from_slice(&msg).map_err(|e| Error::Derp(format!("client info: {e}")))?;
        if !super::valid_app_name(&info.app_name) {
            return Err(Error::Derp("invalid app name".into()));
        }

        let si = serde_json::to_vec(&ServerInfo { version: PROTOCOL_VERSION, ..Default::default() }).unwrap();
        let sealed = self.key.seal_to(&client, &si);
        super::write_frame(br.get_mut(), FrameType::ServerInfo, &[&sealed]).await?;

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CLIENT_QUEUE);
        self.clients.lock().unwrap().insert(client, Slot { id, tx: tx.clone() });
        debug!("derp server: {remote} connected as {}", client.short_string());

        let (mut rd, wr) = tokio::io::split(br);
        let mut wr = BufWriter::new(wr);
        let reader = async {
            loop {
                let (t, payload) = super::read_frame(&mut rd, MAX_FRAME_SIZE).await?;
                match FrameType::from_u8(t) {
                    Some(FrameType::SendPacket) if payload.len() >= 32 => {
                        let dst = NodePublic::from_slice(&payload[..32]).expect("32 bytes");
                        let dst_tx = self.clients.lock().unwrap().get(&dst).map(|s| s.tx.clone());
                        match dst_tx {
                            Some(dtx) => {
                                let mut f = Vec::with_capacity(5 + payload.len());
                                super::encode_frame(
                                    &mut f,
                                    FrameType::RecvPacket,
                                    &[client.as_bytes(), &payload[32..]],
                                );
                                let _ = dtx.try_send(f); // drop if the recipient is slow
                            }
                            None => {
                                let mut f = Vec::new();
                                super::encode_frame(
                                    &mut f,
                                    FrameType::PeerGone,
                                    &[dst.as_bytes(), &[PEER_GONE_NOT_HERE]],
                                );
                                let _ = tx.try_send(f);
                            }
                        }
                    }
                    Some(FrameType::Ping) if payload.len() >= 8 => {
                        let mut f = Vec::new();
                        super::encode_frame(&mut f, FrameType::Pong, &[&payload[..8]]);
                        let _ = tx.try_send(f);
                    }
                    _ => {}
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        };
        let writer = async {
            let mut ka = tokio::time::interval(KEEPALIVE);
            ka.tick().await;
            loop {
                tokio::select! {
                    f = rx.recv() => {
                        let Some(f) = f else { return Ok::<(), Error>(()) };
                        wr.write_all(&f).await?;
                        while let Ok(f) = rx.try_recv() {
                            wr.write_all(&f).await?;
                        }
                        wr.flush().await?;
                    }
                    _ = ka.tick() => {
                        super::write_frame(&mut wr, FrameType::KeepAlive, &[]).await?;
                    }
                }
            }
        };
        let res = tokio::select! {
            r = reader => r,
            r = writer => r,
        };
        let mut clients = self.clients.lock().unwrap();
        if clients.get(&client).is_some_and(|s| s.id == id) {
            clients.remove(&client);
        }
        debug!("derp server: {} disconnected", client.short_string());
        res
    }
}

/// Answers STUN binding requests on `sock` forever.
pub async fn serve_stun(sock: UdpSocket) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, src)) = sock.recv_from(&mut buf).await else { return };
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
        Self::start(SocketAddr::from(([127, 0, 0, 1], 0)), SocketAddr::from(([127, 0, 0, 1], 0)), None).await
    }

    /// Starts a relay listening for DERP (TLS) on `derp_addr` and STUN on
    /// `stun_addr`. The region advertises `advertise` (or the DERP
    /// listener's address) as the node's IPv4 address.
    pub async fn start(derp_addr: SocketAddr, stun_addr: SocketAddr, advertise: Option<IpAddr>) -> Result<DevDerp> {
        let server = Server::new();
        let ln = TcpListener::bind(derp_addr).await?;
        let derp_port = ln.local_addr()?.port();
        let udp = UdpSocket::bind(stun_addr).await?;
        let stun_port = udp.local_addr()?.port();
        let ip = advertise.unwrap_or_else(|| ln.local_addr().map(|a| a.ip()).unwrap_or(derp_addr.ip()));
        let tls = Arc::new(crate::tls::self_signed_server_config(&["T", "localhost"])?);
        let tasks = vec![tokio::spawn(server.clone().serve_tls(ln, tls)), tokio::spawn(serve_stun(udp))];
        let (ipv4, ipv6) = match ip {
            IpAddr::V4(v4) => (v4.to_string(), "none".to_string()),
            IpAddr::V6(v6) => ("none".to_string(), v6.to_string()),
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
                // "none" tells clients not to try the other family.
                ipv6,
                stun_port: stun_port as i32,
                derp_port: derp_port as i32,
                insecure_for_tests: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        Ok(DevDerp { server, region, tasks })
    }

    /// Waits until a client with key `k` is connected, or `timeout` passes.
    pub async fn wait_for_client(&self, k: &NodePublic, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.server.is_client_connected(k) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derp::client::DerpClient;

    #[tokio::test]
    async fn relays_between_two_clients() {
        let dev = DevDerp::start_local().await.unwrap();
        let (a_tx, mut a_rx) = mpsc::channel(16);
        let (b_tx, mut b_rx) = mpsc::channel(16);
        let ka = NodePrivate::generate();
        let kb = NodePrivate::generate();
        let a = DerpClient::spawn(dev.region.clone(), ka.clone(), "test-a", true, a_tx);
        let b = DerpClient::spawn(dev.region.clone(), kb.clone(), "test-b", true, b_tx);
        assert!(a.wait_connected(Duration::from_secs(5)).await);
        assert!(b.wait_connected(Duration::from_secs(5)).await);
        assert!(dev.wait_for_client(&kb.public(), Duration::from_secs(5)).await);

        assert!(a.send(&kb.public(), b"hello b"));
        let got = tokio::time::timeout(Duration::from_secs(5), b_rx.recv()).await.unwrap().unwrap();
        assert_eq!(got.src, ka.public());
        assert_eq!(got.data, b"hello b");

        assert!(b.send(&ka.public(), b"hi a"));
        let got = tokio::time::timeout(Duration::from_secs(5), a_rx.recv()).await.unwrap().unwrap();
        assert_eq!(got.data, b"hi a");
    }
}
