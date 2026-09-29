//! A DERP client that stays connected to one region, reconnecting with
//! backoff, and hands received packets to a channel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::client::TlsStream;
use tracing::{debug, trace, warn};

use super::{ClientInfo, FrameType, MAGIC, MAX_FRAME_SIZE, MAX_PACKET_SIZE, PROTOCOL_VERSION, ReceivedPacket};
use crate::derpmap::{DerpNode, DerpRegion};
use crate::key::{NodePrivate, NodePublic};
use crate::{Error, Result};

const DIAL_NODE_TIMEOUT: Duration = Duration::from_millis(1500);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The server sends keepalives every 60s; missing two means it's gone.
const READ_TIMEOUT: Duration = Duration::from_secs(130);
const OUT_QUEUE: usize = 512;

/// Opens a TLS connection to a DERP node, trying its addresses in turn.
pub async fn dial_tls(n: &DerpNode) -> Result<TlsStream<TcpStream>> {
    let port = n.derp_port();
    let addrs = n.resolve_addrs(port).await;
    if addrs.is_empty() {
        return Err(Error::Derp(format!("no addresses for DERP node {:?}", n.host_name)));
    }
    let mut last_err = None;
    for a in addrs {
        match tokio::time::timeout(DIAL_NODE_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(tcp)) => {
                let _ = tcp.set_nodelay(true);
                return tls_client(tcp, n).await;
            }
            Ok(Err(e)) => last_err = Some(format!("dial {a}: {e}")),
            Err(_) => last_err = Some(format!("dial {a}: timeout")),
        }
    }
    Err(Error::Derp(last_err.unwrap_or_default()))
}

async fn tls_client(tcp: TcpStream, n: &DerpNode) -> Result<TlsStream<TcpStream>> {
    let config = crate::tls::client_config_for_node(n)?;
    let server_name = crate::tls::server_name(&n.host_name)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Derp(format!("TLS handshake with {}: {e}", n.host_name)))
}

/// Performs the HTTP upgrade and DERP login on an established stream,
/// returning the server's key.
pub(crate) async fn login<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut BufReader<S>,
    host: &str,
    key: &NodePrivate,
    app_name: &str,
) -> Result<NodePublic> {
    let req = format!(
        "GET /derp HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tailcat-rs\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
    );
    s.get_mut().write_all(req.as_bytes()).await?;
    s.get_mut().flush().await?;

    let mut status = String::new();
    s.read_line(&mut status).await?;
    if !status.starts_with("HTTP/1.1 101") && !status.starts_with("HTTP/1.0 101") {
        return Err(Error::Derp(format!("DERP upgrade failed: {}", status.trim())));
    }
    loop {
        let mut line = String::new();
        if s.read_line(&mut line).await? == 0 {
            return Err(Error::Derp("EOF in DERP upgrade response".into()));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let (t, payload) = super::read_frame(s, 1 << 10).await?;
    if t != FrameType::ServerKey as u8 || payload.len() < 40 || &payload[..8] != MAGIC {
        return Err(Error::Derp("invalid DERP server greeting".into()));
    }
    let server_key = NodePublic::from_slice(&payload[8..40]).expect("32 bytes");

    let info = ClientInfo {
        version: PROTOCOL_VERSION,
        can_ack_pings: true,
        app_name: app_name.to_string(),
        ..Default::default()
    };
    let msg = serde_json::to_vec(&info).expect("ClientInfo serializes");
    let sealed = key.seal_to(&server_key, &msg);
    super::write_frame(s.get_mut(), FrameType::ClientInfo, &[key.public().as_bytes(), &sealed]).await?;
    Ok(server_key)
}

/// A handle to a background task that keeps a DERP connection to one
/// region alive. Dropping it closes the connection.
pub struct DerpClient {
    region_id: i32,
    out: mpsc::Sender<Vec<u8>>,
    connected: watch::Receiver<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DerpClient {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DerpClient {
    /// Starts connecting to `region` as `key`. Received packets go to
    /// `recv`. `preferred` marks this as the node's home region.
    pub fn spawn(
        region: DerpRegion,
        key: NodePrivate,
        app_name: &str,
        preferred: bool,
        recv: mpsc::Sender<ReceivedPacket>,
    ) -> Self {
        let (out_tx, out_rx) = mpsc::channel(OUT_QUEUE);
        let (conn_tx, conn_rx) = watch::channel(false);
        let app_name = if super::valid_app_name(app_name) { app_name.to_string() } else { String::new() };
        let region_id = region.region_id;
        let task = tokio::spawn(run(region, key, app_name, preferred, recv, out_rx, conn_tx));
        DerpClient { region_id, out: out_tx, connected: conn_rx, task }
    }

    /// The region this client connects to.
    pub fn region_id(&self) -> i32 {
        self.region_id
    }

    /// Queues a packet to `dst`. It reports false if the packet was
    /// dropped (not connected, queue full, or too big); DERP delivery is
    /// best effort anyway.
    pub fn send(&self, dst: &NodePublic, pkt: &[u8]) -> bool {
        if pkt.len() > MAX_PACKET_SIZE || !*self.connected.borrow() {
            return false;
        }
        let mut frame = Vec::with_capacity(5 + 32 + pkt.len());
        super::encode_frame(&mut frame, FrameType::SendPacket, &[dst.as_bytes(), pkt]);
        self.out.try_send(frame).is_ok()
    }

    /// Reports whether the client is currently logged in to the relay.
    pub fn is_connected(&self) -> bool {
        *self.connected.borrow()
    }

    /// Waits until connected, or `timeout` passes.
    pub async fn wait_connected(&self, timeout: Duration) -> bool {
        wait_connected(self.connected.clone(), timeout).await
    }

    /// Watches whether the client is connected.
    pub fn connected_watch(&self) -> watch::Receiver<bool> {
        self.connected.clone()
    }
}

/// Waits until a [`DerpClient::connected_watch`] says connected.
pub async fn wait_connected(mut rx: watch::Receiver<bool>, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, rx.wait_for(|c| *c)).await.is_ok_and(|r| r.is_ok())
}

async fn run(
    region: DerpRegion,
    key: NodePrivate,
    app_name: String,
    preferred: bool,
    recv: mpsc::Sender<ReceivedPacket>,
    mut out: mpsc::Receiver<Vec<u8>>,
    connected: watch::Sender<bool>,
) {
    let mut backoff = Duration::from_millis(100);
    loop {
        match connect_region(&region, &key, &app_name).await {
            Ok((stream, node)) => {
                debug!(region = region.region_id, node = %node, "derp: connected");
                backoff = Duration::from_millis(100);
                // Drop anything queued while we were disconnected.
                while out.try_recv().is_ok() {}
                connected.send_replace(true);
                let res = serve(stream, region.region_id, preferred, &recv, &mut out).await;
                connected.send_replace(false);
                match res {
                    Ok(()) => return, // the owner went away
                    Err(e) => debug!(region = region.region_id, "derp: connection lost: {e}"),
                }
            }
            Err(e) => {
                warn!(region = region.region_id, "derp: connect failed: {e}");
            }
        }
        if recv.is_closed() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

type Stream = BufReader<TlsStream<TcpStream>>;

async fn connect_region(region: &DerpRegion, key: &NodePrivate, app_name: &str) -> Result<(Stream, String)> {
    let mut last = Error::Derp(format!("no nodes in DERP region {}", region.region_id));
    for n in region.nodes.iter().filter(|n| !n.stun_only) {
        let attempt = async {
            let tls = dial_tls(n).await?;
            let mut s = BufReader::new(tls);
            let host =
                if n.derp_port() == 443 { n.host_name.clone() } else { format!("{}:{}", n.host_name, n.derp_port()) };
            login(&mut s, &host, key, app_name).await?;
            Ok::<_, Error>(s)
        };
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt).await {
            Ok(Ok(s)) => return Ok((s, n.host_name.clone())),
            Ok(Err(e)) => last = e,
            Err(_) => last = Error::Derp(format!("timeout connecting to {}", n.host_name)),
        }
    }
    Err(last)
}

/// Runs a logged-in connection until it fails (`Err`) or the packet
/// receiver is dropped (`Ok`).
async fn serve(
    stream: Stream,
    region_id: i32,
    preferred: bool,
    recv: &mpsc::Sender<ReceivedPacket>,
    out: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let (rd, wr) = tokio::io::split(stream);
    let mut rd = rd;
    let mut wr = BufWriter::new(wr);
    if preferred {
        super::write_frame(&mut wr, FrameType::NotePreferred, &[&[1]]).await?;
    }
    let (pong_tx, mut pong_rx) = mpsc::channel::<[u8; 8]>(8);

    let reader = async {
        loop {
            let (t, payload) = tokio::time::timeout(READ_TIMEOUT, super::read_frame(&mut rd, MAX_FRAME_SIZE))
                .await
                .map_err(|_| Error::Derp("read timeout".into()))??;
            match FrameType::from_u8(t) {
                Some(FrameType::RecvPacket) => {
                    if payload.len() < 32 {
                        return Err(Error::Derp("short recv packet frame".into()));
                    }
                    let src = NodePublic::from_slice(&payload[..32]).expect("32 bytes");
                    let pkt = ReceivedPacket { region_id, src, data: payload[32..].to_vec() };
                    if recv.send(pkt).await.is_err() {
                        return Ok(());
                    }
                }
                Some(FrameType::Ping) if payload.len() >= 8 => {
                    let mut d = [0u8; 8];
                    d.copy_from_slice(&payload[..8]);
                    let _ = pong_tx.try_send(d);
                }
                Some(FrameType::ServerInfo) => trace!("derp: got server info"),
                Some(FrameType::KeepAlive) => {}
                Some(FrameType::PeerGone) => {
                    if let Some(k) = payload.get(..32).and_then(NodePublic::from_slice) {
                        trace!(peer = %k.short_string(), "derp: peer gone");
                    }
                }
                Some(FrameType::Health) => {
                    if !payload.is_empty() {
                        warn!("derp: server says: {}", String::from_utf8_lossy(&payload));
                    }
                }
                Some(FrameType::Restarting) => {
                    debug!("derp: server restarting");
                }
                _ => {}
            }
        }
    };
    let writer = async {
        loop {
            tokio::select! {
                f = out.recv() => {
                    let Some(f) = f else { return Ok::<(), Error>(()) };
                    wr.write_all(&f).await?;
                    // Coalesce whatever else is queued before flushing.
                    while let Ok(f) = out.try_recv() {
                        wr.write_all(&f).await?;
                    }
                    wr.flush().await?;
                }
                p = pong_rx.recv() => {
                    if let Some(p) = p {
                        super::write_frame(&mut wr, FrameType::Pong, &[&p]).await?;
                    }
                }
            }
        }
    };
    tokio::select! {
        r = reader => r,
        r = writer => r,
    }
}

/// Resolves a node's addresses for callers that just need one.
pub async fn first_addr(n: &DerpNode) -> Option<SocketAddr> {
    n.resolve_addrs(n.derp_port()).await.into_iter().next()
}
