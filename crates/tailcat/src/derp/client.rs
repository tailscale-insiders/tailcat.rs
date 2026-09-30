//! A DERP client that stays connected to one region, reconnecting with
//! backoff, and hands received packets to a channel.

use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::client::TlsStream;
use tracing::{debug, trace, warn};

use super::{AppName, ClientInfo, FrameType, MAGIC, MAX_FRAME_SIZE, MAX_PACKET_SIZE, PROTOCOL_VERSION, ReceivedPacket};
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
    let host = node_host(n)?;
    let mut err = format!("no addresses for DERP node {host:?}");
    for a in n.resolve_addrs(n.derp_port()).await {
        match tokio::time::timeout(DIAL_NODE_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(tcp)) => {
                let _ = tcp.set_nodelay(true);
                let connector = tokio_rustls::TlsConnector::from(Arc::new(crate::tls::client_config_for_node(n)?));
                return connector
                    .connect(crate::tls::server_name(&host)?, tcp)
                    .await
                    .map_err(|e| Error::Derp(format!("TLS handshake with {host}: {e}")));
            }
            Ok(Err(e)) => err = format!("dial {a}: {e}"),
            Err(_) => err = format!("dial {a}: timeout"),
        }
    }
    Err(Error::Derp(err))
}

/// The name a node is dialed by, which it can't be without.
fn node_host(n: &DerpNode) -> Result<Cow<'_, str>> {
    n.host_name.dialable().ok_or_else(|| Error::Derp(format!("DERP node {} has no hostname", n.name)))
}

/// Performs the HTTP upgrade and DERP login on an established stream,
/// returning the server's key.
pub(crate) async fn login<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut BufReader<S>,
    host: &str,
    key: &NodePrivate,
    app_name: &AppName,
) -> Result<NodePublic> {
    let req = format!(
        "GET /derp HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tailcat-rs\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
    );
    s.get_mut().write_all(req.as_bytes()).await?;
    s.get_mut().flush().await?;

    let mut line = String::new();
    s.read_line(&mut line).await?;
    if !line.starts_with("HTTP/1.1 101") && !line.starts_with("HTTP/1.0 101") {
        return Err(Error::Derp(format!("DERP upgrade failed: {}", line.trim())));
    }
    // Skip the response headers.
    while !line.trim_end().is_empty() {
        line.clear();
        if s.read_line(&mut line).await? == 0 {
            return Err(Error::Derp("EOF in DERP upgrade response".into()));
        }
    }

    let (t, payload) = super::read_frame(s, 1 << 10).await?;
    let (server_key, _) = payload
        .strip_prefix(MAGIC)
        .and_then(super::split_key)
        .filter(|_| t == FrameType::ServerKey as u8)
        .ok_or_else(|| Error::Derp("invalid DERP server greeting".into()))?;

    let info =
        ClientInfo { version: PROTOCOL_VERSION, can_ack_pings: true, app_name: app_name.clone(), ..Default::default() };
    let sealed = key.seal_to(&server_key, &serde_json::to_vec(&info).expect("ClientInfo serializes"));
    super::write_frame(s.get_mut(), FrameType::ClientInfo, &[key.public().as_bytes(), &sealed]).await?;
    Ok(server_key)
}

/// A handle to a background task that keeps a DERP connection to one
/// region alive. Dropping it closes the connection.
pub struct DerpClient {
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
        app_name: &AppName,
        preferred: bool,
        recv: mpsc::Sender<ReceivedPacket>,
    ) -> Self {
        let (out, out_rx) = mpsc::channel(OUT_QUEUE);
        let (conn_tx, connected) = watch::channel(false);
        let app_name = if app_name.is_valid() { app_name.clone() } else { AppName::Unset };
        let task = tokio::spawn(run(region, key, app_name, preferred, recv, out_rx, conn_tx));
        DerpClient { out, connected, task }
    }

    /// Queues a packet to `dst`. It reports false if the packet was
    /// dropped (not connected, queue full, or too big); DERP delivery is
    /// best effort anyway.
    pub fn send(&self, dst: &NodePublic, pkt: &[u8]) -> bool {
        pkt.len() <= MAX_PACKET_SIZE
            && *self.connected.borrow()
            && self.out.try_send(super::frame(FrameType::SendPacket, &[dst.as_bytes(), pkt])).is_ok()
    }

    /// Returns a future that reports true once connected, or false when
    /// `timeout` passes first. The future doesn't borrow the client.
    pub fn wait_connected(&self, timeout: Duration) -> impl Future<Output = bool> + Send + 'static {
        let mut rx = self.connected.clone();
        async move { tokio::time::timeout(timeout, rx.wait_for(|c| *c)).await.is_ok_and(|r| r.is_ok()) }
    }
}

async fn run(
    region: DerpRegion,
    key: NodePrivate,
    app_name: AppName,
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
                let Err(e) = res else { return }; // the owner went away
                debug!(region = region.region_id, "derp: connection lost: {e}");
            }
            Err(e) => warn!(region = region.region_id, "derp: connect failed: {e}"),
        }
        if recv.is_closed() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

type Stream = BufReader<TlsStream<TcpStream>>;

async fn connect_region(region: &DerpRegion, key: &NodePrivate, app_name: &AppName) -> Result<(Stream, String)> {
    let mut last = Error::Derp(format!("no nodes in DERP region {}", region.region_id));
    for n in region.nodes.iter().filter(|n| !n.stun_only) {
        let host = n.host_name.text();
        let attempt = async {
            let mut s = BufReader::new(dial_tls(n).await?);
            let authority = if n.derp_port() == 443 { host.to_string() } else { format!("{host}:{}", n.derp_port()) };
            login(&mut s, &authority, key, app_name).await?;
            Ok::<_, Error>(s)
        };
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt).await {
            Ok(Ok(s)) => return Ok((s, host.into_owned())),
            Ok(Err(e)) => last = e,
            Err(_) => last = Error::Derp(format!("timeout connecting to {host}")),
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
    let (mut rd, wr) = tokio::io::split(stream);
    let mut wr = BufWriter::new(wr);
    if preferred {
        super::write_frame(&mut wr, FrameType::NotePreferred, &[&[1]]).await?;
    }
    let (pong_tx, mut pong_rx) = mpsc::channel::<[u8; 8]>(8);

    let reader = async {
        loop {
            let (t, mut payload) = tokio::time::timeout(READ_TIMEOUT, super::read_frame(&mut rd, MAX_FRAME_SIZE))
                .await
                .map_err(|_| Error::Derp("read timeout".into()))??;
            match FrameType::from_u8(t) {
                Some(FrameType::RecvPacket) => {
                    let (src, _) =
                        super::split_key(&payload).ok_or_else(|| Error::Derp("short recv packet frame".into()))?;
                    // The frame's own buffer, less the key, is the packet.
                    payload.drain(..crate::key::KEY_LEN);
                    if recv.send(ReceivedPacket { region_id, src, data: payload }).await.is_err() {
                        return Ok(());
                    }
                }
                Some(FrameType::Ping) => {
                    if let Some(d) = payload.first_chunk() {
                        let _ = pong_tx.try_send(*d);
                    }
                }
                Some(FrameType::PeerGone) => {
                    if let Some((k, _)) = super::split_key(&payload) {
                        trace!(peer = %k.short_string(), "derp: peer gone");
                    }
                }
                Some(FrameType::Health) if !payload.is_empty() => {
                    warn!("derp: server says: {}", String::from_utf8_lossy(&payload))
                }
                Some(FrameType::Restarting) => debug!("derp: server restarting"),
                _ => {}
            }
        }
    };
    let writer = async {
        loop {
            tokio::select! {
                f = out.recv() => {
                    let Some(f) = f else { return Ok::<(), Error>(()) };
                    super::write_queued(&mut wr, f, out).await?;
                }
                Some(p) = pong_rx.recv() => super::write_frame(&mut wr, FrameType::Pong, &[&p]).await?,
            }
        }
    };
    tokio::select! {
        r = reader => r,
        r = writer => r,
    }
}
