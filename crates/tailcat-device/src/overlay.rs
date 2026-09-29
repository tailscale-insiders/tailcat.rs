//! The mesh overlay: one WireGuard engine per node, carrying IP packets
//! between a packet device (normally a TUN interface) and every peer.
//!
//! The mesh is symmetric: every peer is known in advance from its node
//! record, so there's no client/server join handshake. Each node keeps a
//! DERP connection to its home region for rendezvous and relaying, and
//! upgrades to direct UDP paths through the same disco-based NAT
//! traversal as tailcat.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use tailcat::magicsock::{self, MagicSock};
use tailcat::wg::{self, Engine, InboundPacket, IpNet};
use tailcat::{DerpMap, NodePublic, PresharedKey};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::record::{DeviceKey, NodeRecord};

/// Something that carries raw IP packets: a TUN device, or a channel in
/// tests.
pub trait PacketDevice: Send + Sync + 'static {
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    fn send(&self, pkt: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

impl PacketDevice for tun_rs::AsyncDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        tun_rs::AsyncDevice::recv(self, buf).await
    }
    async fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        tun_rs::AsyncDevice::send(self, pkt).await
    }
}

/// Overlay configuration.
pub struct OverlayConfig {
    pub key: DeviceKey,
    /// Regions to rendezvous in; each record names its home region here
    /// (or embeds its own).
    pub derp_map: DerpMap,
    /// The UDP port for direct paths (0 picks one).
    pub listen_port: u16,
    /// The overlay network; its addresses are never advertised as
    /// endpoints for direct paths.
    pub overlay_prefix: IpNet,
    /// Whether to try direct UDP paths (else DERP only).
    pub enable_udp: bool,
}

/// A peer's status.
#[derive(Debug, Clone, Serialize)]
pub struct PeerStatus {
    pub index: u32,
    pub nodekey: NodePublic,
    pub overlay_ip: IpAddr,
    /// The direct UDP path in use, if any.
    pub direct: Option<SocketAddr>,
    /// The DERP region relaying traffic when there's no direct path.
    pub derp_region: i32,
    /// Seconds since the last WireGuard handshake, if any.
    pub handshake_age_secs: Option<u64>,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
}

/// A running overlay node.
pub struct Overlay {
    me: NodeRecord,
    ms: Arc<MagicSock>,
    engine: Arc<Engine>,
    peers: Mutex<HashMap<NodePublic, NodeRecord>>,
    inbound: Mutex<Option<mpsc::Receiver<InboundPacket>>>,
}

impl Overlay {
    /// Starts the node: connects to its home DERP region and brings up
    /// the WireGuard engine. Peers are added with [`Overlay::add_peer`]
    /// and packets flow once [`Overlay::run`] is given a device.
    pub async fn start(cfg: OverlayConfig) -> Result<Arc<Overlay>> {
        let me = cfg.key.record.clone();
        let home = me
            .home_region(&cfg.derp_map)
            .ok_or_else(|| anyhow!("home DERP region {} is not in the DERP map", me.derp_region))?;
        let mut dm = cfg.derp_map.clone();
        dm.regions.insert(home.region_id, home.clone());
        let prefix = cfg.overlay_prefix;
        let filter: magicsock::EndpointFilter = Arc::new(move |ip| !prefix.contains(&ip));
        let (ms, wg_rx) = MagicSock::start(magicsock::Config {
            private_key: cfg.key.private.clone(),
            derp_map: dm,
            home_region: home.region_id,
            derp_app_name: "tailcat-device".into(),
            listen_port: cfg.listen_port,
            on_derp_recv: None,
            endpoint_filter: Some(filter),
            enable_udp: cfg.enable_udp,
        })
        .await
        .context("starting magicsock")?;
        let (engine, inbound) = Engine::start(&cfg.key.private, ms.clone(), wg_rx, None, None);
        info!(overlay_ip = %me.overlay_ip, region = home.region_id, "overlay: node {} up as {}", me.index, me.nodekey.short_string());
        Ok(Arc::new(Overlay { me, ms, engine, peers: Mutex::default(), inbound: Mutex::new(Some(inbound)) }))
    }

    /// This node's record.
    pub fn record(&self) -> &NodeRecord {
        &self.me
    }

    /// The path manager, for diagnostics.
    pub fn magicsock(&self) -> &Arc<MagicSock> {
        &self.ms
    }

    /// Waits until the home DERP connection is up.
    pub async fn wait_derp(&self, timeout: Duration) -> bool {
        self.ms.wait_derp_connected(timeout).await
    }

    /// Adds or updates a peer from its record. Our own record is ignored.
    /// It reports whether the peer was new.
    pub fn add_peer(&self, r: &NodeRecord, dm: &DerpMap) -> Result<bool> {
        if r.nodekey == self.me.nodekey {
            return Ok(false);
        }
        let region = r
            .home_region(dm)
            .ok_or_else(|| anyhow!("peer {}: DERP region {} is not in the DERP map", r.index, r.derp_region))?;
        self.ms.add_region(region.clone());
        let new = {
            let mut peers = self.peers.lock().unwrap();
            if peers.get(&r.nodekey) == Some(r) {
                return Ok(false);
            }
            // An address may only belong to one peer.
            if let Some((k, _)) = peers.iter().find(|(k, p)| p.overlay_ip == r.overlay_ip && **k != r.nodekey) {
                let k = *k;
                peers.remove(&k);
                self.engine.remove_peer(&k);
                self.ms.remove_peer(&k);
            }
            peers.insert(r.nodekey, r.clone()).is_none()
        };
        self.ms.upsert_peer(magicsock::PeerConfig {
            node_key: r.nodekey,
            disco_key: r.discokey,
            home_region: region.region_id,
            endpoints: r.endpoints.clone(),
        });
        self.engine.upsert_peer(
            r.nodekey,
            wg::PeerConfig {
                allowed_ips: r.allowed_ips(),
                preshared_key: PresharedKey::default(),
                persistent_keepalive: None,
            },
        );
        if new {
            info!(peer = r.index, overlay_ip = %r.overlay_ip, "overlay: added peer {}", r.nodekey.short_string());
            self.ms.send_call_me_maybe(&r.nodekey);
        }
        Ok(new)
    }

    /// Removes a peer.
    pub fn remove_peer(&self, k: &NodePublic) -> bool {
        let removed = self.peers.lock().unwrap().remove(k).is_some();
        if removed {
            self.engine.remove_peer(k);
            self.ms.remove_peer(k);
        }
        removed
    }

    /// The number of peers.
    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    /// Carries packets between `dev` and the peers until either fails.
    /// It can be called once.
    pub async fn run<D: PacketDevice>(self: Arc<Self>, dev: Arc<D>) -> Result<()> {
        let mut inbound = self.inbound.lock().unwrap().take().ok_or_else(|| anyhow!("Overlay::run called twice"))?;
        let up = {
            let dev = dev.clone();
            let engine = self.engine.clone();
            async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = dev.recv(&mut buf).await?;
                    if n > 0 {
                        engine.send_ip(&buf[..n]);
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), io::Error>(())
            }
        };
        let down = async move {
            while let Some(p) = inbound.recv().await {
                if let Err(e) = dev.send(&p.data).await {
                    debug!("overlay: device write: {e}");
                }
            }
            Ok::<(), io::Error>(())
        };
        tokio::select! {
            r = up => r.context("reading from the device"),
            r = down => r.context("writing to the device"),
        }
    }

    /// Returns every peer's status, ordered by index.
    pub fn status(&self) -> Vec<PeerStatus> {
        let peers: Vec<NodeRecord> = self.peers.lock().unwrap().values().cloned().collect();
        let mut out: Vec<PeerStatus> = peers
            .into_iter()
            .map(|r| {
                let path = self.ms.peer_path(&r.nodekey);
                let (hs, tx, rx) = self.engine.peer_stats(&r.nodekey).unwrap_or((None, 0, 0));
                let direct = path.as_ref().filter(|p| p.direct_trusted).and_then(|p| p.best.map(|b| b.0));
                PeerStatus {
                    index: r.index,
                    nodekey: r.nodekey,
                    overlay_ip: r.overlay_ip,
                    direct,
                    derp_region: path.map(|p| p.home_region).unwrap_or(0),
                    handshake_age_secs: hs.map(|d| d.as_secs()),
                    tx_bytes: tx,
                    rx_bytes: rx,
                }
            })
            .collect();
        out.sort_by_key(|p| p.index);
        out
    }

    /// Pings a peer over the disco protocol, driving path discovery.
    pub async fn ping(&self, k: &NodePublic, timeout: Duration) -> Result<magicsock::PingResult> {
        Ok(self.ms.ping(k, timeout).await?)
    }

    /// Shuts the node down.
    pub fn close(&self) {
        self.engine.close();
        self.ms.close();
    }
}

impl Drop for Overlay {
    fn drop(&mut self) {
        self.close();
    }
}

/// An in-memory packet device, for tests and embedding: packets the
/// overlay emits arrive on `out`, and packets sent on the returned
/// sender go into the overlay.
pub struct ChannelDevice {
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    out: mpsc::Sender<Vec<u8>>,
}

impl ChannelDevice {
    /// Returns the device, a sender to inject packets, and a receiver of
    /// packets delivered to it.
    pub fn new() -> (Arc<ChannelDevice>, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (in_tx, in_rx) = mpsc::channel(1024);
        let (out_tx, out_rx) = mpsc::channel(1024);
        (Arc::new(ChannelDevice { rx: tokio::sync::Mutex::new(in_rx), out: out_tx }), in_tx, out_rx)
    }
}

impl PacketDevice for ChannelDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rx.lock().await.recv().await {
            Some(p) => {
                let n = p.len().min(buf.len());
                buf[..n].copy_from_slice(&p[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "device closed")),
        }
    }

    async fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        self.out.send(pkt.to_vec()).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "device closed"))?;
        Ok(pkt.len())
    }
}
