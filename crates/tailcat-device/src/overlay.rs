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
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, iter};

use anyhow::{Context, Result, anyhow, ensure};
use serde::Serialize;
use tailcat::magicsock::{self, MagicSock, PeerPath};
use tailcat::wg::{self, Engine, InboundPacket, IpNet};
use tailcat::{DerpMap, DerpRegion, NodePublic, PresharedKey};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::reconcile::{Change, Peer, contested, reconcile};
use crate::record::{DeviceKey, NodeRecord};

/// Something that carries raw IP packets: a TUN device, or a channel in
/// tests.
pub trait PacketDevice: Send + Sync + 'static {
    /// Reads a packet. Reading nothing means the device is closed.
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

/// Embedded DERP regions get local IDs from here up. The IDs they carry
/// can't be trusted to be unique: every `init --region host,...` region
/// is 900, and every `tailcat dev-derp --region-file` region is 1, the
/// same as a region of the public DERP map.
pub const EMBEDDED_REGION_BASE: i32 = 1_000_000;

/// A running overlay node.
pub struct Overlay {
    me: NodeRecord,
    ms: Arc<MagicSock>,
    engine: Arc<Engine>,
    /// Held across updates to magicsock and the engine, so they always
    /// know the same peers.
    state: Mutex<State>,
    inbound: Mutex<Option<mpsc::Receiver<InboundPacket>>>,
    closed: watch::Sender<bool>,
}

#[derive(Default)]
struct State {
    peers: HashMap<NodePublic, Peer>,
    /// Our claims that our run's nodes route elsewhere, as of the last
    /// sync, and the node each goes to.
    contested: Vec<(IpNet, NodePublic)>,
    /// Distinct embedded regions (with their IDs zeroed), each known by
    /// `EMBEDDED_REGION_BASE` plus its position.
    embedded: Vec<DerpRegion>,
}

impl State {
    /// A record's home region: from `dm`, or embedded under a local ID.
    fn region(&mut self, r: &NodeRecord, dm: &DerpMap) -> Option<DerpRegion> {
        let Some(e) = &r.derp else { return dm.regions.get(&r.derp_region).cloned() };
        let e = DerpRegion { region_id: 0, ..e.clone() };
        let i = self.embedded.iter().position(|x| *x == e).unwrap_or_else(|| {
            self.embedded.push(e.clone());
            self.embedded.len() - 1
        });
        Some(DerpRegion { region_id: EMBEDDED_REGION_BASE + i as i32, ..e })
    }
}

impl Overlay {
    /// Starts the node: connects to its home DERP region and brings up
    /// the WireGuard engine. Peers are added with [`Overlay::sync`] or
    /// [`Overlay::add_peer`], and packets flow once [`Overlay::run`] is
    /// given a device.
    pub async fn start(cfg: OverlayConfig) -> Result<Arc<Overlay>> {
        let OverlayConfig {
            key: DeviceKey { private, record: me },
            mut derp_map,
            listen_port,
            overlay_prefix,
            enable_udp,
        } = cfg;
        let mut state = State::default();
        let home = state
            .region(&me, &derp_map)
            .ok_or_else(|| anyhow!("home DERP region {} is not in the DERP map", me.derp_region))?;
        let home_region = home.region_id;
        derp_map.regions.insert(home_region, home);
        let (ms, wg_rx) = MagicSock::start(magicsock::Config {
            private_key: private.clone(),
            derp_map,
            home_region,
            derp_app_name: tailcat::derp::AppName::Device,
            listen_port,
            on_derp_recv: None,
            endpoint_filter: Some(Arc::new(move |ip| !overlay_prefix.contains(&ip))),
            enable_udp,
        })
        .await
        .context("starting magicsock")?;
        let (engine, inbound) = Engine::start(&private, ms.clone(), wg_rx, None, None);
        // A peer routed a prefix around our address or routes still
        // mustn't send from them.
        engine.set_local_ips(me.allowed_ips());
        let key = me.nodekey.short_string();
        info!(overlay_ip = %me.overlay_ip, region = home_region, "overlay: node {} up as {key}", me.index);
        Ok(Arc::new(Overlay {
            me,
            ms,
            engine,
            state: Mutex::new(state),
            inbound: Mutex::new(Some(inbound)),
            closed: watch::Sender::new(false),
        }))
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

    /// The WireGuard engine, for diagnostics.
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    /// Brings the peers in line with a poll of every record, as
    /// [`reconcile`] decides: one peer per overlay address, and each
    /// route to one peer, chosen the same way however often and in
    /// whatever order records are polled. Records whose home region isn't
    /// known are skipped, and peers whose records the poll leaves out are
    /// removed. Claims of ours that our run's nodes route elsewhere, as
    /// [`contested`] says, are logged when that changes.
    pub fn sync(&self, polled: &[NodeRecord], dm: &DerpMap) {
        let mut st = self.state.lock().unwrap();
        let contested = contested(&self.me, polled);
        for (n, r) in &contested {
            if st.contested.contains(&(*n, r.nodekey)) {
                continue;
            }
            let who = format!("node {} ({})", r.index, r.nodekey.short_string());
            if *n == IpNet::host(self.me.overlay_ip) {
                let ip = self.me.overlay_ip;
                warn!("overlay: {who} outranks us at our address {ip}, so our run's nodes send it all of our traffic");
            } else {
                warn!("overlay: {who} outranks our claim to {n}, so our run's nodes route {n} to it");
            }
        }
        for (n, _) in &st.contested {
            if !contested.iter().any(|(m, _)| m == n) {
                info!("overlay: our run's nodes route {n} to us again");
            }
        }
        st.contested = contested.into_iter().map(|(n, r)| (n, r.nodekey)).collect();
        // Records `st.region` finds a region for, checked without cloning
        // it or registering embedded ones, which upserting does.
        let usable = polled.iter().filter(|r| {
            let ok = r.nodekey == self.me.nodekey || r.derp.is_some() || dm.regions.contains_key(&r.derp_region);
            if !ok {
                warn!("peer {}: DERP region {} is not in the DERP map", r.index, r.derp_region);
            }
            ok
        });
        let changes = reconcile(&self.me, &st.peers, usable);
        for c in changes {
            self.apply_locked(&mut st, c, dm);
        }
    }

    /// Adds or updates a peer from its record, taking over its overlay
    /// address from any other peer. Our own record is ignored. It
    /// reports whether the peer was new.
    pub fn add_peer(&self, r: &NodeRecord, dm: &DerpMap) -> Result<bool> {
        if r.nodekey == self.me.nodekey {
            return Ok(false);
        }
        ensure!(r.overlay_ip != self.me.overlay_ip, "peer {}: claims our overlay IP {}", r.index, r.overlay_ip);
        let mut st = self.state.lock().unwrap();
        st.region(r, dm)
            .ok_or_else(|| anyhow!("peer {}: DERP region {} is not in the DERP map", r.index, r.derp_region))?;
        let new = !st.peers.contains_key(&r.nodekey);
        // As if polled with every other peer, less any at its address.
        let others =
            st.peers.values().map(|p| &p.record).filter(|p| p.nodekey != r.nodekey && p.overlay_ip != r.overlay_ip);
        let changes = reconcile(&self.me, &st.peers, iter::once(r).chain(others));
        for c in changes {
            self.apply_locked(&mut st, c, dm);
        }
        Ok(new && st.peers.contains_key(&r.nodekey))
    }

    fn apply_locked(&self, st: &mut State, c: Change, dm: &DerpMap) {
        match c {
            Change::Upsert(p) => {
                let r = &p.record;
                // Upserted records passed the region check.
                let Some(region) = st.region(r, dm) else { return };
                let home_region = region.region_id;
                self.ms.add_region(region);
                self.ms.upsert_peer(magicsock::PeerConfig {
                    node_key: r.nodekey,
                    disco_key: r.discokey,
                    home_region,
                    endpoints: r.endpoints.clone(),
                });
                self.engine.upsert_peer(
                    r.nodekey,
                    wg::PeerConfig {
                        allowed_ips: p.allowed_ips.clone(),
                        preshared_key: PresharedKey::default(),
                        persistent_keepalive: None,
                    },
                );
                let (k, index, ip) = (r.nodekey, r.index, r.overlay_ip);
                if st.peers.insert(k, p).is_none() {
                    info!(peer = index, overlay_ip = %ip, "overlay: added peer {}", k.short_string());
                    self.ms.send_call_me_maybe(&k);
                }
            }
            Change::Remove(k) => {
                if let Some(Peer { record: r, .. }) = st.peers.remove(&k) {
                    info!(peer = r.index, overlay_ip = %r.overlay_ip, "overlay: removed peer {}", k.short_string());
                }
                self.engine.remove_peer(&k);
                self.ms.remove_peer(&k);
            }
        }
    }

    /// Removes a peer.
    pub fn remove_peer(&self, k: &NodePublic) -> bool {
        let mut st = self.state.lock().unwrap();
        let known = st.peers.contains_key(k);
        if known {
            self.apply_locked(&mut st, Change::Remove(*k), &DerpMap::default());
        }
        known
    }

    /// The number of peers.
    pub fn peer_count(&self) -> usize {
        self.state.lock().unwrap().peers.len()
    }

    /// Our claims that our run's nodes route elsewhere, as of the last
    /// [`Overlay::sync`], and the node each goes to.
    pub fn contested(&self) -> Vec<(IpNet, NodePublic)> {
        self.state.lock().unwrap().contested.clone()
    }

    /// Carries packets between `dev` and the peers until either fails or
    /// the overlay is closed. It can be called once.
    pub async fn run<D: PacketDevice>(self: Arc<Self>, dev: Arc<D>) -> Result<()> {
        let mut inbound = self.inbound.lock().unwrap().take().ok_or_else(|| anyhow!("Overlay::run called twice"))?;
        let mut closed = self.closed.subscribe();
        let up = async {
            let mut buf = vec![0u8; 65536];
            loop {
                match dev.recv(&mut buf).await {
                    Ok(0) => return io::Error::new(io::ErrorKind::UnexpectedEof, "the device closed"),
                    Ok(n) => self.engine.send_ip(&buf[..n]),
                    Err(e) => return e,
                }
            }
        };
        let down = async {
            while let Some(p) = inbound.recv().await {
                if let Err(e) = dev.send(&p.data).await {
                    debug!("overlay: device write: {e}");
                }
            }
        };
        tokio::select! {
            e = up => Err(anyhow::Error::new(e).context("reading from the device")),
            () = down => Ok(()),
            _ = closed.wait_for(|c| *c) => Ok(()),
        }
    }

    /// Returns every peer's status, ordered by index.
    pub fn status(&self) -> Vec<PeerStatus> {
        let st = self.state.lock().unwrap();
        let mut out: Vec<PeerStatus> = st
            .peers
            .values()
            .map(|Peer { record: r, .. }| {
                let path = self.ms.peer_path(&r.nodekey);
                let (hs, tx_bytes, rx_bytes) = self.engine.peer_stats(&r.nodekey).unwrap_or((None, 0, 0));
                PeerStatus {
                    index: r.index,
                    nodekey: r.nodekey,
                    overlay_ip: r.overlay_ip,
                    direct: path.as_ref().and_then(PeerPath::direct),
                    derp_region: path.map_or(0, |p| p.home_region),
                    handshake_age_secs: hs.map(|d| d.as_secs()),
                    tx_bytes,
                    rx_bytes,
                }
            })
            .collect();
        drop(st);
        out.sort_by_key(|p| p.index);
        out
    }

    /// Pings a peer over the disco protocol, driving path discovery.
    pub async fn ping(&self, k: &NodePublic, timeout: Duration) -> Result<magicsock::PingResult> {
        Ok(self.ms.ping(k, timeout).await?)
    }

    /// Shuts the node down, ending [`Overlay::run`].
    pub fn close(&self) {
        self.closed.send_replace(true);
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
        let mut rx = self.rx.lock().await;
        // An empty packet would read as the device closing.
        let p = loop {
            match rx.recv().await {
                Some(p) if p.is_empty() => {}
                Some(p) => break p,
                None => return Err(closed()),
            }
        };
        let n = p.len().min(buf.len());
        buf[..n].copy_from_slice(&p[..n]);
        Ok(n)
    }

    async fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        self.out.send(pkt.to_vec()).await.map_err(|_| closed())?;
        Ok(pkt.len())
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "device closed")
}
