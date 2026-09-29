//! A WireGuard engine: one boringtun tunnel per peer, carried over a
//! [`MagicSock`]. IP packets go in through [`Engine::send_ip`] and come
//! out, decrypted and source-checked, on the receiver returned by
//! [`Engine::start`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use crate::key::{NodePrivate, NodePublic, PresharedKey};
use crate::magicsock::{MagicSock, PathAddr, WireguardPacket};

/// An IP prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpNet {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        IpNet { addr, prefix_len }
    }

    /// A single-address prefix.
    pub fn host(addr: IpAddr) -> Self {
        IpNet { addr, prefix_len: if addr.is_ipv4() { 32 } else { 128 } }
    }

    /// Reports whether `ip` is inside the prefix.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let bits = self.prefix_len.min(32) as u32;
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                (u32::from(a) & mask) == (u32::from(*b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let bits = self.prefix_len.min(128) as u32;
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                (u128::from(a) & mask) == (u128::from(*b) & mask)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl std::str::FromStr for IpNet {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.split_once('/') {
            Some((a, l)) => {
                let addr: IpAddr = a.parse().map_err(|e| format!("{s}: {e}"))?;
                let prefix_len: u8 = l.parse().map_err(|e| format!("{s}: {e}"))?;
                let max = if addr.is_ipv4() { 32 } else { 128 };
                if prefix_len > max {
                    return Err(format!("{s}: prefix length too long"));
                }
                Ok(IpNet { addr, prefix_len })
            }
            None => Ok(IpNet::host(s.parse().map_err(|e| format!("{s}: {e}"))?)),
        }
    }
}

/// WireGuard configuration for one peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Source addresses the peer may send from, and (for routing)
    /// destinations reached through it.
    pub allowed_ips: Vec<IpNet>,
    pub preshared_key: PresharedKey,
    pub persistent_keepalive: Option<u16>,
}

/// Looks up configuration for a peer the engine doesn't know yet, when
/// its handshake arrives. Returning `None` ignores the peer.
pub type PeerConfigFn = Arc<dyn Fn(&NodePublic) -> Option<PeerConfig> + Send + Sync>;

/// Picks the peer for an outbound packet's destination when no peer's
/// allowed IPs match.
pub type RouteFn = Arc<dyn Fn(&IpAddr) -> Option<NodePublic> + Send + Sync>;

struct WgPeer {
    tunn: Mutex<Tunn>,
    cfg: Mutex<PeerConfig>,
    index: u32,
}

/// A decrypted IP packet from a peer.
#[derive(Debug)]
pub struct InboundPacket {
    pub peer: NodePublic,
    pub data: Vec<u8>,
}

/// The WireGuard engine.
pub struct Engine {
    private: x25519::StaticSecret,
    public: x25519::PublicKey,
    ms: Arc<MagicSock>,
    peers: Mutex<HashMap<NodePublic, Arc<WgPeer>>>,
    by_index: Mutex<HashMap<u32, NodePublic>>,
    next_index: AtomicU32,
    peer_config: Option<PeerConfigFn>,
    route: Option<RouteFn>,
    inbound: mpsc::Sender<InboundPacket>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Engine {
    /// Starts an engine on `ms`, consuming the WireGuard packets it
    /// receives. `peer_config` enables lazily adding peers on handshake;
    /// `route` resolves destinations outside every peer's allowed IPs.
    pub fn start(
        key: &NodePrivate,
        ms: Arc<MagicSock>,
        wg_rx: mpsc::Receiver<WireguardPacket>,
        peer_config: Option<PeerConfigFn>,
        route: Option<RouteFn>,
    ) -> (Arc<Engine>, mpsc::Receiver<InboundPacket>) {
        let private = key.x25519();
        let public = x25519::PublicKey::from(&private);
        let (tx, rx) = mpsc::channel(4096);
        let e = Arc::new(Engine {
            private,
            public,
            ms,
            peers: Mutex::default(),
            by_index: Mutex::default(),
            next_index: AtomicU32::new(rand::random::<u32>() & 0x7f_ffff | 1),
            peer_config,
            route,
            inbound: tx,
            tasks: Mutex::default(),
        });
        let w = Arc::downgrade(&e);
        *e.tasks.lock().unwrap() = vec![tokio::spawn(recv_loop(w.clone(), wg_rx)), tokio::spawn(timer_loop(w))];
        (e, rx)
    }

    /// The magicsock this engine sends through.
    pub fn magicsock(&self) -> &Arc<MagicSock> {
        &self.ms
    }

    /// Adds or reconfigures a peer. Reconfiguring keeps its sessions
    /// unless the pre-shared key changed.
    pub fn upsert_peer(&self, key: NodePublic, cfg: PeerConfig) {
        let mut peers = self.peers.lock().unwrap();
        if let Some(p) = peers.get(&key) {
            let mut cur = p.cfg.lock().unwrap();
            if cur.preshared_key == cfg.preshared_key && cur.persistent_keepalive == cfg.persistent_keepalive {
                *cur = cfg;
                return;
            }
        }
        self.insert_new_locked(&mut peers, key, cfg);
    }

    fn new_tunn(&self, key: &NodePublic, cfg: &PeerConfig, index: u32) -> Tunn {
        Tunn::new(
            self.private.clone(),
            key.x25519(),
            cfg.preshared_key.for_wireguard(),
            cfg.persistent_keepalive,
            index,
            None,
        )
    }

    fn insert_new_locked(&self, peers: &mut HashMap<NodePublic, Arc<WgPeer>>, key: NodePublic, cfg: PeerConfig) -> Arc<WgPeer> {
        let index = self.next_index.fetch_add(1, Ordering::Relaxed) & 0xff_ffff;
        let p = Arc::new(WgPeer { tunn: Mutex::new(self.new_tunn(&key, &cfg, index)), cfg: Mutex::new(cfg), index });
        if let Some(old) = peers.insert(key, p.clone()) {
            self.by_index.lock().unwrap().remove(&old.index);
        }
        self.by_index.lock().unwrap().insert(index, key);
        p
    }

    /// Removes a peer, dropping its sessions.
    pub fn remove_peer(&self, key: &NodePublic) -> bool {
        let Some(p) = self.peers.lock().unwrap().remove(key) else { return false };
        self.by_index.lock().unwrap().remove(&p.index);
        true
    }

    /// Reports whether `key` is a configured peer.
    pub fn has_peer(&self, key: &NodePublic) -> bool {
        self.peers.lock().unwrap().contains_key(key)
    }

    /// Returns the time since the peer's last completed handshake, and
    /// bytes sent and received.
    pub fn peer_stats(&self, key: &NodePublic) -> Option<(Option<Duration>, usize, usize)> {
        let p = self.peers.lock().unwrap().get(key).cloned()?;
        let (hs, tx, rx, _, _) = p.tunn.lock().unwrap().stats();
        Some((hs, tx, rx))
    }

    fn peer_for_dst(&self, dst: &IpAddr) -> Option<(NodePublic, Arc<WgPeer>)> {
        let peers = self.peers.lock().unwrap();
        let mut best: Option<(u8, NodePublic, Arc<WgPeer>)> = None;
        for (k, p) in peers.iter() {
            for net in &p.cfg.lock().unwrap().allowed_ips {
                if net.contains(dst) && best.as_ref().is_none_or(|b| net.prefix_len > b.0) {
                    best = Some((net.prefix_len, *k, p.clone()));
                }
            }
        }
        if let Some((_, k, p)) = best {
            return Some((k, p));
        }
        let k = self.route.as_ref()?(dst)?;
        peers.get(&k).map(|p| (k, p.clone()))
    }

    /// Encrypts and sends an IP packet to the peer that routes its
    /// destination. Packets with no route are dropped.
    pub fn send_ip(&self, pkt: &[u8]) {
        let Some(dst) = Tunn::dst_address(pkt) else { return };
        let Some((key, peer)) = self.peer_for_dst(&dst) else {
            trace!("wg: no peer for {dst}; dropping");
            return;
        };
        self.send_ip_to(&key, &peer, pkt);
    }

    /// Encrypts and sends an IP packet to a specific peer.
    pub fn send_ip_to_peer(&self, key: &NodePublic, pkt: &[u8]) {
        let Some(peer) = self.peers.lock().unwrap().get(key).cloned() else { return };
        self.send_ip_to(key, &peer, pkt);
    }

    fn send_ip_to(&self, key: &NodePublic, peer: &WgPeer, pkt: &[u8]) {
        let mut buf = vec![0u8; (pkt.len() + 32).max(148)];
        let res = peer.tunn.lock().unwrap().encapsulate(pkt, &mut buf);
        match res {
            TunnResult::WriteToNetwork(b) => {
                let _ = self.ms.send_wireguard(key, b);
            }
            TunnResult::Err(e) => debug!(peer = %key.short_string(), "wg: encapsulate: {e:?}"),
            _ => {}
        }
    }

    fn identify(&self, pkt: &WireguardPacket) -> Option<(NodePublic, Arc<WgPeer>)> {
        if let Some(k) = pkt.peer {
            if let Some(p) = self.peers.lock().unwrap().get(&k).cloned() {
                return Some((k, p));
            }
            // A known sender but not (yet) a WireGuard peer: only a
            // handshake initiation can make it one.
        }
        match Tunn::parse_incoming_packet(&pkt.data).ok()? {
            Packet::HandshakeInit(init) => {
                let hh = parse_handshake_anon(&self.private, &self.public, &init).ok()?;
                let k = NodePublic::from_bytes(hh.peer_static_public);
                if let Some(expected) = pkt.peer {
                    if expected != k {
                        return None;
                    }
                }
                if let Some(p) = self.peers.lock().unwrap().get(&k).cloned() {
                    return Some((k, p));
                }
                let cfg = self.peer_config.as_ref()?(&k)?;
                debug!(peer = %k.short_string(), "wg: adding peer on handshake");
                let mut peers = self.peers.lock().unwrap();
                Some((k, self.insert_new_locked(&mut peers, k, cfg)))
            }
            Packet::HandshakeResponse(r) => self.by_receiver(r.receiver_idx),
            Packet::PacketCookieReply(r) => self.by_receiver(r.receiver_idx),
            Packet::PacketData(d) => self.by_receiver(d.receiver_idx),
        }
    }

    fn by_receiver(&self, idx: u32) -> Option<(NodePublic, Arc<WgPeer>)> {
        let k = *self.by_index.lock().unwrap().get(&(idx >> 8))?;
        let p = self.peers.lock().unwrap().get(&k).cloned()?;
        Some((k, p))
    }

    async fn handle(&self, pkt: WireguardPacket) {
        let Some((key, peer)) = self.identify(&pkt) else {
            trace!(src = %pkt.src, "wg: packet from unknown peer");
            return;
        };
        let src_ip = match pkt.src {
            PathAddr::Udp(a) => Some(a.ip()),
            PathAddr::Derp(_) => None,
        };
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut inbound: Option<Vec<u8>> = None;
        {
            let mut buf = vec![0u8; pkt.data.len().max(256) + 64];
            let mut tunn = peer.tunn.lock().unwrap();
            match tunn.decapsulate(src_ip, &pkt.data, &mut buf) {
                TunnResult::WriteToNetwork(b) => {
                    out.push(b.to_vec());
                    // Flush packets queued while the handshake completed.
                    loop {
                        let mut buf = vec![0u8; 65536];
                        match tunn.decapsulate(None, &[], &mut buf) {
                            TunnResult::WriteToNetwork(b) => out.push(b.to_vec()),
                            _ => break,
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(b, src) => {
                    if allowed(&peer.cfg.lock().unwrap(), IpAddr::V4(src)) {
                        inbound = Some(b.to_vec());
                    } else {
                        trace!(peer = %key.short_string(), "wg: dropping packet from disallowed source {src}");
                    }
                }
                TunnResult::WriteToTunnelV6(b, src) => {
                    if allowed(&peer.cfg.lock().unwrap(), IpAddr::V6(src)) {
                        inbound = Some(b.to_vec());
                    } else {
                        trace!(peer = %key.short_string(), "wg: dropping packet from disallowed source {src}");
                    }
                }
                TunnResult::Err(e) => trace!(peer = %key.short_string(), "wg: decapsulate: {e:?}"),
                TunnResult::Done => {}
            }
        }
        for b in out {
            let _ = self.ms.send_wireguard(&key, &b);
        }
        if let Some(data) = inbound {
            if !data.is_empty() {
                let _ = self.inbound.send(InboundPacket { peer: key, data }).await;
            }
        }
    }

    fn tick(&self) {
        let peers: Vec<(NodePublic, Arc<WgPeer>)> =
            self.peers.lock().unwrap().iter().map(|(k, p)| (*k, p.clone())).collect();
        let mut buf = vec![0u8; 256];
        for (k, p) in peers {
            let res = p.tunn.lock().unwrap().update_timers(&mut buf);
            if let TunnResult::WriteToNetwork(b) = res {
                let _ = self.ms.send_wireguard(&k, b);
            }
        }
    }

    /// Stops the engine's background tasks.
    pub fn close(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.close();
    }
}

fn allowed(cfg: &PeerConfig, src: IpAddr) -> bool {
    cfg.allowed_ips.iter().any(|n| n.contains(&src))
}

async fn recv_loop(e: Weak<Engine>, mut rx: mpsc::Receiver<WireguardPacket>) {
    while let Some(pkt) = rx.recv().await {
        let Some(e) = e.upgrade() else { return };
        e.handle(pkt).await;
    }
}

async fn timer_loop(e: Weak<Engine>) {
    let mut t = tokio::time::interval(Duration::from_millis(250));
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        t.tick().await;
        let Some(e) = e.upgrade() else { return };
        e.tick();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipnet_contains() {
        let n: IpNet = "100.64.1.0/24".parse().unwrap();
        assert!(n.contains(&"100.64.1.9".parse().unwrap()));
        assert!(!n.contains(&"100.64.2.9".parse().unwrap()));
        let all: IpNet = "::/0".parse().unwrap();
        assert!(all.contains(&"fd7a::1".parse().unwrap()));
        assert!(!all.contains(&"1.2.3.4".parse().unwrap()));
        let h: IpNet = "fd7a:115c:a1e0::1".parse().unwrap();
        assert_eq!(h.prefix_len, 128);
        assert!("1.2.3.4/33".parse::<IpNet>().is_err());
    }
}
