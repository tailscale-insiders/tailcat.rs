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

/// The length in bits of `addr`'s family.
fn bits(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

impl IpNet {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        IpNet { addr, prefix_len }
    }

    /// A single-address prefix.
    pub fn host(addr: IpAddr) -> Self {
        IpNet { addr, prefix_len: bits(addr) }
    }

    /// Reports whether `ip` is inside the prefix.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let (a, b) = match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a).into(), u32::from(*b).into()),
            (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(*b)),
            _ => return false,
        };
        let host_bits = bits(self.addr) - self.prefix_len.min(bits(self.addr));
        (a ^ b).checked_shr(host_bits.into()).unwrap_or(0) == 0
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
        let err = |e: &dyn std::fmt::Display| format!("{s}: {e}");
        let (a, len) = s.split_once('/').map_or((s, None), |(a, l)| (a, Some(l)));
        let addr: IpAddr = a.parse().map_err(|e| err(&e))?;
        let prefix_len = len.map_or(Ok(bits(addr)), |l| l.parse().map_err(|e| err(&e)))?;
        if prefix_len > bits(addr) {
            return Err(err(&"prefix length too long"));
        }
        Ok(IpNet { addr, prefix_len })
    }
}

/// WireGuard configuration for one peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Destinations routed to the peer, and source addresses it may send
    /// from, except where another peer's match more specifically (or as
    /// specifically, with a lower key), or one of our own prefixes (see
    /// [`Engine::set_local_ips`]) matches as specifically.
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
    key: NodePublic,
    tunn: Mutex<Tunn>,
    cfg: Mutex<PeerConfig>,
    /// Our session index for the peer, the top 24 bits of the receiver
    /// index on packets addressed to us.
    index: u32,
}

impl WgPeer {
    /// The length of the most specific of its allowed IPs containing `ip`.
    fn matches(&self, ip: &IpAddr) -> Option<u8> {
        self.cfg.lock().unwrap().allowed_ips.iter().filter(|n| n.contains(ip)).map(|n| n.prefix_len).max()
    }
}

#[derive(Default)]
struct Peers {
    by_key: HashMap<NodePublic, Arc<WgPeer>>,
    by_index: HashMap<u32, Arc<WgPeer>>,
    /// Counts calls to `remove_peer`, known peer or not.
    removals: u64,
    /// Our own prefixes, from `set_local_ips`.
    local: Vec<IpNet>,
}

impl Peers {
    /// The peer that owns `ip`: the one whose allowed IPs match it most
    /// specifically, the lowest key breaking ties, unless one of our own
    /// prefixes matches it as specifically. Outbound packets go to it,
    /// and inbound ones are only taken from it.
    fn owner(&self, ip: &IpAddr) -> Option<&Arc<WgPeer>> {
        let best = self.by_key.values().filter_map(|p| Some((p.matches(ip)?, p)));
        let (len, p) = best.max_by(|(la, a), (lb, b)| la.cmp(lb).then(b.key.cmp(&a.key)))?;
        (self.local_match(ip) < Some(len)).then_some(p)
    }

    /// The length of the most specific of our own prefixes containing
    /// `ip`.
    fn local_match(&self, ip: &IpAddr) -> Option<u8> {
        self.local.iter().filter(|n| n.contains(ip)).map(|n| n.prefix_len).max()
    }
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
    peers: Mutex<Peers>,
    next_index: AtomicU32,
    peer_config: Option<PeerConfigFn>,
    route: Option<RouteFn>,
    inbound: mpsc::Sender<InboundPacket>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Every packet sent, for tests to deliver by hand.
    #[cfg(test)]
    sent: Mutex<Vec<(NodePublic, Vec<u8>)>>,
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
        let (tx, rx) = mpsc::channel(4096);
        let e = Arc::new(Engine {
            public: x25519::PublicKey::from(&private),
            private,
            ms,
            peers: Mutex::default(),
            next_index: AtomicU32::new(rand::random::<u32>() & 0x7f_ffff | 1),
            peer_config,
            route,
            inbound: tx,
            tasks: Mutex::default(),
            #[cfg(test)]
            sent: Mutex::default(),
        });
        let w = Arc::downgrade(&e);
        *e.tasks.lock().unwrap() = vec![tokio::spawn(recv_loop(w.clone(), wg_rx)), tokio::spawn(timer_loop(w))];
        (e, rx)
    }

    /// Adds or reconfigures a peer. Reconfiguring keeps its sessions
    /// unless the pre-shared key or keepalive changed.
    pub fn upsert_peer(&self, key: NodePublic, cfg: PeerConfig) {
        let mut peers = self.peers.lock().unwrap();
        if let Some(p) = peers.by_key.get(&key) {
            let mut cur = p.cfg.lock().unwrap();
            if cur.preshared_key == cfg.preshared_key && cur.persistent_keepalive == cfg.persistent_keepalive {
                *cur = cfg;
                return;
            }
        }
        self.insert_locked(&mut peers, key, cfg);
    }

    fn insert_locked(&self, peers: &mut Peers, key: NodePublic, cfg: PeerConfig) -> Arc<WgPeer> {
        let index = self.next_index.fetch_add(1, Ordering::Relaxed) & 0xff_ffff;
        let tunn = Tunn::new(
            self.private.clone(),
            key.x25519(),
            cfg.preshared_key.for_wireguard(),
            cfg.persistent_keepalive,
            index,
            None,
        );
        let p = Arc::new(WgPeer { key, tunn: Mutex::new(tunn), cfg: Mutex::new(cfg), index });
        if let Some(old) = peers.by_key.insert(key, p.clone()) {
            peers.by_index.remove(&old.index);
        }
        peers.by_index.insert(index, p.clone());
        p
    }

    /// Removes a peer, dropping its sessions.
    pub fn remove_peer(&self, key: &NodePublic) -> bool {
        let mut peers = self.peers.lock().unwrap();
        peers.removals += 1;
        let Some(p) = peers.by_key.remove(key) else { return false };
        peers.by_index.remove(&p.index);
        true
    }

    fn peer(&self, key: &NodePublic) -> Option<Arc<WgPeer>> {
        self.peers.lock().unwrap().by_key.get(key).cloned()
    }

    /// Returns the time since the peer's last completed handshake, and
    /// bytes sent and received.
    pub fn peer_stats(&self, key: &NodePublic) -> Option<(Option<Duration>, usize, usize)> {
        let (hs, tx, rx, _, _) = self.peer(key)?.tunn.lock().unwrap().stats();
        Some((hs, tx, rx))
    }

    /// Sets our own prefixes, replacing any set before: an address in one
    /// of them is ours, not a peer's, unless one of the peer's allowed IPs
    /// matches it more specifically. No packet for it is sent (nor is the
    /// route hook asked), and none from it is taken. A peer routed a
    /// prefix around our address thus still can't send from it.
    pub fn set_local_ips(&self, nets: Vec<IpNet>) {
        self.peers.lock().unwrap().local = nets;
    }

    /// The peer that owns `dst`, else, if it isn't ours, the one the
    /// route hook picks.
    fn peer_for_dst(&self, dst: &IpAddr) -> Option<Arc<WgPeer>> {
        let peers = self.peers.lock().unwrap();
        match peers.owner(dst) {
            Some(p) => Some(p.clone()),
            None if peers.local_match(dst).is_some() => None,
            None => peers.by_key.get(&self.route.as_ref()?(dst)?).cloned(),
        }
    }

    /// Reports whether `peer` owns `src`, so that a packet from it routes
    /// back the same way: another peer's more specific prefix, or a newer
    /// session for the same key, takes precedence.
    fn owns(&self, peer: &Arc<WgPeer>, src: &IpAddr) -> bool {
        self.peers.lock().unwrap().owner(src).is_some_and(|o| Arc::ptr_eq(o, peer))
    }

    /// Encrypts and sends an IP packet to the peer that routes its
    /// destination. Packets with no route are dropped.
    pub fn send_ip(&self, pkt: &[u8]) {
        let Some(dst) = Tunn::dst_address(pkt) else { return };
        match self.peer_for_dst(&dst) {
            Some(peer) => self.send_ip_to(&peer, pkt),
            None => trace!("wg: no peer for {dst}; dropping"),
        }
    }

    /// Encrypts and sends an IP packet to a specific peer.
    pub fn send_ip_to_peer(&self, key: &NodePublic, pkt: &[u8]) {
        if let Some(peer) = self.peer(key) {
            self.send_ip_to(&peer, pkt);
        }
    }

    fn send_ip_to(&self, peer: &WgPeer, pkt: &[u8]) {
        let mut buf = vec![0u8; (pkt.len() + 32).max(148)];
        let res = peer.tunn.lock().unwrap().encapsulate(pkt, &mut buf);
        match res {
            TunnResult::WriteToNetwork(b) => {
                self.send(&peer.key, b);
            }
            TunnResult::Err(e) => debug!(peer = %peer.key.short_string(), "wg: encapsulate: {e:?}"),
            _ => {}
        }
    }

    fn send(&self, k: &NodePublic, pkt: &[u8]) {
        #[cfg(test)]
        self.sent.lock().unwrap().push((*k, pkt.to_vec()));
        let _ = self.ms.send_wireguard(k, pkt);
    }

    /// Finds the peer a packet is from, as wireguard-go does: a handshake
    /// initiation by the static key inside (adding the peer if it's new),
    /// anything else by the session it's addressed to. Magicsock's label
    /// on a UDP packet is only a guess from the source address, which a
    /// peer can claim as its own, so it counts for nothing; over DERP the
    /// relay vouches for the sender, so a packet from anyone else is
    /// dropped.
    fn identify(&self, pkt: &WireguardPacket) -> Option<Arc<WgPeer>> {
        let sent_by = |k: NodePublic| match pkt.src {
            PathAddr::Derp(_) => pkt.peer == Some(k),
            PathAddr::Udp(_) => true,
        };
        let idx = match Tunn::parse_incoming_packet(&pkt.data).ok()? {
            Packet::HandshakeInit(init) => {
                let hh = parse_handshake_anon(&self.private, &self.public, &init).ok()?;
                let k = NodePublic::from_bytes(hh.peer_static_public);
                return if sent_by(k) { self.peer_or_add(k) } else { None };
            }
            Packet::HandshakeResponse(r) => r.receiver_idx,
            Packet::PacketCookieReply(r) => r.receiver_idx,
            Packet::PacketData(d) => d.receiver_idx,
        };
        let p = self.peers.lock().unwrap().by_index.get(&(idx >> 8)).cloned()?;
        sent_by(p.key).then_some(p)
    }

    /// The peer with key `k`, else a new one if the `peer_config` hook
    /// has a configuration for it.
    fn peer_or_add(&self, k: NodePublic) -> Option<Arc<WgPeer>> {
        let removals = {
            let peers = self.peers.lock().unwrap();
            if let Some(p) = peers.by_key.get(&k) {
                return Some(p.clone());
            }
            peers.removals
        };
        // The hook runs unlocked, since it may take a while. If the owner
        // adds the peer meanwhile, its configuration wins; if it removes
        // one, which may be this peer, the handshake is dropped (and
        // retried) rather than bring it back.
        let cfg = self.peer_config.as_ref()?(&k)?;
        let mut peers = self.peers.lock().unwrap();
        if let Some(p) = peers.by_key.get(&k) {
            return Some(p.clone());
        }
        if peers.removals != removals {
            return None;
        }
        debug!(peer = %k.short_string(), "wg: adding peer on handshake");
        Some(self.insert_locked(&mut peers, k, cfg))
    }

    async fn handle(&self, pkt: WireguardPacket) {
        let Some(peer) = self.identify(&pkt) else {
            trace!(src = %pkt.src, "wg: packet from unknown peer");
            return;
        };
        let key = peer.key;
        let src_ip = match pkt.src {
            PathAddr::Udp(a) => Some(a.ip()),
            PathAddr::Derp(_) => None,
        };
        let mut out: Vec<Vec<u8>> = Vec::new();
        // Decrypted data goes at the start of `buf`, which then becomes
        // the packet.
        let mut buf = vec![0u8; pkt.data.len().max(256) + 64];
        let inbound = {
            let mut tunn = peer.tunn.lock().unwrap();
            match tunn.decapsulate(src_ip, &pkt.data, &mut buf) {
                TunnResult::WriteToNetwork(b) => {
                    out.push(b.to_vec());
                    // Flush packets queued while the handshake completed.
                    let mut buf = vec![0u8; 65536];
                    while let TunnResult::WriteToNetwork(b) = tunn.decapsulate(None, &[], &mut buf) {
                        out.push(b.to_vec());
                    }
                    None
                }
                TunnResult::WriteToTunnelV4(b, src) => Some((b.len(), IpAddr::V4(src))),
                TunnResult::WriteToTunnelV6(b, src) => Some((b.len(), IpAddr::V6(src))),
                TunnResult::Err(e) => {
                    trace!(peer = %key.short_string(), "wg: decapsulate: {e:?}");
                    None
                }
                TunnResult::Done => None,
            }
        };
        for b in out {
            self.send(&key, &b);
        }
        match inbound {
            Some((_, src)) if !self.owns(&peer, &src) => {
                trace!(peer = %key.short_string(), "wg: dropping packet from disallowed source {src}");
            }
            Some((n, _)) if n > 0 => {
                buf.truncate(n);
                let _ = self.inbound.send(InboundPacket { peer: key, data: buf }).await;
            }
            _ => {}
        }
    }

    fn tick(&self) {
        let peers: Vec<Arc<WgPeer>> = self.peers.lock().unwrap().by_key.values().cloned().collect();
        let mut buf = vec![0u8; 256];
        for p in peers {
            let mut tunn = p.tunn.lock().unwrap();
            let res = tunn.update_timers(&mut buf);
            drop(tunn);
            if let TunnResult::WriteToNetwork(b) = res {
                self.send(&p.key, b);
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
mod model_tests;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::OnceLock;

    use hegel::TestCase;
    use hegel::generators as gs;
    use tokio::runtime;
    use tokio::time::timeout;

    use super::*;
    use crate::derp::server::DevDerp;
    use crate::derpmap::DerpMap;
    use crate::magicsock;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipnet_contains() {
        let cases = [
            ("100.64.1.0/24", "100.64.1.9", true),
            ("100.64.1.0/24", "100.64.2.9", false),
            ("::/0", "fd7a::1", true),
            ("::/0", "1.2.3.4", false),
            ("0.0.0.0/0", "255.255.255.255", true),
            ("0.0.0.0/0", "::", false),
            ("fd7a:115c:a1e0::1", "fd7a:115c:a1e0::1", true),
            ("fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2", false),
            ("fd7a:115c:a1e0::/48", "fd7a:115c:a1e0:ffff::", true),
            ("fd7a:115c:a1e0::/48", "fd7a:115c:a1e1::", false),
        ];
        for (n, a, want) in cases {
            assert_eq!(net(n).contains(&ip(a)), want, "{n} contains {a}");
        }
        assert_eq!(net("fd7a:115c:a1e0::1").prefix_len, 128);
        // Host bits in the address don't matter.
        assert!(IpNet::new(ip("10.1.2.3"), 8).contains(&ip("10.9.9.9")));
        assert_eq!(IpNet::host(ip("10.0.0.1")).to_string(), "10.0.0.1/32");
        for bad in ["1.2.3.4/33", "::/129", "1.2.3.4/x", "nope/8"] {
            assert!(bad.parse::<IpNet>().is_err(), "parsed {bad}");
        }
    }

    /// A minimal IPv4 header plus payload; boringtun only reads the
    /// version, length and addresses.
    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let len = (20 + payload.len()) as u16;
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    struct Node {
        key: NodePrivate,
        ip: Ipv4Addr,
        engine: Arc<Engine>,
        rx: mpsc::Receiver<InboundPacket>,
    }

    impl Node {
        fn public(&self) -> NodePublic {
            self.key.public()
        }

        /// A packet from this node to `to`.
        fn packet_to(&self, to: &Node, payload: &[u8]) -> Vec<u8> {
            ipv4(self.ip, to.ip, payload)
        }

        async fn recv(&mut self) -> InboundPacket {
            timeout(Duration::from_secs(10), self.rx.recv()).await.unwrap().unwrap()
        }
    }

    async fn node(dev: &DevDerp, last_octet: u8, peer_config: Option<PeerConfigFn>) -> Node {
        let key = NodePrivate::generate();
        let mut derp_map = DerpMap::default();
        derp_map.regions.insert(1, dev.region.clone());
        let cfg = magicsock::Config {
            private_key: key.clone(),
            derp_map,
            home_region: 1,
            derp_app_name: "test".into(),
            listen_port: 0,
            on_derp_recv: None,
            endpoint_filter: None,
            enable_udp: false,
        };
        let (ms, wg_rx) = MagicSock::start(cfg).await.unwrap();
        assert!(ms.wait_derp_connected(Duration::from_secs(5)).await);
        let (engine, rx) = Engine::start(&key, ms, wg_rx, peer_config, None);
        Node { key, ip: Ipv4Addr::new(10, 0, 0, last_octet), engine, rx }
    }

    fn allow(ip: Ipv4Addr) -> PeerConfig {
        PeerConfig {
            allowed_ips: vec![IpNet::host(ip.into())],
            preshared_key: PresharedKey::default(),
            persistent_keepalive: None,
        }
    }

    /// Tells `from`'s magicsock how to reach `to`.
    fn meet(from: &Node, to: &Node) {
        from.engine.ms.upsert_peer(magicsock::PeerConfig {
            node_key: to.public(),
            disco_key: to.key.disco_private().public(),
            home_region: 1,
            endpoints: vec![],
        });
    }

    /// Makes `to` a WireGuard peer of `from`.
    fn introduce(from: &Node, to: &Node) {
        meet(from, to);
        from.engine.upsert_peer(to.public(), allow(to.ip));
    }

    #[tokio::test]
    async fn tunnels_and_checks_sources() {
        let dev = DevDerp::start_local().await.unwrap();
        let mut a = node(&dev, 1, None).await;
        let mut b = node(&dev, 2, None).await;
        introduce(&a, &b);
        introduce(&b, &a);

        // The first packet waits for the handshake, then goes through.
        let one = a.packet_to(&b, b"one");
        a.engine.send_ip(&one);
        let got = b.recv().await;
        assert_eq!(got.peer, a.public());
        assert_eq!(got.data, one);
        let (last_handshake, ..) = a.engine.peer_stats(&b.public()).unwrap();
        assert!(last_handshake.is_some(), "no handshake");

        // A source outside the sender's allowed IPs is dropped...
        let spoofed = ipv4(Ipv4Addr::new(10, 0, 0, 99), b.ip, b"spoofed");
        a.engine.send_ip_to_peer(&b.public(), &spoofed);
        // ...while the next legitimate one arrives, and replies route back.
        let two = a.packet_to(&b, b"two");
        a.engine.send_ip(&two);
        assert_eq!(b.recv().await.data, two);
        let back = b.packet_to(&a, b"back");
        b.engine.send_ip(&back);
        assert_eq!(a.recv().await.data, back);

        // Destinations nobody routes are dropped without a handshake.
        a.engine.send_ip(&ipv4(a.ip, Ipv4Addr::new(192, 0, 2, 1), b"nowhere"));
        assert!(a.engine.remove_peer(&b.public()));
        assert!(!a.engine.remove_peer(&b.public()));
        assert!(a.engine.peer_stats(&b.public()).is_none());
    }

    #[tokio::test]
    async fn adds_peers_on_handshake() {
        let dev = DevDerp::start_local().await.unwrap();
        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let lookup: PeerConfigFn = Arc::new(move |_| Some(allow(client_ip)));
        let mut server = node(&dev, 2, Some(lookup)).await;
        let client = node(&dev, 1, None).await;
        // Only the client knows the other side in advance; the server's
        // magicsock learns the client from the DERP packet's source.
        introduce(&client, &server);
        meet(&server, &client);
        assert!(server.engine.peer(&client.public()).is_none());

        client.engine.send_ip(&client.packet_to(&server, b"hi"));

        assert_eq!(server.recv().await.peer, client.public());
        assert!(server.engine.peer(&client.public()).is_some());
    }

    /// An engine on a magicsock with no network, for driving `identify`.
    fn offline(peer_config: Option<PeerConfigFn>) -> (Arc<Engine>, NodePrivate) {
        let key = NodePrivate::generate();
        let (ms, wg_rx) = MagicSock::offline(key.clone(), true);
        let (engine, _) = Engine::start(&key, ms, wg_rx, peer_config, None);
        (engine, key)
    }

    /// A UDP source address, which vouches for no one.
    fn udp_src() -> PathAddr {
        PathAddr::Udp("192.0.2.1:41641".parse().unwrap())
    }

    /// A handshake initiation from `from` to `to`.
    fn handshake_init(from: &NodePrivate, to: &NodePublic) -> Vec<u8> {
        let mut t = Tunn::new(from.x25519(), to.x25519(), None, None, 1, None);
        let mut buf = vec![0u8; 256];
        let TunnResult::WriteToNetwork(b) = t.format_handshake_initiation(&mut buf, false) else {
            panic!("no handshake initiation");
        };
        b.to_vec()
    }

    /// A handshake response (type 2), cookie reply (3) or data packet (4)
    /// addressed to our session `index`, with zeros for its contents.
    fn addressed_to(kind: u8, index: u32) -> Vec<u8> {
        let (len, at) = match kind {
            2 => (92, 8),
            3 => (64, 4),
            _ => (32, 4),
        };
        let mut p = vec![0u8; len];
        p[0] = kind;
        p[at..at + 4].copy_from_slice(&(index << 8 | 1).to_le_bytes());
        p
    }

    /// Packets are attributed to the peer whose session they're addressed
    /// to, or whose static key signs the handshake, whatever peer
    /// magicsock guessed from a UDP source address; a peer can advertise
    /// another's address as its own. Over DERP, where the relay vouches
    /// for the sender, a packet claiming to be from anyone else is dropped.
    #[hegel::test(test_cases = 100)]
    fn identifies_senders_by_session_or_static_key(tc: TestCase) {
        let rt = runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _guard = rt.enter();
        let (engine, key) = offline(None);
        let peers = [NodePrivate::generate(), NodePrivate::generate()];
        engine.upsert_peer(peers[0].public(), allow(Ipv4Addr::new(10, 0, 0, 2)));
        engine.upsert_peer(peers[1].public(), allow(Ipv4Addr::new(10, 0, 0, 3)));
        let stranger = NodePrivate::generate().public();
        let labels = [None, Some(peers[0].public()), Some(peers[1].public()), Some(stranger)];

        let sender = &peers[tc.draw(gs::integers::<usize>().max_value(1))];
        let label = labels[tc.draw(gs::integers::<usize>().max_value(3))];
        let over_derp = tc.draw(gs::booleans());
        let kind = tc.draw(gs::integers::<u8>().min_value(1).max_value(4));
        let data = match kind {
            1 => handshake_init(sender, &key.public()),
            kind => addressed_to(kind, engine.peer(&sender.public()).unwrap().index),
        };
        let src = if over_derp { PathAddr::Derp(1) } else { udp_src() };

        let got = engine.identify(&WireguardPacket { peer: label, src, data }).map(|p| p.key);

        let want = (!over_derp || label == Some(sender.public())).then_some(sender.public());
        assert_eq!(got, want);
    }

    /// An offline engine whose lookup hook first lets the owner `race` it
    /// on the engine, then configures the peer to allow `lookup_ip`; and a
    /// handshake initiation, from a client only the hook knows, that
    /// drives the lookup.
    fn racing_lookup(
        race: impl Fn(&Engine, &NodePublic) + Send + Sync + 'static,
        lookup_ip: Ipv4Addr,
    ) -> (Arc<Engine>, NodePublic, WireguardPacket) {
        let slot: Arc<OnceLock<Weak<Engine>>> = Arc::default();
        let hook_slot = slot.clone();
        let lookup: PeerConfigFn = Arc::new(move |k| {
            let engine = hook_slot.get()?.upgrade()?;
            race(&engine, k);
            Some(allow(lookup_ip))
        });
        let (engine, key) = offline(Some(lookup));
        slot.set(Arc::downgrade(&engine)).unwrap();
        let client = NodePrivate::generate();
        let pkt = WireguardPacket { peer: None, src: udp_src(), data: handshake_init(&client, &key.public()) };
        (engine, client.public(), pkt)
    }

    /// The owner configuring a peer while its handshake is being looked
    /// up wins over the lookup hook's configuration.
    #[tokio::test]
    async fn owner_config_wins_over_a_racing_lookup() {
        let owners_ip = Ipv4Addr::new(10, 0, 0, 2);
        let (engine, client, pkt) =
            racing_lookup(move |e, k| e.upsert_peer(*k, allow(owners_ip)), Ipv4Addr::new(10, 0, 0, 99));

        let p = engine.identify(&pkt).expect("handshake from a peer the hook knows");

        assert!(Arc::ptr_eq(&p, &engine.peer(&client).unwrap()), "identified a replaced peer");
        assert!(p.matches(&owners_ip.into()).is_some(), "the owner's configuration was overwritten");
    }

    /// The owner removing a peer while its handshake is being looked up
    /// wins too: the lookup mustn't bring back a peer the owner has let
    /// go of, which the owner would never remove again.
    #[tokio::test]
    async fn owner_removal_wins_over_a_racing_lookup() {
        let remove = |e: &Engine, k: &NodePublic| {
            e.remove_peer(k);
        };
        let (engine, client, pkt) = racing_lookup(remove, Ipv4Addr::new(10, 0, 0, 2));

        let identified = engine.identify(&pkt);

        assert!(identified.is_none(), "a peer removed during its lookup was taken");
        assert!(engine.peer(&client).is_none(), "a peer removed during its lookup came back");
    }
}
