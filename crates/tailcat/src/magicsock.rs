//! A path manager for WireGuard packets, after Tailscale's `magicsock`:
//! it sends each packet to a peer over the best known path, a direct UDP
//! address when one has been verified recently, else the peer's DERP
//! relay (plus the stale UDP address, in case it still works).
//!
//! Paths are found with disco messages. Each side advertises its UDP
//! endpoints (local interface addresses and the public address STUN
//! reports) to the other in a `CallMeMaybe` over DERP; the recipient
//! pings each endpoint, and a pong over UDP proves that path. Pings in
//! both directions at once punch holes in stateful NATs and firewalls.
//! The timing constants match Tailscale's, so a Rust node and a Go node
//! settle on the same path.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use crate::derp::client::DerpClient;
use crate::derp::{AppName, ReceivedPacket};
use crate::derpmap::{DERP_MAGIC_IP, DerpMap, DerpRegion};
use crate::disco::{self, Message, TxId};
use crate::key::{DiscoPrivate, DiscoPublic, DiscoShared, NodePrivate, NodePublic};
use crate::stun;
use crate::{Error, Result};

/// How often a peer's best path is pinged while it's in use.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
/// How long a pong on a path lets us send only on that path.
const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);
/// The minimum time between discovery pings to one endpoint.
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);
/// How long after the last send a peer counts as active.
const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);
/// How long to wait for a pong.
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// How often to look for a better path while one is working.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(60);
/// Latency below which we stop looking for better paths.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// Where a packet came from or goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathAddr {
    /// A direct UDP address.
    Udp(SocketAddr),
    /// A DERP relay region.
    Derp(i32),
}

impl std::fmt::Display for PathAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathAddr::Udp(a) => write!(f, "{a}"),
            PathAddr::Derp(r) => write!(f, "DERP({r})"),
        }
    }
}

/// A WireGuard packet received from the network.
#[derive(Debug)]
pub struct WireguardPacket {
    /// The sending peer, if known from the path: always for DERP, where
    /// the relay vouches for it, and for UDP from an address the peer has
    /// sent disco messages from (which doesn't prove who sent this one).
    pub peer: Option<NodePublic>,
    pub src: PathAddr,
    pub data: Vec<u8>,
}

impl WireguardPacket {
    /// A packet from `src` over UDP, from `peer` if the address is known.
    pub fn udp(peer: Option<NodePublic>, src: SocketAddr, data: impl Into<Vec<u8>>) -> Self {
        WireguardPacket { peer, src: PathAddr::Udp(src), data: data.into() }
    }

    /// A packet `peer` sent through region `region_id`'s relay, which
    /// vouches for who sent it.
    pub fn derp(region_id: i32, peer: NodePublic, data: impl Into<Vec<u8>>) -> Self {
        WireguardPacket { peer: Some(peer), src: PathAddr::Derp(region_id), data: data.into() }
    }
}

/// A hook consulted for every non-disco packet received from DERP before
/// it's treated as WireGuard. Returning true consumes the packet.
pub type DerpRecvHook = Arc<dyn Fn(i32, NodePublic, &[u8]) -> bool + Send + Sync>;

/// Decides which local IPs may be advertised as endpoints.
pub type EndpointFilter = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// Configuration for [`MagicSock::start`].
pub struct Config {
    pub private_key: NodePrivate,
    /// Regions this node may use; the home region must be among them.
    pub derp_map: DerpMap,
    /// The region this node stays connected to and advertises.
    pub home_region: i32,
    /// An app name reported to DERP servers for their stats.
    pub derp_app_name: AppName,
    /// The UDP port to listen on (0 picks one).
    pub listen_port: u16,
    pub on_derp_recv: Option<DerpRecvHook>,
    /// Filters local interface addresses before advertising them, e.g.
    /// to leave out a TUN device's own overlay addresses.
    pub endpoint_filter: Option<EndpointFilter>,
    /// Whether to use direct UDP paths at all.
    pub enable_udp: bool,
}

/// What we know about a peer, as set by the owner.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub node_key: NodePublic,
    pub disco_key: DiscoPublic,
    /// The region to reach the peer through.
    pub home_region: i32,
    /// Endpoints known in advance (for example from a node record).
    pub endpoints: Vec<SocketAddr>,
}

/// The result of a disco ping.
#[derive(Debug, Clone)]
pub struct PingResult {
    pub latency: Duration,
    /// How the pong came back.
    pub via: PathAddr,
}

/// A snapshot of a peer's paths.
#[derive(Debug, Clone)]
pub struct PeerPath {
    pub node_key: NodePublic,
    pub disco_key: DiscoPublic,
    pub home_region: i32,
    /// The current direct path and its latency, if any.
    pub best: Option<(SocketAddr, Duration)>,
    /// Whether the direct path is currently trusted (recently ponged).
    pub direct_trusted: bool,
    pub candidates: Vec<SocketAddr>,
    pub last_send: Option<Instant>,
    pub last_recv: Option<Instant>,
}

impl PeerPath {
    /// The direct UDP address in use, if the direct path is trusted.
    pub fn direct(&self) -> Option<SocketAddr> {
        self.best.filter(|_| self.direct_trusted).map(|(a, _)| a)
    }
}

struct Peer {
    cfg: PeerConfig,
    shared: Arc<DiscoShared>,
    /// Candidate endpoints, and when each was last pinged.
    candidates: HashMap<SocketAddr, Option<Instant>>,
    /// The endpoints in the peer's latest CallMeMaybe.
    advertised: Vec<SocketAddr>,
    best: Option<(SocketAddr, Duration)>,
    trust_until: Option<Instant>,
    last_send: Option<Instant>,
    last_recv: Option<Instant>,
    last_full_ping: Option<Instant>,
    last_call_me_maybe: Option<Instant>,
    last_upgrade: Option<Instant>,
    /// The region we last heard from this peer over.
    derp_seen: Option<i32>,
}

impl Peer {
    fn new(cfg: PeerConfig, shared: Arc<DiscoShared>) -> Self {
        Peer {
            cfg,
            shared,
            candidates: HashMap::new(),
            advertised: Vec::new(),
            best: None,
            trust_until: None,
            last_send: None,
            last_recv: None,
            last_full_ping: None,
            last_call_me_maybe: None,
            last_upgrade: None,
            derp_seen: None,
        }
    }

    fn trusted(&self, now: Instant) -> bool {
        self.best.is_some() && self.trust_until.is_some_and(|t| now < t)
    }

    fn derp_region(&self) -> i32 {
        if self.cfg.home_region != 0 { self.cfg.home_region } else { self.derp_seen.unwrap_or(0) }
    }

    /// Drops candidate `a` unless the config lists it or the peer still
    /// advertises it.
    fn forget_candidate(&mut self, a: &SocketAddr) {
        if !self.cfg.endpoints.contains(a) && !self.advertised.contains(a) {
            self.candidates.remove(a);
        }
    }
}

struct PendingPing {
    peer: NodePublic,
    to: PathAddr,
    sent: Instant,
    /// Where a [`MagicSock::ping`] caller waits for the first pong to any
    /// of its pings: a channel of capacity 1, so later pongs are dropped.
    waiter: Option<mpsc::Sender<PingResult>>,
}

#[derive(Default)]
struct Inner {
    peers: HashMap<NodePublic, Peer>,
    /// A peer holding each disco key. Peers normally have their own, but
    /// nothing stops two claiming the same one.
    by_disco: HashMap<DiscoPublic, NodePublic>,
    /// The peer each UDP address last sent us a disco message for.
    by_addr: HashMap<SocketAddr, NodePublic>,
    derp: HashMap<i32, DerpClient>,
    derp_map: DerpMap,
    pending: HashMap<TxId, PendingPing>,
    /// Outstanding STUN requests: when sent, and which round.
    stun_pending: HashMap<stun::TxId, (Instant, u64)>,
    stun_round: u64,
    /// The round `stun_endpoints` came from.
    stun_endpoints_round: u64,
    local_endpoints: Vec<SocketAddr>,
    stun_endpoints: Vec<SocketAddr>,
    endpoints: Vec<SocketAddr>,
    closed: bool,
}

impl Inner {
    /// Unindexes disco key `d` from `key`, which no longer holds it,
    /// indexing it to another peer holding it instead, if any.
    fn unindex_disco(&mut self, d: &DiscoPublic, key: &NodePublic) {
        if self.by_disco.get(d) != Some(key) {
            return;
        }
        match self.peers.iter().find(|(_, p)| p.cfg.disco_key == *d) {
            Some((k, _)) => self.by_disco.insert(*d, *k),
            None => self.by_disco.remove(d),
        };
    }
}

/// The path manager. Create it with [`MagicSock::start`].
pub struct MagicSock {
    private_key: NodePrivate,
    public_key: NodePublic,
    disco_private: DiscoPrivate,
    disco_public: DiscoPublic,
    home_region: i32,
    app_name: AppName,
    enable_udp: bool,
    endpoint_filter: Option<EndpointFilter>,
    on_derp_recv: Option<DerpRecvHook>,
    udp4: Option<Arc<UdpSocket>>,
    udp6: Option<Arc<UdpSocket>>,
    inner: Mutex<Inner>,
    wg_tx: mpsc::Sender<WireguardPacket>,
    derp_tx: mpsc::Sender<ReceivedPacket>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl MagicSock {
    /// Binds the UDP sockets, connects to the home DERP region, and
    /// starts the receive loops. WireGuard packets arrive on the returned
    /// channel.
    pub async fn start(cfg: Config) -> Result<(Arc<MagicSock>, mpsc::Receiver<WireguardPacket>)> {
        if !cfg.derp_map.regions.contains_key(&cfg.home_region) {
            return Err(Error::other(format!("home DERP region {} not in DERP map", cfg.home_region)));
        }
        let (udp4, udp6) = if cfg.enable_udp {
            let udp4 = match UdpSocket::bind(("0.0.0.0", cfg.listen_port)).await {
                Ok(s) => Some(Arc::new(s)),
                Err(_) => UdpSocket::bind("0.0.0.0:0").await.ok().map(Arc::new),
            };
            let udp6 = UdpSocket::bind("[::]:0").await.ok().map(Arc::new);
            (udp4, udp6)
        } else {
            (None, None)
        };
        let (wg_tx, wg_rx) = mpsc::channel(1024);
        let (derp_tx, derp_rx) = mpsc::channel(1024);
        let disco_private = cfg.private_key.disco_private();
        let ms = Arc::new(MagicSock {
            public_key: cfg.private_key.public(),
            disco_public: disco_private.public(),
            disco_private,
            private_key: cfg.private_key,
            home_region: cfg.home_region,
            app_name: cfg.derp_app_name,
            enable_udp: cfg.enable_udp,
            endpoint_filter: cfg.endpoint_filter,
            on_derp_recv: cfg.on_derp_recv,
            udp4,
            udp6,
            inner: Mutex::new(Inner { derp_map: cfg.derp_map, ..Default::default() }),
            wg_tx,
            derp_tx,
            tasks: Mutex::default(),
        });
        ms.ensure_derp(ms.home_region);
        let weak = Arc::downgrade(&ms);
        let mut tasks = vec![tokio::spawn(derp_recv_loop(weak.clone(), derp_rx))];
        for s in [&ms.udp4, &ms.udp6].into_iter().flatten() {
            tasks.push(tokio::spawn(udp_recv_loop(weak.clone(), s.clone())));
        }
        tasks.push(tokio::spawn(timer_loop(weak.clone())));
        if ms.enable_udp {
            tasks.push(tokio::spawn(endpoint_loop(weak)));
        }
        *ms.tasks.lock().unwrap() = tasks;
        Ok((ms, wg_rx))
    }

    /// Our node public key.
    pub fn public_key(&self) -> NodePublic {
        self.public_key
    }

    /// Our disco public key.
    pub fn disco_public(&self) -> DiscoPublic {
        self.disco_public
    }

    /// Our home DERP region.
    pub fn home_region(&self) -> i32 {
        self.home_region
    }

    /// Waits until the home DERP connection is up, or `timeout` passes.
    pub async fn wait_derp_connected(&self, timeout: Duration) -> bool {
        let wait = self.inner.lock().unwrap().derp.get(&self.home_region).map(|c| c.wait_connected(timeout));
        match wait {
            Some(w) => w.await,
            None => false,
        }
    }

    /// Our current advertised endpoints.
    pub fn endpoints(&self) -> Vec<SocketAddr> {
        self.inner.lock().unwrap().endpoints.clone()
    }

    /// Adds (or replaces) a DERP region that peers may be reached through.
    pub fn add_region(&self, r: DerpRegion) {
        let mut inner = self.inner.lock().unwrap();
        if r.region_id != 0 && inner.derp_map.regions.get(&r.region_id) != Some(&r) {
            // A changed non-home region reconnects with the new details on
            // next use; the home connection is kept.
            if r.region_id != self.home_region {
                inner.derp.remove(&r.region_id);
            }
            inner.derp_map.regions.insert(r.region_id, r);
        }
    }

    /// Adds a peer or updates what we know about it.
    pub fn upsert_peer(&self, cfg: PeerConfig) {
        let mut guard = self.inner.lock().unwrap();
        let inner = &mut *guard;
        self.ensure_derp_locked(inner, cfg.home_region);
        let key = cfg.node_key;
        let disco_key = cfg.disco_key;
        let shared = || Arc::new(self.disco_private.shared(&cfg.disco_key));
        let p = inner.peers.entry(key).or_insert_with(|| Peer::new(cfg.clone(), shared()));
        if p.cfg.disco_key != cfg.disco_key {
            p.shared = shared();
        }
        // Configured endpoints are only candidates: until a disco message
        // comes from one, it might be anyone's.
        for ep in &cfg.endpoints {
            p.candidates.entry(*ep).or_default();
        }
        let old = std::mem::replace(&mut p.cfg, cfg);
        for ep in &old.endpoints {
            p.forget_candidate(ep);
        }
        if old.disco_key != disco_key {
            inner.unindex_disco(&old.disco_key, &key);
        }
        inner.by_disco.insert(disco_key, key);
    }

    /// Forgets a peer. It reports whether the peer was known.
    pub fn remove_peer(&self, key: &NodePublic) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(p) = inner.peers.remove(key) else { return false };
        inner.unindex_disco(&p.cfg.disco_key, key);
        inner.by_addr.retain(|_, k| k != key);
        inner.pending.retain(|_, pp| pp.peer != *key);
        true
    }

    /// Returns a snapshot of a peer's paths.
    pub fn peer_path(&self, key: &NodePublic) -> Option<PeerPath> {
        let inner = self.inner.lock().unwrap();
        let p = inner.peers.get(key)?;
        let now = Instant::now();
        Some(PeerPath {
            node_key: p.cfg.node_key,
            disco_key: p.cfg.disco_key,
            home_region: p.derp_region(),
            best: p.best,
            direct_trusted: p.trusted(now),
            candidates: p.candidates.keys().copied().collect(),
            last_send: p.last_send,
            last_recv: p.last_recv,
        })
    }

    /// Sends a raw packet to `peer` through DERP region `region` (or the
    /// peer's region if 0). It reports whether the packet was queued.
    pub fn send_derp(&self, peer: &NodePublic, region: i32, pkt: &[u8]) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let region = if region != 0 {
            region
        } else {
            inner.peers.get(peer).map(|p| p.derp_region()).filter(|r| *r != 0).unwrap_or(self.home_region)
        };
        self.send_derp_locked(&mut inner, region, peer, pkt)
    }

    /// Sends a WireGuard packet to `peer` over its best path(s), starting
    /// path discovery if no direct path is trusted.
    pub fn send_wireguard(&self, peer: &NodePublic, pkt: &[u8]) -> Result<()> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let Some(p) = inner.peers.get_mut(peer) else {
            return Err(Error::other(format!("unknown peer {}", peer.short_string())));
        };
        p.last_send = Some(now);
        let trusted = p.trusted(now);
        let udp = p.best.map(|b| b.0);
        // Without a trusted direct path, also send over DERP: through the
        // peer's region, or our own if there's no direct path to try.
        let derp =
            (!trusted).then(|| p.derp_region()).filter(|r| *r != 0).or(udp.is_none().then_some(self.home_region));
        if !trusted && self.enable_udp {
            self.discover_locked(&mut inner, peer, now, true);
        }
        let derp_sent = derp.is_some_and(|r| self.send_derp_locked(&mut inner, r, peer, pkt));
        drop(inner);
        match udp {
            Some(a) => self.send_udp(a, pkt),
            None if !derp_sent => trace!(peer = %peer.short_string(), "magicsock: WireGuard packet dropped: no path"),
            None => {}
        }
        Ok(())
    }

    /// Advertises our endpoints to `peer` in a CallMeMaybe over DERP.
    pub fn send_call_me_maybe(&self, peer: &NodePublic) {
        let mut inner = self.inner.lock().unwrap();
        self.call_me_maybe_locked(&mut inner, peer, Instant::now());
    }

    /// Sends disco pings to `peer` over every path (DERP and each known
    /// endpoint) and returns the first pong. It also advertises our
    /// endpoints, nudging the peer to try a direct path.
    pub async fn ping(&self, peer: &NodePublic, timeout: Duration) -> Result<PingResult> {
        let (tx, mut rx) = mpsc::channel(1);
        self.start_ping(peer, tx)?;
        tokio::time::timeout(timeout, rx.recv()).await.ok().flatten().ok_or_else(|| Error::Timeout("disco ping".into()))
    }

    /// Sends [`MagicSock::ping`]'s pings, each reporting its pong to `tx`.
    fn start_ping(&self, peer: &NodePublic, tx: mpsc::Sender<PingResult>) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let Some(p) = inner.peers.get(peer) else {
            return Err(Error::other(format!("unknown peer {}", peer.short_string())));
        };
        // Like Tailscale's CLI ping: with a trusted direct path, ping
        // just that; otherwise ping over DERP and every candidate.
        let direct = p.best.filter(|_| p.trusted(now));
        let paths: Vec<PathAddr> = match direct {
            Some((best, _)) => vec![PathAddr::Udp(best)],
            None => {
                let derp = Some(p.derp_region()).filter(|r| *r != 0).map(PathAddr::Derp);
                let udp = p.candidates.keys().filter(|_| self.enable_udp).copied().map(PathAddr::Udp);
                derp.into_iter().chain(udp).collect()
            }
        };
        for to in paths {
            self.send_ping_locked(&mut inner, peer, to, now, Some(tx.clone()));
        }
        if direct.is_none() {
            self.call_me_maybe_locked(&mut inner, peer, now);
        }
        drop(inner);
        Ok(())
    }

    /// Stops all background work.
    pub fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        inner.derp.clear();
        drop(inner);
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for t in tasks {
            t.abort();
        }
    }

    // -----------------------------------------------------------------

    fn send_derp_locked(&self, inner: &mut Inner, region: i32, peer: &NodePublic, pkt: &[u8]) -> bool {
        self.ensure_derp_locked(inner, region);
        inner.derp.get(&region).is_some_and(|c| c.send(peer, pkt))
    }

    /// Connects to DERP region `region`, if not already.
    fn ensure_derp(&self, region: i32) {
        let mut inner = self.inner.lock().unwrap();
        self.ensure_derp_locked(&mut inner, region);
        drop(inner);
    }

    fn ensure_derp_locked(&self, inner: &mut Inner, region: i32) {
        if region == 0 || inner.closed || inner.derp.contains_key(&region) {
            return;
        }
        let Some(r) = inner.derp_map.regions.get(&region).cloned() else { return };
        let c = DerpClient::spawn(
            r,
            self.private_key.clone(),
            &self.app_name,
            region == self.home_region,
            self.derp_tx.clone(),
        );
        inner.derp.insert(region, c);
    }

    fn send_udp(&self, a: SocketAddr, pkt: &[u8]) {
        let sock = if a.is_ipv4() { &self.udp4 } else { &self.udp6 };
        if let Some(Err(e)) = sock.as_ref().map(|s| s.try_send_to(pkt, a)) {
            trace!("magicsock: send to {a}: {e}");
        }
    }

    fn send_disco(&self, inner: &mut Inner, peer: &NodePublic, to: PathAddr, msg: &Message) {
        let Some(p) = inner.peers.get(peer) else { return };
        let pkt = disco::seal(&self.disco_public, &p.shared, msg);
        if crate::verbose() {
            debug!(peer = %peer.short_string(), %to, "magicsock: disco send {}", msg.summary());
        }
        match to {
            PathAddr::Udp(a) => self.send_udp(a, &pkt),
            PathAddr::Derp(r) => {
                self.send_derp_locked(inner, r, peer, &pkt);
            }
        }
    }

    fn send_ping_locked(
        &self,
        inner: &mut Inner,
        peer: &NodePublic,
        to: PathAddr,
        now: Instant,
        waiter: Option<mpsc::Sender<PingResult>>,
    ) {
        let tx_id: TxId = rand::thread_rng().r#gen();
        inner.pending.insert(tx_id, PendingPing { peer: *peer, to, sent: now, waiter });
        if let (PathAddr::Udp(a), Some(p)) = (to, inner.peers.get_mut(peer))
            && let Some(last_ping) = p.candidates.get_mut(&a)
        {
            *last_ping = Some(now);
        }
        let msg = Message::Ping { tx_id, node_key: Some(self.public_key), padding: 0 };
        self.send_disco(inner, peer, to, &msg);
    }

    /// Pings every candidate endpoint of `peer` not pinged recently, and
    /// optionally advertises our endpoints over DERP.
    fn discover_locked(&self, inner: &mut Inner, peer: &NodePublic, now: Instant, call_me_maybe: bool) {
        let Some(p) = inner.peers.get_mut(peer) else { return };
        if p.last_full_ping.is_some_and(|t| now - t < DISCO_PING_INTERVAL) {
            return;
        }
        p.last_full_ping = Some(now);
        let due: Vec<SocketAddr> = p
            .candidates
            .iter()
            .filter(|(_, last_ping)| last_ping.is_none_or(|t| now - t >= DISCO_PING_INTERVAL))
            .map(|(a, _)| *a)
            .collect();
        for a in due {
            self.send_ping_locked(inner, peer, PathAddr::Udp(a), now, None);
        }
        if call_me_maybe {
            self.call_me_maybe_locked(inner, peer, now);
        }
    }

    fn call_me_maybe_locked(&self, inner: &mut Inner, peer: &NodePublic, now: Instant) {
        if !self.enable_udp || inner.endpoints.is_empty() {
            return;
        }
        let Some(p) = inner.peers.get_mut(peer) else { return };
        let region = p.derp_region();
        if region == 0 {
            return;
        }
        p.last_call_me_maybe = Some(now);
        let msg = Message::CallMeMaybe { endpoints: inner.endpoints.clone() };
        self.send_disco(inner, peer, PathAddr::Derp(region), &msg);
    }

    fn handle_disco(&self, pkt: &[u8], src: PathAddr, derp_src: Option<NodePublic>) {
        let Some(sender) = disco::source(pkt) else { return };
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        // Over DERP the relay vouches for the sender's node key.
        let Some(mut peer_key) = derp_src.or_else(|| inner.by_disco.get(&sender).copied()) else {
            trace!(disco = %sender.short_string(), "magicsock: disco from unknown key");
            return;
        };
        let holds = |inner: &Inner, k: &NodePublic| inner.peers.get(k).is_some_and(|p| p.cfg.disco_key == sender);
        if !holds(&inner, &peer_key) {
            trace!("magicsock: disco key/node key mismatch");
            return;
        }
        let shared = inner.peers[&peer_key].shared.clone();
        let Some(msg) = disco::open(&shared, pkt) else {
            trace!("magicsock: disco box didn't open");
            return;
        };
        if derp_src.is_none() {
            // Over UDP, peers sharing the disco key are told apart by the
            // node key in a ping, or the peer a pong's ping went to.
            let named = match &msg {
                Message::Ping { node_key, .. } => *node_key,
                Message::Pong { tx_id, .. } => inner.pending.get(tx_id).map(|pp| pp.peer),
                Message::CallMeMaybe { .. } => None,
            };
            if let Some(k) = named.filter(|k| holds(&inner, k)) {
                peer_key = k;
            }
        }
        if crate::verbose() {
            debug!(peer = %peer_key.short_string(), %src, "magicsock: disco recv {}", msg.summary());
        }
        match msg {
            Message::Ping { tx_id, .. } => {
                let pong_src = match src {
                    PathAddr::Udp(a) => {
                        inner.by_addr.insert(a, peer_key);
                        let p = inner.peers.get_mut(&peer_key).expect("known peer");
                        if p.candidates.entry(a).or_default().is_none_or(|t| now - t >= DISCO_PING_INTERVAL) {
                            // Ping back: it both verifies the path for our
                            // side and helps punch through the NAT.
                            self.send_ping_locked(&mut inner, &peer_key, PathAddr::Udp(a), now, None);
                        }
                        a
                    }
                    PathAddr::Derp(r) => {
                        inner.peers.get_mut(&peer_key).expect("known peer").derp_seen = Some(r);
                        SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), r as u16)
                    }
                };
                self.send_disco(&mut inner, &peer_key, src, &Message::Pong { tx_id, src: pong_src });
            }
            Message::Pong { tx_id, .. } => {
                let pp = match inner.pending.entry(tx_id) {
                    Entry::Occupied(e) if e.get().peer == peer_key => e.remove(),
                    _ => return,
                };
                let latency = now - pp.sent;
                if let Some(w) = &pp.waiter {
                    let _ = w.try_send(PingResult { latency, via: src });
                }
                if let (PathAddr::Udp(from), PathAddr::Udp(to)) = (src, pp.to) {
                    inner.by_addr.insert(from, peer_key);
                    let p = inner.peers.get_mut(&peer_key).expect("known peer");
                    // A pong confirms the path in use, renewing its trust,
                    // or replaces it if that's untrusted or worse.
                    let current = p.best.map(|b| b.0);
                    if current == Some(to) || !p.trusted(now) || better_addr((to, latency), p.best) {
                        if current != Some(to) {
                            debug!(peer = %peer_key.short_string(), "magicsock: now using {to} ({latency:?})");
                        }
                        p.best = Some((to, latency));
                        p.trust_until = Some(now + TRUST_UDP_ADDR_DURATION);
                    }
                }
            }
            Message::CallMeMaybe { mut endpoints } => {
                let PathAddr::Derp(_) = src else {
                    trace!("magicsock: CallMeMaybe not over DERP; ignored");
                    return;
                };
                if !self.enable_udp {
                    return;
                }
                // The endpoints are only the peer's claims (they might be
                // another peer's), so they replace its earlier claims as
                // candidates, and a pong from one maps it to the peer.
                endpoints.retain(|e| !matches!(e.ip(), IpAddr::V6(v6) if v6.is_unicast_link_local()));
                let p = inner.peers.get_mut(&peer_key).expect("known peer");
                for e in std::mem::replace(&mut p.advertised, endpoints.clone()) {
                    p.forget_candidate(&e);
                }
                for e in &endpoints {
                    p.candidates.entry(*e).or_default();
                }
                for e in endpoints {
                    self.send_ping_locked(&mut inner, &peer_key, PathAddr::Udp(e), now, None);
                }
            }
        }
    }

    fn handle_udp(&self, pkt: &[u8], src: SocketAddr) {
        if stun::is_stun(pkt) {
            self.handle_stun(pkt);
            return;
        }
        if disco::looks_like_disco(pkt) {
            self.handle_disco(pkt, PathAddr::Udp(src), None);
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let peer = inner.by_addr.get(&src).copied();
        if let Some(p) = peer.and_then(|k| inner.peers.get_mut(&k)) {
            p.last_recv = Some(Instant::now());
        }
        drop(inner);
        let _ = self.wg_tx.try_send(WireguardPacket::udp(peer, src, pkt));
    }

    fn handle_derp(&self, rp: ReceivedPacket) {
        if disco::looks_like_disco(&rp.data) {
            self.handle_disco(&rp.data, PathAddr::Derp(rp.region_id), Some(rp.src));
            return;
        }
        if self.on_derp_recv.as_ref().is_some_and(|h| h(rp.region_id, rp.src, &rp.data)) {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if let Some(p) = inner.peers.get_mut(&rp.src) {
            p.derp_seen = Some(rp.region_id);
            p.last_recv = Some(Instant::now());
        }
        drop(inner);
        let _ = self.wg_tx.try_send(WireguardPacket::derp(rp.region_id, rp.src, rp.data));
    }

    fn handle_stun(&self, pkt: &[u8]) {
        let Some((tx, addr)) = stun::parse_response(pkt) else { return };
        let mut inner = self.inner.lock().unwrap();
        let Some((_, round)) = inner.stun_pending.remove(&tx) else { return };
        if round < inner.stun_endpoints_round {
            return; // a late reply from an old round
        }
        if round > inner.stun_endpoints_round {
            // The first reply of a new round replaces the old results.
            inner.stun_endpoints.clear();
            inner.stun_endpoints_round = round;
        }
        if !inner.stun_endpoints.contains(&addr) {
            inner.stun_endpoints.push(addr);
        }
        self.recompute_endpoints_locked(&mut inner);
    }

    fn recompute_endpoints_locked(&self, inner: &mut Inner) {
        let mut eps: Vec<SocketAddr> =
            inner.stun_endpoints.iter().chain(inner.local_endpoints.iter()).copied().collect();
        eps.sort();
        eps.dedup();
        if eps != inner.endpoints {
            debug!("magicsock: endpoints now {eps:?}");
            inner.endpoints = eps;
            // Tailcat has no control plane distributing endpoints, so tell
            // every peer directly whenever they change.
            let now = Instant::now();
            let peers: Vec<NodePublic> = inner.peers.keys().copied().collect();
            for p in peers {
                self.call_me_maybe_locked(inner, &p, now);
            }
        }
    }

    /// Gathers local interface endpoints and re-STUNs.
    async fn refresh_endpoints(&self) {
        let port = |s: &Option<Arc<UdpSocket>>| s.as_ref().and_then(|s| s.local_addr().ok()).map(|a| a.port());
        let (port4, port6) = (port(&self.udp4), port(&self.udp6));
        let mut local: Vec<SocketAddr> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.ip())
            .filter(|ip| !ip.is_loopback() && self.endpoint_filter.as_ref().is_none_or(|f| f(*ip)))
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) if !v4.is_link_local() => Some(SocketAddr::new(ip, port4?)),
                IpAddr::V6(v6) if !v6.is_unicast_link_local() && !is_tailscale_ula(&v6) => {
                    Some(SocketAddr::new(ip, port6?))
                }
                _ => None,
            })
            .collect();
        local.sort();
        local.dedup();

        let (region, round) = self.begin_stun_round(local);
        let Some(region) = region else { return };
        for n in region.nodes.iter().take(2) {
            let Some(port) = n.stun_port() else { continue };
            for a in n.resolve_addrs(port).await {
                let tx = stun::new_txid();
                self.inner.lock().unwrap().stun_pending.insert(tx, (Instant::now(), round));
                self.send_udp(a, &stun::request(tx));
            }
        }
    }

    /// Records our local endpoints and starts a new STUN round,
    /// returning the home region to send it to and the round's number.
    fn begin_stun_round(&self, local: Vec<SocketAddr>) -> (Option<DerpRegion>, u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.local_endpoints = local;
        inner.stun_pending.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(5));
        inner.stun_round += 1;
        self.recompute_endpoints_locked(&mut inner);
        let region = inner.derp_map.regions.get(&self.home_region).cloned();
        let round = inner.stun_round;
        drop(inner);
        (region, round)
    }

    fn on_timer(&self) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner.pending.retain(|_, pp| now - pp.sent < PING_TIMEOUT);
        if !self.enable_udp {
            return;
        }
        let keys: Vec<NodePublic> = inner.peers.keys().copied().collect();
        for k in keys {
            let p = &inner.peers[&k];
            let active = p.last_send.is_some_and(|t| now - t < SESSION_ACTIVE_TIMEOUT);
            if !active {
                continue;
            }
            if let Some((best, lat)) = p.best {
                let needs_upgrade =
                    lat > GOOD_ENOUGH_LATENCY && p.last_upgrade.is_none_or(|t| now - t > UPGRADE_INTERVAL);
                if p.trusted(now) {
                    // Heartbeat the path in use to keep it trusted.
                    self.send_ping_locked(&mut inner, &k, PathAddr::Udp(best), now, None);
                    if needs_upgrade {
                        inner.peers.get_mut(&k).unwrap().last_upgrade = Some(now);
                        self.discover_locked(&mut inner, &k, now, false);
                    }
                    continue;
                }
            }
            self.discover_locked(&mut inner, &k, now, true);
        }
    }
}

impl Drop for MagicSock {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
impl MagicSock {
    /// A magicsock with no sockets, relays or background tasks, whose
    /// state tests drive by calling its handlers directly.
    pub(crate) fn offline(key: NodePrivate, enable_udp: bool) -> (Arc<MagicSock>, mpsc::Receiver<WireguardPacket>) {
        let (wg_tx, wg_rx) = mpsc::channel(1024);
        let disco_private = key.disco_private();
        let ms = MagicSock {
            public_key: key.public(),
            disco_public: disco_private.public(),
            disco_private,
            private_key: key,
            home_region: 1,
            app_name: "test".into(),
            enable_udp,
            endpoint_filter: None,
            on_derp_recv: None,
            udp4: None,
            udp6: None,
            inner: Mutex::default(),
            wg_tx,
            derp_tx: mpsc::channel(1).0,
            tasks: Mutex::default(),
        };
        (Arc::new(ms), wg_rx)
    }
}

fn is_tailscale_ula(v6: &std::net::Ipv6Addr) -> bool {
    let o = v6.octets();
    o[..6] == [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0]
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => (v6.octets()[0] & 0xfe) == 0xfc || v6.is_loopback(),
    }
}

/// Reports whether `a` is a better path than `b`: noticeably lower
/// latency, with a bonus for private addresses and for IPv6, as in
/// Tailscale's `betterAddr`.
fn better_addr(a: (SocketAddr, Duration), b: Option<(SocketAddr, Duration)>) -> bool {
    let Some(b) = b else { return true };
    if a.0 == b.0 {
        return false;
    }
    // Points for being faster (by how many percent), for being on the
    // local network, and for IPv6.
    let (al, bl) = (a.1.as_micros() as i64, b.1.as_micros() as i64);
    let (ap, bp) = if al > bl && al > 0 {
        (0, 100 - bl * 100 / al)
    } else if bl > 0 {
        (100 - al * 100 / bl, 0)
    } else {
        (0, 0)
    };
    let bonus = |a: SocketAddr| 20 * is_private(a.ip()) as i64 + 10 * a.is_ipv6() as i64;
    let (ap, bp) = (ap + bonus(a.0), bp + bonus(b.0));
    if ap == bp { a.1 < b.1 } else { ap > bp }
}

async fn derp_recv_loop(ms: Weak<MagicSock>, mut rx: mpsc::Receiver<ReceivedPacket>) {
    while let Some(rp) = rx.recv().await {
        let Some(ms) = ms.upgrade() else { return };
        ms.handle_derp(rp);
    }
}

async fn udp_recv_loop(ms: Weak<MagicSock>, sock: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let r = sock.recv_from(&mut buf).await;
        let Some(ms) = ms.upgrade() else { return };
        match r {
            Ok((n, src)) => ms.handle_udp(&buf[..n], SocketAddr::new(src.ip().to_canonical(), src.port())),
            Err(e) => {
                // ICMP-induced errors (connection refused etc.) are transient.
                trace!("magicsock: UDP recv: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn timer_loop(ms: Weak<MagicSock>) {
    let mut t = tokio::time::interval(HEARTBEAT_INTERVAL);
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        t.tick().await;
        let Some(ms) = ms.upgrade() else { return };
        ms.on_timer();
    }
}

async fn endpoint_loop(ms: Weak<MagicSock>) {
    // STUN right away, twice more soon after (in case the first round
    // was lost while the relay connection came up), then every 20–26s.
    let later = std::iter::repeat_with(|| rand::thread_rng().gen_range(20_000..26_000));
    for delay_ms in [300, 2000].into_iter().chain(later) {
        {
            let Some(ms) = ms.upgrade() else { return };
            ms.refresh_endpoints().await;
        }
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

#[cfg(test)]
mod model_tests;

#[cfg(test)]
mod tests {
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::derp::server::DevDerp;

    const T: Duration = Duration::from_secs(10);

    async fn sock(dev: &DevDerp, enable_udp: bool) -> (Arc<MagicSock>, mpsc::Receiver<WireguardPacket>) {
        let mut derp_map = DerpMap::default();
        derp_map.regions.insert(1, dev.region.clone());
        let cfg = Config {
            private_key: NodePrivate::generate(),
            derp_map,
            home_region: 1,
            derp_app_name: "test".into(),
            listen_port: 0,
            on_derp_recv: None,
            endpoint_filter: None,
            enable_udp,
        };
        let (ms, rx) = MagicSock::start(cfg).await.unwrap();
        assert!(ms.wait_derp_connected(T).await);
        (ms, rx)
    }

    fn introduce(a: &MagicSock, b: &MagicSock) {
        for (x, y) in [(a, b), (b, a)] {
            x.upsert_peer(PeerConfig {
                node_key: y.public_key(),
                disco_key: y.disco_public(),
                home_region: 1,
                endpoints: vec![],
            });
        }
    }

    async fn recv(rx: &mut mpsc::Receiver<WireguardPacket>) -> WireguardPacket {
        timeout(T, rx.recv()).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn pings_and_sends_over_derp_without_udp() {
        let dev = DevDerp::start_local().await.unwrap();
        let (a, _a_rx) = sock(&dev, false).await;
        let (b, mut b_rx) = sock(&dev, false).await;
        let b_key = b.public_key();
        let stranger = NodePrivate::generate().public();
        assert!(a.ping(&b_key, T).await.is_err(), "pinged an unknown peer");
        introduce(&a, &b);

        let r = a.ping(&b_key, T).await.unwrap();
        assert_eq!(r.via, PathAddr::Derp(1));
        let path = a.peer_path(&b_key).unwrap();
        assert!(path.best.is_none());
        assert!(!path.direct_trusted);
        assert!(path.candidates.is_empty());
        assert_eq!(path.home_region, 1);

        a.send_wireguard(&b_key, b"not really WireGuard").unwrap();
        let p = recv(&mut b_rx).await;
        assert_eq!(p.peer, Some(a.public_key()));
        assert_eq!(p.src, PathAddr::Derp(1));
        assert_eq!(p.data, b"not really WireGuard");
        assert!(b.peer_path(&a.public_key()).unwrap().last_recv.is_some());
        assert!(a.send_wireguard(&stranger, b"x").is_err());

        assert!(a.remove_peer(&b_key));
        assert!(!a.remove_peer(&b_key));
        assert!(a.peer_path(&b_key).is_none());
        assert!(a.ping(&b_key, T).await.is_err());
    }

    /// Pings `b` from `a` until `a` trusts a direct path to it, returning
    /// that path.
    async fn direct_path(a: &MagicSock, b: &MagicSock) -> SocketAddr {
        let trusted = async {
            loop {
                let _ = a.ping(&b.public_key(), Duration::from_secs(1)).await;
                if let Some(PeerPath { best: Some((addr, _)), direct_trusted: true, .. }) = a.peer_path(&b.public_key())
                {
                    return addr;
                }
                sleep(Duration::from_millis(100)).await;
            }
        };
        timeout(T, trusted).await.expect("no direct path")
    }

    #[tokio::test]
    async fn upgrades_to_a_direct_path() {
        let dev = DevDerp::start_local().await.unwrap();
        let (a, _a_rx) = sock(&dev, true).await;
        let (b, mut b_rx) = sock(&dev, true).await;
        introduce(&a, &b);
        // STUN against the local relay finds each side's loopback address,
        // which CallMeMaybe then hands to the other.
        let best = direct_path(&a, &b).await;
        assert!(!a.endpoints().is_empty());

        // With a trusted path, pings and packets go only that way.
        let r = a.ping(&b.public_key(), T).await.unwrap();
        assert_eq!(r.via, PathAddr::Udp(best));
        while b_rx.try_recv().is_ok() {}
        a.send_wireguard(&b.public_key(), b"direct").unwrap();
        let p = recv(&mut b_rx).await;
        assert!(matches!(p.src, PathAddr::Udp(_)), "came via {}", p.src);
        assert_eq!(p.peer, Some(a.public_key()));
        assert_eq!(p.data, b"direct");
    }

    #[test]
    fn peer_derp_region_falls_back_to_where_it_was_heard() {
        let k = NodePrivate::generate();
        let disco = k.disco_private();
        let cfg = PeerConfig { node_key: k.public(), disco_key: disco.public(), home_region: 0, endpoints: vec![] };
        let mut p = Peer::new(cfg, Arc::new(disco.shared(&disco.public())));
        assert_eq!(p.derp_region(), 0);
        p.derp_seen = Some(7);
        assert_eq!(p.derp_region(), 7);
        p.cfg.home_region = 3;
        assert_eq!(p.derp_region(), 3);

        let now = Instant::now();
        assert!(!p.trusted(now));
        p.trust_until = Some(now + TRUST_UDP_ADDR_DURATION);
        assert!(!p.trusted(now), "trust without a path");
        p.best = Some(("192.0.2.1:1".parse().unwrap(), Duration::ZERO));
        assert!(p.trusted(now));
        assert!(!p.trusted(now + TRUST_UDP_ADDR_DURATION));
    }

    #[test]
    fn better_addr_prefers_faster_and_private() {
        let pubv4: SocketAddr = "203.0.113.1:1".parse().unwrap();
        let pubv4b: SocketAddr = "203.0.113.2:1".parse().unwrap();
        let lan: SocketAddr = "192.168.1.2:1".parse().unwrap();
        let pubv6: SocketAddr = "[2001:db8::1]:1".parse().unwrap();
        let ms = Duration::from_millis;
        // Whether `a` at `a_ms` beats `b` at `b_ms`.
        let better = |a, a_ms, b, b_ms| better_addr((a, ms(a_ms)), Some((b, ms(b_ms))));

        assert!(better_addr((pubv4, ms(10)), None));
        assert!(better(pubv4, 10, pubv4b, 50));
        assert!(better(pubv4, 49, pubv4b, 50));
        assert!(!better(pubv4, 51, pubv4b, 50));
        assert!(better(lan, 12, pubv4, 10));
        assert!(!better(pubv4, 10, pubv4, 50));
        // IPv6 earns a bonus too, but less than being local.
        assert!(better(pubv6, 10, pubv4, 10));
        assert!(!better(pubv4, 10, pubv6, 10));
        assert!(!better(pubv6, 10, lan, 10));
        // Equal scores fall back to raw latency, zero included.
        assert!(!better(pubv4, 0, pubv4b, 0));
    }
}
