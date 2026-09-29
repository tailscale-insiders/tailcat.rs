//! The tailcat server: listens for clients through a DERP relay and
//! serves TCP connections and UDP flows over WireGuard.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::addr::{Addr, ConnInfo};
use crate::derpmap::{DerpMap, DerpMapCache, DerpRegion, FetchMode, FetchOptions};
use crate::key::{DiscoPublic, NodePrivate, NodePublic, PresharedKey};
use crate::magicsock::{self, MagicSock, PeerPath};
use crate::netstack::{BoxFuture, Stack, StackConfig, TcpDecision, TcpPolicy, TcpStream, UdpConn, UdpPolicy};
use crate::wg::{self, Engine, IpNet};
use crate::{Error, Result, meow};

/// How long an idle inbound UDP flow stays open by default.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// A TCP connection handler.
pub type TcpHandler = Arc<dyn Fn(TcpStream) -> BoxFuture<()> + Send + Sync>;

/// A UDP flow handler.
pub type UdpHandler = Arc<dyn Fn(UdpConn) -> BoxFuture<()> + Send + Sync>;

/// Wraps an async function as a [`TcpHandler`].
pub fn handler<F, Fut>(f: F) -> TcpHandler
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |c| Box::pin(f(c)))
}

/// Wraps an async function as a [`UdpHandler`].
pub fn udp_handler<F, Fut>(f: F) -> UdpHandler
where
    F: Fn(UdpConn) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |c| Box::pin(f(c)))
}

/// An inclusive range of ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

impl PortRange {
    pub const ALL: PortRange = PortRange { first: 0, last: 65535 };

    pub fn single(p: u16) -> Self {
        PortRange { first: p, last: p }
    }

    pub fn contains(&self, p: u16) -> bool {
        (self.first..=self.last).contains(&p)
    }

    /// Coalesces sorted ports into contiguous ranges.
    pub fn coalesce(sorted: &[u16]) -> Vec<PortRange> {
        let mut out: Vec<PortRange> = Vec::new();
        for &p in sorted {
            match out.last_mut() {
                Some(r) if r.last.checked_add(1) == Some(p) => r.last = p,
                _ => out.push(PortRange::single(p)),
            }
        }
        out
    }
}

type AllowFn = Arc<dyn Fn(NodePublic) -> bool + Send + Sync>;
type OnTcp = Arc<dyn Fn(u16) -> Option<TcpHandler> + Send + Sync>;
type OnTcpForward = Arc<dyn Fn(SocketAddr) -> Option<TcpHandler> + Send + Sync>;
type OnUdp = Arc<dyn Fn(u16) -> Option<UdpHandler> + Send + Sync>;
type OnUdpForward = Arc<dyn Fn(SocketAddr) -> Option<UdpHandler> + Send + Sync>;

/// Configures and starts a [`Server`]. Every field has a default: a fresh
/// ephemeral key and pre-shared key, and the lowest-latency region of
/// the default DERP map.
#[derive(Default)]
pub struct ServerBuilder {
    key: Option<NodePrivate>,
    psk: Option<PresharedKey>,
    disable_psk: bool,
    region: Option<DerpRegion>,
    region_id: i32,
    derp_map_url: Option<String>,
    derp_map_cache: Option<Arc<dyn DerpMapCache>>,
    listen_port: u16,
    cfg: Handlers,
}

impl ServerBuilder {
    /// The server's node key; a new ephemeral key if unset.
    pub fn key(mut self, k: NodePrivate) -> Self {
        self.key = Some(k);
        self
    }

    /// The WireGuard pre-shared key clients must know; a new random one
    /// if unset. A persistent server must restore it along with the key
    /// for its address to stay valid.
    pub fn preshared_key(mut self, psk: PresharedKey) -> Self {
        self.psk = Some(psk);
        self
    }

    /// Disables the pre-shared-key layer, for shorter addresses usable by
    /// old clients. Not recommended.
    pub fn disable_preshared_key(mut self, v: bool) -> Self {
        self.disable_psk = v;
        self
    }

    /// The DERP region to use, with no DERP map fetch.
    pub fn region(mut self, r: DerpRegion) -> Self {
        self.region = Some(r);
        self
    }

    /// A region ID in the DERP map (used when no region is set).
    pub fn region_id(mut self, id: i32) -> Self {
        self.region_id = id;
        self
    }

    /// An alternate DERP map URL.
    pub fn derp_map_url(mut self, url: impl Into<String>) -> Self {
        self.derp_map_url = Some(url.into());
        self
    }

    /// A cache for DERP map fetches.
    pub fn derp_map_cache(mut self, c: Arc<dyn DerpMapCache>) -> Self {
        self.derp_map_cache = Some(c);
        self
    }

    /// Decides whether a client may connect. It's asked when a client
    /// that isn't connected announces itself; a rejected client is
    /// ignored (and asks again about once a second). It may block. With
    /// no hook, every client is allowed; see [`crate::KeySet`].
    pub fn allow_client(mut self, f: impl Fn(NodePublic) -> bool + Send + Sync + 'static) -> Self {
        self.cfg.allow_client = Some(Arc::new(f));
        self
    }

    /// Returns the handler for connections to a port on the server's own
    /// address; `None` answers with a RST.
    pub fn on_tcp(mut self, f: impl Fn(u16) -> Option<TcpHandler> + Send + Sync + 'static) -> Self {
        self.cfg.on_tcp = Some(Arc::new(f));
        self
    }

    /// Returns the handler for connections relayed through the server to
    /// another address (exit node mode). IPv4 destinations arrive
    /// unmapped from the NAT64 prefix. Setting it widens the packet
    /// filter to admit any destination.
    pub fn on_tcp_forward(mut self, f: impl Fn(SocketAddr) -> Option<TcpHandler> + Send + Sync + 'static) -> Self {
        self.cfg.on_tcp_forward = Some(Arc::new(f));
        self
    }

    /// Like [`ServerBuilder::on_tcp`] for UDP flows (one per client
    /// source address); `None` drops the flow.
    pub fn on_udp(mut self, f: impl Fn(u16) -> Option<UdpHandler> + Send + Sync + 'static) -> Self {
        self.cfg.on_udp = Some(Arc::new(f));
        self
    }

    /// Like [`ServerBuilder::on_tcp_forward`] for UDP flows.
    pub fn on_udp_forward(mut self, f: impl Fn(SocketAddr) -> Option<UdpHandler> + Send + Sync + 'static) -> Self {
        self.cfg.on_udp_forward = Some(Arc::new(f));
        self
    }

    /// Restricts which TCP ports on the server's address the filter
    /// admits, for defense in depth; filtered SYNs get no reply.
    pub fn served_tcp_ports(mut self, p: Vec<PortRange>) -> Self {
        self.cfg.served_tcp_ports = Some(p);
        self
    }

    /// Restricts which UDP ports on the server's address are admitted.
    pub fn served_udp_ports(mut self, p: Vec<PortRange>) -> Self {
        self.cfg.served_udp_ports = Some(p);
        self
    }

    /// How long an idle inbound UDP flow stays open.
    pub fn udp_idle_timeout(mut self, d: Duration) -> Self {
        self.cfg.udp_idle_timeout = Some(d);
        self
    }

    /// The UDP port for direct connections (0 picks one).
    pub fn listen_port(mut self, p: u16) -> Self {
        self.listen_port = p;
        self
    }

    /// Connects to the DERP relay and starts accepting clients.
    pub async fn start(self) -> Result<Server> {
        Server::start(self).await
    }
}

#[derive(Default)]
struct Listeners {
    tcp: HashMap<u16, mpsc::Sender<TcpStream>>,
    udp: HashMap<u16, mpsc::Sender<UdpConn>>,
}

struct Inner {
    key: NodePrivate,
    public: NodePublic,
    psk: PresharedKey,
    addr: Ipv6Addr,
    region: DerpRegion,
    ms: Arc<MagicSock>,
    engine: Arc<Engine>,
    stack: Stack,
    /// Connected clients and their node IDs, for logs; like the Go
    /// server, IDs are never reused.
    clients: Mutex<HashMap<NodePublic, u64>>,
    next_client_id: AtomicU64,
    pending_allow: Mutex<HashSet<NodePublic>>,
    listeners: Mutex<Listeners>,
    cfg: Handlers,
    task: tokio::task::JoinHandle<()>,
}

impl Inner {
    fn close(&self) {
        self.stack.close();
        self.engine.close();
        self.ms.close();
        self.task.abort();
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.close();
    }
}

/// The per-flow hooks and filters, set through [`ServerBuilder`].
#[derive(Default)]
struct Handlers {
    allow_client: Option<AllowFn>,
    on_tcp: Option<OnTcp>,
    on_tcp_forward: Option<OnTcpForward>,
    on_udp: Option<OnUdp>,
    on_udp_forward: Option<OnUdpForward>,
    served_tcp_ports: Option<Vec<PortRange>>,
    served_udp_ports: Option<Vec<PortRange>>,
    udp_idle_timeout: Option<Duration>,
}

/// Reports whether an optional port filter admits `port`.
fn admits(filter: &Option<Vec<PortRange>>, port: u16) -> bool {
    filter.as_ref().is_none_or(|ranges| ranges.iter().any(|r| r.contains(port)))
}

/// A running tailcat server. Clones share the same server.
#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

/// The status of a connected client.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub key: NodePublic,
    pub tailcat_ip: Ipv6Addr,
    /// The direct UDP path in use, if any.
    pub cur_addr: Option<SocketAddr>,
    /// The DERP region code, when relayed.
    pub relay: String,
    pub last_handshake: Option<Duration>,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
}

/// A server status snapshot.
#[derive(Debug, Clone)]
pub struct ServerStatus {
    pub public_key: NodePublic,
    pub region_id: i32,
    pub endpoints: Vec<SocketAddr>,
    pub peers: Vec<PeerStatus>,
}

/// The NAT64 prefix `64:ff9b::/96`.
const NAT64_PREFIX: u128 = 0x64_ff9b << 96;

/// Unmaps an address in the NAT64 prefix to IPv4.
pub(crate) fn unmap_nat64(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) if u128::from(v6) >> 32 == NAT64_PREFIX >> 32 => {
            SocketAddr::new(Ipv4Addr::from(u128::from(v6) as u32).into(), a.port())
        }
        _ => a,
    }
}

/// Maps an IPv4 address into the NAT64 prefix for the IPv6-only tunnel.
pub(crate) fn map_nat64(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V4(v4) => SocketAddr::new(Ipv6Addr::from(NAT64_PREFIX | u128::from(u32::from(v4))).into(), a.port()),
        IpAddr::V6(_) => a,
    }
}

impl Server {
    /// Returns a builder for configuring a server.
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    async fn start(b: ServerBuilder) -> Result<Server> {
        let key = b.key.unwrap_or_else(NodePrivate::generate);
        let psk = if b.disable_psk {
            PresharedKey::default()
        } else {
            b.psk.filter(|p| !p.is_zero()).unwrap_or_else(PresharedKey::generate)
        };
        let region = match b.region {
            Some(r) => r,
            None => {
                let mut ci =
                    ConnInfo { region_id: if b.region_id != 0 { b.region_id } else { -1 }, ..Default::default() };
                ci.expand(
                    FetchOptions {
                        url: b.derp_map_url.as_deref(),
                        mode: FetchMode::Server,
                        cache: b.derp_map_cache.as_deref(),
                    },
                    None,
                )
                .await?;
                ci.region.into_iter().next().ok_or_else(|| Error::other("no DERP region"))?
            }
        };
        if region.region_id == 0 {
            return Err(Error::other("missing RegionID in DERP region"));
        }
        let public = key.public();
        let addr = public.tailcat_ip();

        // The hooks below need the server, which doesn't exist yet.
        let me: Arc<OnceLock<Weak<Inner>>> = Arc::new(OnceLock::new());
        let server = {
            let me = me.clone();
            move || me.get().and_then(Weak::upgrade).map(|inner| Server { inner })
        };
        let hook_server = server.clone();
        let hook: magicsock::DerpRecvHook = Arc::new(move |region_id, src, pkt| {
            if !meow::is_meow(pkt) {
                return false;
            }
            if meow::is_meowed(pkt) {
                return true; // servers ignore acks
            }
            if let Some((_, disco)) = meow::parse_ping(pkt)
                && let Some(s) = hook_server()
            {
                tokio::spawn(async move {
                    // Ack only once the client is fully added: "meowed"
                    // tells it to start dialing. Disallowed clients get
                    // no reply.
                    if s.on_meow(src, disco).await {
                        s.inner.ms.send_derp(&src, region_id, &meow::encode_meowed());
                    }
                });
            }
            true
        });

        let mut dm = DerpMap::default();
        dm.regions.insert(region.region_id, region.clone());
        let (ms, wg_rx) = MagicSock::start(magicsock::Config {
            private_key: key.clone(),
            derp_map: dm,
            home_region: region.region_id,
            derp_app_name: "tailcat-server".into(),
            listen_port: b.listen_port,
            on_derp_recv: Some(hook),
            endpoint_filter: None,
            enable_udp: true,
        })
        .await?;
        let (engine, mut inbound) = Engine::start(&key, ms.clone(), wg_rx, None, None);

        let any_ip = b.cfg.on_tcp_forward.is_some() || b.cfg.on_udp_forward.is_some();
        let tcp_server = server.clone();
        let tcp_policy: TcpPolicy =
            Arc::new(move |_, dst| tcp_server().map_or(TcpDecision::Drop, |s| s.tcp_decision(dst)));
        let udp_policy: UdpPolicy = Arc::new(move |_, dst| server()?.udp_decision(dst));
        let out_engine = Arc::downgrade(&engine);
        let stack = Stack::new(
            StackConfig { addrs: vec![IpAddr::V6(addr)], any_ip, mtu: crate::TUNNEL_MTU },
            Arc::new(move |pkt| {
                if let Some(e) = out_engine.upgrade() {
                    e.send_ip(&pkt);
                }
            }),
            Some(tcp_policy),
            Some(udp_policy),
        );

        let inject = stack.clone();
        let task = tokio::spawn(async move {
            while let Some(p) = inbound.recv().await {
                inject.inject(p.data);
            }
        });
        let inner = Arc::new(Inner {
            key,
            public,
            psk,
            addr,
            region,
            ms,
            engine,
            stack,
            clients: Mutex::default(),
            next_client_id: AtomicU64::new(2),
            pending_allow: Mutex::default(),
            listeners: Mutex::default(),
            cfg: b.cfg,
            task,
        });
        let _ = me.set(Arc::downgrade(&inner));

        // Don't hand out an address clients can't use yet: wait (briefly)
        // for the relay connection.
        if !inner.ms.wait_derp_connected(Duration::from_secs(10)).await {
            info!("tailcat: not yet connected to DERP region {}; continuing", inner.region.region_id);
        }
        Ok(Server { inner })
    }

    /// The server's node public key.
    pub fn public_key(&self) -> NodePublic {
        self.inner.public
    }

    /// The server's IPv6 tailcat address, derived from its public key.
    pub fn addr(&self) -> Ipv6Addr {
        self.inner.addr
    }

    /// The DERP region the server listens in.
    pub fn region(&self) -> &DerpRegion {
        &self.inner.region
    }

    /// The server's pre-shared key (zero if disabled).
    pub fn preshared_key(&self) -> PresharedKey {
        self.inner.psk
    }

    /// The connection info for this server, embedding the full region.
    pub fn conn_info(&self) -> ConnInfo {
        crate::addr::conn_info_for(&self.inner.key, self.inner.psk, vec![self.inner.region.clone()], 0)
    }

    /// The tailcat address clients use to connect. It embeds the full
    /// DERP region, so clients don't need to fetch the DERP map.
    pub fn tailcat_addr(&self) -> Addr {
        self.conn_info().addr()
    }

    /// The underlying path manager, for status and diagnostics.
    pub fn magicsock(&self) -> &Arc<MagicSock> {
        &self.inner.ms
    }

    /// Returns the node key of the peer at `remote`, the remote address
    /// of an accepted connection or flow. The tunnel has already
    /// authenticated the peer by this key.
    pub fn peer_key(&self, remote: SocketAddr) -> Option<NodePublic> {
        let IpAddr::V6(ip) = remote.ip() else { return None };
        self.inner.clients.lock().unwrap().keys().find(|k| k.tailcat_ip() == ip).copied()
    }

    /// Drops the connected client `k` and reports whether it was
    /// connected. Its connections stall rather than reset. Nothing stops
    /// it reconnecting unless the allow hook now rejects it.
    pub fn disconnect_client(&self, k: &NodePublic) -> bool {
        let Some(id) = self.inner.clients.lock().unwrap().remove(k) else { return false };
        debug!("tailcat: disconnecting client {} (peer {id})", k.short_string());
        self.inner.engine.remove_peer(k);
        self.inner.ms.remove_peer(k);
        true
    }

    /// Returns a status snapshot with one entry per connected client.
    pub fn status(&self) -> ServerStatus {
        let clients: Vec<NodePublic> = self.inner.clients.lock().unwrap().keys().copied().collect();
        let peers = clients
            .into_iter()
            .map(|k| {
                let path = self.inner.ms.peer_path(&k);
                let (hs, tx, rx) = self.inner.engine.peer_stats(&k).unwrap_or((None, 0, 0));
                let direct = path.as_ref().and_then(PeerPath::direct);
                PeerStatus {
                    key: k,
                    tailcat_ip: k.tailcat_ip(),
                    cur_addr: direct,
                    relay: if direct.is_none() { self.inner.region.region_code.clone() } else { String::new() },
                    last_handshake: hs,
                    tx_bytes: tx,
                    rx_bytes: rx,
                }
            })
            .collect();
        ServerStatus {
            public_key: self.inner.public,
            region_id: self.inner.region.region_id,
            endpoints: self.inner.ms.endpoints(),
            peers,
        }
    }

    /// Waits until every TCP connection has fully closed, or `timeout`
    /// passes. The whole TCP stack runs in this process, so a process
    /// that closes a connection and exits should call this first.
    pub async fn drain_tcp(&self, timeout: Duration) -> bool {
        self.inner.stack.drain_tcp(timeout).await
    }

    /// Listens on a TCP port of the server's address (0 picks an unused
    /// one). Connections to the port go to the listener instead of the
    /// `on_tcp` handler, and the port is admitted by the packet filter.
    pub fn listen_tcp(&self, port: u16) -> Result<Listener<TcpStream>> {
        self.listen(port, |l| &mut l.tcp)
    }

    /// Listens on a UDP port; each accepted item is one client flow.
    pub fn listen_udp(&self, port: u16) -> Result<Listener<UdpConn>> {
        self.listen(port, |l| &mut l.udp)
    }

    fn listen<T>(&self, port: u16, table: fn(&mut Listeners) -> &mut ListenerMap<T>) -> Result<Listener<T>> {
        let mut l = self.inner.listeners.lock().unwrap();
        let map = table(&mut l);
        let port = pick_port(port, |p| map.contains_key(&p))?;
        let (tx, rx) = mpsc::channel(64);
        map.insert(port, tx);
        Ok(Listener {
            server: Arc::downgrade(&self.inner),
            table,
            addr: SocketAddr::new(IpAddr::V6(self.inner.addr), port),
            rx,
        })
    }

    /// Shuts the server down.
    pub fn close(&self) {
        self.inner.close();
    }

    async fn on_meow(&self, src: NodePublic, disco: DiscoPublic) -> bool {
        debug!("tailcat: got meow from {src}");
        if self.inner.clients.lock().unwrap().contains_key(&src) {
            return true;
        }
        if let Some(allow) = self.inner.cfg.allow_client.clone() {
            if !self.inner.pending_allow.lock().unwrap().insert(src) {
                // An earlier meow is still waiting on the hook; the client retries.
                return false;
            }
            let allowed = tokio::task::spawn_blocking(move || allow(src)).await.unwrap_or(false);
            self.inner.pending_allow.lock().unwrap().remove(&src);
            if !allowed {
                debug!("tailcat: ignoring meow from {src}: rejected by the allow hook");
                return false;
            }
        }
        match self.inner.clients.lock().unwrap().entry(src) {
            Entry::Occupied(_) => return true,
            Entry::Vacant(e) => {
                let id = *e.insert(self.inner.next_client_id.fetch_add(1, Ordering::Relaxed));
                debug!("tailcat: client {} added as peer {id}", src.short_string());
            }
        }
        self.inner.ms.upsert_peer(magicsock::PeerConfig {
            node_key: src,
            disco_key: disco,
            home_region: self.inner.region.region_id,
            endpoints: Vec::new(),
        });
        self.inner.engine.upsert_peer(
            src,
            wg::PeerConfig {
                allowed_ips: vec![IpNet::host(IpAddr::V6(src.tailcat_ip()))],
                preshared_key: self.inner.psk,
                persistent_keepalive: None,
            },
        );
        // Tell the new client our UDP endpoints so both sides can try a
        // direct path.
        self.inner.ms.send_call_me_maybe(&src);
        true
    }

    fn tcp_decision(&self, dst: SocketAddr) -> TcpDecision {
        let cfg = &self.inner.cfg;
        let h = if dst.ip() == IpAddr::V6(self.inner.addr) {
            let port = dst.port();
            if let Some(tx) = self.inner.listeners.lock().unwrap().tcp.get(&port).cloned() {
                return TcpDecision::Accept(Box::new(move |s| {
                    tokio::spawn(async move { tx.send(s).await });
                }));
            }
            if !admits(&cfg.served_tcp_ports, port) {
                return TcpDecision::Drop;
            }
            cfg.on_tcp.as_ref().and_then(|f| f(port))
        } else {
            let Some(fwd) = &cfg.on_tcp_forward else { return TcpDecision::Drop };
            fwd(unmap_nat64(dst))
        };
        match h {
            Some(h) => TcpDecision::Accept(Box::new(move |s| {
                tokio::spawn(h(s));
            })),
            None => TcpDecision::Reset,
        }
    }

    fn udp_decision(&self, dst: SocketAddr) -> Option<Box<dyn FnOnce(UdpConn) + Send>> {
        let cfg = &self.inner.cfg;
        let idle = Some(cfg.udp_idle_timeout.unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT));
        let h: UdpHandler = if dst.ip() == IpAddr::V6(self.inner.addr) {
            let port = dst.port();
            if let Some(tx) = self.inner.listeners.lock().unwrap().udp.get(&port).cloned() {
                return Some(Box::new(move |c: UdpConn| {
                    c.set_idle_timeout(idle);
                    tokio::spawn(async move { tx.send(c).await });
                }));
            }
            if !admits(&cfg.served_udp_ports, port) {
                return None;
            }
            cfg.on_udp.as_ref()?(port)?
        } else {
            cfg.on_udp_forward.as_ref()?(unmap_nat64(dst))?
        };
        Some(Box::new(move |c: UdpConn| {
            c.set_idle_timeout(idle);
            tokio::spawn(h(c));
        }))
    }
}

/// Returns `port` if it's free, or a random free ephemeral port for 0.
fn pick_port(port: u16, used: impl Fn(u16) -> bool) -> Result<u16> {
    if port != 0 {
        return if used(port) { Err(Error::other(format!("port {port} already in use"))) } else { Ok(port) };
    }
    const LO: u32 = 32768;
    const N: u32 = 60999 - LO + 1;
    let start = rand::random::<u32>();
    (0..N)
        .map(|i| (LO + start.wrapping_add(i) % N) as u16)
        .find(|&p| !used(p))
        .ok_or_else(|| Error::other("no unused ports"))
}

type ListenerMap<T> = HashMap<u16, mpsc::Sender<T>>;

/// A listener on one port of a server's address, from
/// [`Server::listen_tcp`] or [`Server::listen_udp`]. Dropping it releases
/// the port.
pub struct Listener<T> {
    server: Weak<Inner>,
    /// Which of the server's listener tables holds this one.
    table: fn(&mut Listeners) -> &mut ListenerMap<T>,
    addr: SocketAddr,
    rx: mpsc::Receiver<T>,
}

impl<T> Listener<T> {
    /// Waits for the next connection or flow; `None` once closed.
    pub async fn accept(&mut self) -> Option<T> {
        self.rx.recv().await
    }

    /// The listener's address: the server's tailcat IP and the port.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The listening port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl<T> Drop for Listener<T> {
    fn drop(&mut self) {
        if let Some(inner) = self.server.upgrade() {
            (self.table)(&mut inner.listeners.lock().unwrap()).remove(&self.addr.port());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat64_round_trip() {
        let a: SocketAddr = "10.1.2.3:80".parse().unwrap();
        let m = map_nat64(a);
        assert_eq!(m.to_string(), "[64:ff9b::a01:203]:80");
        assert_eq!(unmap_nat64(m), a);
    }

    #[test]
    fn coalesce_ports() {
        let r = PortRange::coalesce(&[22, 80, 81, 82, 443]);
        assert_eq!(r, vec![PortRange::single(22), PortRange { first: 80, last: 82 }, PortRange::single(443)]);
    }

    #[test]
    fn port_filters() {
        assert!(PortRange::ALL.contains(0) && PortRange::ALL.contains(65535));
        assert_eq!(PortRange::coalesce(&[65534, 65535]), vec![PortRange { first: 65534, last: 65535 }]);
        assert!(admits(&None, 1));
        let only_ssh = Some(vec![PortRange::single(22)]);
        assert!(admits(&only_ssh, 22) && !admits(&only_ssh, 23));
        assert!(!admits(&Some(vec![]), 22));
    }

    #[test]
    fn pick_port_avoids_used_ports() {
        assert_eq!(pick_port(80, |_| false).unwrap(), 80);
        assert!(pick_port(80, |p| p == 80).is_err());
        let p = pick_port(0, |p| p % 2 == 0).unwrap();
        assert!(p % 2 == 1 && (32768..=60999).contains(&p));
        assert!(pick_port(0, |_| true).is_err());
    }
}
