//! The tailcat server: listens for clients through a DERP relay and
//! serves TCP connections and UDP flows over WireGuard.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
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
    pub fn coalesce(sorted: impl IntoIterator<Item = u16>) -> Vec<PortRange> {
        let mut out: Vec<PortRange> = Vec::new();
        for p in sorted {
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
    clients: Mutex<Clients>,
    pending_allow: Mutex<HashSet<NodePublic>>,
    listeners: Mutex<Listeners>,
    cfg: Handlers,
    task: tokio::task::JoinHandle<()>,
    /// Set by close; a closing server admits no clients.
    closed: AtomicBool,
}

impl Inner {
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        close_tunnel(&self.stack, &self.engine, &self.ms);
        self.task.abort();
    }

    /// The connected client at `remote`, if any.
    fn client_at(&self, remote: SocketAddr) -> Option<NodePublic> {
        let IpAddr::V6(ip) = remote.ip() else { return None };
        self.clients.lock().unwrap().ids.keys().find(|k| k.tailcat_ip() == ip).copied()
    }
}

/// Closes a tunnel from the top: the stack at once, aborting its
/// connections, then the engine and magicsock below it once the RSTs
/// from the stack's last poll have had a moment to get out through them.
pub(crate) fn close_tunnel(stack: &Stack, engine: &Arc<Engine>, ms: &Arc<MagicSock>) {
    stack.close();
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        engine.close();
        ms.close();
        return;
    };
    let (stack, engine, ms) = (stack.clone(), engine.clone(), ms.clone());
    rt.spawn(async move {
        stack.drain_tcp(Duration::from_secs(1)).await;
        engine.close();
        ms.close();
    });
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.close();
    }
}

/// The connected clients. Joins and disconnects configure a client's
/// WireGuard and magicsock peers while holding this, so neither can
/// catch the other half done: a client is a peer exactly when it's here.
struct Clients {
    /// Node IDs, for logs; like the Go server, IDs are never reused.
    ids: HashMap<NodePublic, u64>,
    next_id: u64,
    /// Counts calls to [`Server::disconnect_client`], so a join whose
    /// allow hook answered before a revocation can't complete after it.
    disconnects: u64,
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
            Arc::new(move |src, dst| tcp_server().map_or(TcpDecision::Drop, |s| s.tcp_decision(src, dst)));
        let udp_policy: UdpPolicy = Arc::new(move |src, dst| server()?.udp_decision(src, dst));
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
            clients: Mutex::new(Clients { ids: HashMap::new(), next_id: 2, disconnects: 0 }),
            pending_allow: Mutex::default(),
            listeners: Mutex::default(),
            cfg: b.cfg,
            task,
            closed: AtomicBool::new(false),
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
        self.inner.client_at(remote)
    }

    /// Drops the connected client `k` and reports whether it was
    /// connected. Its TCP connections are aborted and its UDP flows
    /// closed, so their handlers see errors (the RSTs don't reach it,
    /// since it's no longer a peer). Nothing stops it reconnecting unless
    /// the allow hook now rejects it (a join the hook approved before
    /// this call is dropped, and asked about again).
    pub fn disconnect_client(&self, k: &NodePublic) -> bool {
        let mut clients = self.inner.clients.lock().unwrap();
        clients.disconnects += 1;
        let Some(id) = clients.ids.remove(k) else { return false };
        debug!("tailcat: disconnecting client {} (peer {id})", k.short_string());
        self.inner.engine.remove_peer(k);
        self.inner.ms.remove_peer(k);
        // It's no longer a client, so it opens nothing new (see
        // `for_client`), and this gets every connection it has. The stack
        // never calls out to us holding its lock, so taking it under ours
        // is safe.
        self.inner.stack.abort_peer(IpAddr::V6(k.tailcat_ip()));
        true
    }

    /// Returns a status snapshot with one entry per connected client.
    pub fn status(&self) -> ServerStatus {
        let clients: Vec<NodePublic> = self.inner.clients.lock().unwrap().ids.keys().copied().collect();
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
        if self.inner.closed.load(Ordering::Relaxed) {
            return false;
        }
        let (known, disconnects) = {
            let clients = self.inner.clients.lock().unwrap();
            (clients.ids.contains_key(&src), clients.disconnects)
        };
        if !known && let Some(allow) = self.inner.cfg.allow_client.clone() {
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
        let mut clients = self.inner.clients.lock().unwrap();
        if clients.disconnects != disconnects {
            // The hook's answer may predate a revocation; the client retries.
            debug!("tailcat: ignoring meow from {src}: a client was disconnected meanwhile");
            return false;
        }
        let id = clients.next_id;
        if let Entry::Vacant(e) = clients.ids.entry(src) {
            e.insert(id);
            clients.next_id += 1;
            debug!("tailcat: client {} added as peer {id}", src.short_string());
        }
        // A known client is refreshed, since it may have restarted with a
        // new disco key; neither upsert disturbs a working session.
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
        drop(clients);
        // Tell the client our UDP endpoints so both sides can try a
        // direct path.
        self.inner.ms.send_call_me_maybe(&src);
        true
    }

    /// Wraps the hand-off of a new connection or flow from `src`. The
    /// stack makes it after the policy says yes, and a revocation in
    /// between would miss it, so it's dropped, which closes it, if `src`
    /// is no longer a client by then.
    fn for_client<T: 'static>(&self, src: SocketAddr, f: impl FnOnce(T) + Send + 'static) -> Box<dyn FnOnce(T) + Send> {
        let inner = Arc::downgrade(&self.inner);
        Box::new(move |t| {
            if inner.upgrade().is_some_and(|i| i.client_at(src).is_some()) {
                f(t);
            }
        })
    }

    fn tcp_decision(&self, src: SocketAddr, dst: SocketAddr) -> TcpDecision {
        // The tunnel only admits clients, but packets a client sent just
        // before it was revoked can still be on their way in.
        if self.inner.client_at(src).is_none() {
            return TcpDecision::Drop;
        }
        let cfg = &self.inner.cfg;
        let h = if dst.ip() == IpAddr::V6(self.inner.addr) {
            let port = dst.port();
            if let Some(tx) = self.inner.listeners.lock().unwrap().tcp.get(&port).cloned() {
                return TcpDecision::Accept(self.for_client(src, move |s| {
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
            Some(h) => TcpDecision::Accept(self.for_client(src, move |s| {
                tokio::spawn(h(s));
            })),
            None => TcpDecision::Reset,
        }
    }

    fn udp_decision(&self, src: SocketAddr, dst: SocketAddr) -> Option<Box<dyn FnOnce(UdpConn) + Send>> {
        // As for TCP.
        self.inner.client_at(src)?;
        let cfg = &self.inner.cfg;
        let idle = Some(cfg.udp_idle_timeout.unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT));
        let h: UdpHandler = if dst.ip() == IpAddr::V6(self.inner.addr) {
            let port = dst.port();
            if let Some(tx) = self.inner.listeners.lock().unwrap().udp.get(&port).cloned() {
                return Some(self.for_client(src, move |c: UdpConn| {
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
        Some(self.for_client(src, move |c: UdpConn| {
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
mod model_tests;

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::sync::Barrier;

    use hegel::TestCase;
    use hegel::generators as gs;
    use tokio::io::AsyncReadExt;
    use tokio::runtime::{self, Handle, Runtime};
    use tokio::task;
    use tokio::time::timeout;

    use super::*;
    use crate::derp::server::DevDerp;
    use crate::key::DiscoPrivate;
    use crate::{Client, ClientOptions, KeySet};

    /// Whether `k` is a connected client, a WireGuard peer, and a
    /// magicsock peer, which should always agree.
    fn membership(s: &Server, k: &NodePublic) -> (bool, bool, bool) {
        let client = s.status().peers.iter().any(|p| p.key == *k);
        (client, s.inner.engine.peer_stats(k).is_some(), s.inner.ms.peer_path(k).is_some())
    }

    fn allowlist(k: NodePublic) -> KeySet {
        let allow = KeySet::default();
        allow.add(k);
        allow
    }

    /// Waits at `barrier` without blocking the runtime.
    async fn wait_at(barrier: &Arc<Barrier>) {
        let barrier = barrier.clone();
        task::spawn_blocking(move || barrier.wait()).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn disconnect_beats_a_pending_allow() {
        let dev = DevDerp::start_local().await.unwrap();
        let k = NodePrivate::generate().public();
        let allow = allowlist(k);
        // The hook reads the allowlist, then stalls until the test has
        // revoked the key, like a slow lookup.
        let (asked, resume) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
        let (check, hook_asked, hook_resume) = (allow.checker(), asked.clone(), resume.clone());
        let slow_hook = move |k| {
            let ok = check(k);
            hook_asked.wait();
            hook_resume.wait();
            ok
        };
        let server = Server::builder().region(dev.region.clone()).allow_client(slow_hook).start().await.unwrap();
        let meow = tokio::spawn({
            let s = server.clone();
            async move { s.on_meow(k, DiscoPrivate::generate().public()).await }
        });
        wait_at(&asked).await;

        // The documented revocation, while the hook's stale answer is
        // still in flight.
        allow.remove(&k);
        assert!(!server.disconnect_client(&k));
        wait_at(&resume).await;

        let acked = meow.await.unwrap();
        assert!(!acked, "revoked client was acked");
        assert_eq!(membership(&server, &k), (false, false, false));
        server.close();
    }

    /// Asserts that `c` is aborted soon rather than left open.
    async fn assert_aborted(c: &mut TcpStream) {
        let read = timeout(Duration::from_secs(5), c.read(&mut [0u8; 1])).await;
        let read = read.unwrap_or_else(|_| panic!("{c:?}: a revoked client's connection stayed open"));
        assert_eq!(read.unwrap_err().kind(), ErrorKind::ConnectionAborted, "{c:?}");
    }

    /// Revoking a client tears down its connections at once, idle ones
    /// included, whether a handler or a listener holds them.
    #[tokio::test(flavor = "multi_thread")]
    async fn disconnect_tears_down_connections() {
        let dev = DevDerp::start_local().await.unwrap();
        let key = NodePrivate::generate();
        let allow = allowlist(key.public());
        let (tx, mut handled) = mpsc::unbounded_channel();
        // Every port's connections go to the test.
        let to_test = move |_| {
            let tx = tx.clone();
            Some(handler(move |c| {
                let _ = tx.send(c);
                async {}
            }))
        };
        let builder = Server::builder().region(dev.region.clone()).allow_client(allow.checker()).on_tcp(to_test);
        let server = builder.start().await.unwrap();
        let mut listener = server.listen_tcp(2).unwrap();
        let opts = ClientOptions { key: Some(key.clone()), ..Default::default() };
        let client = Client::with_options(server.tailcat_addr(), opts);
        let _held = (client.dial_tcp_port(1).await.unwrap(), client.dial_tcp_port(2).await.unwrap());
        let mut conns = [handled.recv().await.unwrap(), listener.accept().await.unwrap()];

        allow.remove(&key.public());
        assert!(server.disconnect_client(&key.public()));

        for c in &mut conns {
            assert_aborted(c).await;
        }
        server.close();
    }

    /// Clients meowing and being disconnected from several threads at
    /// once, against one server.
    struct Membership {
        server: Server,
        rt: Handle,
        keys: [NodePublic; 2],
    }

    impl Membership {
        fn key(&self, tc: &TestCase) -> NodePublic {
            self.keys[tc.draw(gs::integers::<usize>().max_value(self.keys.len() - 1))]
        }

        fn meow(&self, k: NodePublic) -> bool {
            self.rt.block_on(self.server.on_meow(k, DiscoPrivate::generate().public()))
        }
    }

    #[hegel::concurrent_state_machine]
    impl Membership {
        #[rule(group = "churn")]
        fn join(&self, tc: TestCase) {
            let k = self.key(&tc);
            self.meow(k);
        }

        #[rule(group = "churn")]
        fn disconnect(&self, tc: TestCase) {
            let k = self.key(&tc);
            self.server.disconnect_client(&k);
        }

        /// With no disconnects about, an ack means the client is a
        /// WireGuard peer: it starts dialing on the ack.
        #[rule(group = "joins")]
        fn join_then_check(&self, tc: TestCase) {
            let k = self.key(&tc);
            assert!(self.meow(k));
            assert!(self.server.inner.engine.peer_stats(&k).is_some(), "acked before the WireGuard peer was added");
        }

        #[invariant]
        fn peers_agree(&self, _: TestCase) {
            for k in &self.keys {
                let (client, wg, ms) = membership(&self.server, k);
                assert!(client == wg && wg == ms, "{k}: client {client}, WireGuard peer {wg}, magicsock peer {ms}");
            }
        }
    }

    /// One relay and server for every test case; each case uses fresh keys.
    fn shared_server() -> &'static (Runtime, DevDerp, Server) {
        static WORLD: OnceLock<(Runtime, DevDerp, Server)> = OnceLock::new();
        WORLD.get_or_init(|| {
            let rt = runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            let (dev, server) = rt.block_on(async {
                let dev = DevDerp::start_local().await.unwrap();
                let server = Server::builder().region(dev.region.clone()).start().await.unwrap();
                (dev, server)
            });
            (rt, dev, server)
        })
    }

    #[hegel::test(test_cases = 200)]
    fn joins_and_disconnects_are_atomic(tc: TestCase) {
        let (rt, _, server) = shared_server();
        let keys = [(); 2].map(|_| NodePrivate::generate().public());
        let m = Membership { server: server.clone(), rt: rt.handle().clone(), keys };
        hegel::stateful::machine(m).steps(20).max_concurrency(4).run_concurrent(tc);
    }

    #[test]
    fn nat64_round_trip() {
        let a: SocketAddr = "10.1.2.3:80".parse().unwrap();
        let m = map_nat64(a);
        assert_eq!(m.to_string(), "[64:ff9b::a01:203]:80");
        assert_eq!(unmap_nat64(m), a);
    }

    #[test]
    fn coalesce_ports() {
        let r = PortRange::coalesce([22, 80, 81, 82, 443]);
        assert_eq!(r, vec![PortRange::single(22), PortRange { first: 80, last: 82 }, PortRange::single(443)]);
    }

    #[test]
    fn port_filters() {
        assert!(PortRange::ALL.contains(0));
        assert!(PortRange::ALL.contains(65535));
        assert_eq!(PortRange::coalesce([65534, 65535]), vec![PortRange { first: 65534, last: 65535 }]);
        assert!(admits(&None, 1));
        let only_ssh = Some(vec![PortRange::single(22)]);
        assert!(admits(&only_ssh, 22));
        assert!(!admits(&only_ssh, 23));
        assert!(!admits(&Some(vec![]), 22));
    }

    #[test]
    fn pick_port_avoids_used_ports() {
        assert_eq!(pick_port(80, |_| false).unwrap(), 80);
        assert!(pick_port(80, |p| p == 80).is_err());
        let p = pick_port(0, |p| p % 2 == 0).unwrap();
        assert_eq!(p % 2, 1, "picked used port {p}");
        assert!((32768..=60999).contains(&p), "picked {p}, outside the ephemeral range");
        assert!(pick_port(0, |_| true).is_err());
    }
}
