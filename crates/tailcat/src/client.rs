//! The tailcat client: connects to a [`crate::Server`] named by an
//! [`Addr`], lazily on first use.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use std::{fmt, io};

use tokio::sync::{OnceCell, watch};
use tracing::debug;

use crate::addr::{Addr, ConnInfo};
use crate::derpmap::{DerpMap, DerpMapCache, DerpRegion, FetchMode, FetchOptions, RegionCode};
use crate::key::{NodePrivate, NodePublic};
use crate::magicsock::{self, MagicSock, PathAddr};
use crate::netstack::{Stack, StackConfig, TcpDecision, TcpStream, UdpConn};
use crate::server::{close_tunnel, map_nat64};
use crate::wg::{self, Engine, IpNet};
use crate::{Error, Result, meow};

/// How long [`Client::ping`] waits for the server's acknowledgment.
const MEOW_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a TCP dial may go unanswered before the client suspects the
/// server has lost track of it, joins again, and redials.
const DIAL_REJOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long data sent to the server may go unanswered before the client
/// joins again. A live WireGuard peer answers any data within its
/// 10-second passive keepalive; this is WireGuard's own dead-peer rule
/// (keepalive plus rekey timeout), after which it starts a handshake
/// that goes nowhere if the server no longer knows us.
const STALL_TIMEOUT: Duration = Duration::from_secs(15);

/// The result of [`Client::ping`].
#[derive(Debug, Clone)]
pub struct PingResult {
    /// The round-trip time of the join handshake through the relay.
    pub latency: Duration,
}

/// The result of [`Client::disco_ping`].
#[derive(Debug, Clone)]
pub struct DiscoPingResult {
    pub latency: Duration,
    /// The path the pong came back on.
    pub via: Via,
}

/// How traffic reaches the other end.
#[derive(Debug, Clone, PartialEq)]
pub enum Via {
    /// A direct UDP path, to this endpoint.
    Direct(SocketAddr),
    /// Relayed through a DERP region; its code is `Unset` if the region
    /// isn't one we know by more than its ID.
    Derp { region_id: i32, region_code: RegionCode },
}

impl Via {
    /// The DERP region relaying, if any: its code, or else its ID.
    pub fn derp_region(&self) -> Option<String> {
        match self {
            Via::Direct(_) => None,
            Via::Derp { region_id, region_code } if region_code.is_empty() => Some(region_id.to_string()),
            Via::Derp { region_code, .. } => Some(region_code.to_string()),
        }
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self, self.derp_region()) {
            (Via::Direct(a), _) => write!(f, "{a}"),
            (_, r) => write!(f, "DERP({})", r.unwrap_or_default()),
        }
    }
}

struct Running {
    ci: ConnInfo,
    server_ip: Ipv6Addr,
    /// Our own tailcat address, the source of every dial.
    my_ip: IpAddr,
    ms: Arc<MagicSock>,
    engine: Arc<Engine>,
    stack: Stack,
    /// Counts the server's "meowed" acknowledgments.
    meowed: watch::Receiver<u64>,
    /// Set once the server has acknowledged us.
    joined: AtomicBool,
    /// How the client's last try at joining again went, to share one
    /// rejoin between everyone who wants it.
    rejoined: tokio::sync::Mutex<Option<Rejoined>>,
    /// The server's peer configuration, to reset its paths and session.
    server_ms: magicsock::PeerConfig,
    server_wg: wg::PeerConfig,
    tasks: [tokio::task::JoinHandle<()>; 2],
}

/// How a try at joining again went.
#[derive(Clone, Copy)]
struct Rejoined {
    /// When it ended.
    at: Instant,
    /// Whether the server answered.
    answered: bool,
}

/// The error for a server that didn't answer a join.
fn no_answer() -> Error {
    Error::Timeout("no answer from the tailcat server".into())
}

impl Running {
    /// Does the work of [`Client::ping`], returning the round-trip time.
    async fn meow(&self) -> Result<Duration> {
        let t0 = Instant::now();
        let pkt = meow::encode_ping(&self.ms.public_key(), &self.ms.disco_public());
        let server = self.ci.server_public;
        let region = self.ms.home_region();
        let mut meowed = self.meowed.clone();
        // Only acks from here on answer this ping.
        meowed.borrow_and_update();
        let deadline = tokio::time::Instant::now() + MEOW_TIMEOUT;
        // Give the relay connection a moment so the first meow isn't lost.
        self.ms.wait_derp_connected(Duration::from_secs(5)).await;
        let mut resend = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = resend.tick() => {
                    if !self.ms.send_derp(&server, region, &pkt) {
                        debug!("tailcat: meow not sent (relay not connected, or backed up)");
                    }
                }
                res = meowed.changed() => {
                    res.map_err(|_| Error::other("tailcat client closed"))?;
                    // The server just learned who we are; tell it our
                    // endpoints so both sides can try a direct path.
                    self.ms.send_call_me_maybe(&server);
                    self.joined.store(true, Ordering::Relaxed);
                    return Ok(t0.elapsed());
                }
                _ = tokio::time::sleep_until(deadline) => return Err(no_answer()),
            }
        }
    }

    /// Announces the client again, for when the server seems to have lost
    /// track of it: it restarted (with the same key, so the same address)
    /// or disconnected us. A restarted server can't read our old
    /// WireGuard session and may listen on a new port, so the server's
    /// session and paths are reset too: the next packet starts a fresh
    /// handshake, over DERP until a direct path is found again.
    /// Concurrent callers share one rejoin, whether the server answers
    /// it or not.
    async fn rejoin(&self) -> Result<()> {
        let asked = Instant::now();
        let mut rejoined = self.rejoined.lock().await;
        // A try that ended since we asked is ours too.
        if let Some(r) = rejoined.filter(|r| r.at >= asked) {
            return if r.answered { Ok(()) } else { Err(no_answer()) };
        }
        debug!("tailcat: no answer from the server; announcing the client again");
        if let Err(e) = self.meow().await {
            // Otherwise each caller waiting its turn would wait out the
            // server again. A closed client fails fast, and isn't kept.
            if matches!(e, Error::Timeout(_)) {
                *rejoined = Some(Rejoined { at: Instant::now(), answered: false });
            }
            return Err(e);
        }
        let server = self.ci.server_public;
        self.ms.remove_peer(&server);
        self.ms.upsert_peer(self.server_ms.clone());
        self.engine.remove_peer(&server);
        self.engine.upsert_peer(server, self.server_wg.clone());
        self.ms.send_call_me_maybe(&server);
        *rejoined = Some(Rejoined { at: Instant::now(), answered: true });
        Ok(())
    }

    /// Closes the tunnel and stops its tasks, the watchdog included.
    fn close(&self) {
        close_tunnel(&self.stack, &self.engine, &self.ms);
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// A client of one tailcat server. The tunnel comes up lazily on the
/// first dial or ping. Clones share the same connection. If the server
/// loses track of the client (it restarted, or disconnected it), the
/// client announces itself again when a dial or its traffic goes
/// unanswered.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    server: Addr,
    key: NodePrivate,
    derp_map_url: Option<String>,
    derp_map_cache: Option<Arc<dyn DerpMapCache>>,
    derp_map: Option<DerpMap>,
    /// The tunnel, once started. The watchdog shares it, and may hold it
    /// through a rejoin, so dropping the client closes it explicitly.
    running: OnceCell<Arc<Running>>,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        if let Some(r) = self.running.get() {
            r.close();
        }
    }
}

/// Options for [`Client::with_options`].
#[derive(Default, Clone)]
pub struct ClientOptions {
    /// The client's identity, which servers may allowlist; a fresh
    /// ephemeral key if `None`.
    pub key: Option<NodePrivate>,
    pub derp_map_url: Option<String>,
    pub derp_map_cache: Option<Arc<dyn DerpMapCache>>,
    /// A DERP map to resolve region IDs from instead of fetching one.
    pub derp_map: Option<DerpMap>,
}

impl Client {
    /// A client for the server at `server`, with an ephemeral key.
    pub fn new(server: impl Into<Addr>) -> Client {
        Self::with_options(server, ClientOptions::default())
    }

    /// A client with explicit options.
    pub fn with_options(server: impl Into<Addr>, opts: ClientOptions) -> Client {
        Client {
            inner: Arc::new(ClientInner {
                server: server.into(),
                key: opts.key.unwrap_or_else(NodePrivate::generate),
                derp_map_url: opts.derp_map_url,
                derp_map_cache: opts.derp_map_cache,
                derp_map: opts.derp_map,
                running: OnceCell::new(),
            }),
        }
    }

    /// The client's node public key.
    pub fn public_key(&self) -> NodePublic {
        self.inner.key.public()
    }

    /// The server's address.
    pub fn server(&self) -> &Addr {
        &self.inner.server
    }

    /// The DERP region used to reach the server, once started.
    pub fn derp_region(&self) -> Option<DerpRegion> {
        self.inner.running.get().and_then(|r| r.ci.region.first().cloned())
    }

    /// The underlying path manager, once started.
    pub fn magicsock(&self) -> Option<Arc<MagicSock>> {
        self.inner.running.get().map(|r| r.ms.clone())
    }

    async fn ensure_started(&self) -> Result<&Running> {
        self.inner.running.get_or_try_init(|| self.start()).await.map(Arc::as_ref)
    }

    async fn start(&self) -> Result<Arc<Running>> {
        let mut ci = self.inner.server.parse()?;
        if ci.server_disco_public.is_zero() {
            return Err(Error::Addr(
                "legacy tailcat address lacks a separate disco key; generate a new address with an updated tailcat server".into(),
            ));
        }
        ci.expand(
            FetchOptions {
                url: self.inner.derp_map_url.as_deref(),
                mode: FetchMode::Client,
                cache: self.inner.derp_map_cache.as_deref(),
            },
            self.inner.derp_map.as_ref(),
        )
        .await?;
        let region =
            ci.region.first().cloned().ok_or_else(|| Error::Addr("no DERP regions in tailcat address".into()))?;
        let server_key = ci.server_public;
        let server_ip = server_key.tailcat_ip();

        let (meow_tx, meow_rx) = watch::channel(0);
        let hook: magicsock::DerpRecvHook = Arc::new(move |_region, src, pkt| {
            if !meow::is_meow(pkt) {
                return false;
            }
            if meow::is_meowed(pkt) && src == server_key {
                meow_tx.send_modify(|n| *n += 1);
            }
            true // clients ignore meow pings
        });
        let mut dm = DerpMap::default();
        for r in &ci.region {
            dm.regions.insert(r.region_id, r.clone());
        }
        let (ms, wg_rx) = MagicSock::start(magicsock::Config {
            private_key: self.inner.key.clone(),
            derp_map: dm,
            home_region: region.region_id,
            derp_app_name: crate::derp::AppName::Client,
            listen_port: 0,
            on_derp_recv: Some(hook),
            endpoint_filter: None,
            enable_udp: true,
        })
        .await?;
        let server_ms = magicsock::PeerConfig {
            node_key: server_key,
            disco_key: ci.server_disco_public,
            home_region: region.region_id,
            endpoints: Vec::new(),
        };
        ms.upsert_peer(server_ms.clone());
        let (engine, mut inbound) = Engine::start(&self.inner.key, ms.clone(), wg_rx, None, None);
        // The server may send from any address: it can be an exit node.
        let server_wg = wg::PeerConfig {
            allowed_ips: vec![IpNet::host(IpAddr::V6(server_ip)), "::/0".parse().expect("valid prefix")],
            preshared_key: ci.preshared_key,
            persistent_keepalive: None,
        };
        engine.upsert_peer(server_key, server_wg.clone());
        let out_engine = Arc::downgrade(&engine);
        let my_ip = IpAddr::V6(self.inner.key.public().tailcat_ip());
        // The client accepts no inbound connections at all.
        let stack = Stack::new(
            StackConfig { addrs: vec![my_ip], any_ip: false, mtu: crate::TUNNEL_MTU },
            Arc::new(move |pkt| {
                if let Some(e) = out_engine.upgrade() {
                    e.send_ip_to_peer(&server_key, &pkt);
                }
            }),
            Some(Arc::new(|_, _| TcpDecision::Drop)),
            None,
        );
        let inject = stack.clone();
        let task = tokio::spawn(async move {
            while let Some(p) = inbound.recv().await {
                inject.inject(p.data);
            }
        });
        Ok(Arc::new_cyclic(|running| Running {
            ci,
            server_ip,
            my_ip,
            ms,
            engine,
            stack,
            meowed: meow_rx,
            joined: AtomicBool::new(false),
            rejoined: tokio::sync::Mutex::new(None),
            server_ms,
            server_wg,
            tasks: [task, tokio::spawn(watch_server(running.clone()))],
        }))
    }

    /// Starts the client if needed, then announces it to the server over
    /// DERP (resending once a second, since DERP delivery is best effort)
    /// and waits for the acknowledgment, which also means the server has
    /// added it as a WireGuard peer. Dials do this implicitly; calling it
    /// first tests connectivity and measures the relay round trip. (Acks
    /// can't be matched to announcements, so a late ack to an earlier
    /// ping can end this one.)
    pub async fn ping(&self) -> Result<PingResult> {
        let latency = self.ensure_started().await?.meow().await?;
        Ok(PingResult { latency })
    }

    async fn up(&self) -> Result<&Running> {
        let r = self.ensure_started().await?;
        if !r.joined.load(Ordering::Relaxed) {
            r.meow().await?;
        }
        Ok(r)
    }

    /// Sends a disco ping to the server and reports how the pong came
    /// back. Unlike [`Client::ping`], repeated disco pings also drive
    /// direct path discovery.
    pub async fn disco_ping(&self, timeout: Duration) -> Result<DiscoPingResult> {
        let r = self.up().await?;
        let server = r.ci.server_public;
        // Nudge path discovery with some tunnel traffic too.
        r.ms.send_call_me_maybe(&server);
        let res = r.ms.ping(&server, timeout).await?;
        let via = match res.via {
            PathAddr::Udp(a) => Via::Direct(a),
            PathAddr::Derp(region_id) => {
                let region = r.ci.region.iter().find(|x| x.region_id == region_id);
                Via::Derp { region_id, region_code: region.map(|x| x.region_code.clone()).unwrap_or_default() }
            }
        };
        Ok(DiscoPingResult { latency: res.latency, via })
    }

    /// Opens a TCP connection to a port on the server.
    pub async fn dial_tcp_port(&self, port: u16) -> io::Result<TcpStream> {
        self.dial_tcp(SocketAddr::new(self.up().await?.server_ip.into(), port)).await
    }

    /// Opens a TCP connection to any address through the server, which
    /// must be an exit node. IPv4 destinations ride the NAT64 prefix
    /// over the IPv6-only tunnel.
    pub async fn dial_tcp(&self, dst: SocketAddr) -> io::Result<TcpStream> {
        let r = self.up().await?;
        let dst = map_nat64(dst);
        if let Ok(res) = tokio::time::timeout(DIAL_REJOIN_TIMEOUT, r.stack.dial_tcp(r.my_ip, dst)).await {
            return res;
        }
        r.rejoin().await?;
        r.stack.dial_tcp(r.my_ip, dst).await
    }

    /// Opens a UDP flow to a port on the server.
    pub async fn dial_udp_port(&self, port: u16) -> io::Result<UdpConn> {
        self.dial_udp(SocketAddr::new(self.up().await?.server_ip.into(), port)).await
    }

    /// Opens a UDP flow to any address through the server (which must
    /// forward UDP).
    pub async fn dial_udp(&self, dst: SocketAddr) -> io::Result<UdpConn> {
        let r = self.up().await?;
        r.stack.dial_udp(r.my_ip, map_nat64(dst))
    }

    /// Waits until none of the client's TCP connections have anything
    /// left to send or acknowledge, or `timeout` passes. Call it before
    /// exiting after the last connection closes: the TCP stack lives in
    /// this process, so exiting at once can lose the final ACK.
    pub async fn drain_tcp(&self, timeout: Duration) -> bool {
        let Some(r) = self.inner.running.get() else { return true };
        r.stack.drain_tcp(timeout).await
    }
}

/// Joins again whenever data sent to the server goes unanswered, which
/// is how the client notices a server that lost track of it while no
/// dial is waiting (say, a UDP flow's).
async fn watch_server(running: Weak<Running>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut stall = Stall::default();
    loop {
        tick.tick().await;
        // Not up yet: `start` is still making it. Closing the tunnel
        // aborts this task, so it never outlives it.
        let Some(r) = running.upgrade() else { continue };
        let server = r.ci.server_public;
        let (_, tx, rx) = r.engine.peer_stats(&server).unwrap_or_default();
        let path = r.ms.peer_path(&server);
        let (last_send, last_recv) = path.map_or((None, None), |p| (p.last_send, p.last_recv));
        if stall.stalled(Instant::now(), tx, rx, last_send, last_recv)
            && let Err(e) = r.rejoin().await
        {
            debug!("tailcat: joining again: {e}");
        }
    }
}

/// Decides, from samples of the server's WireGuard byte counters and
/// path timestamps, when data we sent has gone unanswered too long.
#[derive(Default)]
struct Stall {
    tx: usize,
    rx: usize,
    /// When data first went out that nothing has answered since.
    since: Option<Instant>,
}

impl Stall {
    /// Takes a sample: bytes of data sent and received so far, and when
    /// anything (keepalives and handshakes too) was last sent to or heard
    /// from the server. It reports whether to join again.
    fn stalled(
        &mut self,
        now: Instant,
        tx: usize,
        rx: usize,
        last_send: Option<Instant>,
        last_recv: Option<Instant>,
    ) -> bool {
        // The counters restart when the session is reset, hence `!=`.
        let (sent, received) = (tx != self.tx, rx != self.rx);
        (self.tx, self.rx) = (tx, rx);
        if sent && self.since.is_none() {
            self.since = Some(last_send.unwrap_or(now));
        }
        if received || last_recv.zip(self.since).is_some_and(|(heard, since)| heard >= since) {
            self.since = None;
        }
        let stalled = self.since.is_some_and(|since| now.saturating_duration_since(since) >= STALL_TIMEOUT);
        if stalled {
            self.since = None;
        }
        stalled
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::Server;
    use crate::derp::server::DevDerp;

    /// Feeds `stall` one sample a second for `secs` seconds from `t0`,
    /// with `sample` giving (tx, rx, last send, last receive) in seconds.
    /// It returns the seconds at which it said to join again.
    fn run(secs: u64, mut sample: impl FnMut(u64) -> (usize, usize, Option<u64>, Option<u64>)) -> Vec<u64> {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut stall = Stall::default();
        (1..=secs)
            .filter(|&s| {
                let (tx, rx, send, recv) = sample(s);
                stall.stalled(at(s), tx, rx, send.map(at), recv.map(at))
            })
            .collect()
    }

    const NEVER: &[u64] = &[];

    /// Dropping the client closes its tunnel at once, even while the
    /// watchdog holds it through a rejoin the server doesn't answer.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_client_beats_a_rejoin() {
        let dev = DevDerp::start_local().await.unwrap();
        let server = Server::builder().region(dev.region.clone()).start().await.unwrap();
        let client = Client::new(server.tailcat_addr());
        client.ping().await.unwrap();
        server.close();
        let key = client.public_key();
        // Holding the tunnel as the watchdog does, on a stall.
        let running = client.inner.running.get().unwrap().clone();
        let rejoin = tokio::spawn(async move { running.rejoin().await });

        drop(client);
        let gone = async {
            while dev.server.is_client_connected(&key) {
                sleep(Duration::from_millis(10)).await;
            }
        };
        let closed = timeout(Duration::from_secs(5), gone).await.is_ok();
        rejoin.abort();
        assert!(closed, "the dropped client's tunnel stayed up for the rejoin");
    }

    #[test]
    fn answered_data_never_stalls() {
        // A request a second, each answered at once.
        let got = run(60, |s| (s as usize, s as usize, Some(s), Some(s)));
        assert_eq!(got, NEVER);
    }

    #[test]
    fn keepalives_answer_one_way_data() {
        // Data a second, answered only by the server's keepalive every
        // 10 seconds (which carries no data).
        let got = run(60, |s| (s as usize, 0, Some(s), Some(s / 10 * 10)));
        assert_eq!(got, NEVER);
    }

    #[test]
    fn idle_never_stalls() {
        // One exchange, then quiet but for our own passive keepalive at
        // 11 seconds, which nothing answers.
        let last_send = |s| if s < 11 { 1 } else { 11 };
        let got = run(60, |s| (1, 1, Some(last_send(s)), Some(1)));
        assert_eq!(got, NEVER);
    }

    #[test]
    fn unanswered_data_stalls() {
        // After an exchange, data every second into the void: it stalls
        // once per timeout, while the data keeps going unanswered.
        let got = run(60, |s| (s as usize, 1, Some(s), Some(1)));
        assert_eq!(got, [17, 33, 49]);
        // A single unanswered packet, sent at 5 seconds, stalls once.
        let got = run(60, |s| if s < 5 { (1, 1, Some(1), Some(1)) } else { (2, 1, Some(5), Some(1)) });
        assert_eq!(got, [20]);
    }
}
