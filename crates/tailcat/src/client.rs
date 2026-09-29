//! The tailcat client: connects to a [`crate::Server`] named by an
//! [`Addr`], lazily on first use.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, watch};
use tracing::debug;

use crate::addr::{Addr, ConnInfo};
use crate::derpmap::{DerpMap, DerpMapCache, DerpRegion, FetchMode, FetchOptions};
use crate::key::{NodePrivate, NodePublic};
use crate::magicsock::{self, MagicSock, PathAddr};
use crate::netstack::{Stack, StackConfig, TcpDecision, TcpStream, UdpConn};
use crate::server::map_nat64;
use crate::wg::{self, Engine, IpNet};
use crate::{Error, Result, meow};

/// How long [`Client::ping`] waits for the server's acknowledgment.
const MEOW_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Set if the pong came over a direct path.
    pub endpoint: Option<SocketAddr>,
    /// The relay region, if the pong came through DERP.
    pub derp_region_id: i32,
    pub derp_region_code: String,
}

struct Running {
    ci: ConnInfo,
    server_ip: Ipv6Addr,
    ms: Arc<MagicSock>,
    engine: Arc<Engine>,
    stack: Stack,
    meowed: watch::Receiver<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stack.close();
        self.engine.close();
        self.ms.close();
        self.task.abort();
    }
}

/// A client of one tailcat server. The tunnel comes up lazily on the
/// first dial or ping. Clones share the same connection.
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
    start: AsyncMutex<()>,
    running: OnceLock<Running>,
    up_done: AtomicBool,
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
                start: AsyncMutex::new(()),
                running: OnceLock::new(),
                up_done: AtomicBool::new(false),
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
        if let Some(r) = self.inner.running.get() {
            return Ok(r);
        }
        let _g = self.inner.start.lock().await;
        if let Some(r) = self.inner.running.get() {
            return Ok(r);
        }
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

        let (meow_tx, meow_rx) = watch::channel(false);
        let hook: magicsock::DerpRecvHook = Arc::new(move |_region, src, pkt| {
            if !meow::is_meow(pkt) {
                return false;
            }
            if meow::is_meowed(pkt) && src == server_key {
                meow_tx.send_replace(true);
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
            derp_app_name: "tailcat-client".into(),
            listen_port: 0,
            on_derp_recv: Some(hook),
            endpoint_filter: None,
            enable_udp: true,
        })
        .await?;
        ms.upsert_peer(magicsock::PeerConfig {
            node_key: server_key,
            disco_key: ci.server_disco_public,
            home_region: region.region_id,
            endpoints: Vec::new(),
        });
        let (engine, mut inbound) = Engine::start(&self.inner.key, ms.clone(), wg_rx, None, None);
        // The server may send from any address: it can be an exit node.
        engine.upsert_peer(
            server_key,
            wg::PeerConfig {
                allowed_ips: vec![IpNet::host(IpAddr::V6(server_ip)), "::/0".parse().expect("valid prefix")],
                preshared_key: ci.preshared_key,
                persistent_keepalive: None,
            },
        );
        let out_engine = Arc::downgrade(&engine);
        let my_ip = self.inner.key.public().tailcat_ip();
        // The client accepts no inbound connections at all.
        let stack = Stack::new(
            StackConfig { addrs: vec![IpAddr::V6(my_ip)], any_ip: false, mtu: crate::TUNNEL_MTU },
            Arc::new(move |pkt| {
                if let Some(e) = out_engine.upgrade() {
                    e.send_ip_to_peer(&server_key, &pkt);
                }
            }),
            Some(Arc::new(|_, _| TcpDecision::Drop)),
            None,
        );
        let st2 = stack.clone();
        let task = tokio::spawn(async move {
            while let Some(p) = inbound.recv().await {
                st2.inject(p.data);
            }
        });
        let _ = self.inner.running.set(Running { ci, server_ip, ms, engine, stack, meowed: meow_rx, task });
        Ok(self.inner.running.get().expect("just set"))
    }

    /// Starts the client if needed, then announces it to the server over
    /// DERP (resending once a second, since DERP delivery is best effort)
    /// and waits for the acknowledgment, which also means the server has
    /// added it as a WireGuard peer. Dials do this implicitly; calling it
    /// first tests connectivity and measures the relay round trip.
    pub async fn ping(&self) -> Result<PingResult> {
        let r = self.ensure_started().await?;
        let t0 = Instant::now();
        let pkt = meow::encode_ping(&self.inner.key.public(), &r.ms.disco_public());
        let server = r.ci.server_public;
        let region = r.ms.home_region();
        let mut meowed = r.meowed.clone();
        let deadline = tokio::time::Instant::now() + MEOW_TIMEOUT;
        // Give the relay connection a moment so the first meow isn't lost.
        r.ms.wait_derp_connected(Duration::from_secs(5)).await;
        let mut resend = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = resend.tick() => {
                    if !r.ms.send_derp(&server, region, &pkt) {
                        debug!("tailcat: meow not sent (relay not connected yet)");
                    }
                }
                res = meowed.wait_for(|m| *m) => {
                    if res.is_ok() {
                        // The server just learned who we are; tell it our
                        // endpoints so both sides can try a direct path.
                        r.ms.send_call_me_maybe(&server);
                        self.inner.up_done.store(true, Ordering::Relaxed);
                        return Ok(PingResult { latency: t0.elapsed() });
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Error::Timeout("no answer from the tailcat server".into()));
                }
            }
        }
    }

    async fn up(&self) -> Result<&Running> {
        if !self.inner.up_done.load(Ordering::Relaxed) {
            self.ping().await?;
        }
        self.ensure_started().await
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
        Ok(match res.via {
            PathAddr::Udp(a) => DiscoPingResult {
                latency: res.latency,
                endpoint: Some(a),
                derp_region_id: 0,
                derp_region_code: String::new(),
            },
            PathAddr::Derp(rid) => {
                let code =
                    r.ci.region.iter().find(|x| x.region_id == rid).map(|x| x.region_code.clone()).unwrap_or_default();
                DiscoPingResult { latency: res.latency, endpoint: None, derp_region_id: rid, derp_region_code: code }
            }
        })
    }

    /// Opens a TCP connection to a port on the server.
    pub async fn dial_tcp_port(&self, port: u16) -> std::io::Result<TcpStream> {
        let r = self.up().await?;
        let dst = SocketAddr::new(IpAddr::V6(r.server_ip), port);
        r.stack.dial_tcp(IpAddr::V6(self.inner.key.public().tailcat_ip()), dst).await
    }

    /// Opens a TCP connection to any address through the server, which
    /// must be an exit node. IPv4 destinations ride the NAT64 prefix
    /// over the IPv6-only tunnel.
    pub async fn dial_tcp(&self, dst: SocketAddr) -> std::io::Result<TcpStream> {
        let r = self.up().await?;
        r.stack.dial_tcp(IpAddr::V6(self.inner.key.public().tailcat_ip()), map_nat64(dst)).await
    }

    /// Opens a UDP flow to a port on the server.
    pub async fn dial_udp_port(&self, port: u16) -> std::io::Result<UdpConn> {
        let r = self.up().await?;
        r.stack
            .dial_udp(IpAddr::V6(self.inner.key.public().tailcat_ip()), SocketAddr::new(IpAddr::V6(r.server_ip), port))
    }

    /// Opens a UDP flow to any address through the server (which must
    /// forward UDP).
    pub async fn dial_udp(&self, dst: SocketAddr) -> std::io::Result<UdpConn> {
        let r = self.up().await?;
        r.stack.dial_udp(IpAddr::V6(self.inner.key.public().tailcat_ip()), map_nat64(dst))
    }

    /// Waits until none of the client's TCP connections have anything
    /// left to send or acknowledge, or `timeout` passes. Call it before
    /// exiting after the last connection closes: the TCP stack lives in
    /// this process, so exiting at once can lose the final ACK.
    pub async fn drain_tcp(&self, timeout: Duration) -> bool {
        match self.inner.running.get() {
            Some(r) => r.stack.drain_tcp(timeout).await,
            None => true,
        }
    }
}
