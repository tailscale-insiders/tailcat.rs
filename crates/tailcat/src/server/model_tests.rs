//! Model-based tests of how a server dispatches inbound UDP flows,
//! driven by Hegel. Datagrams from a few clients go straight into the
//! server's stack for a port with an `on_udp` handler and a port outside
//! the served ranges, while listeners come and go on both, flows are
//! closed and dropped, and clients are revoked and rejoin. Each new flow
//! must go to the listener if there is one, else to the handler if the
//! port is served, else nowhere, and each datagram for a live flow must
//! reach exactly that flow. A revoked client's flows must close at once,
//! and it must open no more until it rejoins.

use std::collections::HashMap;

use hegel::TestCase;
use hegel::generators as gs;
use tokio::runtime::{self, Runtime};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;

use super::*;
use crate::derp::server::DevDerp;
use crate::netstack::build_udp;

/// Served, with a handler.
const SERVED: u16 = 5000;
/// Outside the served ranges.
const UNSERVED: u16 = 6000;
const PORTS: [u16; 2] = [SERVED, UNSERVED];

/// Flows the handler accepted.
type Sink = Mutex<Option<mpsc::UnboundedSender<UdpConn>>>;

struct World {
    rt: Runtime,
    server: Server,
    handled: AsyncMutex<mpsc::UnboundedReceiver<UdpConn>>,
    _dev: DevDerp,
}

impl World {
    /// Client `k` joins, or refreshes, and is acked.
    fn meow(&self, k: NodePublic) {
        assert!(self.rt.block_on(self.server.meow(k)));
    }
}

fn world() -> &'static World {
    static SINK: Sink = Mutex::new(None);
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let rt = runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        *SINK.lock().unwrap() = Some(tx);
        let (dev, server) = rt.block_on(async {
            let dev = DevDerp::start_local().await.unwrap();
            let server = Server::builder()
                .region(dev.region.clone())
                .served_udp_ports([PortRange::single(SERVED)])
                .on_udp(|_| {
                    Some(udp_handler(|c| async move {
                        let _ = SINK.lock().unwrap().as_ref().unwrap().send(c);
                    }))
                })
                .start()
                .await
                .unwrap();
            (dev, server)
        });
        World { rt, server, handled: AsyncMutex::new(rx), _dev: dev }
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Via {
    Handler,
    Listener,
}

struct Flow {
    conn: UdpConn,
    via: Via,
}

/// Checks that datagram `seq` from `src` reached `port`'s flow.
async fn expect_datagram(conn: &UdpConn, src: SocketAddr, port: u16, seq: u32) {
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(1), conn.recv(&mut buf)).await;
    let n = n.unwrap_or_else(|_| panic!("{src} -> {port}: datagram {seq} didn't reach its flow")).unwrap();
    assert_eq!(buf[..n], seq.to_be_bytes(), "{src} -> {port}: wrong datagram");
}

/// Checks that a revoked client's flow from `src` to `port` closes.
async fn expect_closed(conn: &UdpConn, src: SocketAddr, port: u16) {
    let mut buf = [0u8; 16];
    let r = timeout(Duration::from_secs(1), conn.recv(&mut buf)).await;
    let r = r.unwrap_or_else(|_| panic!("{src} -> {port}: a revoked client's flow stayed open"));
    assert!(r.is_err(), "{src} -> {port}: a revoked client's flow got a datagram");
}

struct Dispatch {
    w: &'static World,
    keys: [NodePublic; 2],
    /// Each client's source address.
    srcs: [SocketAddr; 2],
    /// Which clients are revoked.
    revoked: [bool; 2],
    listeners: HashMap<u16, Listener<UdpConn>>,
    /// Live flows by (source, port).
    flows: HashMap<(SocketAddr, u16), Flow>,
    /// Flows closed but not yet dropped.
    closed: Vec<UdpConn>,
    next: u32,
}

impl Dispatch {
    fn new() -> Dispatch {
        // Fresh clients for each test case, so flows from earlier ones
        // can't interfere.
        let w = world();
        let keys = [(); 2].map(|_| NodePrivate::generate().public());
        for k in keys {
            w.meow(k);
        }
        Dispatch {
            w,
            keys,
            srcs: keys.map(|k| SocketAddr::new(IpAddr::V6(k.tailcat_ip()), 1000)),
            revoked: [false; 2],
            listeners: HashMap::new(),
            flows: HashMap::new(),
            closed: Vec::new(),
            next: 0,
        }
    }

    fn client(&self, tc: &TestCase) -> usize {
        tc.draw(gs::integers::<usize>().max_value(self.keys.len() - 1))
    }

    fn port(tc: &TestCase) -> u16 {
        PORTS[tc.draw(gs::integers::<usize>().max_value(PORTS.len() - 1))]
    }

    fn flow(&self, tc: &TestCase) -> Option<(SocketAddr, u16)> {
        let mut keys: Vec<_> = self.flows.keys().copied().collect();
        keys.sort();
        (!keys.is_empty()).then(|| keys[tc.draw(gs::integers::<usize>().max_value(keys.len() - 1))])
    }

    /// The next flow handed to the handler or `port`'s listener, if one
    /// comes soon.
    async fn accepted(&mut self, port: u16, wait: Duration) -> Option<(UdpConn, Via)> {
        let mut handled = self.w.handled.lock().await;
        let listener = self.listeners.get_mut(&port);
        timeout(wait, async {
            match listener {
                Some(l) => tokio::select! {
                    c = handled.recv() => (c.unwrap(), Via::Handler),
                    c = l.accept() => (c.unwrap(), Via::Listener),
                },
                None => (handled.recv().await.unwrap(), Via::Handler),
            }
        })
        .await
        .ok()
    }

    /// Where a new flow from `src` to `port` should go.
    fn route(&self, src: SocketAddr, port: u16) -> Option<Via> {
        let revoked = self.srcs.iter().zip(self.revoked).any(|(s, r)| *s == src && r);
        if revoked {
            None
        } else if self.listeners.contains_key(&port) {
            Some(Via::Listener)
        } else {
            (port == SERVED).then_some(Via::Handler)
        }
    }

    /// Puts a datagram carrying `seq` straight into the server's stack.
    fn inject(&self, src: SocketAddr, dst: SocketAddr, seq: u32) {
        // The stack hands new flows to handlers on the runtime.
        let _rt = self.w.rt.enter();
        self.w.server.inner.stack.inject(build_udp(src, dst, &seq.to_be_bytes()).unwrap());
    }

    /// Checks that datagram `seq`, from `src` to `dst` with no flow yet,
    /// opens a flow where `route` says, or none.
    async fn expect_new_flow(&mut self, src: SocketAddr, dst: SocketAddr, seq: u32) {
        let port = dst.port();
        let want = self.route(src, port);
        let wait = Duration::from_millis(if want.is_some() { 2000 } else { 20 });
        let got = self.accepted(port, wait).await;
        let (want, (conn, via)) = match (want, got) {
            (None, None) => return,
            (Some(want), Some(got)) => (want, got),
            (want, got) => panic!("{src} -> {port}: wanted a flow via {want:?}, got {:?}", got.map(|g| g.1)),
        };
        assert_eq!(via, want, "{src} -> {port}: new flow went to the wrong place");
        assert_eq!((conn.peer_addr(), conn.local_addr()), (src, dst));
        let mut buf = [0u8; 16];
        let n = conn.recv(&mut buf).await.unwrap();
        assert_eq!(buf[..n], seq.to_be_bytes());
        self.flows.insert((src, port), Flow { conn, via });
    }

    /// Sends a datagram and checks where it goes.
    fn send(&mut self, src: SocketAddr, port: u16) {
        let seq = self.next;
        self.next += 1;
        let dst = SocketAddr::new(IpAddr::V6(self.w.server.addr()), port);
        self.inject(src, dst, seq);
        let rt = &self.w.rt;
        match self.flows.get(&(src, port)) {
            // Datagrams for a flow queue on it at once.
            Some(f) => rt.block_on(expect_datagram(&f.conn, src, port, seq)),
            None => rt.block_on(self.expect_new_flow(src, dst, seq)),
        }
    }
}

#[hegel::state_machine]
impl Dispatch {
    #[rule]
    fn datagram(&mut self, tc: TestCase) {
        let src = self.srcs[self.client(&tc)];
        self.send(src, Self::port(&tc));
    }

    /// The server revokes a client, whose flows close at once, even
    /// ones nobody is using.
    #[rule]
    fn revoke(&mut self, tc: TestCase) {
        let i = self.client(&tc);
        let was_connected = !self.revoked[i];
        assert_eq!(self.w.server.disconnect_client(&self.keys[i]), was_connected);
        self.revoked[i] = true;
        let src = self.srcs[i];
        let gone: Vec<_> = self.flows.extract_if(|(s, _), _| *s == src).collect();
        for ((_, port), f) in gone {
            self.w.rt.block_on(expect_closed(&f.conn, src, port));
        }
    }

    /// A revoked client joins again, or a connected one refreshes.
    #[rule]
    fn rejoin(&mut self, tc: TestCase) {
        let i = self.client(&tc);
        self.w.meow(self.keys[i]);
        self.revoked[i] = false;
    }

    #[rule]
    fn listen(&mut self, tc: TestCase) {
        let port = Self::port(&tc);
        let r = self.w.server.listen_udp(port);
        match self.listeners.entry(port) {
            Entry::Occupied(_) => assert!(r.is_err(), "listened twice on {port}"),
            Entry::Vacant(e) => {
                e.insert(r.unwrap());
            }
        }
    }

    #[rule]
    fn unlisten(&mut self, tc: TestCase) {
        // Flows already accepted outlive their listener.
        self.listeners.remove(&Self::port(&tc));
    }

    /// The flow's owner closes it, and may hold on to it a while.
    #[rule]
    fn close(&mut self, tc: TestCase) {
        let Some(k) = self.flow(&tc) else { return };
        let f = self.flows.remove(&k).unwrap();
        f.conn.close();
        self.closed.push(f.conn);
    }

    /// The flow's owner drops it, which closes it.
    #[rule]
    fn drop_flow(&mut self, tc: TestCase) {
        if let Some(k) = self.flow(&tc) {
            self.flows.remove(&k);
        }
    }

    /// Owners finally drop the flows they closed.
    #[rule]
    fn drop_closed(&mut self, _: TestCase) {
        self.closed.clear();
    }

    #[invariant(always_run)]
    fn flows_came_the_right_way(&self, _: TestCase) {
        for ((_, port), f) in &self.flows {
            assert!(f.via == Via::Listener || *port == SERVED, "an unserved port's flow went to the handler");
        }
    }
}

impl Drop for Dispatch {
    fn drop(&mut self) {
        for k in &self.keys {
            self.w.server.disconnect_client(k);
        }
    }
}

#[hegel::test(test_cases = 1000)]
fn udp_dispatch_state_machine(tc: TestCase) {
    hegel::stateful::machine(Dispatch::new()).steps(20).run(tc);
}
