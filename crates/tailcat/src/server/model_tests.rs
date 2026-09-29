//! Model-based tests of how a server dispatches inbound UDP flows,
//! driven by Hegel. Datagrams from a few sources go straight into the
//! server's stack for a port with an `on_udp` handler and a port outside
//! the served ranges, while listeners come and go on both, and flows are
//! closed and dropped. Each new flow must go to the listener if there is
//! one, else to the handler if the port is served, else nowhere, and each
//! datagram for a live flow must reach exactly that flow.

use std::collections::HashMap;
use std::sync::atomic::AtomicU16;

use hegel::TestCase;
use hegel::generators as gs;

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
    rt: tokio::runtime::Runtime,
    server: Server,
    handled: tokio::sync::Mutex<mpsc::UnboundedReceiver<UdpConn>>,
    _dev: DevDerp,
}

fn world() -> &'static World {
    static SINK: Sink = Mutex::new(None);
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        *SINK.lock().unwrap() = Some(tx);
        let (dev, server) = rt.block_on(async {
            let dev = DevDerp::start_local().await.unwrap();
            let server = Server::builder()
                .region(dev.region.clone())
                .served_udp_ports(vec![PortRange::single(SERVED)])
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
        World { rt, server, handled: tokio::sync::Mutex::new(rx), _dev: dev }
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

struct Dispatch {
    w: &'static World,
    srcs: [SocketAddr; 2],
    listeners: HashMap<u16, Listener<UdpConn>>,
    /// Live flows by (source, port).
    flows: HashMap<(SocketAddr, u16), Flow>,
    /// Flows closed but not yet dropped.
    closed: Vec<UdpConn>,
    next: u32,
}

impl Dispatch {
    fn new() -> Dispatch {
        // Fresh sources for each test case, so flows from earlier ones
        // can't interfere.
        static NEXT: AtomicU16 = AtomicU16::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let src = |i| SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, n, i)), 1000);
        Dispatch {
            w: world(),
            srcs: [src(1), src(2)],
            listeners: HashMap::new(),
            flows: HashMap::new(),
            closed: Vec::new(),
            next: 0,
        }
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
        tokio::time::timeout(wait, async {
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

    /// Sends a datagram and checks where it goes.
    fn send(&mut self, src: SocketAddr, port: u16) {
        let seq = self.next;
        self.next += 1;
        let dst = SocketAddr::new(IpAddr::V6(self.w.server.addr()), port);
        let w = self.w;
        // The stack hands new flows to handlers on the runtime.
        let _rt = w.rt.enter();
        w.server.inner.stack.inject(build_udp(src, dst, &seq.to_be_bytes()).unwrap());
        w.rt.block_on(async {
            let mut buf = [0u8; 16];
            if let Some(f) = self.flows.get(&(src, port)) {
                // Datagrams for a flow queue on it at once.
                let n = tokio::time::timeout(Duration::from_secs(1), f.conn.recv(&mut buf)).await;
                let n = n.unwrap_or_else(|_| panic!("{src} -> {port}: datagram {seq} didn't reach its flow")).unwrap();
                assert_eq!(buf[..n], seq.to_be_bytes(), "{src} -> {port}: wrong datagram");
                return;
            }
            let want = if self.listeners.contains_key(&port) {
                Some(Via::Listener)
            } else {
                (port == SERVED).then_some(Via::Handler)
            };
            let wait = Duration::from_millis(if want.is_some() { 2000 } else { 20 });
            let got = self.accepted(port, wait).await;
            match (want, got) {
                (None, None) => {}
                (Some(want), Some((conn, via))) => {
                    assert_eq!(via, want, "{src} -> {port}: new flow went to the wrong place");
                    assert_eq!((conn.peer_addr(), conn.local_addr()), (src, dst));
                    let n = conn.recv(&mut buf).await.unwrap();
                    assert_eq!(buf[..n], seq.to_be_bytes());
                    self.flows.insert((src, port), Flow { conn, via });
                }
                (want, got) => {
                    panic!("{src} -> {port}: wanted a flow via {want:?}, got {:?}", got.map(|g| g.1))
                }
            }
        });
    }
}

#[hegel::state_machine]
impl Dispatch {
    #[rule]
    fn datagram(&mut self, tc: TestCase) {
        let src = self.srcs[tc.draw(gs::integers::<usize>().max_value(self.srcs.len() - 1))];
        self.send(src, Self::port(&tc));
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

#[hegel::test(test_cases = 1000)]
fn udp_dispatch_state_machine(tc: TestCase) {
    hegel::stateful::machine(Dispatch::new()).steps(20).run(tc);
}
