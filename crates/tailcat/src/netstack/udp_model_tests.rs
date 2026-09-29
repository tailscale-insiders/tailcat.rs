//! Model-based tests of the UDP flow table, driven by Hegel. Remotes send
//! datagrams to a few ports and to the stack's dialed flows, and handlers
//! receive, send, close and drop their flows or let them go idle, while
//! the stack dials out and is closed, in generated orders. Some of it
//! happens while the policy is deciding on a new flow, as it would on
//! another thread. Every datagram is checked to reach exactly its own
//! flow's conn, and the flow table to route to exactly the flows still
//! open.

use std::collections::HashSet;

use hegel::TestCase;
use hegel::generators as gs;

use super::*;

const PORTS: [u16; 2] = [53, 54];
/// The idle timeout of a flow let go idle.
const IDLE: Duration = Duration::from_secs(60);

fn local_ip() -> IpAddr {
    "fd7a:115c:a1e0::1".parse().unwrap()
}

/// The policy refuses every flow from this address.
fn denied_ip() -> IpAddr {
    "fd7a:115c:a1e0::bad".parse().unwrap()
}

/// Two remote endpoints on an allowed address and one on the denied one.
fn remotes() -> [SocketAddr; 3] {
    let allowed: IpAddr = "fd7a:115c:a1e0::2".parse().unwrap();
    [SocketAddr::new(allowed, 1000), SocketAddr::new(allowed, 1001), SocketAddr::new(denied_ip(), 1000)]
}

/// Something that happens while the policy decides on a new flow.
#[derive(Clone, Copy, Debug)]
enum Race {
    /// Another datagram arrives, for the flow `key` (local, remote).
    Inbound(FlowKey),
    /// The stack dials `remote`.
    Dial(SocketAddr),
    /// The stack is closed.
    Close,
}

/// One flow's conn, as the model expects it to behave.
struct Flow {
    local: SocketAddr,
    remote: SocketAddr,
    /// The conn, until its handler drops it.
    conn: Option<UdpConn>,
    /// Whether the conn was closed, by its handler or by going idle.
    closed: bool,
    /// Datagrams that arrived for the flow and haven't been received.
    queued: VecDeque<Vec<u8>>,
    /// Whether the conn has gone past its idle timeout.
    idle: bool,
}

type Accepted = Arc<Mutex<Vec<(FlowKey, UdpConn)>>>;
type Hook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

struct Net {
    rt: tokio::runtime::Runtime,
    stack: Stack,
    out: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Conns the policy's handlers were given, with the flow the policy
    /// decided on.
    accepted: Accepted,
    /// What to do the next time the policy is asked.
    hook: Hook,
    /// What a dial made while the policy was deciding returned.
    raced_dial: Arc<Mutex<Option<io::Result<UdpConn>>>>,
    flows: Vec<Flow>,
    /// The open flow on each (local, remote), as an index into `flows`.
    open: HashMap<FlowKey, usize>,
    closed: bool,
    next_payload: u32,
}

impl Net {
    fn new() -> Net {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _guard = rt.enter();
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let accepted: Accepted = Arc::default();
        let hook: Hook = Arc::default();
        let (o, a, h) = (out.clone(), accepted.clone(), hook.clone());
        let policy: UdpPolicy = Arc::new(move |src, dst| {
            let race = h.lock().unwrap().take();
            if let Some(race) = race {
                race();
            }
            if src.ip() == denied_ip() {
                return None;
            }
            let a = a.clone();
            Some(Box::new(move |c| a.lock().unwrap().push(((dst, src), c))))
        });
        let stack = Stack::new(
            StackConfig { addrs: vec![local_ip()], any_ip: false, mtu: 1280 },
            Arc::new(move |p| o.lock().unwrap().push(p)),
            None,
            Some(policy),
        );
        Net {
            rt,
            stack,
            out,
            accepted,
            hook,
            raced_dial: Arc::default(),
            flows: Vec::new(),
            open: HashMap::new(),
            closed: false,
            next_payload: 0,
        }
    }

    fn payload(&mut self) -> Vec<u8> {
        self.next_payload += 1;
        format!("datagram {}", self.next_payload).into_bytes()
    }

    /// A flow to send a datagram on: one of a remote's to one of our
    /// ports, or one we've had before, dialed or not.
    fn draw_key(&self, tc: &TestCase) -> FlowKey {
        if !self.flows.is_empty() && tc.draw(gs::booleans()) {
            let f = &self.flows[tc.draw(gs::integers::<usize>().max_value(self.flows.len() - 1))];
            return (f.local, f.remote);
        }
        let r = remotes()[tc.draw(gs::integers::<usize>().max_value(remotes().len() - 1))];
        let port = PORTS[tc.draw(gs::integers::<usize>().max_value(PORTS.len() - 1))];
        (SocketAddr::new(local_ip(), port), r)
    }

    fn draw_remote(tc: &TestCase) -> SocketAddr {
        remotes()[tc.draw(gs::integers::<usize>().max_value(remotes().len() - 1))]
    }

    /// One of the flows whose conn a handler still holds.
    fn draw_held(&self, tc: &TestCase) -> Option<usize> {
        let held: Vec<usize> = (0..self.flows.len()).filter(|&i| self.flows[i].conn.is_some()).collect();
        if held.is_empty() {
            return None;
        }
        Some(held[tc.draw(gs::integers::<usize>().max_value(held.len() - 1))])
    }

    /// Takes flow `i` out of the flow table, if it's the one there.
    fn unroute(&mut self, i: usize) {
        let key = (self.flows[i].local, self.flows[i].remote);
        if self.open.get(&key) == Some(&i) {
            self.open.remove(&key);
        }
    }

    /// A new flow the model expects, open with `queued`.
    fn add_flow(&mut self, (local, remote): FlowKey, conn: Option<UdpConn>, queued: Vec<u8>) {
        let queued = if queued.is_empty() { VecDeque::new() } else { VecDeque::from([queued]) };
        self.flows.push(Flow { local, remote, conn, closed: false, queued, idle: false });
        self.open.insert((local, remote), self.flows.len() - 1);
    }

    /// What the model expects of a datagram arriving on `key`. New flows
    /// are added to `new`, for the handlers' conns to be matched to.
    fn expect_inbound(&mut self, key: FlowKey, data: Vec<u8>, new: &mut Vec<usize>) {
        if self.closed {
            return;
        }
        if let Some(&i) = self.open.get(&key) {
            self.flows[i].queued.push_back(data);
        } else if key.1.ip() != denied_ip() {
            self.add_flow(key, None, data);
            new.push(self.flows.len() - 1);
        }
    }

    /// What the model expects of dialing `remote`.
    fn expect_dial(&mut self, remote: SocketAddr, r: io::Result<UdpConn>) {
        let r = r.map_err(|e| e.kind());
        assert_eq!(r.is_err(), self.closed, "dialing {remote}: {r:?}, but the stack is closed: {}", self.closed);
        let Ok(c) = r else { return };
        let local = c.local_addr();
        assert_eq!((local.ip(), c.peer_addr()), (local_ip(), remote), "dialed the wrong flow");
        assert!(EPHEMERAL.contains(&local.port()), "dialed from non-ephemeral port {local}");
        assert!(!self.open.keys().any(|(l, _)| *l == local), "dialed from {local}, which is in use");
        self.add_flow((local, remote), Some(c), Vec::new());
    }

    /// Sends a datagram on `key`, with `race` happening while the policy
    /// decides on it, if it's asked.
    fn inbound(&mut self, key: FlowKey, race: Option<Race>) {
        let data = self.payload();
        let raced_data = self.payload();
        if let Some(race) = race {
            let (stack, raced_dial, d) = (self.stack.clone(), self.raced_dial.clone(), raced_data.clone());
            *self.hook.lock().unwrap() = Some(Box::new(move || match race {
                Race::Inbound((l, r)) => stack.inject(build_udp(r, l, &d).unwrap()),
                Race::Dial(remote) => *raced_dial.lock().unwrap() = Some(stack.dial_udp(local_ip(), remote)),
                Race::Close => stack.close(),
            }));
        }
        self.stack.inject(build_udp(key.1, key.0, &data).unwrap());
        let fired = self.hook.lock().unwrap().take().is_none();

        // The race happens first: it finishes before the policy does.
        let mut new = Vec::new();
        match race.filter(|_| fired) {
            Some(Race::Inbound(k)) => self.expect_inbound(k, raced_data, &mut new),
            Some(Race::Dial(remote)) => {
                let r = self.raced_dial.lock().unwrap().take().unwrap();
                self.expect_dial(remote, r);
            }
            Some(Race::Close) => self.close_stack_model(),
            None => {}
        }
        self.expect_inbound(key, data, &mut new);

        let accepted = std::mem::take(&mut *self.accepted.lock().unwrap());
        let got: Vec<FlowKey> = accepted.iter().map(|(k, _)| *k).collect();
        let want: Vec<FlowKey> = new.iter().map(|&i| (self.flows[i].local, self.flows[i].remote)).collect();
        assert_eq!(got, want, "handlers were given the wrong flows (race {race:?})");
        for ((k, c), i) in accepted.into_iter().zip(new) {
            assert_eq!((c.local_addr(), c.peer_addr()), k, "the policy decided on {k:?}, but got {c:?}");
            self.flows[i].conn = Some(c);
        }
    }

    fn dial(&mut self, remote: SocketAddr) {
        let r = self.stack.dial_udp(local_ip(), remote);
        self.expect_dial(remote, r);
    }

    fn close_stack(&mut self) {
        self.stack.close();
        self.close_stack_model();
    }

    fn close_stack_model(&mut self) {
        self.closed = true;
        self.open.clear();
    }

    /// Receives on flow `i` without waiting for more datagrams.
    fn recv(&mut self, i: usize) {
        let c = self.flows[i].conn.as_ref().unwrap();
        let got = self.rt.block_on(async {
            let mut buf = [0u8; 64];
            let r = tokio::time::timeout(Duration::from_millis(1), c.recv(&mut buf)).await.ok()?;
            Some(r.map(|n| buf[..n].to_vec()).map_err(|e| e.kind()))
        });
        let f = &mut self.flows[i];
        let flow = format!("{} <- {}", f.local, f.remote);
        let routed = self.open.get(&(f.local, f.remote)) == Some(&i);
        // A flow is out of the table once it's closed, or the stack is.
        let want = if f.closed || !routed {
            Some(Err(io::ErrorKind::NotConnected))
        } else if let Some(d) = f.queued.pop_front() {
            Some(Ok(d))
        } else if f.idle {
            f.closed = true;
            Some(Err(io::ErrorKind::TimedOut))
        } else {
            None
        };
        assert_eq!(got, want, "{flow}: wrong receive");
        if matches!(got, Some(Ok(_))) {
            f.idle = false;
        }
        if f.closed {
            self.unroute(i);
        }
    }

    /// Lets flow `i` go past its idle timeout, as if nothing had been sent
    /// or received on it for longer.
    fn idle(&mut self, i: usize) {
        let c = self.flows[i].conn.as_ref().unwrap();
        c.set_idle_timeout(Some(IDLE));
        let last = *c.last_activity.lock().unwrap();
        *c.last_activity.lock().unwrap() = last.checked_sub(IDLE + Duration::from_secs(1)).unwrap();
        self.flows[i].idle = true;
    }

    /// Sends a datagram on flow `i`.
    fn send(&mut self, i: usize) {
        let data = self.payload();
        let c = self.flows[i].conn.as_ref().unwrap();
        let r = self.rt.block_on(c.send(&data)).map_err(|e| e.kind());
        let f = &mut self.flows[i];
        let flow = format!("{} -> {}", f.local, f.remote);
        let sent = std::mem::take(&mut *self.out.lock().unwrap());
        if f.closed || self.closed {
            assert_eq!(r, Err(io::ErrorKind::NotConnected), "{flow}: sent on a closed flow");
            assert!(sent.is_empty(), "{flow}: a closed flow sent {sent:?}");
            return;
        }
        assert_eq!(r, Ok(data.len()), "{flow}: send failed");
        assert_eq!(sent, [build_udp(f.local, f.remote, &data).unwrap()], "{flow}: sent the wrong packets");
        f.idle = false;
    }
}

#[hegel::state_machine]
impl Net {
    /// A datagram arrives, maybe with something else happening while the
    /// policy decides on it.
    #[rule]
    fn inbound_rule(&mut self, tc: TestCase) {
        let key = self.draw_key(&tc);
        let race = match tc.draw(gs::integers::<u8>().max_value(4)) {
            0 => None,
            1 => Some(Race::Inbound(key)),
            2 => Some(Race::Inbound(self.draw_key(&tc))),
            3 => Some(Race::Dial(Self::draw_remote(&tc))),
            _ => Some(Race::Close),
        };
        self.inbound(key, race);
    }

    /// The stack dials out.
    #[rule]
    fn dial_rule(&mut self, tc: TestCase) {
        self.dial(Self::draw_remote(&tc));
    }

    /// A handler receives a datagram.
    #[rule]
    fn recv_rule(&mut self, tc: TestCase) {
        let Some(i) = self.draw_held(&tc) else { return };
        self.recv(i);
    }

    /// A handler sends a datagram.
    #[rule]
    fn send_rule(&mut self, tc: TestCase) {
        let Some(i) = self.draw_held(&tc) else { return };
        self.send(i);
    }

    /// A handler closes its flow.
    #[rule]
    fn close(&mut self, tc: TestCase) {
        let Some(i) = self.draw_held(&tc) else { return };
        self.flows[i].conn.as_ref().unwrap().close();
        self.flows[i].closed = true;
        self.unroute(i);
    }

    /// A handler drops its conn.
    #[rule]
    fn drop_conn(&mut self, tc: TestCase) {
        let Some(i) = self.draw_held(&tc) else { return };
        self.flows[i].conn = None;
        self.unroute(i);
    }

    /// A flow goes past its idle timeout.
    #[rule]
    fn go_idle(&mut self, tc: TestCase) {
        let Some(i) = self.draw_held(&tc) else { return };
        self.idle(i);
    }

    /// The stack is closed.
    #[rule]
    fn close_stack_rule(&mut self, _: TestCase) {
        self.close_stack();
    }

    /// The flow table routes each open flow's 4-tuple to its conn, and
    /// nothing else.
    #[invariant(always_run)]
    fn table_routes_open_flows(&self, _: TestCase) {
        // Not holding the lock: a panic would poison it for the conns'
        // drops.
        let table: HashSet<FlowKey> = self.stack.shared.lock().udp.keys().copied().collect();
        let open: HashSet<FlowKey> = self.open.keys().copied().collect();
        assert_eq!(table, open, "the flow table is wrong");
        for &i in self.open.values() {
            let f = &self.flows[i];
            let c = f.conn.as_ref().expect("an open flow's conn was dropped");
            let rx = c.rx.try_lock().unwrap();
            assert_eq!(rx.sender_strong_count(), 1, "{} <- {} isn't routed to its conn", f.local, f.remote);
        }
    }
}

#[hegel::test(test_cases = 300)]
fn udp_flow_table_state_machine(tc: TestCase) {
    hegel::stateful::machine(Net::new()).steps(30).run(tc);
}

/// The flows in the stack's table.
fn table(net: &Net) -> HashSet<FlowKey> {
    net.stack.shared.lock().udp.keys().copied().collect()
}

fn port_53(remote: SocketAddr) -> FlowKey {
    (SocketAddr::new(local_ip(), 53), remote)
}

/// The bug the state machine found first: closing a flow a second time,
/// or dropping it after it closed or went idle, took the new flow on its
/// 4-tuple out of the table. The new flow's handler got one datagram and
/// then an error, and the next datagram went to yet another handler.
#[test]
fn closing_again_leaves_a_new_flow_alone() {
    let mut net = Net::new();
    let key = port_53(remotes()[0]);
    net.inbound(key, None);
    net.recv(0);
    net.idle(0);
    net.recv(0);
    assert!(net.flows[0].closed, "the flow didn't time out");
    net.inbound(key, None);
    net.flows[0].conn = None;
    assert_eq!(table(&net), HashSet::from([key]), "dropping the idle flow closed the new one");
    net.inbound(key, None);
    net.recv(1);
    net.recv(1);
    assert_eq!(net.flows.len(), 2, "the flow was opened again");
}

/// Once the stack is closed, datagrams open no flows, even ones the
/// policy was already deciding on, and dials fail.
#[test]
fn nothing_opens_after_the_stack_closes() {
    let mut net = Net::new();
    net.inbound(port_53(remotes()[0]), Some(Race::Close));
    net.inbound(port_53(remotes()[1]), None);
    net.dial(remotes()[0]);
    assert!(net.flows.is_empty() && table(&net).is_empty(), "flows opened on a closed stack");
}

/// Two datagrams on a new flow, one arriving while the policy decides on
/// the other, open one flow. Each used to open one, the later replacing
/// the earlier in the table, whose handler got one datagram and then an
/// error.
#[test]
fn racing_datagrams_open_one_flow() {
    let mut net = Net::new();
    let key = port_53(remotes()[0]);
    net.inbound(key, Some(Race::Inbound(key)));
    assert_eq!(net.flows.len(), 1);
    net.recv(0);
    net.recv(0);
}

/// Sends fail once the stack is closed, as receives do, rather than going
/// out through a tunnel that's shutting down.
#[test]
fn flows_fail_once_the_stack_closes() {
    let mut net = Net::new();
    net.inbound(port_53(remotes()[0]), None);
    net.dial(remotes()[1]);
    net.close_stack();
    for i in 0..2 {
        net.send(i);
        net.recv(i);
    }
}
