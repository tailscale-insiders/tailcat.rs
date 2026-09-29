//! Model-based tests of TCP connection lifecycles, driven by Hegel: the
//! stack dials out and accepts connections, and a scripted remote answers
//! or refuses its SYNs, sends data, FINs and RSTs at any time, or goes
//! silent for good, while our side writes, half-closes, aborts and drops
//! streams, closes the stack, and lets time pass on a paused clock. Every
//! stream is checked against what the remote sent and how the connection
//! ended, and the stack's flow table against its sockets.

use std::collections::HashSet;
use std::task::Waker;

use hegel::TestCase;
use hegel::generators as gs;
use smoltcp::wire::{TcpControl, TcpSeqNumber};

use super::model_tests::segment;
use super::*;

/// Our port for inbound connections, and the remote's for dialed ones.
const SERVICE: u16 = 80;
const DIALED: u16 = 443;
/// The remote's source ports for inbound connections.
const SOURCE_PORTS: [u16; 2] = [1000, 1001];
/// Leeway for timeouts: the stack notices them on its next poll.
const SLACK: Duration = Duration::from_secs(5);

fn local_ip() -> IpAddr {
    "fd7a:115c:a1e0::1".parse().unwrap()
}

fn remote_ip() -> IpAddr {
    "fd7a:115c:a1e0::2".parse().unwrap()
}

type Dial = Pin<Box<dyn Future<Output = io::Result<TcpStream>>>>;

/// One connection: the remote's side of it, and ours.
struct Conn {
    /// (local, remote); a dialed connection's local port is learned from
    /// the stack's SYN.
    key: Option<FlowKey>,
    remote: SocketAddr,
    dialed: bool,
    // The remote's side.
    isn: TcpSeqNumber,
    /// The stack's initial sequence number, from its SYN or SYN-ACK.
    stack_isn: Option<TcpSeqNumber>,
    /// Whether the remote has completed the handshake: acked the stack's
    /// SYN-ACK, or answered its SYN with one.
    established: bool,
    sent: Vec<u8>,
    fin: bool,
    reset: bool,
    /// Whether the remote has gone silent for good, and since when.
    dead: Option<tokio::time::Instant>,
    /// When the stack started trying to reach the remote (its dial), and
    /// when the remote answered.
    started: tokio::time::Instant,
    answered: Option<tokio::time::Instant>,
    /// What the remote got from the stack.
    got: Vec<u8>,
    got_fin: bool,
    got_rst: bool,
    /// Whether the remote has acked the stack's FIN.
    fin_acked: bool,
    // Our side.
    dial: Option<Dial>,
    dial_result: Option<Result<(), io::ErrorKind>>,
    stream: Option<TcpStream>,
    handed_off: bool,
    written: Vec<u8>,
    write_closed: bool,
    /// We aborted it, or closed the stack.
    aborted: bool,
    /// When the stream was dropped (or the dial given up).
    dropped: Option<tokio::time::Instant>,
    received: Vec<u8>,
    end: Option<Result<(), io::ErrorKind>>,
}

impl Conn {
    fn new(remote: SocketAddr, dialed: bool, isn: TcpSeqNumber, now: tokio::time::Instant) -> Conn {
        Conn {
            key: None,
            remote,
            dialed,
            isn,
            stack_isn: None,
            established: false,
            sent: Vec::new(),
            fin: false,
            reset: false,
            dead: None,
            started: now,
            answered: None,
            got: Vec::new(),
            got_fin: false,
            got_rst: false,
            fin_acked: false,
            dial: None,
            dial_result: None,
            stream: None,
            handed_off: false,
            written: Vec::new(),
            write_closed: false,
            aborted: false,
            dropped: None,
            received: Vec::new(),
            end: None,
        }
    }

    /// The sequence number of the remote's next segment.
    fn seq(&self) -> TcpSeqNumber {
        self.isn + 1 + self.sent.len() + usize::from(self.fin)
    }

    /// The acknowledgment number the remote sends.
    fn ack(&self) -> Option<TcpSeqNumber> {
        self.stack_isn.map(|isn| isn + 1 + self.got.len() + usize::from(self.got_fin))
    }

    /// Whether the remote can still send on this connection.
    fn talking(&self) -> bool {
        self.dead.is_none() && !self.reset && !self.got_rst
    }

    /// Whether the connection is over as far as the remote is concerned,
    /// so it may reuse the 4-tuple.
    fn over(&self) -> bool {
        self.reset || self.got_rst || (self.fin && self.fin_acked)
    }

    /// Whether the connection ended some way other than a FIN, as far as
    /// the model knows: a RST from either side, or the stack's closing.
    fn broken(&self) -> bool {
        self.reset || self.got_rst || self.aborted
    }

    /// Reads whatever `stream` has, without waiting.
    fn read(&mut self) {
        let Some(s) = &mut self.stream else { return };
        let mut cx = Context::from_waker(Waker::noop());
        while self.end.is_none() {
            let mut buf = [0u8; 64];
            let mut rb = ReadBuf::new(&mut buf);
            match Pin::new(&mut *s).poll_read(&mut cx, &mut rb) {
                Poll::Ready(Ok(())) if rb.filled().is_empty() => self.end = Some(Ok(())),
                Poll::Ready(Ok(())) => self.received.extend_from_slice(rb.filled()),
                Poll::Ready(Err(e)) => self.end = Some(Err(e.kind())),
                Poll::Pending => break,
            }
        }
    }

    fn name(&self) -> String {
        let dir = if self.dialed { "dialed" } else { "accepted" };
        match self.key {
            Some((l, r)) => format!("{dir} {l} -> {r}"),
            None => format!("{dir} ? -> {}", self.remote),
        }
    }
}

struct Net {
    rt: tokio::runtime::Runtime,
    stack: Stack,
    out: Arc<Mutex<Vec<Vec<u8>>>>,
    accepted: Arc<Mutex<Vec<TcpStream>>>,
    conns: Vec<Conn>,
    /// The latest connection on each 4-tuple, as an index into `conns`.
    live: HashMap<FlowKey, usize>,
    next_isn: i32,
    closed: bool,
}

impl Net {
    fn new() -> Net {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap();
        let _guard = rt.enter();
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let accepted: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        let (o, a) = (out.clone(), accepted.clone());
        let policy: TcpPolicy = Arc::new(move |_src, _dst| {
            let a = a.clone();
            TcpDecision::Accept(Box::new(move |s| a.lock().unwrap().push(s)))
        });
        let stack = Stack::new(
            StackConfig { addrs: vec![local_ip()], any_ip: false, mtu: 1280 },
            Arc::new(move |p| o.lock().unwrap().push(p)),
            Some(policy),
            None,
        );
        Net { rt, stack, out, accepted, conns: Vec::new(), live: HashMap::new(), next_isn: 1000, closed: false }
    }

    /// Feeds a segment to the stack, on the paused clock.
    fn inject(&self, pkt: Vec<u8>) {
        let _guard = self.rt.enter();
        self.stack.inject(pkt);
    }

    fn now(&self) -> tokio::time::Instant {
        self.rt.block_on(async { tokio::time::Instant::now() })
    }

    fn isn(&mut self) -> TcpSeqNumber {
        self.next_isn += 100_000;
        TcpSeqNumber(self.next_isn)
    }

    /// Lets the stack run until it's quiet: the remotes see what it sent
    /// (acking what an established, live remote would), our side takes
    /// its dials' results and the handler's connections, and reads what
    /// they have.
    fn settle(&mut self) {
        let rt = self.rt.handle().clone();
        let _guard = rt.enter();
        for _ in 0..64 {
            self.rt.block_on(async {
                for _ in 0..16 {
                    tokio::task::yield_now().await;
                }
            });
            let dialed = self.poll_dials();
            let out = std::mem::take(&mut *self.out.lock().unwrap());
            let accepted = std::mem::take(&mut *self.accepted.lock().unwrap());
            if out.is_empty() && accepted.is_empty() && !dialed {
                break;
            }
            out.into_iter().for_each(|p| self.deliver(p));
            for s in accepted {
                let key = (s.local_addr(), s.peer_addr());
                let c = self
                    .live
                    .get(&key)
                    .map(|&i| &mut self.conns[i])
                    .unwrap_or_else(|| panic!("{s:?} was accepted, but never connected"));
                assert!(!c.dialed && !c.handed_off, "{} was handed off twice", c.name());
                c.handed_off = true;
                c.stream = Some(s);
            }
        }
        self.conns.iter_mut().for_each(Conn::read);
    }

    /// Polls the dials in progress, and says whether any finished.
    fn poll_dials(&mut self) -> bool {
        let mut cx = Context::from_waker(Waker::noop());
        let mut done = false;
        for c in &mut self.conns {
            let Some(d) = &mut c.dial else { continue };
            let Poll::Ready(r) = d.as_mut().poll(&mut cx) else { continue };
            c.dial = None;
            done = true;
            match r {
                Ok(s) => {
                    c.dial_result = Some(Ok(()));
                    c.stream = Some(s);
                }
                Err(e) => c.dial_result = Some(Err(e.kind())),
            }
        }
        done
    }

    /// A segment from the stack reaches its remote.
    fn deliver(&mut self, p: Vec<u8>) {
        let ip = Ipv6Packet::new_checked(&p[..]).unwrap();
        let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else { return };
        let local = SocketAddr::new(IpAddr::from(ip.src_addr()), tcp.src_port());
        let remote = SocketAddr::new(IpAddr::from(ip.dst_addr()), tcp.dst_port());
        let key = (local, remote);
        let mut i = self.live.get(&key).copied();
        if tcp.syn() && !tcp.ack() && i.is_none_or(|i| self.conns[i].stack_isn != Some(tcp.seq_number())) {
            // A dial's first SYN.
            let Some(j) = self.conns.iter().position(|c| c.dialed && c.key.is_none() && c.remote == remote) else {
                return;
            };
            self.conns[j].key = Some(key);
            self.live.insert(key, j);
            i = Some(j);
        }
        let Some(i) = i else { return };
        let c = &mut self.conns[i];
        if tcp.rst() {
            // Like a real peer, ignore RSTs that aren't for this connection.
            c.got_rst |= match c.stack_isn {
                None => tcp.ack() && tcp.ack_number() == c.isn + 1,
                Some(isn) => tcp.seq_number() == isn + 1 + c.got.len() + usize::from(c.got_fin),
            };
            return;
        }
        if tcp.syn() {
            c.stack_isn = Some(tcp.seq_number());
        }
        let Some(isn) = c.stack_isn else { return };
        let seq = tcp.seq_number() + usize::from(tcp.syn());
        let expected = isn + 1 + c.got.len();
        let payload = tcp.payload();
        if !c.got_fin && seq <= expected {
            let skip = expected - seq;
            if skip < payload.len() {
                c.got.extend_from_slice(&payload[skip..]);
            }
            if tcp.fin() && seq + payload.len() == isn + 1 + c.got.len() {
                c.got_fin = true;
            }
        }
        // Anything taking sequence space (keep-alives included) gets an
        // ACK from a live remote.
        let occupies = !payload.is_empty() || tcp.fin() || seq < expected;
        if occupies && c.established && c.talking() {
            let pkt = segment(c.remote, local, TcpControl::None, c.seq(), c.ack(), &[]);
            c.fin_acked |= c.got_fin;
            self.inject(pkt);
        }
    }

    /// Picks a connection that satisfies `f`, or rejects the rule.
    fn pick(&self, tc: &TestCase, f: impl Fn(&Conn) -> bool) -> usize {
        let ok: Vec<usize> = (0..self.conns.len()).filter(|&i| f(&self.conns[i])).collect();
        tc.assume(!ok.is_empty());
        ok[tc.draw(gs::integers::<usize>().max_value(ok.len() - 1))]
    }

    /// The remote sends a segment on connection `i`.
    fn remote_send(&mut self, i: usize, control: TcpControl, payload: &[u8]) {
        let c = &mut self.conns[i];
        let (local, _) = c.key.unwrap();
        let pkt = segment(c.remote, local, control, c.seq(), c.ack(), payload);
        c.sent.extend_from_slice(payload);
        c.fin |= control == TcpControl::Fin;
        c.reset |= control == TcpControl::Rst;
        self.inject(pkt);
        self.settle();
    }

    /// Lets `d` pass, a little at a time so the remotes keep up.
    fn wait(&mut self, d: Duration) {
        let end = self.now() + d;
        loop {
            let now = self.now();
            if now >= end {
                break;
            }
            let step = (end - now).min(Duration::from_secs(1));
            // advance rather than sleep: a busy poll loop would keep a
            // paused clock from moving on by itself.
            self.rt.block_on(tokio::time::advance(step));
            self.settle();
        }
    }

    /// Runs `f` for up to `limit`, stepping the paused clock.
    fn run_for<F: Future>(&self, f: F, limit: Duration) -> Option<F::Output> {
        self.rt.block_on(async {
            let mut f = std::pin::pin!(f);
            let end = tokio::time::Instant::now() + limit;
            loop {
                if let Poll::Ready(v) = std::future::poll_fn(|cx| Poll::Ready(f.as_mut().poll(cx))).await {
                    return Some(v);
                }
                if tokio::time::Instant::now() >= end {
                    return None;
                }
                tokio::time::advance(Duration::from_millis(10)).await;
            }
        })
    }

    /// Whether the remote was silent long enough for the stack to give up
    /// on the connection: it went away, or never answered our SYN.
    fn silent_for(&self, c: &Conn, now: tokio::time::Instant) -> Option<Duration> {
        if let Some(t) = c.dead {
            return Some(now - t);
        }
        if c.dialed && c.answered.is_none() && !c.reset {
            return Some(now - c.started);
        }
        None
    }
}

/// The steps the state machine takes, for directed tests too.
impl Net {
    /// A remote opens a connection to us from `port`, and gets a SYN-ACK
    /// unless the stack is closed.
    fn open(&mut self, port: u16) -> usize {
        let key = (SocketAddr::new(local_ip(), SERVICE), SocketAddr::new(remote_ip(), port));
        let (isn, now) = (self.isn(), self.now());
        let mut c = Conn::new(key.1, false, isn, now);
        c.key = Some(key);
        c.answered = Some(now);
        self.conns.push(c);
        let i = self.conns.len() - 1;
        self.live.insert(key, i);
        self.inject(segment(key.1, key.0, TcpControl::Syn, isn, None, &[]));
        self.settle();
        let c = &self.conns[i];
        if !self.closed {
            assert!(c.stack_isn.is_some() && !c.got_rst, "{} got no SYN-ACK (RST: {})", c.name(), c.got_rst);
        }
        i
    }

    /// A remote that got our SYN-ACK completes the handshake.
    fn complete(&mut self, i: usize) {
        self.conns[i].established = true;
        self.remote_send(i, TcpControl::None, &[]);
    }

    /// The stack starts dialing the remote.
    fn dial(&mut self) -> usize {
        let (isn, now) = (self.isn(), self.now());
        let remote = SocketAddr::new(remote_ip(), DIALED);
        let mut c = Conn::new(remote, true, isn, now);
        let stack = self.stack.clone();
        let mut d: Dial = Box::pin(async move { stack.dial_tcp(local_ip(), remote).await });
        {
            let _guard = self.rt.enter();
            let mut cx = Context::from_waker(Waker::noop());
            match d.as_mut().poll(&mut cx) {
                Poll::Ready(Ok(s)) => panic!("dial connected at once: {s:?}"),
                Poll::Ready(Err(e)) => c.dial_result = Some(Err(e.kind())),
                Poll::Pending => c.dial = Some(d),
            }
        }
        self.conns.push(c);
        self.settle();
        let c = self.conns.last().unwrap();
        if self.closed {
            assert!(c.dial.is_none(), "a dial on a closed stack hangs");
        } else {
            assert!(c.key.is_some(), "a dial sent no SYN");
        }
        self.conns.len() - 1
    }

    /// The remote answers our SYN with a SYN-ACK.
    fn answer(&mut self, i: usize) {
        let now = self.now();
        let c = &mut self.conns[i];
        c.answered = Some(now);
        c.established = true;
        let (local, _) = c.key.unwrap();
        let pkt = segment(c.remote, local, TcpControl::Syn, c.isn, c.ack(), &[]);
        self.inject(pkt);
        self.settle();
    }

    /// The remote refuses our SYN with a RST.
    fn refuse(&mut self, i: usize) {
        let c = &mut self.conns[i];
        c.reset = true;
        let (local, _) = c.key.unwrap();
        let pkt = segment(c.remote, local, TcpControl::Rst, TcpSeqNumber(0), c.ack(), &[]);
        self.inject(pkt);
        self.settle();
    }

    /// We give up on a dial in progress.
    fn cancel_dial(&mut self, i: usize) {
        let now = self.now();
        let _guard = self.rt.enter();
        self.conns[i].dial = None;
        self.conns[i].dropped = Some(now);
        self.settle();
    }

    /// A remote goes away without a word.
    fn vanish(&mut self, i: usize) {
        self.conns[i].dead = Some(self.now());
    }

    /// We write `data`, and check the result.
    fn write(&mut self, i: usize, data: &[u8]) {
        let mut cx = Context::from_waker(Waker::noop());
        let c = &mut self.conns[i];
        let r = Pin::new(c.stream.as_mut().unwrap()).poll_write(&mut cx, data);
        let name = c.name();
        match r {
            Poll::Ready(Ok(n)) => {
                assert!(!c.write_closed && !c.broken(), "{name}: a write after it ended succeeded");
                c.written.extend_from_slice(&data[..n]);
            }
            Poll::Ready(Err(e)) => {
                let kind = e.kind();
                let expected: &[io::ErrorKind] = if c.aborted {
                    &[io::ErrorKind::ConnectionAborted]
                } else if c.reset {
                    &[io::ErrorKind::ConnectionReset]
                } else if c.write_closed {
                    &[io::ErrorKind::BrokenPipe, io::ErrorKind::TimedOut]
                } else {
                    // Any RST of ours was for a timeout.
                    &[io::ErrorKind::TimedOut]
                };
                // A connection that had ended by a FIN before it broke
                // reports a broken pipe.
                let fin_first = matches!(c.end, Some(Ok(()))) && kind == io::ErrorKind::BrokenPipe;
                assert!(expected.contains(&kind) || fin_first, "{name}: write failed with {kind:?}");
                if kind == io::ErrorKind::TimedOut {
                    let now = self.now();
                    let silent = self.silent_for(&self.conns[i], now);
                    assert!(
                        silent.is_some_and(|d| d + SLACK >= TCP_TIMEOUT),
                        "{name} timed out, silent for {silent:?}"
                    );
                }
            }
            Poll::Pending => {}
        }
        self.settle();
    }

    /// We half-close a connection.
    fn close_write(&mut self, i: usize) {
        let c = &mut self.conns[i];
        c.stream.as_ref().unwrap().close_write();
        c.write_closed = true;
        self.settle();
    }

    /// We abort a connection.
    fn abort(&mut self, i: usize) {
        let c = &mut self.conns[i];
        c.stream.as_ref().unwrap().abort();
        if !c.broken() && c.end.is_none() {
            c.aborted = true;
        }
        self.settle();
    }

    /// We drop a connection.
    fn drop_stream(&mut self, i: usize) {
        let now = self.now();
        let _guard = self.rt.enter();
        self.conns[i].stream = None;
        self.conns[i].dropped = Some(now);
        self.settle();
    }

    /// The stack shuts down.
    fn close(&mut self) {
        self.stack.close();
        self.closed = true;
        for c in &mut self.conns {
            if !c.broken() {
                c.aborted = true;
            }
        }
        self.settle();
        for c in &self.conns {
            assert!(c.dial.is_none(), "{}: dial still pending after the stack closed", c.name());
        }
    }

    /// Whether stream `i` has nothing left to send.
    fn drained(&self, i: usize) -> bool {
        let c = &self.conns[i];
        c.broken() || (c.talking() && c.got == c.written && c.write_closed == c.got_fin)
    }

    /// Waits for stream `i` to drain, which should be at once.
    fn drain_stream(&mut self, i: usize) {
        let start = self.now();
        let s = self.conns[i].stream.take().unwrap();
        let drained = self.run_for(s.drain(Duration::from_secs(5)), Duration::from_secs(1));
        self.conns[i].stream = Some(s);
        let took = self.now() - start;
        assert!(drained.is_some(), "{}: drain took {took:?}", self.conns[i].name());
        self.settle();
    }

    /// Whether the model knows connection `i` to be finished.
    fn finished(&self, i: usize, now: tokio::time::Instant) -> bool {
        let c = &self.conns[i];
        c.broken()
            || (c.fin && c.fin_acked)
            || (c.dial.is_none() && c.key.is_none())
            || self.silent_for(c, now).is_some_and(|d| d > TCP_TIMEOUT + SLACK)
            || (!c.dialed && !c.established && now - c.started > ACCEPT_TIMEOUT + SLACK)
    }

    /// Waits for the stack to drain, which should be at once.
    fn drain_tcp(&mut self) {
        let start = self.now();
        let drained = self.run_for(self.stack.drain_tcp(Duration::from_secs(5)), Duration::from_secs(1));
        let took = self.now() - start;
        assert_eq!(drained, Some(true), "drain_tcp after {took:?}");
        self.settle();
    }
}

#[hegel::state_machine]
impl Net {
    /// A remote opens a connection to us, on a 4-tuple that's free as far
    /// as it knows.
    #[rule]
    fn open_rule(&mut self, tc: TestCase) {
        let port = SOURCE_PORTS[tc.draw(gs::integers::<usize>().max_value(SOURCE_PORTS.len() - 1))];
        let key = (SocketAddr::new(local_ip(), SERVICE), SocketAddr::new(remote_ip(), port));
        tc.assume(self.live.get(&key).is_none_or(|&i| self.conns[i].over()));
        self.open(port);
    }

    #[rule]
    fn complete_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| !c.dialed && c.stack_isn.is_some() && !c.established && c.talking());
        self.complete(i);
    }

    #[rule]
    fn dial_rule(&mut self, _: TestCase) {
        self.dial();
    }

    #[rule]
    fn answer_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.dialed && c.stack_isn.is_some() && c.answered.is_none() && c.talking());
        self.answer(i);
    }

    #[rule]
    fn refuse_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.dialed && c.stack_isn.is_some() && c.answered.is_none() && c.talking());
        self.refuse(i);
    }

    #[rule]
    fn cancel_dial_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.dial.is_some());
        self.cancel_dial(i);
    }

    /// An established remote sends some data.
    #[rule]
    fn data_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.established && c.talking() && !c.fin);
        let payload = tc.draw(gs::binary().min_size(1).max_size(16));
        self.remote_send(i, TcpControl::Psh, &payload);
    }

    /// An established remote closes its side.
    #[rule]
    fn fin_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.established && c.talking() && !c.fin);
        self.remote_send(i, TcpControl::Fin, &[]);
    }

    /// A remote resets its connection.
    #[rule]
    fn reset_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.established && c.talking());
        self.remote_send(i, TcpControl::Rst, &[]);
    }

    #[rule]
    fn vanish_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.key.is_some() && c.talking());
        self.vanish(i);
    }

    #[rule]
    fn write_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.stream.is_some());
        let data = tc.draw(gs::binary().min_size(1).max_size(64));
        self.write(i, &data);
    }

    #[rule]
    fn close_write_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.stream.is_some());
        self.close_write(i);
    }

    #[rule]
    fn abort_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.stream.is_some());
        self.abort(i);
    }

    #[rule]
    fn drop_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.stream.is_some());
        self.drop_stream(i);
    }

    /// Rare, since it ends the story.
    #[rule(weight = 0.2)]
    fn close_rule(&mut self, tc: TestCase) {
        tc.assume(!self.closed);
        self.close();
    }

    /// Time passes.
    #[rule(weight = 2.0)]
    fn pass_time(&mut self, tc: TestCase) {
        let secs = [1, 5, 31, 125][tc.draw(gs::integers::<usize>().max_value(3))];
        self.wait(Duration::from_secs(secs));
    }

    /// Waiting for a stream to drain returns at once when it has nothing
    /// left to send.
    #[rule]
    fn drain_stream_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.stream.is_some());
        tc.assume(self.drained(i));
        self.drain_stream(i);
    }

    /// Waiting for the stack to drain returns at once when every
    /// connection has finished.
    #[rule]
    fn drain_tcp_rule(&mut self, tc: TestCase) {
        let now = self.now();
        tc.assume((0..self.conns.len()).all(|i| self.finished(i, now)));
        self.drain_tcp();
    }

    /// Each stream reads exactly what its remote sent, then a clean end
    /// of stream if the remote closed the connection, or the error for
    /// how it broke.
    #[invariant(always_run)]
    fn reads_match_what_was_sent(&self, _: TestCase) {
        let now = self.now();
        for c in &self.conns {
            let name = c.name();
            assert!(c.sent.starts_with(&c.received), "{name} read {:?}, but the remote sent {:?}", c.received, c.sent);
            match c.end {
                Some(Ok(())) => {
                    assert!(c.fin, "{name} read EOF, but the remote sent no FIN");
                    assert_eq!(c.received, c.sent, "{name} read EOF before all its data");
                }
                Some(Err(kind)) => {
                    let ok = match kind {
                        io::ErrorKind::ConnectionReset => c.reset,
                        io::ErrorKind::ConnectionAborted => c.aborted,
                        io::ErrorKind::TimedOut => {
                            self.silent_for(c, now).is_some_and(|d| d + SLACK >= TCP_TIMEOUT) && !c.reset && !c.aborted
                        }
                        _ => false,
                    };
                    assert!(ok, "{name} read {kind:?} (reset {}, aborted {}, dead {:?})", c.reset, c.aborted, c.dead);
                }
                None if c.stream.is_some() && c.fin && !c.broken() => {
                    panic!("{name}: the remote sent a FIN, but reads don't end")
                }
                None if c.stream.is_some() && (c.reset || c.aborted) => panic!("{name} broke, but reads don't fail"),
                None => {}
            }
        }
    }

    /// Dials succeed if the remote answered, and fail the right way if not.
    #[invariant(always_run)]
    fn dials_end_right(&self, _: TestCase) {
        for c in self.conns.iter().filter(|c| c.dialed) {
            let name = c.name();
            match c.dial_result {
                Some(Ok(())) => assert!(c.answered.is_some(), "{name} connected, but the remote never answered"),
                Some(Err(io::ErrorKind::ConnectionRefused)) => assert!(c.reset, "{name} was refused"),
                Some(Err(io::ErrorKind::ConnectionAborted)) => assert!(self.closed || c.aborted, "{name} was aborted"),
                Some(Err(io::ErrorKind::TimedOut)) => {
                    let waited = c.answered.unwrap_or_else(|| self.now()) - c.started;
                    assert!(waited + SLACK >= TCP_TIMEOUT, "{name} timed out after {waited:?}");
                }
                Some(Err(kind)) => panic!("{name} failed with {kind:?}"),
                None => {}
            }
        }
    }

    /// The stack gives up on a remote that went silent (telling it, if
    /// it was only slow to finish the handshake), and not on one that
    /// didn't.
    #[invariant(always_run)]
    fn silent_remotes_time_out(&self, _: TestCase) {
        if self.closed {
            return;
        }
        let now = self.now();
        let st = self.stack.shared.lock();
        for c in &self.conns {
            let stalled = !c.dialed && c.stack_isn.is_some() && !c.established && c.talking();
            if stalled && now - c.started > ACCEPT_TIMEOUT + SLACK {
                panic!("{}: the stack gave up on the handshake without a RST", c.name());
            }
            let Some(h) = self.socket_locked(c, &st) else { continue };
            let state = st.sockets.get::<tcp::Socket>(h).state();
            let silent = self.silent_for(c, now);
            if silent.is_some_and(|d| d > TCP_TIMEOUT + SLACK) {
                assert!(
                    matches!(state, tcp::State::Closed | tcp::State::TimeWait | tcp::State::Listen),
                    "{}: the remote has been silent for {silent:?}, but the socket is {state}",
                    c.name()
                );
            }
            if c.established && silent.is_none() && !c.broken() && !c.over() {
                let end = st.end(h);
                assert_ne!(end, Some(End::TimedOut), "{}: a live remote timed out ({state})", c.name());
            }
        }
    }

    /// Every socket has exactly one flow and is held by a stream, a dial,
    /// the handshake or the orphan list; orphans that finished closing
    /// are reaped, and the rest within a while.
    #[invariant(always_run)]
    fn bookkeeping(&self, _: TestCase) {
        if self.closed {
            return;
        }
        let now = self.now();
        let mut st = self.stack.shared.lock();
        let held: HashSet<SocketHandle> = self.conns.iter().filter_map(|c| Some(c.stream.as_ref()?.handle)).collect();
        let live: HashSet<SocketHandle> = st.sockets.iter().map(|(h, _)| h).collect();
        let orphans: HashSet<SocketHandle> = st.orphans.iter().copied().collect();
        assert_eq!(orphans.len(), st.orphans.len(), "a socket was orphaned twice");
        let dials = self.conns.iter().filter(|c| c.dial.is_some()).count();
        let mut unowned = 0;
        for (h, s) in st.sockets.iter() {
            let flows: Vec<_> = st.tuples.iter().filter(|&(_, &v)| v == h).map(|(k, _)| k).collect();
            let state = tcp::Socket::downcast(s).unwrap().state();
            // A closed socket a stream holds may have given its flow up.
            let flowless = flows.is_empty() && state == tcp::State::Closed && held.contains(&h);
            assert!(flows.len() == 1 || flowless, "{state} socket {h} has flows {flows:?}");
            assert!(!(held.contains(&h) && orphans.contains(&h)), "held socket for {flows:?} is an orphan");
            if orphans.contains(&h) {
                assert!(
                    !matches!(state, tcp::State::Closed | tcp::State::TimeWait),
                    "{state} orphan for {flows:?} is left over"
                );
            } else if !held.contains(&h) && !st.accepting.contains_key(&h) {
                unowned += 1;
            }
        }
        assert!(unowned <= dials, "{unowned} sockets belong to nobody");
        assert!(st.tuples.values().all(|h| live.contains(h)), "a flow's socket was removed");
        assert!(st.ends.keys().all(|h| live.contains(h)), "a removed socket's end is kept");
        assert!(st.orphans.iter().all(|h| live.contains(h)), "a removed socket is an orphan");
        let t = st.now();
        let State { iface, sockets, .. } = &mut *st;
        // Timers may have just come due, but nothing is overdue, and no
        // socket has something to send whatever the time.
        let at = iface.poll_at(t, sockets);
        let overdue =
            at.is_some_and(|a| a == smoltcp::time::Instant::ZERO || a + Duration::from_millis(100).into() < t);
        assert!(!overdue, "the stack is settled, but wants polling at {at:?} (now {t})");
        drop(st);
        for c in &self.conns {
            let Some(dropped) = c.dropped else { continue };
            let Some(key) = c.key else { continue };
            if !self.live.get(&key).is_some_and(|&i| std::ptr::eq(&self.conns[i], c)) {
                continue;
            }
            let lingering = self.stack.shared.lock().tuples.contains_key(&key);
            assert!(
                !(lingering && now - dropped > TCP_TIMEOUT + SLACK),
                "{} was dropped {:?} ago, but its socket lingers",
                c.name(),
                now - dropped
            );
        }
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        // A failed check may have poisoned the lock; let the streams go.
        self.stack.shared.state.clear_poison();
    }
}

impl Net {
    fn socket_locked(&self, c: &Conn, st: &State) -> Option<SocketHandle> {
        if let Some(s) = &c.stream {
            return Some(s.handle);
        }
        let key = c.key?;
        let latest = self.live.get(&key).is_some_and(|&i| std::ptr::eq(&self.conns[i], c));
        if latest { st.tuples.get(&key).copied() } else { None }
    }
}

#[hegel::test(test_cases = 300)]
#[ignore = "known bugs, fixed in the commits that follow"]
fn tcp_lifecycle_state_machine(tc: TestCase) {
    hegel::stateful::machine(Net::new()).steps(30).run(tc);
}

/// A dial on a closed stack fails at once: its poll loop has returned,
/// so nothing would ever send the SYN.
#[test]
#[ignore = "known bug: a dial on a closed stack hangs"]
fn dial_after_close_fails() {
    let net = Net::new();
    net.stack.close();
    let stack = net.stack.clone();
    let dial = stack.dial_tcp(local_ip(), SocketAddr::new(remote_ip(), DIALED));
    let r = net.rt.block_on(async { tokio::time::timeout(Duration::from_secs(1), dial).await });
    assert_eq!(r.expect("dial hangs").unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
}

/// A SYN whose policy decision races with closing the stack opens no
/// connection on the closed stack.
#[test]
#[ignore = "known bug: a SYN racing Stack::close opens a socket on the closed stack"]
fn syn_racing_close_opens_nothing() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap();
    let _guard = rt.enter();
    let closing: Arc<Mutex<Option<Stack>>> = Arc::default();
    let c = closing.clone();
    let policy: TcpPolicy = Arc::new(move |_, _| {
        if let Some(s) = c.lock().unwrap().take() {
            s.close();
        }
        TcpDecision::Accept(Box::new(|_| panic!("accepted on a closed stack")))
    });
    let stack = Stack::new(
        StackConfig { addrs: vec![local_ip()], any_ip: false, mtu: 1280 },
        Arc::new(|_| {}),
        Some(policy),
        None,
    );
    *closing.lock().unwrap() = Some(stack.clone());
    let (local, remote) = (SocketAddr::new(local_ip(), SERVICE), SocketAddr::new(remote_ip(), SOURCE_PORTS[0]));
    stack.inject(segment(remote, local, TcpControl::Syn, TcpSeqNumber(1000), None, &[]));
    let st = stack.shared.lock();
    assert_eq!(st.sockets.iter().count(), 0, "a socket was opened on the closed stack");
}

/// An idle connection to a live peer stays up: smoltcp's timeout counts
/// from the last segment received, even with nothing waiting on an
/// answer, so without keep-alives it was reset after TCP_TIMEOUT.
#[test]
#[ignore = "known bug: an idle connection times out"]
fn idle_connection_stays_up() {
    let mut net = Net::new();
    let (dialed, accepted) = (net.dial(), net.open(SOURCE_PORTS[0]));
    net.answer(dialed);
    net.complete(accepted);
    net.wait(TCP_TIMEOUT * 2);
    for i in [dialed, accepted] {
        let c = &net.conns[i];
        assert_eq!((c.end, c.got_rst), (None, false), "{} ended", c.name());
        net.write(i, b"still here");
        assert_eq!(net.conns[i].got, b"still here", "{} lost a write", net.conns[i].name());
    }
}

/// A remote that reset a connection may reuse its 4-tuple while our
/// stream for the old connection is still held: the new SYN went to the
/// old, closed socket, bypassing the policy, and was refused.
#[test]
#[ignore = "known bug: a SYN on a finished connection's 4-tuple is refused"]
fn reused_tuple_reaches_the_policy() {
    let mut net = Net::new();
    let first = net.open(SOURCE_PORTS[0]);
    net.complete(first);
    net.remote_send(first, TcpControl::Rst, &[]);
    assert!(net.conns[first].stream.is_some());
    let second = net.open(SOURCE_PORTS[0]);
    net.complete(second);
    net.remote_send(second, TcpControl::Psh, b"hello");
    assert_eq!(net.conns[second].received, b"hello");
    assert_eq!(net.conns[first].end, Some(Err(io::ErrorKind::ConnectionReset)));
}

/// Draining a connection that was aborted (or reset) with data still
/// unacknowledged returns at once: the data stays queued in the closed
/// socket, but will never be sent. drain and drain_tcp waited it out.
#[test]
#[ignore = "known bug: drains wait on data an aborted connection will never send"]
fn aborted_connection_is_drained() {
    let mut net = Net::new();
    let i = net.dial();
    net.answer(i);
    net.vanish(i);
    net.write(i, b"unacked");
    net.abort(i);
    net.drain_stream(i);
    net.drain_tcp();
}

/// A dropped connection whose peer acks our FIN but never sends its own
/// is aborted after a while, instead of sitting in FIN-WAIT-2 forever.
#[test]
#[ignore = "known bug: a dropped connection can sit in FIN-WAIT-2 forever"]
fn orphan_in_fin_wait_2_is_reaped() {
    let mut net = Net::new();
    let i = net.dial();
    net.answer(i);
    net.drop_stream(i);
    for _ in 0..3 {
        net.wait(TCP_TIMEOUT / 2);
        net.remote_send(i, TcpControl::Psh, b"still here");
    }
    let st = net.stack.shared.lock();
    let states: Vec<_> = st.tcp_sockets().map(|s| s.state()).collect();
    assert!(states.is_empty(), "sockets left: {states:?}");
}

/// A handshake that times out is aborted with a RST to the peer: the
/// socket was reaped in the same pass that aborted it, before the RST
/// went out.
#[test]
#[ignore = "known bug: a stalled handshake is reaped without a RST"]
fn stalled_handshake_is_reset() {
    let mut net = Net::new();
    let i = net.open(SOURCE_PORTS[0]);
    net.wait(ACCEPT_TIMEOUT + SLACK);
    assert!(net.conns[i].got_rst, "the peer wasn't told");
}

/// A remote may reuse a 4-tuple as soon as both sides have closed, while
/// our socket for it is in TIME-WAIT and its stream still held.
#[test]
#[ignore = "known bug: a SYN on a finished connection's 4-tuple is refused"]
fn tuple_reused_after_time_wait() {
    let mut net = Net::new();
    let first = net.open(SOURCE_PORTS[0]);
    net.complete(first);
    net.close_write(first);
    net.remote_send(first, TcpControl::Fin, &[]);
    assert!(net.conns[first].over() && net.conns[first].stream.is_some());
    let second = net.open(SOURCE_PORTS[0]);
    net.complete(second);
    net.remote_send(second, TcpControl::Psh, b"hello");
    assert_eq!(net.conns[second].received, b"hello");
}

/// Waiting for a busy connection to drain doesn't spin: drain_tcp woke
/// the poll loop after every poll, so the two ran back to back until
/// the deadline.
#[test]
#[ignore = "known bug: drain_tcp keeps the poll loop spinning"]
fn drain_tcp_waits_quietly() {
    let mut net = Net::new();
    let i = net.dial();
    net.answer(i);
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (shared, p) = (net.stack.shared.clone(), polls.clone());
    let counter = net.rt.spawn(async move {
        loop {
            shared.polled.notified().await;
            p.fetch_add(1, Ordering::Relaxed);
        }
    });
    let drained = net.run_for(net.stack.drain_tcp(Duration::from_millis(500)), Duration::from_secs(1));
    counter.abort();
    assert_eq!(drained, Some(false), "an open connection drained");
    let n = polls.load(Ordering::Relaxed);
    assert!(n < 20, "{n} polls in half a second");
}
