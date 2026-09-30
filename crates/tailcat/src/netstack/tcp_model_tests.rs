//! Model-based tests of TCP connection lifecycles, driven by Hegel: the
//! stack dials out and accepts connections, and a scripted remote answers
//! or refuses its SYNs, sends data, FINs and RSTs at any time, or goes
//! silent for good, while our side writes, half-closes, aborts and drops
//! streams, closes the stack, and lets time pass on a paused clock. Every
//! stream is checked against what the remote sent and how the connection
//! ended, and the stack's flow table against its sockets.

use std::collections::HashSet;
use std::future::poll_fn;
use std::mem;
use std::pin::pin;
use std::ptr;
use std::sync::atomic::AtomicUsize;
use std::sync::{OnceLock, mpsc as std_mpsc};
use std::task::Waker;
use std::thread;

use hegel::TestCase;
use hegel::generators as gs;
use smoltcp::wire::{TcpControl, TcpSeqNumber};
use tokio::runtime::{self, Runtime};
use tokio::task::yield_now;
use tokio::time::{self, Instant};

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

/// The 4-tuple of a connection to us from the remote's `port`.
fn inbound(port: u16) -> FlowKey {
    (SocketAddr::new(local_ip(), SERVICE), SocketAddr::new(remote_ip(), port))
}

/// A current-thread runtime on a paused clock.
fn paused_runtime() -> Runtime {
    runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap()
}

fn stack_config() -> StackConfig {
    StackConfig { addrs: vec![local_ip()], any_ip: false, mtu: 1280 }
}

/// A policy that accepts every connection, handing its stream to `accepted`.
fn accept_into(accepted: Arc<Mutex<Vec<TcpStream>>>) -> TcpPolicy {
    Arc::new(move |_src, _dst| {
        let accepted = accepted.clone();
        TcpDecision::Accept(Box::new(move |s| accepted.lock().unwrap().push(s)))
    })
}

/// Polls `f` once, with a waker that does nothing.
fn poll_once<F: Future + ?Sized>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

/// Draws one of `items`, or rejects the rule if there are none.
fn draw_from<T: Copy>(tc: &TestCase, items: &[T]) -> T {
    tc.assume(!items.is_empty());
    items[tc.draw(gs::integers::<usize>().max_value(items.len() - 1))]
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
    dead: Option<Instant>,
    /// When the stack started trying to reach the remote (its dial), and
    /// when the remote answered.
    started: Instant,
    answered: Option<Instant>,
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
    dropped: Option<Instant>,
    received: Vec<u8>,
    end: Option<Result<(), io::ErrorKind>>,
}

impl Conn {
    fn new(remote: SocketAddr, dialed: bool, isn: TcpSeqNumber, now: Instant) -> Conn {
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

    /// Whether the remote got our SYN-ACK, and could still ack it.
    fn awaiting_ack(&self) -> bool {
        !self.dialed && self.stack_isn.is_some() && !self.established && self.talking()
    }

    /// Whether the remote got our SYN, and could still answer it.
    fn awaiting_answer(&self) -> bool {
        self.dialed && self.stack_isn.is_some() && self.answered.is_none() && self.talking()
    }

    /// Whether the remote can send data or a FIN.
    fn can_send(&self) -> bool {
        self.established && self.talking() && !self.fin
    }

    /// Whether an accepted connection's handshake has had more than its
    /// time.
    fn handshake_overdue(&self, now: Instant) -> bool {
        now - self.started > ACCEPT_TIMEOUT + SLACK
    }

    /// Whether the remote was silent long enough for the stack to give up
    /// on the connection: it went away, or never answered our SYN.
    fn silent_for(&self, now: Instant) -> Option<Duration> {
        if let Some(t) = self.dead {
            return Some(now - t);
        }
        if self.dialed && self.answered.is_none() && !self.reset {
            return Some(now - self.started);
        }
        None
    }

    /// Whether the remote was silent long enough for the stack to time
    /// the connection out.
    fn may_have_timed_out(&self, now: Instant) -> bool {
        self.silent_for(now).is_some_and(|d| d + SLACK >= TCP_TIMEOUT)
    }

    /// Whether the stack should have timed the connection out by now.
    fn must_have_timed_out(&self, now: Instant) -> bool {
        self.silent_for(now).is_some_and(|d| d > TCP_TIMEOUT + SLACK)
    }

    /// Whether a RST from the stack is for this connection, as a real
    /// peer would check.
    fn is_our_rst(&self, tcp: &TcpPacket<&[u8]>) -> bool {
        match self.ack() {
            None => tcp.ack() && tcp.ack_number() == self.isn + 1,
            Some(ack) => tcp.seq_number() == ack,
        }
    }

    /// The errors a write may fail with, given how the connection ended.
    fn write_errors(&self) -> &'static [io::ErrorKind] {
        if self.aborted {
            &[io::ErrorKind::ConnectionAborted]
        } else if self.reset {
            &[io::ErrorKind::ConnectionReset]
        } else if self.write_closed {
            &[io::ErrorKind::BrokenPipe, io::ErrorKind::TimedOut]
        } else {
            // Any RST of ours was for a timeout.
            &[io::ErrorKind::TimedOut]
        }
    }

    /// Whether a read failing with `kind` fits how the connection ended.
    fn read_error_fits(&self, kind: io::ErrorKind, now: Instant) -> bool {
        match kind {
            io::ErrorKind::ConnectionReset => self.reset,
            io::ErrorKind::ConnectionAborted => self.aborted,
            io::ErrorKind::TimedOut => self.may_have_timed_out(now) && !self.reset && !self.aborted,
            _ => false,
        }
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
    rt: Runtime,
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
        let rt = paused_runtime();
        let _guard = rt.enter();
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let accepted: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        let o = out.clone();
        let emit: Output = Arc::new(move |p| o.lock().unwrap().push(p));
        let stack = Stack::new(stack_config(), emit, Some(accept_into(accepted.clone())), None);
        Net { rt, stack, out, accepted, conns: Vec::new(), live: HashMap::new(), next_isn: 1000, closed: false }
    }

    /// Feeds a segment to the stack, on the paused clock.
    fn inject(&self, pkt: Vec<u8>) {
        let _guard = self.rt.enter();
        self.stack.inject(pkt);
    }

    fn now(&self) -> Instant {
        self.rt.block_on(async { Instant::now() })
    }

    fn isn(&mut self) -> TcpSeqNumber {
        self.next_isn += 100_000;
        TcpSeqNumber(self.next_isn)
    }

    /// Whether `c` is the latest connection on its 4-tuple.
    fn is_latest(&self, c: &Conn) -> bool {
        c.key.and_then(|key| self.live.get(&key)).is_some_and(|&i| ptr::eq(&self.conns[i], c))
    }

    /// Lets the runtime's tasks, the stack's poll loop among them, run.
    fn let_tasks_run(&self) {
        self.rt.block_on(async {
            for _ in 0..16 {
                yield_now().await;
            }
        });
    }

    /// Lets the stack run until it's quiet: the remotes see what it sent
    /// (acking what an established, live remote would), our side takes
    /// its dials' results and the handler's connections, and reads what
    /// they have.
    fn settle(&mut self) {
        let rt = self.rt.handle().clone();
        let _guard = rt.enter();
        for _ in 0..64 {
            self.let_tasks_run();
            let dialed = self.poll_dials();
            let out = mem::take(&mut *self.out.lock().unwrap());
            let accepted = mem::take(&mut *self.accepted.lock().unwrap());
            if out.is_empty() && accepted.is_empty() && !dialed {
                break;
            }
            out.into_iter().for_each(|p| self.deliver(p));
            accepted.into_iter().for_each(|s| self.hand_off(s));
        }
        self.conns.iter_mut().for_each(Conn::read);
    }

    /// The handler passes us a connection it accepted.
    fn hand_off(&mut self, s: TcpStream) {
        let key = (s.local_addr(), s.peer_addr());
        let Some(&i) = self.live.get(&key) else { panic!("{s:?} was accepted, but never connected") };
        let c = &mut self.conns[i];
        assert!(!c.dialed && !c.handed_off, "{} was handed off twice", c.name());
        c.handed_off = true;
        c.stream = Some(s);
    }

    /// Polls the dials in progress, and says whether any finished.
    fn poll_dials(&mut self) -> bool {
        let mut done = false;
        for c in &mut self.conns {
            let Some(d) = &mut c.dial else { continue };
            let Poll::Ready(r) = poll_once(d.as_mut()) else { continue };
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

    /// The connection a segment from the stack on `key` is for: the latest
    /// on its 4-tuple, or, for a dial's first SYN, the dial it starts.
    fn conn_for(&mut self, key: FlowKey, tcp: &TcpPacket<&[u8]>) -> Option<usize> {
        let latest = self.live.get(&key).copied();
        let retransmitted = latest.is_some_and(|i| self.conns[i].stack_isn == Some(tcp.seq_number()));
        if !tcp.syn() || tcp.ack() || retransmitted {
            return latest;
        }
        let (_, remote) = key;
        let i = self.conns.iter().position(|c| c.dialed && c.key.is_none() && c.remote == remote)?;
        self.conns[i].key = Some(key);
        self.live.insert(key, i);
        Some(i)
    }

    /// A segment from the stack reaches its remote.
    fn deliver(&mut self, p: Vec<u8>) {
        let ip = Ipv6Packet::new_checked(&p[..]).unwrap();
        let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else { return };
        let local = SocketAddr::new(IpAddr::from(ip.src_addr()), tcp.src_port());
        let remote = SocketAddr::new(IpAddr::from(ip.dst_addr()), tcp.dst_port());
        let Some(i) = self.conn_for((local, remote), &tcp) else { return };
        let c = &mut self.conns[i];
        if tcp.rst() {
            // Like a real peer, ignore RSTs that aren't for this connection.
            c.got_rst |= c.is_our_rst(&tcp);
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

    /// Picks a connection whose index satisfies `f`, or rejects the rule.
    fn pick_where(&self, tc: &TestCase, f: impl Fn(usize) -> bool) -> usize {
        let ok: Vec<usize> = (0..self.conns.len()).filter(|&i| f(i)).collect();
        draw_from(tc, &ok)
    }

    /// Picks a connection that satisfies `f`, or rejects the rule.
    fn pick(&self, tc: &TestCase, f: impl Fn(&Conn) -> bool) -> usize {
        self.pick_where(tc, |i| f(&self.conns[i]))
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
        while self.now() < end {
            let step = (end - self.now()).min(Duration::from_secs(1));
            // advance rather than sleep: a busy poll loop would keep a
            // paused clock from moving on by itself.
            self.rt.block_on(time::advance(step));
            self.settle();
        }
    }

    /// Runs `f` for up to `limit`, stepping the paused clock.
    fn run_for<F: Future>(&self, f: F, limit: Duration) -> Option<F::Output> {
        self.rt.block_on(async {
            let mut f = pin!(f);
            let end = Instant::now() + limit;
            loop {
                if let Poll::Ready(v) = poll_fn(|cx| Poll::Ready(f.as_mut().poll(cx))).await {
                    return Some(v);
                }
                if Instant::now() >= end {
                    return None;
                }
                time::advance(Duration::from_millis(10)).await;
            }
        })
    }
}

/// The steps the state machine takes, for directed tests too.
impl Net {
    /// A remote opens a connection to us from `port`, and gets a SYN-ACK
    /// unless the stack is closed.
    fn open(&mut self, port: u16) -> usize {
        let key = inbound(port);
        let (local, remote) = key;
        let (isn, now) = (self.isn(), self.now());
        let mut c = Conn::new(remote, false, isn, now);
        c.key = Some(key);
        c.answered = Some(now);
        self.conns.push(c);
        let i = self.conns.len() - 1;
        self.live.insert(key, i);
        self.inject(segment(remote, local, TcpControl::Syn, isn, None, &[]));
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
        let polled = {
            let _guard = self.rt.enter();
            poll_once(d.as_mut())
        };
        match polled {
            Poll::Ready(Ok(s)) => panic!("dial connected at once: {s:?}"),
            Poll::Ready(Err(e)) => c.dial_result = Some(Err(e.kind())),
            Poll::Pending => c.dial = Some(d),
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

    /// The remote sends `data` on connection `i`.
    fn remote_data(&mut self, i: usize, data: &[u8]) {
        self.remote_send(i, TcpControl::Psh, data);
    }

    /// The remote closes its side of connection `i`.
    fn remote_fin(&mut self, i: usize) {
        self.remote_send(i, TcpControl::Fin, &[]);
    }

    /// The remote resets connection `i`.
    fn remote_reset(&mut self, i: usize) {
        self.remote_send(i, TcpControl::Rst, &[]);
    }

    /// We write `data`, and check the result.
    fn write(&mut self, i: usize, data: &[u8]) {
        let mut cx = Context::from_waker(Waker::noop());
        let c = &mut self.conns[i];
        let r = Pin::new(c.stream.as_mut().unwrap()).poll_write(&mut cx, data);
        match r {
            Poll::Ready(Ok(n)) => {
                assert!(!c.write_closed && !c.broken(), "{}: a write after it ended succeeded", c.name());
                c.written.extend_from_slice(&data[..n]);
            }
            Poll::Ready(Err(e)) => self.check_write_error(i, e.kind()),
            Poll::Pending => {}
        }
        self.settle();
    }

    /// Checks that a write on connection `i` failed the way it ended.
    fn check_write_error(&self, i: usize, kind: io::ErrorKind) {
        let c = &self.conns[i];
        let name = c.name();
        // A connection that had ended by a FIN before it broke reports a
        // broken pipe.
        let fin_first = matches!(c.end, Some(Ok(()))) && kind == io::ErrorKind::BrokenPipe;
        assert!(c.write_errors().contains(&kind) || fin_first, "{name}: write failed with {kind:?}");
        if kind == io::ErrorKind::TimedOut {
            let silent = c.silent_for(self.now());
            assert!(silent.is_some_and(|d| d + SLACK >= TCP_TIMEOUT), "{name} timed out, silent for {silent:?}");
        }
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

    /// Whether connection `i` is the latest on its 4-tuple, and our socket
    /// for it is in TIME-WAIT.
    fn time_wait(&self, i: usize) -> bool {
        let c = &self.conns[i];
        let Some(key) = c.key.filter(|_| self.is_latest(c)) else { return false };
        let st = self.stack.shared.lock();
        let in_time_wait = |&h: &SocketHandle| st.sockets.get::<tcp::Socket>(h).state() == tcp::State::TimeWait;
        st.tuples.get(&key).is_some_and(in_time_wait)
    }

    /// A delayed duplicate of connection `j`'s SYN arrives while our
    /// socket for the latest connection on its 4-tuple, `i`, is in
    /// TIME-WAIT. It starts below where `i` ended, so it's old: it opens
    /// no connection, and `i`'s socket keeps the 4-tuple.
    fn replay_syn(&mut self, i: usize, j: usize) {
        let (first, dup) = (&self.conns[i], &self.conns[j]);
        let key = first.key.unwrap();
        let (local, remote) = key;
        assert_eq!(dup.key, Some(key), "{} isn't on {}'s 4-tuple", dup.name(), first.name());
        let socket = |net: &Net| net.stack.shared.lock().tuples.get(&key).copied();
        let (before, stack_isn) = (socket(self), first.stack_isn);

        self.inject(segment(remote, local, TcpControl::Syn, dup.isn, None, &[]));
        self.settle();

        let name = self.conns[i].name();
        assert_eq!(self.conns[i].stack_isn, stack_isn, "{name}: an old SYN was answered with a SYN-ACK");
        assert_eq!(socket(self), before, "{name}: an old SYN took the 4-tuple from its TIME-WAIT socket");
        assert!(self.time_wait(i), "{name}: an old SYN ended TIME-WAIT");
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
    fn finished(&self, i: usize, now: Instant) -> bool {
        let c = &self.conns[i];
        c.broken()
            || (c.fin && c.fin_acked)
            || (c.dial.is_none() && c.key.is_none())
            || c.must_have_timed_out(now)
            || (!c.dialed && !c.established && c.handshake_overdue(now))
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

/// Composite steps, for directed tests.
impl Net {
    /// A remote opens a connection to us from `port`, and completes the
    /// handshake.
    fn accept_from(&mut self, port: u16) -> usize {
        let i = self.open(port);
        self.complete(i);
        i
    }

    /// The stack dials the remote, and it answers.
    fn dial_answered(&mut self) -> usize {
        let i = self.dial();
        self.answer(i);
        i
    }
}

#[hegel::state_machine]
impl Net {
    /// A remote opens a connection to us, on a 4-tuple that's free as far
    /// as it knows.
    #[rule]
    fn open_rule(&mut self, tc: TestCase) {
        let port = draw_from(&tc, &SOURCE_PORTS);
        tc.assume(self.live.get(&inbound(port)).is_none_or(|&i| self.conns[i].over()));
        self.open(port);
    }

    #[rule]
    fn complete_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, Conn::awaiting_ack);
        self.complete(i);
    }

    #[rule]
    fn dial_rule(&mut self, _: TestCase) {
        self.dial();
    }

    #[rule]
    fn answer_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, Conn::awaiting_answer);
        self.answer(i);
    }

    #[rule]
    fn refuse_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, Conn::awaiting_answer);
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
        let i = self.pick(&tc, Conn::can_send);
        let payload = tc.draw(gs::binary().min_size(1).max_size(16));
        self.remote_data(i, &payload);
    }

    /// An established remote closes its side.
    #[rule]
    fn fin_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, Conn::can_send);
        self.remote_fin(i);
    }

    /// A remote resets its connection.
    #[rule]
    fn reset_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.established && c.talking());
        self.remote_reset(i);
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

    /// We close a connection and the remote closes back, leaving our side
    /// in TIME-WAIT: rare as two separate steps.
    #[rule]
    fn close_both_rule(&mut self, tc: TestCase) {
        let i = self.pick(&tc, |c| c.stream.is_some() && c.can_send() && !c.write_closed);
        self.close_write(i);
        if self.conns[i].talking() {
            self.remote_fin(i);
        }
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

    /// A remote's delayed duplicate of an earlier SYN arrives, on a 4-tuple
    /// our side holds in TIME-WAIT.
    #[rule]
    fn replay_syn_rule(&mut self, tc: TestCase) {
        let i = self.pick_where(&tc, |i| self.time_wait(i));
        let j = self.pick(&tc, |c| c.key == self.conns[i].key);
        self.replay_syn(i, j);
    }

    /// Time passes.
    #[rule(weight = 2.0)]
    fn pass_time(&mut self, tc: TestCase) {
        let secs = draw_from(&tc, &[1, 5, 31, 125]);
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
                Some(Err(kind)) => assert!(
                    c.read_error_fits(kind, now),
                    "{name} read {kind:?} (reset {}, aborted {}, dead {:?})",
                    c.reset,
                    c.aborted,
                    c.dead
                ),
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
            let name = c.name();
            let stalled = c.awaiting_ack() && c.handshake_overdue(now);
            assert!(!stalled, "{name}: the stack gave up on the handshake without a RST");
            let Some(h) = self.socket_locked(c, &st) else { continue };
            let state = st.sockets.get::<tcp::Socket>(h).state();
            if c.must_have_timed_out(now) {
                let silent = c.silent_for(now);
                assert!(
                    matches!(state, tcp::State::Closed | tcp::State::TimeWait | tcp::State::Listen),
                    "{name}: the remote has been silent for {silent:?}, but the socket is {state}"
                );
            }
            let alive = c.established && c.silent_for(now).is_none() && !c.broken() && !c.over();
            if alive {
                assert_ne!(st.end(h), Some(End::TimedOut), "{name}: a live remote timed out ({state})");
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
        self.check_socket_owners();
        self.check_nothing_overdue();
        self.check_dropped_sockets_reaped(now);
    }
}

/// The parts of the `bookkeeping` invariant.
impl Net {
    /// Every socket has exactly one flow and one owner, and removed
    /// sockets leave nothing behind.
    fn check_socket_owners(&self) {
        let st = self.stack.shared.lock();
        let held: HashSet<SocketHandle> = self.conns.iter().filter_map(|c| Some(c.stream.as_ref()?.handle)).collect();
        let live: HashSet<SocketHandle> = st.sockets.iter().map(|(h, _)| h).collect();
        let orphans: HashSet<SocketHandle> = st.orphans.iter().map(|&(h, _)| h).collect();
        assert_eq!(orphans.len(), st.orphans.len(), "a socket was orphaned twice");
        for (h, s) in st.sockets.iter() {
            let flows: Vec<_> = st.tuples.iter().filter(|&(_, &v)| v == h).map(|(k, _)| k).collect();
            let state = tcp::Socket::downcast(s).unwrap().state();
            let (is_held, is_orphan) = (held.contains(&h), orphans.contains(&h));
            // A closed socket a stream holds may have given its flow up.
            let flowless = flows.is_empty() && state == tcp::State::Closed && is_held;
            assert!(flows.len() == 1 || flowless, "{state} socket {h} has flows {flows:?}");
            assert!(!(is_held && is_orphan), "held socket for {flows:?} is an orphan");
            let reapable = matches!(state, tcp::State::Closed | tcp::State::TimeWait);
            assert!(!(is_orphan && reapable), "{state} orphan for {flows:?} is left over");
        }
        let dials = self.conns.iter().filter(|c| c.dial.is_some()).count();
        let owned = |h: &SocketHandle| held.contains(h) || orphans.contains(h) || st.accepting.contains_key(h);
        let unowned = live.iter().filter(|h| !owned(h)).count();
        assert!(unowned <= dials, "{unowned} sockets belong to nobody");
        assert!(st.tuples.values().all(|h| live.contains(h)), "a flow's socket was removed");
        assert!(st.ends.keys().all(|h| live.contains(h)), "a removed socket's end is kept");
        assert!(st.fins.keys().all(|h| live.contains(h)), "a removed socket's FIN is kept");
        assert!(st.orphans.iter().all(|(h, _)| live.contains(h)), "a removed socket is an orphan");
    }

    /// Timers may have just come due, but nothing is overdue, and no
    /// socket has something to send whatever the time.
    fn check_nothing_overdue(&self) {
        let mut st = self.stack.shared.lock();
        let t = st.now();
        let State { iface, sockets, .. } = &mut *st;
        let at = iface.poll_at(t, sockets);
        let overdue =
            at.is_some_and(|a| a == smoltcp::time::Instant::ZERO || a + Duration::from_millis(100).into() < t);
        assert!(!overdue, "the stack is settled, but wants polling at {at:?} (now {t})");
    }

    /// A dropped connection's socket is gone within a while.
    fn check_dropped_sockets_reaped(&self, now: Instant) {
        for c in self.conns.iter().filter(|c| self.is_latest(c)) {
            let (Some(dropped), Some(key)) = (c.dropped, c.key) else { continue };
            let lingering = self.stack.shared.lock().tuples.contains_key(&key);
            let since = now - dropped;
            let overdue = lingering && since > TCP_TIMEOUT + SLACK;
            assert!(!overdue, "{} was dropped {since:?} ago, but its socket lingers", c.name());
        }
    }

    fn socket_locked(&self, c: &Conn, st: &State) -> Option<SocketHandle> {
        if let Some(s) = &c.stream {
            return Some(s.handle);
        }
        if !self.is_latest(c) {
            return None;
        }
        st.tuples.get(&c.key?).copied()
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        // A failed check may have poisoned the lock; let the streams go.
        self.stack.shared.state.clear_poison();
    }
}

#[hegel::test(test_cases = 300)]
fn tcp_lifecycle_state_machine(tc: TestCase) {
    hegel::stateful::machine(Net::new()).steps(30).run(tc);
}

/// A dial on a closed stack fails at once: its poll loop has returned,
/// so nothing would ever send the SYN.
#[test]
fn dial_after_close_fails() {
    let net = Net::new();
    net.stack.close();

    let dial = net.stack.dial_tcp(local_ip(), SocketAddr::new(remote_ip(), DIALED));
    let r = net.rt.block_on(async { time::timeout(Duration::from_secs(1), dial).await });

    let err = r.expect("dial hangs").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
}

/// A SYN whose policy decision races with closing the stack opens no
/// connection on the closed stack.
#[test]
fn syn_racing_close_opens_nothing() {
    let rt = paused_runtime();
    let _guard = rt.enter();
    let closing: Arc<Mutex<Option<Stack>>> = Arc::default();
    let c = closing.clone();
    let policy: TcpPolicy = Arc::new(move |_, _| {
        if let Some(s) = c.lock().unwrap().take() {
            s.close();
        }
        TcpDecision::Accept(Box::new(|_| panic!("accepted on a closed stack")))
    });
    let stack = Stack::new(stack_config(), Arc::new(|_| {}), Some(policy), None);
    *closing.lock().unwrap() = Some(stack.clone());
    let (local, remote) = inbound(SOURCE_PORTS[0]);

    stack.inject(segment(remote, local, TcpControl::Syn, TcpSeqNumber(1000), None, &[]));

    let sockets = stack.shared.lock().sockets.iter().count();
    assert_eq!(sockets, 0, "a socket was opened on the closed stack");
}

/// An idle connection to a live peer stays up: smoltcp's timeout counts
/// from the last segment received, even with nothing waiting on an
/// answer, so without keep-alives it was reset after TCP_TIMEOUT.
#[test]
fn idle_connection_stays_up() {
    let mut net = Net::new();
    let dialed = net.dial();
    let accepted = net.open(SOURCE_PORTS[0]);
    net.answer(dialed);
    net.complete(accepted);

    net.wait(TCP_TIMEOUT * 2);

    for i in [dialed, accepted] {
        let c = &net.conns[i];
        assert_eq!((c.end, c.got_rst), (None, false), "{} ended", c.name());
        net.write(i, b"still here");
        let c = &net.conns[i];
        assert_eq!(c.got, b"still here", "{} lost a write", c.name());
    }
}

/// A remote that reset a connection may reuse its 4-tuple while our
/// stream for the old connection is still held: the new SYN went to the
/// old, closed socket, bypassing the policy, and was refused.
#[test]
fn reused_tuple_reaches_the_policy() {
    let mut net = Net::new();
    let first = net.accept_from(SOURCE_PORTS[0]);
    net.remote_reset(first);
    assert!(net.conns[first].stream.is_some());

    let second = net.accept_from(SOURCE_PORTS[0]);
    net.remote_data(second, b"hello");

    assert_eq!(net.conns[second].received, b"hello");
    assert_eq!(net.conns[first].end, Some(Err(io::ErrorKind::ConnectionReset)));
}

/// Draining a connection that was aborted (or reset) with data still
/// unacknowledged returns at once: the data stays queued in the closed
/// socket, but will never be sent. drain and drain_tcp waited it out.
#[test]
fn aborted_connection_is_drained() {
    let mut net = Net::new();
    let i = net.dial_answered();
    net.vanish(i);
    net.write(i, b"unacked");
    net.abort(i);

    net.drain_stream(i);
    net.drain_tcp();
}

/// A dropped connection whose peer acks our FIN but never sends its own
/// is aborted after a while, instead of sitting in FIN-WAIT-2 forever.
#[test]
fn orphan_in_fin_wait_2_is_reaped() {
    let mut net = Net::new();
    let i = net.dial_answered();

    net.drop_stream(i);
    for _ in 0..3 {
        net.wait(TCP_TIMEOUT / 2);
        net.remote_data(i, b"still here");
    }

    let st = net.stack.shared.lock();
    let states: Vec<_> = st.tcp_sockets().map(|s| s.state()).collect();
    assert!(states.is_empty(), "sockets left: {states:?}");
}

/// A handshake that times out is aborted with a RST to the peer: the
/// socket was reaped in the same pass that aborted it, before the RST
/// went out.
#[test]
fn stalled_handshake_is_reset() {
    let mut net = Net::new();
    let i = net.open(SOURCE_PORTS[0]);

    net.wait(ACCEPT_TIMEOUT + SLACK);

    assert!(net.conns[i].got_rst, "the peer wasn't told");
}

/// A remote may reuse a 4-tuple as soon as both sides have closed, while
/// our socket for it is in TIME-WAIT and its stream still held.
#[test]
fn tuple_reused_after_time_wait() {
    let mut net = Net::new();
    let first = net.accept_from(SOURCE_PORTS[0]);
    net.close_write(first);
    net.remote_fin(first);
    assert!(net.conns[first].over());
    assert!(net.conns[first].stream.is_some());

    let second = net.accept_from(SOURCE_PORTS[0]);
    net.remote_data(second, b"hello");

    assert_eq!(net.conns[second].received, b"hello");
}

/// A delayed duplicate of a connection's SYN, arriving while our side of
/// it is in TIME-WAIT, is old: it starts below where the connection
/// ended. Since a SYN on a finished connection's 4-tuple could take the
/// flow, the duplicate went to the policy and opened a new connection. A
/// real new connection from the remote still gets through.
#[test]
fn old_syn_in_time_wait_is_a_duplicate() {
    let mut net = Net::new();
    let first = net.accept_from(SOURCE_PORTS[0]);
    net.remote_data(first, b"hello");
    net.close_write(first);
    net.remote_fin(first);
    assert!(net.time_wait(first));

    net.replay_syn(first, first);
    let second = net.accept_from(SOURCE_PORTS[0]);
    net.remote_data(second, b"again");

    assert_eq!(net.conns[second].received, b"again");
}

/// Counts the stack's polls into `polls`, until aborted.
async fn count_polls(shared: Arc<Shared>, polls: Arc<AtomicUsize>) {
    loop {
        shared.polled.notified().await;
        polls.fetch_add(1, Ordering::Relaxed);
    }
}

/// Waiting for a busy connection to drain doesn't spin: drain_tcp woke
/// the poll loop after every poll, so the two ran back to back until
/// the deadline.
#[test]
fn drain_tcp_waits_quietly() {
    let mut net = Net::new();
    net.dial_answered();
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = net.rt.spawn(count_polls(net.stack.shared.clone(), polls.clone()));

    let drained = net.run_for(net.stack.drain_tcp(Duration::from_millis(500)), Duration::from_secs(1));
    counter.abort();

    assert_eq!(drained, Some(false), "an open connection drained");
    let n = polls.load(Ordering::Relaxed);
    assert!(n < 20, "{n} polls in half a second");
}

/// Runs `f` on another thread, failing the test if it hangs: a thread
/// that locks the stack again while holding the lock never returns.
fn finishes(what: &str, f: impl FnOnce() + Send + 'static) {
    let (done_tx, done_rx) = std_mpsc::channel();
    thread::spawn(move || {
        f();
        let _ = done_tx.send(());
    });
    done_rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|e| panic!("{what}: {e}"));
}

/// A policy accepting every connection with a handler that holds a UDP
/// flow of `stack`'s, which locks the stack when dropped; with `close`,
/// the stack is closed before the policy answers.
fn accept_holding_flow(stack: Arc<OnceLock<Stack>>, close: bool) -> TcpPolicy {
    Arc::new(move |_, _| {
        let s = stack.get().unwrap();
        let flow = s.dial_udp(local_ip(), SocketAddr::new(remote_ip(), DIALED)).unwrap();
        if close {
            s.close();
        }
        TcpDecision::Accept(Box::new(move |_| drop(flow)))
    })
}

/// A handler the stack doesn't keep, since the stack closed while the
/// policy decided, is dropped with the stack unlocked: it was dropped
/// under the lock, and one holding a stream or flow deadlocked.
#[test]
fn handler_left_by_close_drops_unlocked() {
    finishes("inject", || {
        let rt = paused_runtime();
        let _guard = rt.enter();
        let cell: Arc<OnceLock<Stack>> = Arc::default();
        let stack = Stack::new(stack_config(), Arc::new(|_| {}), Some(accept_holding_flow(cell.clone(), true)), None);
        let _ = cell.set(stack.clone());
        let (local, remote) = inbound(SOURCE_PORTS[0]);

        stack.inject(segment(remote, local, TcpControl::Syn, TcpSeqNumber(1000), None, &[]));

        assert!(stack.shared.lock().udp.is_empty(), "the handler's flow is still open");
    });
}

/// The handler of a connection whose handshake times out is dropped
/// with the stack unlocked, as above.
#[test]
fn handler_of_stalled_handshake_drops_unlocked() {
    finishes("the poll loop", || {
        let rt = paused_runtime();
        let _guard = rt.enter();
        let cell: Arc<OnceLock<Stack>> = Arc::default();
        let stack = Stack::new(stack_config(), Arc::new(|_| {}), Some(accept_holding_flow(cell.clone(), false)), None);
        let _ = cell.set(stack.clone());
        let (local, remote) = inbound(SOURCE_PORTS[0]);

        stack.inject(segment(remote, local, TcpControl::Syn, TcpSeqNumber(1000), None, &[]));
        rt.block_on(async {
            let end = Instant::now() + ACCEPT_TIMEOUT + SLACK;
            while Instant::now() < end {
                time::advance(Duration::from_secs(1)).await;
                yield_now().await;
            }
        });

        assert!(stack.shared.lock().udp.is_empty(), "the handler's flow is still open");
    });
}
