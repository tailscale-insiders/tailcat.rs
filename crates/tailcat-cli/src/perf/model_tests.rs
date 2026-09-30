//! Model-based tests of perf tests run over in-memory pipes, driven by
//! Hegel. A client and a server [`Test`] run against each other with
//! generated parameters, while one link, or everything one side has, may
//! be cut partway through, or one side's run cancelled with its links
//! left up. Both sides must finish promptly, and either agree on what
//! was delivered or report an error.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use hegel::TestCase;
use hegel::generators::{self as gs, Generator};
use tokio::io::{DuplexStream, ReadBuf, duplex, split};
use tokio::runtime;
use tokio::time::{sleep, timeout};

use super::tests::DIRECTIONS;
use super::*;

const PIPE: usize = 64 << 10;

/// One side's end of a link. Once the link's cut fires, writes fail and
/// the end of its data reads as a reset, as on a TCP connection whose
/// path died, rather than as the peer closing.
struct End {
    pipe: DuplexStream,
    cut: Flag,
}

impl AsyncRead for End {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.pipe).poll_read(cx, buf))?;
        if buf.filled().len() == before && buf.remaining() > 0 && self.cut.is_set() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for End {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.cut.is_set() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.pipe).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_shutdown(cx)
    }
}

/// How a link counts down a byte budget, which links may share: `fired`
/// fires once it runs out, and then, if the link `cuts`, it's severed.
#[derive(Clone)]
struct Budget {
    left: Arc<AtomicUsize>,
    fired: Flag,
    cuts: bool,
}

impl Budget {
    /// Takes `n` bytes from the budget, returning how many of them may
    /// cross, and whether the link is to go on carrying data after.
    fn take(&self, n: usize) -> (usize, bool) {
        let had = self.left.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| Some(l.saturating_sub(n))).unwrap();
        if n < had {
            return (n, true);
        }
        self.fired.set();
        if self.cuts { (had, false) } else { (n, true) }
    }
}

/// Copies until EOF, then passes the EOF on, taking what crosses from
/// `budget`, if any, until it runs out.
async fn pump(mut r: impl AsyncRead + Unpin, mut w: impl AsyncWrite + Unpin, budget: Option<&Budget>) {
    let mut buf = vec![0u8; 16 << 10];
    loop {
        let Ok(n @ 1..) = r.read(&mut buf).await else {
            let _ = w.shutdown().await;
            return;
        };
        let (take, more) = budget.map_or((n, true), |b| b.take(n));
        if w.write_all(&buf[..take]).await.is_err() || !more {
            return;
        }
    }
}

/// Carries a link between its ends until both directions close, or `cut`
/// fires.
async fn relay(a: DuplexStream, b: DuplexStream, cut: Flag, budget: Option<Budget>) {
    let ((ar, aw), (br, bw)) = (split(a), split(b));
    tokio::select! {
        _ = async { tokio::join!(pump(ar, bw, budget.as_ref()), pump(br, aw, budget.as_ref())) } => {}
        _ = cut.wait() => {}
    }
}

/// A link between the client and the server, counting down `budget`, if
/// any, and severed once it runs out if it cuts.
fn link(budget: Option<Budget>) -> (End, End) {
    let cut = budget.as_ref().filter(|b| b.cuts).map_or_else(Flag::default, |b| b.fired.clone());
    let ((c, rc), (s, rs)) = (duplex(PIPE), duplex(PIPE));
    tokio::spawn(relay(rc, rs, cut.clone(), budget));
    (End { pipe: c, cut: cut.clone() }, End { pipe: s, cut })
}

/// A link that is never cut.
fn intact_link() -> (End, End) {
    link(None)
}

fn ctrl(e: End) -> Ctrl {
    let (rd, wr) = split(e);
    Ctrl::new(BufReader::new(Box::new(rd)), Box::new(wr))
}

fn attach(t: &Test, i: usize, e: End) {
    let (rd, wr) = split(e);
    assert!(t.attach(i, tcp_stream(Box::new(rd), Box::new(wr))));
}

/// What happens once a byte budget runs out.
#[derive(Debug, Clone, Copy)]
enum Scenario {
    Nothing,
    /// The control link (0) or a stream's link (1 and up) is cut,
    /// counting that link's bytes.
    Link(usize),
    /// Every link is cut, and that side stops running: a crash. Counts
    /// the bytes of all links.
    Crash {
        server: bool,
    },
    /// That side's run is cancelled, as an interrupt or a timeout does,
    /// and its links stay up. Counts the bytes of all links.
    Cancel {
        server: bool,
    },
}

impl Scenario {
    /// A scenario for a test with `streams` streams.
    fn draw(tc: &TestCase, streams: usize) -> Scenario {
        match tc.draw(gs::integers::<u8>().max_value(5)) {
            0 => Scenario::Nothing,
            1 => Scenario::Link(tc.draw(gs::integers::<usize>().max_value(streams))),
            n @ (2 | 3) => Scenario::Crash { server: n == 3 },
            n => Scenario::Cancel { server: n == 5 },
        }
    }

    /// Whether link `i` (0 for control) counts down the budget.
    fn counts(self, i: usize) -> bool {
        match self {
            Scenario::Nothing => false,
            Scenario::Link(k) => k == i,
            Scenario::Crash { .. } | Scenario::Cancel { .. } => true,
        }
    }

    /// Whether the links are cut once the budget runs out.
    fn cuts(self) -> bool {
        !matches!(self, Scenario::Cancel { .. })
    }

    /// Whether the server, or else the client, stops running.
    fn stops(self, server: bool) -> bool {
        match self {
            Scenario::Crash { server: s } | Scenario::Cancel { server: s } => s == server,
            _ => false,
        }
    }
}

struct Outcome {
    /// `None` if the side stopped running.
    result: Option<Result<PerfResult, String>>,
    elapsed: Duration,
}

/// Runs one side's test, abandoning it if `stop` fires, and checks that
/// it doesn't outlive the test, which would hold its connections open.
async fn side(t: Arc<Test>, stop: Option<Flag>) -> Outcome {
    let start = Instant::now();
    let result = match stop {
        Some(stop) => tokio::select! {
            r = t.clone().run() => Some(r),
            _ = stop.wait() => None,
        },
        None => Some(t.clone().run().await),
    };
    if matches!(result, Some(Ok(_))) {
        assert_eq!(t.err.lock().unwrap().clone(), None, "the test failed after it succeeded");
    }
    let elapsed = start.elapsed();
    assert_released(&t).await;
    Outcome { result, elapsed }
}

/// Asserts that `t`'s tasks let go of it soon, as they must once it's
/// over, rather than hold its connections open.
async fn assert_released(t: &Arc<Test>) {
    let released = async {
        while Arc::strong_count(t) > 1 {
            sleep(Duration::from_millis(1)).await;
        }
    };
    timeout(Duration::from_secs(1), released).await.expect("the test's tasks outlived it");
}

/// Runs a client and a server test against each other, playing out
/// `scenario` once `budget` bytes have crossed the links it counts, and
/// returns how each side came out; `fired` fires when it plays out.
async fn run_pair(p: &Params, scenario: Scenario, fired: &Flag, budget: usize) -> (Outcome, Outcome) {
    let budget = Budget { left: Arc::new(AtomicUsize::new(budget)), fired: fired.clone(), cuts: scenario.cuts() };
    let links: Vec<_> = (0..=p.streams).map(|i| link(scenario.counts(i).then(|| budget.clone()))).collect();
    let mut links = links.into_iter();
    let (cc, sc) = links.next().unwrap();
    let id = [7; 8];
    let client = Test::new(p.clone(), id, false, ctrl(cc), None);
    let server = Test::new(p.clone(), id, true, ctrl(sc), None);
    for (i, (c, s)) in links.enumerate() {
        attach(&client, i, c);
        attach(&server, i, s);
    }
    let stop = |server: bool| scenario.stops(server).then(|| fired.clone());
    let both = async { tokio::join!(tokio::spawn(side(client, stop(false))), tokio::spawn(side(server, stop(true)))) };
    let (c, s) = timeout(p.duration + Duration::from_secs(30), both).await.expect("the test hung");
    (c.unwrap(), s.unwrap())
}

fn draw_params(tc: &TestCase) -> Params {
    let direction = tc.draw(gs::sampled_from(&DIRECTIONS).print_as_debug());
    let (bytes, duration) = if tc.draw(gs::booleans()) {
        (tc.draw(gs::integers::<i64>().min_value(1).max_value(256 << 10)), Duration::ZERO)
    } else {
        (0, Duration::from_millis(tc.draw(gs::integers::<u64>().min_value(1).max_value(200))))
    };
    Params {
        proto: Proto::Tcp,
        direction,
        duration,
        bytes,
        streams: tc.draw(gs::integers::<usize>().min_value(1).max_value(4)),
        length: tc.draw(gs::integers::<usize>().min_value(1).max_value(64 << 10)),
        bitrate: 0,
        interval: if tc.draw(gs::booleans()) { MIN_INTERVAL } else { Duration::ZERO },
    }
}

/// A byte budget spread over orders of magnitude, from a few bytes of the
/// control link to past a test's whole transfer.
fn draw_budget(tc: &TestCase) -> usize {
    let magnitude = tc.draw(gs::integers::<u32>().max_value(21));
    tc.draw(gs::integers::<usize>().max_value(1 << magnitude))
}

fn bytes(s: &Option<Stats>) -> Option<i64> {
    s.as_ref().map(|s| s.bytes)
}

/// Checks one direction's transfer: the bytes sent and received as the
/// client reports them (`ours`), and as the server does (`theirs`).
fn check_transfer(p: &Params, ours: [&Option<Stats>; 2], theirs: [&Option<Stats>; 2], cut: bool) {
    let [Some(sent), Some(received)] = ours.map(bytes) else {
        panic!("missing stats: {ours:?}");
    };
    assert_eq!(theirs.map(bytes), [Some(sent), Some(received)], "sides disagree");
    if p.bytes > 0 {
        assert_eq!(sent, p.bytes * p.streams as i64, "sent the wrong amount");
    }
    // A link cut after its data was sent can lose some in flight, which
    // the receiver reports rather than failing.
    if cut {
        assert!(received <= sent, "received {received} of {sent} bytes");
    } else {
        assert_eq!(received, sent, "lost data with nothing cut");
    }
}

#[hegel::test(test_cases = 100)]
fn tests_finish_and_agree(tc: TestCase) {
    let p = draw_params(&tc);
    let scenario = Scenario::draw(&tc, p.streams);
    let budget = draw_budget(&tc);
    tc.note(&format!("{p:?}, {scenario:?} after {budget} bytes"));
    let rt = runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let fired = Flag::default();

    let (c, s) = rt.block_on(run_pair(&p, scenario, &fired, budget));

    let bound = p.duration + Duration::from_secs(5);
    assert!(c.elapsed <= bound, "the client took {:?}: {:?}", c.elapsed, c.result.map(|_| ()));
    assert!(s.elapsed <= bound, "the server took {:?}: {:?}", s.elapsed, s.result.map(|_| ()));
    let (Some(Ok(cr)), Some(Ok(sr))) = (&c.result, &s.result) else {
        let errs = (c.result.map(|r| r.err()), s.result.map(|r| r.err()));
        assert!(fired.is_set(), "a test failed with nothing cut or cancelled: {errs:?}");
        return;
    };
    // Both sides ran to the end, so anything that happened was a cut.
    let cut = fired.is_set();
    if p.direction != Direction::Download {
        check_transfer(&p, [&cr.client_sent, &cr.server_received], [&sr.client_sent, &sr.server_received], cut);
    }
    if p.direction != Direction::Upload {
        check_transfer(&p, [&cr.server_sent, &cr.client_received], [&sr.server_sent, &sr.client_received], cut);
    }
}

/// A stream task that panics fails the test, and the others' results
/// stay at their streams' indices.
#[tokio::test]
async fn panicked_stream_tasks_fail_the_test() {
    let (c, _s) = intact_link();
    let p = Params {
        proto: Proto::Tcp,
        direction: Direction::Upload,
        duration: Duration::from_secs(1),
        bytes: 0,
        streams: 3,
        length: 1,
        bitrate: 0,
        interval: Duration::ZERO,
    };
    let t = Test::new(p, [0; 8], false, ctrl(c), None);
    let tasks = (0..3).map(|i| tokio::spawn(async move { if i == 1 { panic!("boom") } else { i } })).collect();
    assert_eq!(t.join_streams(tasks).await, [Some(0), None, Some(2)]);
    let e = t.err();
    assert!(e.starts_with("stream 1: ") && e.contains("panicked"), "{e}");
    assert!(t.done.is_set());
}
