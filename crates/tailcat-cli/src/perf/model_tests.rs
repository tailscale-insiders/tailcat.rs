//! Model-based tests of perf tests run over in-memory pipes, driven by
//! Hegel. A client and a server [`Test`] run against each other with
//! generated parameters, while one link, or everything one side has, may
//! be cut partway through. Both sides must finish promptly, and either
//! agree on what was delivered or report an error.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use hegel::TestCase;
use hegel::generators as gs;
use tokio::io::{DuplexStream, ReadBuf};

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

/// Copies until EOF, then passes the EOF on. With `left` counting down a
/// byte budget, fires `cut` once it runs out.
async fn pump(mut r: impl AsyncRead + Unpin, mut w: impl AsyncWrite + Unpin, left: &AtomicUsize, cut: &Flag) {
    let mut buf = vec![0u8; 16 << 10];
    loop {
        let Ok(n @ 1..) = r.read(&mut buf).await else {
            let _ = w.shutdown().await;
            return;
        };
        let had = left.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| Some(l.saturating_sub(n))).unwrap();
        let take = n.min(had);
        if w.write_all(&buf[..take]).await.is_err() {
            return;
        }
        if take == had {
            cut.set();
            return;
        }
    }
}

/// Carries a link between its ends until both directions close, or its
/// cut fires. Given a byte budget, which links may share, it fires the
/// cut once the budget runs out.
async fn relay(a: DuplexStream, b: DuplexStream, cut: Flag, budget: Option<Arc<AtomicUsize>>) {
    let left = budget.unwrap_or_else(|| Arc::new(AtomicUsize::new(usize::MAX)));
    let ((ar, aw), (br, bw)) = (tokio::io::split(a), tokio::io::split(b));
    tokio::select! {
        _ = async { tokio::join!(pump(ar, bw, &left, &cut), pump(br, aw, &left, &cut)) } => {}
        _ = cut.wait() => {}
    }
}

/// A link between the client and the server, severed when `cut` fires.
fn link(cut: Flag, budget: Option<Arc<AtomicUsize>>) -> (End, End) {
    let ((c, rc), (s, rs)) = (tokio::io::duplex(PIPE), tokio::io::duplex(PIPE));
    tokio::spawn(relay(rc, rs, cut.clone(), budget));
    (End { pipe: c, cut: cut.clone() }, End { pipe: s, cut })
}

fn ctrl(e: End) -> Ctrl {
    let (rd, wr) = tokio::io::split(e);
    Ctrl::new(BufReader::new(Box::new(rd)), Box::new(wr))
}

fn attach(t: &Test, i: usize, e: End) {
    let (rd, wr) = tokio::io::split(e);
    assert!(t.attach(i, tcp_stream(Box::new(rd), Box::new(wr))));
}

/// What gets cut, once a byte budget runs out.
#[derive(Debug, Clone, Copy)]
enum Scenario {
    Nothing,
    /// The control link (0) or a stream's link (1 and up), counting that
    /// link's bytes.
    Link(usize),
    /// Every link, and that side stops running: a crash. Counts the
    /// bytes of all links.
    Crash {
        server: bool,
    },
}

struct Outcome {
    /// `None` if the side crashed.
    result: Option<Result<PerfResult, String>>,
    elapsed: Duration,
}

/// Runs one side's test, abandoning it if `crash` fires, and checks that
/// it doesn't outlive the test, which would hold its connections open.
async fn side(t: Arc<Test>, crash: Option<Flag>) -> Outcome {
    let start = Instant::now();
    let result = match crash {
        Some(c) => tokio::select! {
            r = t.clone().run() => Some(r),
            _ = c.wait() => None,
        },
        None => Some(t.clone().run().await),
    };
    if let Some(Ok(_)) = result {
        assert_eq!(t.err.lock().unwrap().clone(), None, "the test failed after it succeeded");
    }
    let elapsed = start.elapsed();
    t.done.set();
    let released = async {
        while Arc::strong_count(&t) > 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(1), released).await.expect("the test's tasks outlived it");
    Outcome { result, elapsed }
}

fn draw_params(tc: &TestCase) -> Params {
    let direction = [Direction::Upload, Direction::Download, Direction::Bidirectional]
        [tc.draw(gs::integers::<usize>().max_value(2))];
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

fn bytes(s: &Option<Stats>) -> Option<i64> {
    s.as_ref().map(|s| s.bytes)
}

#[hegel::test(test_cases = 100)]
fn tests_finish_and_agree(tc: TestCase) {
    let p = draw_params(&tc);
    let scenario = match tc.draw(gs::integers::<u8>().max_value(3)) {
        0 => Scenario::Nothing,
        1 => Scenario::Link(tc.draw(gs::integers::<usize>().max_value(p.streams))),
        n => Scenario::Crash { server: n == 3 },
    };
    // Spread over orders of magnitude, from a few bytes of the control
    // link to past a test's whole transfer.
    let budget = tc.draw(gs::integers::<usize>().max_value(1 << tc.draw(gs::integers::<u32>().max_value(21))));
    tc.note(&format!("{p:?}, cutting {scenario:?} after {budget} bytes"));

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let cut = Flag::default();
        let budget = Arc::new(AtomicUsize::new(budget));
        let links: Vec<_> = (0..=p.streams)
            .map(|i| match scenario {
                Scenario::Nothing => link(Flag::default(), None),
                Scenario::Link(k) if k == i => link(cut.clone(), Some(budget.clone())),
                Scenario::Link(_) => link(Flag::default(), None),
                Scenario::Crash { .. } => link(cut.clone(), Some(budget.clone())),
            })
            .collect();
        let mut links = links.into_iter();
        let (cc, sc) = links.next().unwrap();
        let id = [7; 8];
        let client = Test::new(p.clone(), id, false, ctrl(cc), None);
        let server = Test::new(p.clone(), id, true, ctrl(sc), None);
        for (i, (c, s)) in links.enumerate() {
            attach(&client, i, c);
            attach(&server, i, s);
        }
        let crash = |server: bool| match scenario {
            Scenario::Crash { server: s } if s == server => Some(cut.clone()),
            _ => None,
        };
        let limit = p.duration + Duration::from_secs(30);
        let (c, s) = tokio::time::timeout(limit, async {
            tokio::join!(tokio::spawn(side(client, crash(false))), tokio::spawn(side(server, crash(true))))
        })
        .await
        .expect("the test hung");
        let (c, s) = (c.unwrap(), s.unwrap());

        let bound = p.duration + Duration::from_secs(5);
        assert!(c.elapsed <= bound, "the client took {:?}: {:?}", c.elapsed, c.result.map(|_| ()));
        assert!(s.elapsed <= bound, "the server took {:?}: {:?}", s.elapsed, s.result.map(|_| ()));
        let (Some(Ok(cr)), Some(Ok(sr))) = (&c.result, &s.result) else {
            let errs = (c.result.map(|r| r.err()), s.result.map(|r| r.err()));
            assert!(cut.is_set(), "a test failed with nothing cut: {errs:?}");
            return;
        };
        let up = (&cr.client_sent, &cr.server_received, &sr.client_sent, &sr.server_received);
        let down = (&cr.server_sent, &cr.client_received, &sr.server_sent, &sr.client_received);
        for (active, (sent, received, their_sent, their_received)) in
            [(p.direction != Direction::Download, up), (p.direction != Direction::Upload, down)]
        {
            if !active {
                continue;
            }
            let (Some(sent), Some(received)) = (bytes(sent), bytes(received)) else {
                panic!("missing stats: {cr:?}");
            };
            assert_eq!((bytes(their_sent), bytes(their_received)), (Some(sent), Some(received)), "sides disagree");
            if p.bytes > 0 {
                assert_eq!(sent, p.bytes * p.streams as i64, "sent the wrong amount");
            }
            // A link cut after its data was sent can lose some in flight,
            // which the receiver reports rather than failing.
            if cut.is_set() {
                assert!(received <= sent, "received {received} of {sent} bytes");
            } else {
                assert_eq!(received, sent, "lost data with nothing cut");
            }
        }
    });
}

/// A stream task that panics fails the test, and the others' results
/// stay at their streams' indices.
#[tokio::test]
async fn panicked_stream_tasks_fail_the_test() {
    let (c, _s) = link(Flag::default(), None);
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
