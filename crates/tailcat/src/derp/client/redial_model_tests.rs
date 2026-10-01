//! Model-based tests of when a relay client redials, driven by Hegel. On
//! a paused clock, a scripted relay fails the client's dials or takes
//! them, and closes connections, while time passes a tick at a time. A
//! connection nobody closes stays silent, so the client gives up on it
//! itself. The client must dial at once, then [`MIN_BACKOFF`] after a
//! dial fails or a connection ends, doubling the wait each time up to
//! [`MAX_BACKOFF`], and going back to the shortest wait only after a
//! connection that lasted [`STEADY`].

use hegel::TestCase;
use hegel::generators as gs;
use tokio::io::{DuplexStream, duplex};
use tokio::runtime::{self, Runtime};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, yield_now};
use tokio::time::{self, Instant};

use super::*;

/// Every wait is a whole number of ticks.
const TICK: Duration = Duration::from_millis(100);

type Dial = oneshot::Sender<Result<(BufReader<DuplexStream>, String)>>;

struct Relay {
    rt: Runtime,
    /// The client's dials, as it makes them.
    dials: mpsc::UnboundedReceiver<Dial>,
    /// A dial the client is waiting on.
    pending: Option<Dial>,
    /// The relay's end of the connection that's up, and when it came up.
    conn: Option<(DuplexStream, Instant)>,
    connected: watch::Receiver<bool>,
    task: JoinHandle<()>,
    /// Kept so the client has somewhere to deliver packets, and a send
    /// queue that stays open.
    _recv: mpsc::Receiver<ReceivedPacket>,
    _out: mpsc::Sender<Vec<u8>>,
    /// The wait the client should use next.
    backoff: Duration,
    /// When the client should next dial, while it's waiting to.
    redial_at: Option<Instant>,
    /// When the client dialed.
    dialed: Vec<Instant>,
}

impl Relay {
    fn new() -> Relay {
        let rt = runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap();
        let (dial_tx, dials) = mpsc::unbounded_channel();
        let (recv_tx, recv) = mpsc::channel(16);
        let (out, out_rx) = mpsc::channel(16);
        let (conn_tx, connected) = watch::channel(false);
        let connect = move || {
            let dial_tx = dial_tx.clone();
            async move {
                let (tx, rx) = oneshot::channel();
                let gone = |_| Error::Derp("the test is over".into());
                dial_tx.send(tx).map_err(|_| gone(()))?;
                rx.await.map_err(|_| gone(()))?
            }
        };
        let (task, start) = rt.block_on(async {
            let task = tokio::spawn(keep_connected(connect, 1, false, recv_tx, out_rx, conn_tx));
            (task, Instant::now())
        });
        let mut relay = Relay {
            rt,
            dials,
            pending: None,
            conn: None,
            connected,
            task,
            _recv: recv,
            _out: out,
            backoff: MIN_BACKOFF,
            // The first dial is at once.
            redial_at: Some(start),
            dialed: Vec::new(),
        };
        relay.settle();
        relay
    }

    fn now(&self) -> Instant {
        self.rt.block_on(async { Instant::now() })
    }

    /// Lets the client catch up, and takes any dial it made, which must
    /// be when it should have.
    fn settle(&mut self) {
        self.rt.block_on(async {
            for _ in 0..20 {
                yield_now().await;
            }
        });
        let now = self.now();
        while let Ok(d) = self.dials.try_recv() {
            assert!(self.pending.is_none() && self.conn.is_none(), "the client dialed twice");
            assert_eq!(self.redial_at, Some(now), "the client dialed at the wrong time");
            self.redial_at = None;
            self.pending = Some(d);
            self.dialed.push(now);
        }
    }

    /// A dial failed or a connection ended just now: the client waits,
    /// and longer the next time.
    fn wait_to_redial(&mut self) {
        self.redial_at = Some(self.now() + self.backoff);
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    /// The connection that's up ended just now.
    fn ended(&mut self) {
        let (_, up) = self.conn.take().unwrap();
        if self.now() - up >= STEADY {
            self.backoff = MIN_BACKOFF;
        }
        self.wait_to_redial();
    }

    fn accept_dial(&mut self) {
        let Some(d) = self.pending.take() else { return };
        let (near, far) = duplex(1 << 16);
        let _ = d.send(Ok((BufReader::new(near), "t1".into())));
        self.conn = Some((far, self.now()));
        self.settle();
    }

    fn close_conn(&mut self) {
        if self.conn.is_none() {
            return;
        }
        self.ended();
        self.settle();
    }

    /// One tick passes. A connection nobody's closed, which has been
    /// silent all along, the client gives up on when its ping goes
    /// unanswered.
    fn tick(&mut self) {
        self.rt.block_on(time::advance(TICK));
        if self.conn.as_ref().is_some_and(|&(_, up)| self.now() - up >= PING_AFTER_IDLE + PING_TIMEOUT) {
            self.ended();
        }
        self.settle();
    }
}

#[hegel::state_machine]
impl Relay {
    /// Up to 10 seconds pass, a tick at a time.
    #[rule]
    fn wait(&mut self, tc: TestCase) {
        let ticks = tc.draw_named("ticks", gs::integers::<u32>().min_value(1).max_value(100));
        for _ in 0..ticks {
            self.tick();
        }
    }

    /// The dial the client is waiting on fails.
    #[rule]
    fn fail(&mut self, _: TestCase) {
        let Some(d) = self.pending.take() else { return };
        let _ = d.send(Err(Error::Derp("refused".into())));
        self.wait_to_redial();
        self.settle();
    }

    /// The dial the client is waiting on connects.
    #[rule]
    fn accept(&mut self, _: TestCase) {
        self.accept_dial();
    }

    /// The relay closes the connection that's up.
    #[rule]
    fn close(&mut self, _: TestCase) {
        self.close_conn();
    }

    #[invariant(always_run)]
    fn dials_on_time(&self, _: TestCase) {
        let now = self.now();
        assert!(self.redial_at.is_none_or(|t| t > now), "the client didn't redial on time");
        assert_eq!(*self.connected.borrow(), self.conn.is_some(), "connected");
        assert!(!self.task.is_finished(), "the client stopped");
    }
}

#[hegel::test(test_cases = 300)]
fn redial_state_machine(tc: TestCase) {
    hegel::stateful::machine(Relay::new()).steps(30).run(tc);
}

/// A relay that closes every connection it takes, as soon as it takes
/// it, gets dialed less and less often, down to once every MAX_BACKOFF.
#[test]
fn backs_off_from_a_relay_that_closes_every_connection() {
    let mut relay = Relay::new();
    let start = relay.now();
    while relay.now() - start < Duration::from_secs(60) {
        relay.accept_dial();
        relay.close_conn();
        relay.tick();
    }
    let gaps: Vec<Duration> = relay.dialed.windows(2).map(|w| w[1] - w[0]).collect();
    let ms = |n| Duration::from_millis(n);
    assert_eq!(gaps[..7], [ms(100), ms(200), ms(400), ms(800), ms(1600), ms(3200), MAX_BACKOFF]);
    assert!(gaps[7..].iter().all(|&g| g == MAX_BACKOFF), "{gaps:?}");
}
