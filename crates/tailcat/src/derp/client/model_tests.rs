//! Model-based tests of how a relay connection notices it's gone quiet,
//! driven by Hegel. On a paused clock, a scripted relay sends keepalives
//! and pings of its own, answers the client's pings or stops answering,
//! while time passes a second at a time. The client must ping a relay
//! exactly once per [`PING_AFTER_IDLE`] of silence, answer the relay's
//! pings, and give up on the connection exactly when [`PING_TIMEOUT`]
//! passes after its ping with nothing heard.

use hegel::TestCase;
use hegel::generators as gs;
use tokio::io::{DuplexStream, ReadHalf, WriteHalf, duplex};
use tokio::runtime::{self, Runtime};
use tokio::task::{JoinHandle, yield_now};
use tokio::time::{self, Instant};

use super::*;
use crate::derp::{frame, read_frame};

const TICK: Duration = Duration::from_secs(1);

struct Relay {
    rt: Runtime,
    /// The relay's end of the connection.
    wr: WriteHalf<DuplexStream>,
    /// Frames the client sent, as the relay read them.
    sent: mpsc::UnboundedReceiver<(u8, Vec<u8>)>,
    /// The client's connection task.
    task: JoinHandle<Result<()>>,
    /// Kept so the client has somewhere to deliver packets, and a send
    /// queue that stays open.
    _recv: mpsc::Receiver<ReceivedPacket>,
    _out: mpsc::Sender<Vec<u8>>,
    /// Whether the relay answers the client's pings.
    answers: bool,
    /// When the client last heard from the relay.
    heard: Instant,
    /// Whether the client has pinged since it last heard anything.
    pinged: bool,
    /// The pings the client should have sent, and has.
    want_pings: usize,
    pings: usize,
    /// Whether the client should have given up.
    gone: bool,
}

impl Relay {
    fn new() -> Relay {
        let rt = runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap();
        let (near, far) = duplex(1 << 16);
        let (recv_tx, recv) = mpsc::channel(16);
        let (out, out_rx) = mpsc::channel(16);
        let (rd, wr) = tokio::io::split(far);
        let (sent_tx, sent) = mpsc::unbounded_channel();
        let (task, heard) = rt.block_on(async {
            tokio::spawn(read_all(rd, sent_tx));
            let task = tokio::spawn(async move {
                let mut out_rx = out_rx;
                serve(BufReader::new(near), 1, false, &recv_tx, &mut out_rx).await
            });
            (task, Instant::now())
        });
        let relay = Relay {
            rt,
            wr,
            sent,
            task,
            _recv: recv,
            _out: out,
            answers: true,
            heard,
            pinged: false,
            want_pings: 0,
            pings: 0,
            gone: false,
        };
        // Logged in just now, which counts as hearing from the relay.
        relay.settle();
        relay
    }

    /// Lets the client and the relay's reader catch up.
    fn settle(&self) {
        self.rt.block_on(async {
            for _ in 0..20 {
                yield_now().await;
            }
        });
    }

    fn send(&mut self, f: Vec<u8>) {
        self.rt.block_on(self.wr.write_all(&f)).unwrap();
        self.settle();
    }

    fn now(&self) -> Instant {
        self.rt.block_on(async { Instant::now() })
    }

    /// The client heard from the relay just now.
    fn heard_now(&mut self) {
        self.heard = self.now();
        self.pinged = false;
    }

    /// Takes the frames the client has sent, answering its pings if the
    /// relay does, and returns the other ones.
    fn take_sent(&mut self) -> Vec<(u8, Vec<u8>)> {
        let mut other = Vec::new();
        while let Ok((t, payload)) = self.sent.try_recv() {
            if t != FrameType::Ping as u8 {
                other.push((t, payload));
                continue;
            }
            assert_eq!(payload.len(), 8, "a ping carries 8 bytes");
            self.pings += 1;
            if self.answers {
                self.send(frame(FrameType::Pong, &[&payload]));
                self.heard_now();
            }
        }
        other
    }

    /// One second passes. The client pings once it's heard nothing for
    /// PING_AFTER_IDLE, and gives up PING_TIMEOUT after that.
    fn tick(&mut self) {
        self.rt.block_on(time::advance(TICK));
        self.settle();
        let quiet = self.now() - self.heard;
        if quiet >= PING_AFTER_IDLE && !self.pinged {
            self.pinged = true;
            self.want_pings += 1;
        }
        if quiet >= PING_AFTER_IDLE + PING_TIMEOUT {
            self.gone = true;
        }
        let other = self.take_sent();
        assert!(other.is_empty(), "the client sent unasked-for frames: {other:?}");
    }
}

/// Reads frames from `rd` into `tx` until the connection ends.
async fn read_all(mut rd: ReadHalf<DuplexStream>, tx: mpsc::UnboundedSender<(u8, Vec<u8>)>) {
    while let Ok(f) = read_frame(&mut rd, 1 << 10).await {
        let _ = tx.send(f);
    }
}

#[hegel::state_machine]
impl Relay {
    /// Up to a minute passes, a second at a time.
    #[rule]
    fn wait(&mut self, tc: TestCase) {
        let secs = tc.draw_named("secs", gs::integers::<u32>().min_value(1).max_value(60));
        for _ in 0..secs {
            if self.gone {
                return;
            }
            self.tick();
        }
    }

    /// The relay starts or stops answering pings.
    #[rule]
    fn answer(&mut self, tc: TestCase) {
        self.answers = tc.draw_named("answers", gs::booleans());
    }

    /// The relay sends a keepalive, which counts as hearing from it.
    #[rule]
    fn keepalive(&mut self, _: TestCase) {
        if self.gone {
            return;
        }
        self.send(frame(FrameType::KeepAlive, &[]));
        self.heard_now();
    }

    /// The relay pings the client, which answers.
    #[rule]
    fn relay_pings(&mut self, tc: TestCase) {
        if self.gone {
            return;
        }
        let data: [u8; 8] = tc.draw_named("data", gs::integers::<u64>()).to_be_bytes();
        self.send(frame(FrameType::Ping, &[&data]));
        self.heard_now();
        let other = self.take_sent();
        assert_eq!(other, [(FrameType::Pong as u8, data.to_vec())]);
    }

    #[invariant(always_run)]
    fn pings_and_gives_up_on_time(&self, _: TestCase) {
        assert_eq!(self.pings, self.want_pings, "pings sent");
        assert_eq!(self.task.is_finished(), self.gone, "connection ended");
    }
}

#[hegel::test(test_cases = 300)]
fn liveness_state_machine(tc: TestCase) {
    hegel::stateful::machine(Relay::new()).steps(30).run(tc);
}

/// A relay that goes silent is given up on PING_AFTER_IDLE plus
/// PING_TIMEOUT after it was last heard, with a ping between.
#[test]
fn gives_up_on_a_silent_relay() {
    let mut relay = Relay::new();
    relay.answers = false;
    let start = relay.now();
    while !relay.task.is_finished() {
        relay.tick();
        assert!(relay.now() - start <= PING_AFTER_IDLE + PING_TIMEOUT, "the client is still waiting");
    }
    assert_eq!(relay.now() - start, PING_AFTER_IDLE + PING_TIMEOUT);
    assert_eq!(relay.pings, 1);
    let err = relay.rt.block_on(&mut relay.task).unwrap().unwrap_err();
    assert!(err.to_string().contains("no answer to a ping"), "{err}");
}
