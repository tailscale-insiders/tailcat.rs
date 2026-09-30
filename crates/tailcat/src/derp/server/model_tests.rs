//! Model-based tests of the relay's client table, driven by Hegel.
//! Clients with a few keys connect, replacing each other's connections,
//! send each other packets, and hang up or have the relay's side of the
//! connection cancelled, as a task is at shutdown. The relay must count
//! a key as connected exactly when it has a connection that's up and
//! not replaced, deliver packets for the key to that connection, and
//! answer that the peer is gone when there's none.

use std::sync::OnceLock;

use hegel::TestCase;
use hegel::generators as gs;
use tokio::io::{DuplexStream, duplex};
use tokio::runtime::{self, Runtime};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::*;
use crate::derp::client::login;
use crate::derp::read_frame;

const KEYS: usize = 3;
/// How long anything that should happen may take.
const WAIT: Duration = Duration::from_secs(2);

/// One runtime for every test case; each case has a relay of its own.
fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap())
}

/// A client's connection to the relay.
struct Session {
    conn: BufReader<DuplexStream>,
    /// The relay's task serving it.
    task: JoinHandle<Result<()>>,
}

impl Session {
    /// Connects to `server` and logs in as `key`.
    async fn open(server: &Arc<Server>, key: &NodePrivate) -> Session {
        let (near, far) = duplex(1 << 16);
        let s = server.clone();
        let task = tokio::spawn(async move { s.handle_http(far, SocketAddr::from(([127, 0, 0, 1], 1))).await });
        let mut conn = BufReader::new(near);
        login(&mut conn, "T", key, &"test".into()).await.unwrap();
        let (t, _) = read_frame(&mut conn, 1 << 10).await.unwrap();
        assert_eq!(t, FrameType::ServerInfo as u8);
        Session { conn, task }
    }

    async fn send(&mut self, frame: &[u8]) {
        self.conn.get_mut().write_all(frame).await.unwrap();
    }

    /// The next frame the relay sends.
    async fn next_frame(&mut self) -> (u8, Vec<u8>) {
        let f = timeout(WAIT, read_frame(&mut self.conn, 1 << 10)).await;
        f.expect("no frame came").expect("the connection failed")
    }

    /// Waits for the relay to close the connection, then for its task to
    /// end.
    async fn expect_closed(mut self) {
        let mut rest = Vec::new();
        let read = timeout(WAIT, self.conn.read_to_end(&mut rest)).await;
        assert!(read.is_ok(), "the relay kept a replaced connection open");
        expect_ended(self.task).await;
    }

    /// Hangs up, and waits for the relay's task to end.
    async fn hang_up(self) {
        drop(self.conn);
        expect_ended(self.task).await;
    }

    /// Cancels the relay's task, and waits for it to end. The client
    /// hangs up only after, so it's the cancel that ends it.
    async fn cancel(self) {
        self.task.abort();
        expect_ended(self.task).await;
        drop(self.conn);
    }
}

/// Waits for a relay's task to end, by when its connection is out of the
/// table if it's going.
async fn expect_ended(task: JoinHandle<Result<()>>) {
    assert!(timeout(WAIT, task).await.is_ok(), "the relay's task went on");
}

struct Relay {
    rt: &'static Runtime,
    server: Arc<Server>,
    keys: [NodePrivate; KEYS],
    /// Each key's connection, if it's up and not replaced.
    sessions: [Option<Session>; KEYS],
    next: u32,
}

impl Relay {
    fn new() -> Relay {
        Relay {
            rt: runtime(),
            server: Server::new(),
            keys: [(); KEYS].map(|_| NodePrivate::generate()),
            sessions: [(); KEYS].map(|_| None),
            next: 0,
        }
    }

    fn key(tc: &TestCase) -> usize {
        tc.draw(gs::integers::<usize>().max_value(KEYS - 1))
    }

    /// A key with a connection, if any has one.
    fn connected(&self, tc: &TestCase) -> Option<usize> {
        let up: Vec<usize> = (0..KEYS).filter(|&k| self.sessions[k].is_some()).collect();
        (!up.is_empty()).then(|| up[tc.draw(gs::integers::<usize>().max_value(up.len() - 1))])
    }

    fn public(&self, k: usize) -> NodePublic {
        self.keys[k].public()
    }
}

#[hegel::state_machine]
impl Relay {
    /// A client connects with a key, replacing any connection with it,
    /// which the relay closes.
    #[rule]
    fn connect(&mut self, tc: TestCase) {
        let k = Self::key(&tc);
        let s = self.rt.block_on(Session::open(&self.server, &self.keys[k]));
        if let Some(old) = self.sessions[k].replace(s) {
            self.rt.block_on(old.expect_closed());
        }
    }

    /// A connected client sends a packet to a key, which goes to its
    /// connection, or else back as the peer being gone.
    #[rule]
    fn send(&mut self, tc: TestCase) {
        let Some(from) = self.connected(&tc) else { return };
        let to = Self::key(&tc);
        let (src, dst) = (self.public(from), self.public(to));
        self.next += 1;
        let pkt = self.next.to_be_bytes();
        let rt = self.rt;
        let sender = self.sessions[from].as_mut().unwrap();
        rt.block_on(sender.send(&frame(FrameType::SendPacket, &[dst.as_bytes(), &pkt])));
        match self.sessions[to].as_mut() {
            Some(receiver) => {
                let got = rt.block_on(receiver.next_frame());
                assert_eq!(got, (FrameType::RecvPacket as u8, [src.as_bytes().as_slice(), &pkt].concat()));
            }
            None => {
                let got = rt.block_on(self.sessions[from].as_mut().unwrap().next_frame());
                assert_eq!(
                    got,
                    (FrameType::PeerGone as u8, [dst.as_bytes().as_slice(), &[PEER_GONE_NOT_HERE]].concat())
                );
            }
        }
    }

    #[rule]
    fn hang_up(&mut self, tc: TestCase) {
        let Some(k) = self.connected(&tc) else { return };
        let s = self.sessions[k].take().unwrap();
        self.rt.block_on(s.hang_up());
    }

    /// The relay's task for a connection is cancelled, as at shutdown.
    #[rule]
    fn cancel(&mut self, tc: TestCase) {
        let Some(k) = self.connected(&tc) else { return };
        let s = self.sessions[k].take().unwrap();
        self.rt.block_on(s.cancel());
    }

    #[invariant(always_run)]
    fn connected_exactly_while_up(&self, _: TestCase) {
        for k in 0..KEYS {
            let up = self.sessions[k].is_some();
            assert_eq!(self.server.is_client_connected(&self.public(k)), up, "key {k}: connected, up {up}");
        }
    }
}

#[hegel::test(test_cases = 500)]
fn relay_state_machine(tc: TestCase) {
    hegel::stateful::machine(Relay::new()).steps(20).run(tc);
}
