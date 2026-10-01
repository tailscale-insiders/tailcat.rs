//! Model-based tests of how a server admits clients through its allow
//! hook, driven by Hegel. Clients meow straight through, or have their
//! meow held inside the hook, then released or cancelled, while the
//! owner allows keys, revokes them and disconnects clients. The model
//! says whether each meow is acked: one the hook approved, unless any
//! client was disconnected while it was asked, and not one that comes
//! while an earlier meow of the client's is still being asked about. A
//! cancelled meow must leave the client free to be asked about again.
//! Idle clients expire, and come back (without the hook) when they send
//! again or meow, unless they were disconnected since.

use std::sync::Condvar;

use hegel::TestCase;
use hegel::generators as gs;
use tokio::runtime::{self, Runtime};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::*;
use crate::derp::server::DevDerp;

const KEYS: usize = 2;
/// How long anything that should happen may take.
const WAIT: Duration = Duration::from_secs(5);

/// Holds a meow inside the allow hook until it's opened.
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    /// The hook has asked, and is waiting.
    entered: bool,
    open: bool,
}

impl Gate {
    /// Called by the hook: waits until the gate opens.
    fn enter(&self) {
        let mut s = self.state.lock().unwrap();
        s.entered = true;
        self.changed.notify_all();
        let _open = self.changed.wait_while(s, |s| !s.open).unwrap();
    }

    /// Whether the hook reaches the gate soon.
    fn entered(&self) -> bool {
        let s = self.state.lock().unwrap();
        !self.changed.wait_timeout_while(s, WAIT, |s| !s.entered).unwrap().1.timed_out()
    }

    fn open(&self) {
        self.state.lock().unwrap().open = true;
        self.changed.notify_all();
    }
}

/// What the allow hook answers from: the allowed keys, and a gate for
/// the next meow of each key that's to be held.
#[derive(Default)]
struct Hook {
    allowed: HashSet<NodePublic>,
    gates: HashMap<NodePublic, Arc<Gate>>,
}

struct World {
    rt: Runtime,
    server: Server,
    hook: Arc<Mutex<Hook>>,
    _dev: DevDerp,
}

impl World {
    /// Runs `f` to its end, if it gets there within `WAIT`.
    fn within<F: Future>(&self, f: F) -> Option<F::Output> {
        self.rt.block_on(async { timeout(WAIT, f).await.ok() })
    }
}

fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let rt = runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let hook = Arc::new(Mutex::new(Hook::default()));
        let h = hook.clone();
        // Answers as of asking, then waits at the key's gate, if it has
        // one, as a slow lookup would.
        let allow = move |k| {
            let mut h = h.lock().unwrap();
            let (allowed, gate) = (h.allowed.contains(&k), h.gates.remove(&k));
            drop(h);
            if let Some(g) = gate {
                g.enter();
            }
            allowed
        };
        let (dev, server) = rt.block_on(async {
            let dev = DevDerp::start_local().await.unwrap();
            let server = Server::builder().region(dev.region.clone()).allow_client(allow).start().await.unwrap();
            (dev, server)
        });
        World { rt, server, hook, _dev: dev }
    })
}

/// A meow held inside the allow hook.
struct Held {
    task: JoinHandle<bool>,
    gate: Arc<Gate>,
    /// What the hook answered.
    allowed: bool,
    /// How many clients were disconnected when it started.
    disconnects: u64,
}

impl Held {
    /// Lets the meow go on, and returns whether it was acked.
    fn release(self, w: &World) -> bool {
        self.gate.open();
        w.within(self.task).expect("a released meow didn't finish").unwrap()
    }

    /// Cancels the meow, then lets the hook return, to nobody.
    fn cancel(self, w: &World) {
        self.task.abort();
        let ended = w.within(self.task).expect("a cancelled meow didn't end");
        assert!(ended.unwrap_err().is_cancelled());
        self.gate.open();
    }
}

struct Admission {
    w: &'static World,
    keys: [NodePublic; KEYS],
    allowed: [bool; KEYS],
    clients: [bool; KEYS],
    /// Expired for being idle, so let back in when they send.
    expired: [bool; KEYS],
    held: [Option<Held>; KEYS],
    /// Calls to `disconnect_client`, for any key.
    disconnects: u64,
}

impl Admission {
    fn new() -> Admission {
        // Fresh keys for each test case, on the shared server.
        Admission {
            w: world(),
            keys: [(); KEYS].map(|_| NodePrivate::generate().public()),
            allowed: [false; KEYS],
            clients: [false; KEYS],
            expired: [false; KEYS],
            held: [(); KEYS].map(|_| None),
            disconnects: 0,
        }
    }

    fn key(tc: &TestCase) -> usize {
        tc.draw(gs::integers::<usize>().max_value(KEYS - 1))
    }

    /// A key with a held meow, if any has one.
    fn holding(&self, tc: &TestCase) -> Option<usize> {
        let held: Vec<usize> = (0..KEYS).filter(|&k| self.held[k].is_some()).collect();
        (!held.is_empty()).then(|| held[tc.draw(gs::integers::<usize>().max_value(held.len() - 1))])
    }

    fn disconnect_key(&mut self, k: usize) {
        assert_eq!(self.w.server.disconnect_client(&self.keys[k]), self.clients[k], "key {k}: disconnect");
        self.clients[k] = false;
        self.expired[k] = false;
        self.disconnects += 1;
    }

    /// Whether `k` is a connected client, a WireGuard peer, and a
    /// magicsock peer, which should always agree.
    fn membership(&self, k: &NodePublic) -> [bool; 3] {
        let s = &self.w.server;
        let client = s.status().peers.iter().any(|p| p.key == *k);
        [client, s.inner.engine.peer_stats(k).is_some(), s.inner.ms.peer_path(k).is_some()]
    }

    fn being_asked_about(&self, k: &NodePublic) -> bool {
        self.w.server.inner.pending_allow.0.lock().unwrap().contains(k)
    }
}

#[hegel::state_machine]
impl Admission {
    /// A client meows, and the hook, if it's asked, answers at once. A
    /// client with a meow still being asked about is turned away.
    #[rule]
    fn meow(&mut self, tc: TestCase) {
        let k = Self::key(&tc);
        let acked = self.w.rt.block_on(self.w.server.meow(self.keys[k]));
        let known = self.clients[k] || self.expired[k];
        let expected = known || self.held[k].is_none() && self.allowed[k];
        assert_eq!(acked, expected, "key {k}: meow acked");
        self.clients[k] |= acked;
        self.expired[k] &= !acked;
    }

    /// A new client meows, and its meow is held while the hook is
    /// asked about it.
    #[rule]
    fn hold(&mut self, tc: TestCase) {
        let k = Self::key(&tc);
        if self.clients[k] || self.expired[k] || self.held[k].is_some() {
            return;
        }
        let gate = Arc::new(Gate::default());
        self.w.hook.lock().unwrap().gates.insert(self.keys[k], gate.clone());
        let task = self.w.rt.spawn(self.w.server.meow(self.keys[k]));
        assert!(gate.entered(), "key {k}: the hook wasn't asked");
        self.held[k] = Some(Held { task, gate, allowed: self.allowed[k], disconnects: self.disconnects });
    }

    /// A held meow goes on: acked if the hook approved, unless a client
    /// was disconnected meanwhile.
    #[rule]
    fn release(&mut self, tc: TestCase) {
        let Some(k) = self.holding(&tc) else { return };
        let held = self.held[k].take().unwrap();
        let expected = held.allowed && held.disconnects == self.disconnects;
        let acked = held.release(self.w);
        assert_eq!(acked, expected, "key {k}: held meow acked");
        self.clients[k] |= acked;
    }

    /// A held meow is cancelled, as at shutdown.
    #[rule]
    fn cancel(&mut self, tc: TestCase) {
        let Some(k) = self.holding(&tc) else { return };
        self.held[k].take().unwrap().cancel(self.w);
    }

    /// Every client goes idle long enough to expire.
    #[rule]
    fn expire(&mut self, _: TestCase) {
        std::thread::sleep(Duration::from_millis(1));
        self.w.server.expire_idle_clients(Duration::ZERO);
        for k in 0..KEYS {
            self.expired[k] |= self.clients[k];
            self.clients[k] = false;
        }
    }

    /// A key sends WireGuard traffic: an expired client is let back in,
    /// without asking the hook, and anyone else isn't.
    #[rule]
    fn come_back(&mut self, tc: TestCase) {
        let k = Self::key(&tc);
        let back = self.w.server.readmit(&self.keys[k]).is_some();
        assert_eq!(back, self.expired[k], "key {k}: let back in");
        self.clients[k] |= back;
        self.expired[k] = false;
    }

    #[rule]
    fn allow(&mut self, tc: TestCase) {
        let k = Self::key(&tc);
        self.w.hook.lock().unwrap().allowed.insert(self.keys[k]);
        self.allowed[k] = true;
    }

    /// The owner disconnects a client, which stays allowed.
    #[rule]
    fn disconnect(&mut self, tc: TestCase) {
        let k = Self::key(&tc);
        self.disconnect_key(k);
    }

    /// The documented revocation: the key's no longer allowed, and its
    /// client is disconnected.
    #[rule]
    fn revoke(&mut self, tc: TestCase) {
        let k = Self::key(&tc);
        self.w.hook.lock().unwrap().allowed.remove(&self.keys[k]);
        self.allowed[k] = false;
        self.disconnect_key(k);
    }

    #[invariant(always_run)]
    fn clients_are_peers(&self, _: TestCase) {
        for (k, key) in self.keys.iter().enumerate() {
            let expected = [self.clients[k]; 3];
            assert_eq!(self.membership(key), expected, "key {k}: client, WireGuard peer, magicsock peer");
        }
    }

    #[invariant(always_run)]
    fn expired_clients_are_remembered(&self, _: TestCase) {
        let clients = self.w.server.inner.clients.lock().unwrap();
        let expired = self.keys.map(|key| clients.expired.contains_key(&key));
        drop(clients);
        assert_eq!(expired, self.expired, "expired");
    }

    #[invariant(always_run)]
    fn asked_about_exactly_while_held(&self, _: TestCase) {
        for (k, key) in self.keys.iter().enumerate() {
            assert_eq!(self.being_asked_about(key), self.held[k].is_some(), "key {k}: being asked about");
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        for held in self.held.iter_mut().filter_map(Option::take) {
            held.gate.open();
            self.w.within(held.task);
        }
        let mut hook = self.w.hook.lock().unwrap();
        for k in &self.keys {
            hook.allowed.remove(k);
            hook.gates.remove(k);
        }
        drop(hook);
        for k in &self.keys {
            self.w.server.disconnect_client(k);
        }
    }
}

#[hegel::test(test_cases = 300)]
fn admission_state_machine(tc: TestCase) {
    hegel::stateful::machine(Admission::new()).steps(20).run(tc);
}
