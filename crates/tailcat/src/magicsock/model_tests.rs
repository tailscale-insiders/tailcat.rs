//! Model-based tests of the peer table, driven by Hegel. The owner adds,
//! reconfigures and removes peers while simulated peers send disco pings,
//! pongs and CallMeMaybes over UDP and DERP, some sealed with disco keys
//! the table doesn't expect and some from peers sharing a disco key. The
//! table's indexes are checked against the peers they describe, and each
//! address-to-peer mapping against the evidence it needs. A pong saying
//! the peer sees us at a new address on the path in use, a sign our NAT
//! mapped us anew, must start a STUN round.

use std::collections::HashSet;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use hegel::TestCase;
use hegel::generators as gs;

use super::*;

const NODES: usize = 3;
const DISCOS: usize = 3;
const REGION: i32 = 1;

fn addrs() -> [SocketAddr; 4] {
    ["192.0.2.1:41641", "192.0.2.2:41641", "10.0.0.1:41641", "[2001:db8::1]:41641"].map(|a| a.parse().unwrap())
}

struct Table {
    ms: Arc<MagicSock>,
    _wg_rx: mpsc::Receiver<WireguardPacket>,
    nodes: Vec<NodePublic>,
    discos: Vec<DiscoPrivate>,
    /// The owner's configuration of each peer: its disco key and endpoints.
    configs: HashMap<NodePublic, (DiscoPublic, Vec<SocketAddr>)>,
    /// The endpoints in each peer's latest accepted CallMeMaybe.
    advertised: HashMap<NodePublic, Vec<SocketAddr>>,
    /// Every disco key each node has been configured with.
    history: HashMap<NodePublic, HashSet<DiscoPublic>>,
    /// The UDP addresses disco messages came from, with the disco key
    /// that sealed each.
    heard: HashSet<(SocketAddr, DiscoPublic)>,
}

impl Table {
    fn new() -> Table {
        let (ms, _wg_rx) = MagicSock::offline(NodePrivate::generate(), true);
        Table {
            ms,
            _wg_rx,
            nodes: (0..NODES).map(|_| NodePrivate::generate().public()).collect(),
            discos: (0..DISCOS).map(|_| DiscoPrivate::generate()).collect(),
            configs: HashMap::new(),
            advertised: HashMap::new(),
            history: HashMap::new(),
            heard: HashSet::new(),
        }
    }

    fn draw_node(&self, tc: &TestCase) -> NodePublic {
        self.nodes[tc.draw_named("node", gs::integers::<usize>().max_value(NODES - 1))]
    }

    fn draw_disco(&self, tc: &TestCase) -> DiscoPrivate {
        self.discos[tc.draw_named("disco", gs::integers::<usize>().max_value(DISCOS - 1))].clone()
    }

    fn draw_addr(tc: &TestCase) -> SocketAddr {
        addrs()[tc.draw_named("addr", gs::integers::<usize>().max_value(addrs().len() - 1))]
    }

    fn draw_addrs(tc: &TestCase) -> Vec<SocketAddr> {
        let mask = tc.draw_named("addrs", gs::integers::<u8>().max_value((1 << addrs().len()) - 1));
        addrs().into_iter().enumerate().filter(|(i, _)| mask >> i & 1 == 1).map(|(_, a)| a).collect()
    }

    /// A UDP address, or DERP with the sending node the relay reports.
    fn draw_path(&self, tc: &TestCase) -> (PathAddr, Option<NodePublic>) {
        if tc.draw_named("over_udp", gs::booleans()) {
            (PathAddr::Udp(Self::draw_addr(tc)), None)
        } else {
            (PathAddr::Derp(REGION), Some(self.draw_node(tc)))
        }
    }

    /// Whether the owner configured node `k` with disco key `d`.
    fn holds(&self, k: &NodePublic, d: &DiscoPublic) -> bool {
        self.configs.get(k).is_some_and(|(cd, _)| cd == d)
    }

    /// Whether a disco message sealed with one of node `k`'s keys came
    /// from `a`.
    fn heard_from(&self, k: &NodePublic, a: SocketAddr) -> bool {
        self.history[k].iter().any(|d| self.heard.contains(&(a, *d)))
    }

    /// Our outstanding pings, in a stable order.
    fn pending_pings(&self) -> Vec<(TxId, NodePublic, PathAddr)> {
        let inner = self.ms.inner.lock().unwrap();
        let mut pending: Vec<_> = inner.pending.iter().map(|(tx, pp)| (*tx, pp.peer, pp.to)).collect();
        pending.sort_by_key(|(tx, ..)| *tx);
        pending
    }

    /// The DERP region peer `k` was last heard from.
    fn derp_seen(&self, k: &NodePublic) -> Option<i32> {
        self.ms.inner.lock().unwrap().peers[k].derp_seen
    }

    fn forget_derp_seen(&self, k: &NodePublic) {
        if let Some(p) = self.ms.inner.lock().unwrap().peers.get_mut(k) {
            p.derp_seen = None;
        }
    }

    /// Whether a STUN round was asked for since the last call.
    fn take_restun(&self) -> bool {
        let notified = pin!(self.ms.restun.notified());
        notified.poll(&mut Context::from_waker(Waker::noop())) == Poll::Ready(())
    }

    /// The path peer `k` trusts, if it's one of its candidates.
    fn trusted_candidate(&self, k: &NodePublic) -> Option<SocketAddr> {
        let inner = self.ms.inner.lock().unwrap();
        let p = inner.peers.get(k)?;
        p.best.map(|b| b.0).filter(|a| p.trusted(Instant::now()) && p.candidates.contains_key(a))
    }

    /// Checks that peer `k`'s trusted path `before`, if it's no longer a
    /// candidate, lost its trust. (A pong for a ping sent earlier can
    /// trust it again.)
    fn check_forgotten_path_untrusted(&self, k: &NodePublic, before: Option<SocketAddr>) {
        let inner = self.ms.inner.lock().unwrap();
        let (Some(a), Some(p)) = (before, inner.peers.get(k)) else { return };
        if !p.candidates.contains_key(&a) {
            assert!(!p.trusted(Instant::now()), "{k:?} still trusts {a}, no longer a candidate");
        }
    }

    /// The peer UDP address `a` maps to.
    fn mapped(&self, a: &SocketAddr) -> Option<NodePublic> {
        self.ms.inner.lock().unwrap().by_addr.get(a).copied()
    }

    /// Delivers `msg`, sealed with `from`, over `src`.
    fn deliver(&mut self, from: &DiscoPrivate, msg: &Message, src: PathAddr, derp_src: Option<NodePublic>) {
        let pkt = disco::seal(&from.public(), &from.shared(&self.ms.disco_public()), msg);
        if let PathAddr::Udp(a) = src {
            self.heard.insert((a, from.public()));
        }
        self.ms.handle_disco(&pkt, src, derp_src);
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        // A failed check may have poisoned the lock; closing the
        // magicsock must not panic again.
        self.ms.inner.clear_poison();
    }
}

#[hegel::state_machine]
impl Table {
    /// The owner adds or reconfigures a peer, possibly with another
    /// peer's disco key.
    #[rule]
    fn upsert(&mut self, tc: TestCase) {
        let k = self.draw_node(&tc);
        let d = self.draw_disco(&tc).public();
        let endpoints = Self::draw_addrs(&tc);
        let before = self.trusted_candidate(&k);
        self.ms.upsert_peer(PeerConfig { node_key: k, disco_key: d, home_region: 0, endpoints: endpoints.clone() });
        self.configs.insert(k, (d, endpoints));
        self.history.entry(k).or_default().insert(d);
        self.check_forgotten_path_untrusted(&k, before);
    }

    #[rule]
    fn remove(&mut self, tc: TestCase) {
        let k = self.draw_node(&tc);
        assert_eq!(self.ms.remove_peer(&k), self.configs.remove(&k).is_some());
        self.advertised.remove(&k);
    }

    /// A ping arrives. It reaches the peer holding the sealing key that
    /// the relay names (over DERP) or the ping itself names (over UDP),
    /// whichever peer the key is indexed under.
    #[rule]
    fn ping(&mut self, tc: TestCase) {
        let from = self.draw_disco(&tc);
        let (src, derp_src) = self.draw_path(&tc);
        let node_key = tc.draw_named("with_node_key", gs::booleans()).then(|| self.draw_node(&tc));
        if let Some(k) = derp_src {
            self.forget_derp_seen(&k);
        }

        let ping = Message::Ping { tx_id: rand::random(), node_key, padding: 0 };
        self.deliver(&from, &ping, src, derp_src);

        if let Some(k) = derp_src.filter(|k| self.holds(k, &from.public())) {
            assert_eq!(self.derp_seen(&k), Some(REGION), "a DERP ping from its holder was not attributed to it");
        }
        if let (PathAddr::Udp(a), Some(k)) = (src, node_key.filter(|k| self.holds(k, &from.public()))) {
            assert_eq!(self.mapped(&a), Some(k), "a UDP ping naming its holder was not attributed to it");
        }
    }

    /// A pong answers one of our outstanding pings. It completes the ping
    /// only if it's sealed with the pinged peer's disco key (and, over
    /// DERP, comes from that peer).
    #[rule]
    fn pong(&mut self, tc: TestCase) {
        let pending = self.pending_pings();
        tc.assume(!pending.is_empty());
        let (tx_id, pinged, to) = pending[tc.draw_named("ping", gs::integers::<usize>().max_value(pending.len() - 1))];
        let from = self.draw_disco(&tc);
        let (src, derp_src) = self.draw_path(&tc);
        // How the peer says it sees us.
        let seen_as = Self::draw_addr(&tc);
        let before = {
            let inner = self.ms.inner.lock().unwrap();
            let p = &inner.peers[&pinged];
            (p.best.map(|b| b.0), p.seen_as, p.trusted(Instant::now()))
        };
        self.take_restun();

        self.deliver(&from, &Message::Pong { tx_id, src: seen_as }, src, derp_src);

        let genuine = self.holds(&pinged, &from.public()) && derp_src.is_none_or(|k| k == pinged);
        let restun = self.take_restun();
        let inner = self.ms.inner.lock().unwrap();
        assert_eq!(!inner.pending.contains_key(&tx_id), genuine, "genuine pong: {genuine}");
        if genuine && let (PathAddr::Udp(a), PathAddr::Udp(to)) = (src, to) {
            assert_eq!(inner.by_addr.get(&a), Some(&pinged));
            assert!(inner.peers[&pinged].trusted(Instant::now()));
            let (best, seen_before, trusted) = before;
            if best == Some(to) {
                let moved = seen_before.is_some_and(|b| b != seen_as);
                assert_eq!(inner.peers[&pinged].seen_as, Some(seen_as));
                if moved {
                    assert!(restun, "the peer sees us at {seen_as}, not {seen_before:?}, but no STUN round started");
                } else if trusted {
                    assert!(!restun, "a pong confirming the path in use started a STUN round");
                }
            }
        }
    }

    /// A peer advertises endpoints (over DERP, else they're ignored),
    /// replacing those it advertised before.
    #[rule]
    fn call_me_maybe(&mut self, tc: TestCase) {
        let from = self.draw_disco(&tc);
        let (src, derp_src) = self.draw_path(&tc);
        let endpoints = Self::draw_addrs(&tc);
        let before = derp_src.and_then(|k| self.trusted_candidate(&k));
        self.deliver(&from, &Message::CallMeMaybe { endpoints: endpoints.clone() }, src, derp_src);
        if let Some(k) = derp_src.filter(|k| self.holds(k, &from.public())) {
            self.advertised.insert(k, endpoints);
            self.check_forgotten_path_untrusted(&k, before);
        }
    }

    /// The owner sends to a peer, pinging its candidates.
    #[rule]
    fn send(&mut self, tc: TestCase) {
        let k = self.draw_node(&tc);
        if let Some(p) = self.ms.inner.lock().unwrap().peers.get_mut(&k) {
            p.last_full_ping = None;
            p.candidates.values_mut().for_each(|t| *t = None);
        }
        assert_eq!(self.ms.send_wireguard(&k, b"x").is_ok(), self.configs.contains_key(&k));
    }

    #[rule]
    fn timer(&mut self, _: TestCase) {
        self.ms.on_timer();
    }

    /// The peers are the configured ones, and each indexes its disco key
    /// to a peer holding it.
    #[invariant(always_run)]
    fn disco_index_matches_peers(&self, _: TestCase) {
        let inner = self.ms.inner.lock().unwrap();
        let peers: HashMap<NodePublic, DiscoPublic> = inner.peers.iter().map(|(k, p)| (*k, p.cfg.disco_key)).collect();
        let configured: HashMap<NodePublic, DiscoPublic> = self.configs.iter().map(|(k, (d, _))| (*k, *d)).collect();
        assert_eq!(peers, configured);
        for (d, k) in &inner.by_disco {
            assert_eq!(peers.get(k), Some(d), "disco key {d:?} indexed to {k:?}, which doesn't hold it");
        }
        for (k, d) in &peers {
            assert!(inner.by_disco.contains_key(d), "{k:?}'s disco key {d:?} isn't indexed");
        }
    }

    /// Outstanding pings are to known peers, and an address maps to a
    /// peer only once a disco message sealed with one of that peer's
    /// keys came from it: what a peer or its config claims isn't enough.
    #[invariant(always_run)]
    fn addresses_are_mapped_on_evidence(&self, _: TestCase) {
        let inner = self.ms.inner.lock().unwrap();
        for pp in inner.pending.values() {
            assert!(inner.peers.contains_key(&pp.peer), "ping to removed peer {:?} still pending", pp.peer);
        }
        for (a, k) in &inner.by_addr {
            assert!(inner.peers.contains_key(k), "{a} maps to removed peer {k:?}");
            assert!(self.heard_from(k, *a), "{a} maps to {k:?} without a disco message from there");
        }
    }

    /// A peer's candidates are its configured endpoints, the ones it last
    /// advertised, and addresses it has been heard from.
    #[invariant(always_run)]
    fn candidates_are_current(&self, _: TestCase) {
        let inner = self.ms.inner.lock().unwrap();
        for (k, p) in &inner.peers {
            let advertised = self.advertised.get(k).map_or(&[][..], |v| v);
            for a in p.candidates.keys() {
                let configured = self.configs.get(k).is_some_and(|(_, eps)| eps.contains(a));
                let ok = configured || advertised.contains(a) || self.heard_from(k, *a);
                assert!(ok, "{k:?} still has candidate {a}");
            }
        }
    }
}

#[hegel::test(test_cases = 300)]
fn peer_table_state_machine(tc: TestCase) {
    hegel::stateful::machine(Table::new()).steps(40).run(tc);
}
