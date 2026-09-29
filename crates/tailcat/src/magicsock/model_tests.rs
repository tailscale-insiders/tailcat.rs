//! Model-based tests of the peer table, driven by Hegel. The owner adds,
//! reconfigures and removes peers while simulated peers send disco pings,
//! pongs and CallMeMaybes over UDP and DERP, some sealed with disco keys
//! the table doesn't expect and some from peers sharing a disco key. The
//! table's indexes are checked against the peers they describe, and each
//! address-to-peer mapping against the evidence it needs.

use std::collections::HashSet;

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
        self.ms.upsert_peer(PeerConfig { node_key: k, disco_key: d, home_region: 0, endpoints: endpoints.clone() });
        self.configs.insert(k, (d, endpoints));
        self.history.entry(k).or_default().insert(d);
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
        if let Some(k) = derp_src
            && let Some(p) = self.ms.inner.lock().unwrap().peers.get_mut(&k)
        {
            p.derp_seen = None;
        }
        let tx_id = rand::random();
        self.deliver(&from, &Message::Ping { tx_id, node_key, padding: 0 }, src, derp_src);
        if let Some(k) = derp_src
            && self.holds(&k, &from.public())
        {
            let seen = self.ms.inner.lock().unwrap().peers[&k].derp_seen;
            assert_eq!(seen, Some(REGION), "a DERP ping from its holder was not attributed to it");
        }
        if let (PathAddr::Udp(a), Some(k)) = (src, node_key)
            && self.holds(&k, &from.public())
        {
            let mapped = self.ms.inner.lock().unwrap().by_addr.get(&a).copied();
            assert_eq!(mapped, Some(k), "a UDP ping naming its holder was not attributed to it");
        }
    }

    /// A pong answers one of our outstanding pings. It completes the ping
    /// only if it's sealed with the pinged peer's disco key (and, over
    /// DERP, comes from that peer).
    #[rule]
    fn pong(&mut self, tc: TestCase) {
        let mut pending: Vec<(TxId, NodePublic, PathAddr)> =
            self.ms.inner.lock().unwrap().pending.iter().map(|(tx, pp)| (*tx, pp.peer, pp.to)).collect();
        tc.assume(!pending.is_empty());
        pending.sort_by_key(|(tx, ..)| *tx);
        let (tx_id, pinged, to) = pending[tc.draw_named("ping", gs::integers::<usize>().max_value(pending.len() - 1))];
        let from = self.draw_disco(&tc);
        let (src, derp_src) = self.draw_path(&tc);
        self.deliver(&from, &Message::Pong { tx_id, src: addrs()[0] }, src, derp_src);
        let genuine = self.holds(&pinged, &from.public()) && derp_src.is_none_or(|k| k == pinged);
        let inner = self.ms.inner.lock().unwrap();
        assert_eq!(!inner.pending.contains_key(&tx_id), genuine, "genuine pong: {genuine}");
        if genuine && let (PathAddr::Udp(a), PathAddr::Udp(_)) = (src, to) {
            assert_eq!(inner.by_addr.get(&a), Some(&pinged));
            assert!(inner.peers[&pinged].trusted(Instant::now()));
        }
    }

    /// A peer advertises endpoints (over DERP, else they're ignored),
    /// replacing those it advertised before.
    #[rule]
    fn call_me_maybe(&mut self, tc: TestCase) {
        let from = self.draw_disco(&tc);
        let (src, derp_src) = self.draw_path(&tc);
        let endpoints = Self::draw_addrs(&tc);
        self.deliver(&from, &Message::CallMeMaybe { endpoints: endpoints.clone() }, src, derp_src);
        if let Some(k) = derp_src
            && self.holds(&k, &from.public())
        {
            self.advertised.insert(k, endpoints);
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
            let heard = self.history[k].iter().any(|d| self.heard.contains(&(*a, *d)));
            assert!(heard, "{a} maps to {k:?} without a disco message from there");
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
                let ok = self.configs.get(k).is_some_and(|(_, eps)| eps.contains(a))
                    || advertised.contains(a)
                    || self.history[k].iter().any(|d| self.heard.contains(&(*a, *d)));
                assert!(ok, "{k:?} still has candidate {a}");
            }
        }
    }
}

#[hegel::test(test_cases = 300)]
fn peer_table_state_machine(tc: TestCase) {
    hegel::stateful::machine(Table::new()).steps(40).run(tc);
}
