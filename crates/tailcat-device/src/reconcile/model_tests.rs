//! A reference model of peer reconciliation, and Hegel properties that
//! hold [`reconcile`] to it.
//!
//! The model says, as plainly as it can, what a poll should become:
//!
//! - Records rank by run attempt (our own first), then node key, then
//!   content.
//! - Each key's record is its best one. The peers are those records that
//!   aren't us (by key, or at an address we claim) and that no other
//!   such record outranks at their address.
//! - A packet goes to the peer with the most specific claim (its address,
//!   or one of its routes) containing the destination, leaving out claims
//!   to our own address and routes. Where several peers claim that
//!   prefix, the one at that address wins, then the best-ranked.
//!
//! What the implementation installs is routed the way tailcat's
//! WireGuard engine routes (`Peers::owner` in `wg.rs`): the most
//! specific allowed IP, then the lowest key. The model never needs that
//! tie-break, so the implementation mustn't either.

use std::cmp::Ordering;

use hegel::TestCase;
use hegel::generators as gs;
use tailcat::DiscoPublic;

use super::*;

/// Run attempts a record can come from: ours, an earlier attempt of our
/// run, another run, and none at all (a record made outside GitHub
/// Actions).
const RUNS: [(&str, &str); 4] = [("100", "2"), ("100", "1"), ("101", "1"), ("", "")];

/// Routes, chosen to collide: the same /24 written two ways, a /16
/// around it, our own route, two peers' addresses (one written bare),
/// our address, and the whole overlay.
const ROUTES: [&str; 8] = [
    "10.42.0.0/24",
    "10.42.0.9/24",
    "10.42.0.0/16",
    "10.42.1.0/24",
    "100.64.1.2/32",
    "100.64.1.3",
    "100.64.1.0/32",
    "100.64.0.0/16",
];

/// Destinations that tell every prefix above apart, plus two outside.
const PROBES: [[u8; 4]; 11] = [
    [100, 64, 1, 0],
    [100, 64, 1, 1],
    [100, 64, 1, 2],
    [100, 64, 1, 3],
    [100, 64, 1, 4],
    [100, 64, 2, 1],
    [10, 42, 0, 5],
    [10, 42, 1, 5],
    [10, 42, 2, 5],
    [10, 43, 0, 1],
    [192, 168, 0, 1],
];

/// A deterministic key, so that Hegel can replay and shrink.
fn key(n: u8) -> NodePublic {
    format!("nodekey:{:064x}", n as u32 + 1).parse().unwrap()
}

fn record(k: u8, ip: u8, run: usize, index: u32, routes: &[&str]) -> NodeRecord {
    NodeRecord {
        index,
        nodekey: key(k),
        discokey: format!("discokey:{:064x}", k as u32 + 1).parse::<DiscoPublic>().unwrap(),
        overlay_ip: IpAddr::from([100, 64, 1, ip]),
        derp_region: 1,
        derp: None,
        routes: routes.iter().map(|r| r.to_string()).collect(),
        endpoints: Vec::new(),
        os: String::new(),
        arch: String::new(),
        run_id: RUNS[run].0.into(),
        run_attempt: RUNS[run].1.into(),
        jwt: String::new(),
    }
}

/// Us: key 0 at 100.64.1.0 in run 100 attempt 2, routing 10.42.1.0/24
/// and sometimes also a peer's address.
fn draw_me(tc: &TestCase) -> NodeRecord {
    let routes: &[&str] = if tc.draw(gs::booleans()) { &["10.42.1.0/24", "100.64.1.3"] } else { &["10.42.1.0/24"] };
    record(0, 0, 0, 0, routes)
}

/// A record from a small space, so that collisions are common: key 0
/// and address 0 are ours, and an index tells versions of one key's
/// record apart.
fn draw_record(tc: &TestCase) -> NodeRecord {
    let k = tc.draw(gs::integers::<u8>().max_value(6));
    let ip = tc.draw(gs::integers::<u8>().max_value(4));
    let run = tc.draw(gs::integers::<usize>().max_value(RUNS.len() - 1));
    let index = tc.draw(gs::integers::<u32>().max_value(1));
    let n = tc.draw(gs::integers::<usize>().max_value(2));
    let routes: Vec<&str> = (0..n).map(|_| tc.draw(gs::sampled_from(ROUTES.to_vec()))).collect();
    record(k, ip, run, index, &routes)
}

fn draw_poll(tc: &TestCase) -> Vec<NodeRecord> {
    let n = tc.draw(gs::integers::<usize>().max_value(8));
    (0..n).map(|_| draw_record(tc)).collect()
}

type Peers = HashMap<NodePublic, Peer>;

fn poll(me: &NodeRecord, peers: &mut Peers, polled: &[NodeRecord]) {
    let changes = reconcile(me, peers, polled);
    apply(peers, changes);
}

fn from_scratch(me: &NodeRecord, polled: &[NodeRecord]) -> Peers {
    let mut peers = HashMap::new();
    poll(me, &mut peers, polled);
    peers
}

/// The records behind the peers.
fn records(peers: &Peers) -> Vec<&NodeRecord> {
    let mut v: Vec<&NodeRecord> = peers.values().map(|p| &p.record).collect();
    v.sort_by_key(|r| r.nodekey);
    v
}

/// What each peer's WireGuard configuration routes to it.
fn installed(peers: &Peers) -> Vec<(NodePublic, Vec<IpNet>)> {
    peers.iter().map(|(k, p)| (*k, p.allowed_ips.clone())).collect()
}

/// Where the WireGuard engine sends a packet for `dst`.
fn engine_route(installed: &[(NodePublic, Vec<IpNet>)], dst: IpAddr) -> Option<NodePublic> {
    installed
        .iter()
        .filter_map(|(k, nets)| Some((nets.iter().filter(|n| n.contains(&dst)).map(|n| n.prefix_len).max()?, *k)))
        .max_by(|(la, ka), (lb, kb)| la.cmp(lb).then(kb.cmp(ka)))
        .map(|(_, k)| k)
}

/// Whether two prefixes are the same, however they're written.
fn same(a: &IpNet, b: &IpNet) -> bool {
    a.prefix_len == b.prefix_len && a.contains(&b.addr)
}

/// How a node claims a prefix, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Claim {
    Address,
    Route,
}

/// A node's claims, as written: its address, then its routes.
fn claims_of(r: &NodeRecord) -> Vec<(IpNet, Claim)> {
    let routes = r.routes.iter().filter_map(|s| s.parse().ok()).map(|n| (n, Claim::Route));
    std::iter::once((IpNet::host(r.overlay_ip), Claim::Address)).chain(routes).collect()
}

/// The reference model, as seen by the node with record `me`.
struct Model<'a> {
    me: &'a NodeRecord,
}

impl Model<'_> {
    /// Whether `r` is from our own run attempt: an earlier attempt's
    /// nodes are gone.
    fn ours(&self, r: &NodeRecord) -> bool {
        !self.me.run_id.is_empty() && (&r.run_id, &r.run_attempt) == (&self.me.run_id, &self.me.run_attempt)
    }

    /// Orders records best first.
    fn rank(&self, a: &NodeRecord, b: &NodeRecord) -> Ordering {
        let json = |r: &NodeRecord| serde_json::to_vec(r).unwrap();
        self.ours(b).cmp(&self.ours(a)).then(a.nodekey.cmp(&b.nodekey)).then_with(|| json(a).cmp(&json(b)))
    }

    fn outranks(&self, a: &NodeRecord, b: &NodeRecord) -> bool {
        self.rank(a, b).is_lt()
    }

    /// Whether `n` is one of our own claims.
    fn mine(&self, n: &IpNet) -> bool {
        claims_of(self.me).iter().any(|(m, _)| same(m, n))
    }

    /// The peers `polled` calls for.
    fn peers<'a>(&self, polled: &'a [NodeRecord]) -> Vec<&'a NodeRecord> {
        let best: Vec<&NodeRecord> = polled
            .iter()
            .filter(|r| !polled.iter().any(|o| o.nodekey == r.nodekey && self.outranks(o, r)))
            .filter(|r| r.nodekey != self.me.nodekey && !self.mine(&IpNet::host(r.overlay_ip)))
            .collect();
        let mut peers: Vec<&NodeRecord> = best
            .iter()
            .filter(|r| !best.iter().any(|o| o.overlay_ip == r.overlay_ip && self.outranks(o, r)))
            .copied()
            .collect();
        peers.sort_by_key(|r| r.nodekey);
        peers.dedup();
        peers
    }

    /// The peer a packet for `dst` should go to.
    fn route(&self, peers: &[&NodeRecord], dst: IpAddr) -> Option<NodePublic> {
        let candidates: Vec<(IpNet, Claim, &NodeRecord)> = peers
            .iter()
            .flat_map(|p| claims_of(p).into_iter().map(move |(n, c)| (n, c, *p)))
            .filter(|(n, ..)| n.contains(&dst) && !self.mine(n))
            .collect();
        let len = candidates.iter().map(|(n, ..)| n.prefix_len).max()?;
        candidates
            .into_iter()
            .filter(|(n, ..)| n.prefix_len == len)
            .min_by(|(_, ca, a), (_, cb, b)| ca.cmp(cb).then(self.rank(a, b)))
            .map(|(.., p)| p.nodekey)
    }
}

fn probes() -> impl Iterator<Item = IpAddr> {
    PROBES.iter().map(|&a| IpAddr::from(a))
}

/// Checks `peers`, what `me` has after polling `polled`, against the
/// model.
fn check_model(me: &NodeRecord, peers: &Peers, polled: &[NodeRecord]) {
    let model = Model { me };
    let want = model.peers(polled);
    for (k, p) in peers {
        assert_eq!(*k, p.record.nodekey);
    }
    assert_eq!(records(peers), want, "the peers of {polled:?}");
    let installed = installed(peers);
    for dst in probes() {
        assert_eq!(engine_route(&installed, dst), model.route(&want, dst), "the route to {dst} with peers {want:?}");
    }
}

/// A poll's peers, and only them, and packets go where the model says.
#[hegel::test(test_cases = 1000)]
fn polls_match_the_model(tc: TestCase) {
    let me = draw_me(&tc);
    let polled = draw_poll(&tc);
    check_model(&me, &from_scratch(&me, &polled), &polled);
}

/// A poll's peers are the same whatever came before it: a node that
/// restarts, or joins late, ends up where one that saw every poll did,
/// and a record that's gone takes its peer with it.
#[hegel::test(test_cases = 1000)]
fn history_does_not_matter(tc: TestCase) {
    let me = draw_me(&tc);
    let mut peers = HashMap::new();
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(3)) {
        poll(&me, &mut peers, &draw_poll(&tc));
    }
    let polled = draw_poll(&tc);
    poll(&me, &mut peers, &polled);
    check_model(&me, &peers, &polled);
}

/// No two peers are routed the same prefix, so the engine never has to
/// break a tie; each peer is routed its own address, and a peer is only
/// routed what it claims.
#[hegel::test(test_cases = 1000)]
fn every_claim_is_routed_once(tc: TestCase) {
    let me = draw_me(&tc);
    let peers = from_scratch(&me, &draw_poll(&tc));
    let installed = installed(&peers);
    let mut seen: Vec<IpNet> = Vec::new();
    for (k, nets) in &installed {
        let r = &peers[k].record;
        assert!(nets.contains(&IpNet::host(r.overlay_ip)), "{k} isn't routed its address: {nets:?}");
        for n in nets {
            assert!(claims_of(r).iter().any(|(c, _)| same(c, n)), "{k} is routed {n}, which it doesn't claim");
            assert!(!seen.iter().any(|s| same(s, n)), "{n} is routed twice: {installed:?}");
            seen.push(*n);
        }
    }
}

/// Nodes of one run, polling the same records, agree on where packets
/// go, except to their own claims: each puts itself first, so records
/// at their addresses are left out.
#[hegel::test(test_cases = 500)]
fn our_runs_nodes_agree(tc: TestCase) {
    let (a, b) = (draw_me(&tc), record(6, 4, 0, 4, &[]));
    let viewers: Vec<IpNet> = claims_of(&a).into_iter().chain(claims_of(&b)).map(|(n, _)| n).collect();
    let mut polled: Vec<NodeRecord> = draw_poll(&tc)
        .into_iter()
        .filter(|r| ![a.nodekey, b.nodekey].contains(&r.nodekey))
        .filter(|r| !viewers.iter().any(|n| same(n, &IpNet::host(r.overlay_ip))))
        .collect();
    polled.extend([a.clone(), b.clone()]);
    let (va, vb) = (installed(&from_scratch(&a, &polled)), installed(&from_scratch(&b, &polled)));
    for dst in probes().filter(|d| !viewers.iter().any(|n| n.contains(d))) {
        assert_eq!(engine_route(&va, dst), engine_route(&vb, dst), "{dst}");
    }
}

/// Polling the same records again changes nothing.
#[hegel::test(test_cases = 500)]
fn repeated_polls_change_nothing(tc: TestCase) {
    let me = draw_me(&tc);
    let mut peers = from_scratch(&me, &draw_poll(&tc));
    let polled = draw_poll(&tc);
    poll(&me, &mut peers, &polled);
    assert_eq!(reconcile(&me, &peers, &polled), [], "second poll of {polled:?}");
}

/// Neither the order of a poll nor repeats within it matter.
#[hegel::test(test_cases = 500)]
fn a_poll_is_a_set(tc: TestCase) {
    let me = draw_me(&tc);
    let peers = from_scratch(&me, &draw_poll(&tc));
    let polled = draw_poll(&tc);
    let mut shuffled = polled.clone();
    for i in (1..shuffled.len()).rev() {
        shuffled.swap(i, tc.draw(gs::integers::<usize>().max_value(i)));
    }
    if let Some(r) = polled.first()
        && tc.draw(gs::booleans())
    {
        shuffled.push(r.clone());
    }
    assert_eq!(reconcile(&me, &peers, &polled), reconcile(&me, &peers, &shuffled));
}

/// A record that shares nothing with any other, nor with us, is added
/// without disturbing anyone.
#[hegel::test(test_cases = 500)]
fn an_unrelated_record_disturbs_nobody(tc: TestCase) {
    let me = draw_me(&tc);
    let polled = draw_poll(&tc);
    let peers = from_scratch(&me, &polled);
    let loner = NodeRecord { overlay_ip: [100, 64, 3, 1].into(), ..record(9, 0, 1, 0, &["10.99.0.0/24"]) };
    let mut more = polled.clone();
    more.push(loner.clone());
    let allowed_ips = vec![IpNet::host(loner.overlay_ip), "10.99.0.0/24".parse().unwrap()];
    assert_eq!(reconcile(&me, &peers, &more), [Change::Upsert(Peer { record: loner, allowed_ips })]);
}
