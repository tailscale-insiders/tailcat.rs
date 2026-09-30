//! Deciding which records become peers, and what is routed to each.
//!
//! Every poll of a [`Source`](crate::source::Source) returns every record
//! found so far, and several may claim one overlay address: with
//! `--scope branch`, node `i` of two concurrent runs gets the same
//! default IP, and a re-initialized node leaves its old record behind.
//! Their routes can collide too, when concurrent runs route the same
//! prefixes to node `i`. An address or prefix can only route to one
//! peer, so [`reconcile`] picks a winner for each by a fixed order. That
//! makes the result depend only on what was polled, never on the order
//! records arrive in, nor on what was polled before: a repeated poll
//! changes nothing, so peers aren't torn down and re-added every few
//! seconds, and a node that restarts or joins late ends up with the same
//! peers as one that saw every poll. A poll is the whole truth; smoothing
//! over records that can't be read for a moment is the source's job.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tailcat::NodePublic;
use tailcat::wg::IpNet;

use crate::record::NodeRecord;

/// A peer: its record, and the prefixes routed to it.
#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub record: NodeRecord,
    /// Its overlay address, then those of its routes that no better
    /// claim takes, each once and with its host bits cleared. No two
    /// peers are routed the same prefix, so the WireGuard engine never
    /// breaks a tie by key, which would ignore whose run a peer is from.
    pub allowed_ips: Vec<IpNet>,
}

/// One step towards the peers a poll calls for.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // short-lived, and rarely more than a few
pub enum Change {
    /// Add the peer, or update it.
    Upsert(Peer),
    Remove(NodePublic),
}

/// Returns the changes that turn `current` into the peers `polled` calls
/// for, removals first. For each overlay address claimed by a polled
/// record, the peer there is the best of those records by [`rank`];
/// peers missing from the poll are removed. Records with our node key,
/// or at an address we claim, never become peers. The prefixes the
/// peers claim are then shared out, as `assign` says.
pub fn reconcile(me: &NodeRecord, current: &HashMap<NodePublic, Peer>, polled: &[NodeRecord]) -> Vec<Change> {
    let want = select(me, polled);
    let mut removed: Vec<NodePublic> = current.keys().filter(|k| !want.contains_key(k)).copied().collect();
    removed.sort();
    let mut upserted: Vec<Peer> = want.into_values().filter(|p| current.get(&p.record.nodekey) != Some(p)).collect();
    upserted.sort_by_key(|p| p.record.nodekey);
    removed.into_iter().map(Change::Remove).chain(upserted.into_iter().map(Change::Upsert)).collect()
}

/// The peers `polled` calls for.
fn select(me: &NodeRecord, polled: &[NodeRecord]) -> HashMap<NodePublic, Peer> {
    let ours: HashSet<IpNet> = claims(me).map(|(n, _)| n).collect();
    let mine = |r: &NodeRecord| r.nodekey == me.nodekey || ours.contains(&IpNet::host(r.overlay_ip));
    let mut by_key: HashMap<NodePublic, &NodeRecord> = HashMap::new();
    for r in polled {
        offer(me, &mut by_key, r.nodekey, r);
    }
    let mut by_ip: HashMap<IpAddr, &NodeRecord> = HashMap::new();
    for r in by_key.values().filter(|r| !mine(r)) {
        offer(me, &mut by_ip, r.overlay_ip, r);
    }
    let chosen: Vec<&NodeRecord> = by_ip.into_values().collect();
    assign(me, &ours, &chosen)
}

/// Shares out the prefixes `peers` claim, excluding `ours`: a peer's
/// address is its own, and a route that is no one's address goes to the
/// best of the peers claiming it by [`rank`]. Prefixes are compared with
/// their host bits cleared, as the engine matches them.
fn assign(me: &NodeRecord, ours: &HashSet<IpNet>, peers: &[&NodeRecord]) -> HashMap<NodePublic, Peer> {
    let mut owner: HashMap<IpNet, (Claim, &NodeRecord)> = HashMap::new();
    for &r in peers {
        for (n, c) in claims(r).filter(|(n, _)| !ours.contains(n)) {
            let best = owner.entry(n).or_insert((c, r));
            if c.cmp(&best.0).then_with(|| rank(me, r, best.1)).is_lt() {
                *best = (c, r);
            }
        }
    }
    peers
        .iter()
        .map(|&r| {
            let mut allowed_ips = Vec::new();
            for (n, _) in claims(r) {
                if owner.get(&n).is_some_and(|(_, o)| o.nodekey == r.nodekey) && !allowed_ips.contains(&n) {
                    allowed_ips.push(n);
                }
            }
            (r.nodekey, Peer { record: r.clone(), allowed_ips })
        })
        .collect()
}

/// How a record claims a prefix, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Claim {
    Address,
    Route,
}

/// A record's claims: its address, then its routes, canonical.
fn claims(r: &NodeRecord) -> impl Iterator<Item = (IpNet, Claim)> + '_ {
    let routes = r.routes.iter().filter_map(|s| s.parse().ok()).map(|n| (canonical(n), Claim::Route));
    std::iter::once((IpNet::host(r.overlay_ip), Claim::Address)).chain(routes)
}

/// The prefix with its host bits cleared: `10.42.0.9/24` is
/// `10.42.0.0/24`.
fn canonical(n: IpNet) -> IpNet {
    let addr = match n.addr {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - n.prefix_len.min(32) as u32).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - n.prefix_len.min(128) as u32).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    };
    IpNet::new(addr, n.prefix_len)
}

/// Puts `r` under `k` if it's the best record there so far.
fn offer<'a, K: Eq + Hash>(me: &NodeRecord, m: &mut HashMap<K, &'a NodeRecord>, k: K, r: &'a NodeRecord) {
    let best = m.entry(k).or_insert(r);
    if rank(me, r, best).is_lt() {
        *best = r;
    }
}

/// Orders records claiming the same address or route, best first:
/// records from our own GitHub Actions run attempt, so that concurrent
/// runs, whose default addresses and routes collide, form separate
/// meshes that agree on who is who, and so that an earlier attempt's
/// nodes, which are gone, don't displace this one's; then by node key.
/// The record's content breaks ties between records with the same key.
pub fn rank(me: &NodeRecord, a: &NodeRecord, b: &NodeRecord) -> Ordering {
    let foreign = |r: &NodeRecord| me.run_id.is_empty() || (&r.run_id, &r.run_attempt) != (&me.run_id, &me.run_attempt);
    let json = |r: &NodeRecord| serde_json::to_vec(r).unwrap_or_default();
    foreign(a).cmp(&foreign(b)).then(a.nodekey.cmp(&b.nodekey)).then_with(|| json(a).cmp(&json(b)))
}

/// Applies changes to a peer map, as [`Overlay`](crate::Overlay) does.
pub fn apply(peers: &mut HashMap<NodePublic, Peer>, changes: impl IntoIterator<Item = Change>) {
    for c in changes {
        match c {
            Change::Upsert(p) => {
                peers.insert(p.record.nodekey, p);
            }
            Change::Remove(k) => {
                peers.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod model_tests;

#[cfg(test)]
mod tests {
    use tailcat::DiscoPublic;

    use super::*;

    fn key(n: u8) -> NodePublic {
        format!("nodekey:{:064x}", n as u32 + 1).parse().unwrap()
    }

    /// Key `k` at 100.64.1.`ip`, from run 100 + `run`.
    fn record(k: u8, ip: u8, run: u8, index: u32) -> NodeRecord {
        NodeRecord {
            index,
            nodekey: key(k),
            discokey: format!("discokey:{:064x}", k as u32 + 1).parse::<DiscoPublic>().unwrap(),
            overlay_ip: IpAddr::from([100, 64, 1, ip]),
            derp_region: 1,
            derp: None,
            routes: Vec::new(),
            endpoints: Vec::new(),
            os: String::new(),
            arch: String::new(),
            run_id: format!("{}", 100 + run),
            run_attempt: "1".into(),
            jwt: String::new(),
        }
    }

    fn routing(r: NodeRecord, routes: &[&str]) -> NodeRecord {
        NodeRecord { routes: routes.iter().map(|r| r.to_string()).collect(), ..r }
    }

    /// At 100.64.1.0, routing 10.42.9.0/24 and 100.64.1.9.
    fn me() -> NodeRecord {
        routing(record(0, 0, 0, 0), &["10.42.9.0/24", "100.64.1.9"])
    }

    /// `r` as a peer routed `nets`.
    fn peer(r: &NodeRecord, nets: &[&str]) -> Peer {
        Peer { record: r.clone(), allowed_ips: nets.iter().map(|n| n.parse().unwrap()).collect() }
    }

    fn poll(peers: &mut HashMap<NodePublic, Peer>, polled: &[NodeRecord]) {
        let changes = reconcile(&me(), peers, polled);
        apply(peers, changes);
    }

    fn from_scratch(polled: &[NodeRecord]) -> Vec<Peer> {
        let mut peers = HashMap::new();
        poll(&mut peers, polled);
        let mut v: Vec<Peer> = peers.into_values().collect();
        v.sort_by_key(|p| p.record.nodekey);
        v
    }

    #[test]
    fn duplicate_addresses_do_not_flap() {
        let (a, b) = (record(1, 1, 0, 1), record(2, 1, 0, 1));
        let mut peers = HashMap::new();
        for _ in 0..3 {
            poll(&mut peers, &[a.clone(), b.clone()]);
            assert_eq!(peers.values().collect::<Vec<_>>(), [&peer(&a, &["100.64.1.1"])], "the lower key wins");
        }
        assert_eq!(reconcile(&me(), &peers, &[b.clone(), a.clone()]), []);
    }

    #[test]
    fn our_own_run_wins_an_address() {
        let ours = record(5, 1, 0, 1);
        let theirs = record(1, 1, 1, 1);
        assert_eq!(from_scratch(&[theirs, ours.clone()]), [peer(&ours, &["100.64.1.1"])]);
    }

    /// An earlier attempt of our run is another run: its nodes are gone.
    #[test]
    fn our_own_attempt_wins_an_address() {
        let ours = record(5, 1, 0, 1);
        let earlier = NodeRecord { run_attempt: "0".into(), ..record(1, 1, 0, 1) };
        assert_eq!(from_scratch(&[earlier, ours.clone()]), [peer(&ours, &["100.64.1.1"])]);
    }

    /// Node 1 of our run and node 2 of another both route 10.42.1.0/24:
    /// ours gets it, where the engine alone would pick the lower key.
    #[test]
    fn our_own_run_wins_a_route() {
        let ours = routing(record(5, 1, 0, 1), &["10.42.1.0/24"]);
        let theirs = routing(record(1, 2, 1, 2), &["10.42.1.0/24", "10.42.2.0/24"]);
        assert_eq!(
            from_scratch(&[theirs.clone(), ours.clone()]),
            [peer(&theirs, &["100.64.1.2", "10.42.2.0/24"]), peer(&ours, &["100.64.1.1", "10.42.1.0/24"])]
        );
    }

    /// A route to another peer's address doesn't take it, however the
    /// two rank; and one prefix written two ways is still one prefix.
    #[test]
    fn addresses_beat_routes() {
        let a = record(5, 3, 1, 3);
        let b = routing(record(1, 1, 0, 1), &["100.64.1.3/32", "10.42.0.9/24"]);
        let c = routing(record(2, 2, 0, 2), &["10.42.0.0/24"]);
        assert_eq!(
            from_scratch(&[a.clone(), b.clone(), c.clone()]),
            [peer(&b, &["100.64.1.1", "10.42.0.0/24"]), peer(&c, &["100.64.1.2"]), peer(&a, &["100.64.1.3"])]
        );
    }

    /// Our address and routes are never a peer's, and a record at either
    /// is ignored.
    #[test]
    fn what_we_claim_is_ours() {
        let squatter = record(3, 0, 1, 0);
        let at_our_route = record(4, 9, 0, 9);
        let greedy = routing(record(1, 1, 0, 1), &["100.64.1.0", "10.42.9.0/24", "10.42.0.0/16"]);
        assert_eq!(
            from_scratch(&[me(), squatter, at_our_route, greedy.clone()]),
            [peer(&greedy, &["100.64.1.1", "10.42.0.0/16"])]
        );
    }

    #[test]
    fn missing_peers_are_removed() {
        let (a, b) = (record(1, 1, 0, 1), record(2, 2, 0, 2));
        let mut peers = HashMap::new();
        poll(&mut peers, &[a.clone(), b.clone()]);
        assert_eq!(reconcile(&me(), &peers, std::slice::from_ref(&b)), [Change::Remove(a.nodekey)]);
        let a2 = record(3, 1, 0, 1);
        assert_eq!(
            reconcile(&me(), &peers, &[a2.clone(), b.clone()]),
            [Change::Remove(a.nodekey), Change::Upsert(peer(&a2, &["100.64.1.1"]))]
        );
        let moved = record(2, 3, 0, 2);
        assert_eq!(
            reconcile(&me(), &peers, &[a.clone(), moved.clone()]),
            [Change::Upsert(peer(&moved, &["100.64.1.3"]))]
        );
    }
}
