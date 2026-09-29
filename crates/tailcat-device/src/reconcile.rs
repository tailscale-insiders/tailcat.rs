//! Deciding which records become peers.
//!
//! Every poll of a [`Source`](crate::source::Source) returns every record
//! found so far, and several may claim one overlay address: with
//! `--scope branch`, node `i` of two concurrent runs gets the same
//! default IP, and a re-initialized node leaves its old record behind.
//! An address can only route to one peer, so [`reconcile`] picks a
//! winner for each by a fixed order. That makes the result depend only
//! on what was polled, never on the order records arrive in, and a
//! repeated poll changes nothing: peers aren't torn down and re-added
//! every few seconds.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;

use tailcat::NodePublic;

use crate::record::NodeRecord;

/// One step towards the peers a poll calls for.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // short-lived, and rarely more than a few
pub enum Change {
    /// Add the peer, or update it to this record.
    Upsert(NodeRecord),
    Remove(NodePublic),
}

/// Returns the changes that turn `current` into the peers `polled` calls
/// for, removals first. They are:
///
/// - for each overlay address claimed by a polled record, the best of
///   those records by [`rank`];
/// - peers missing from the poll (for example while their record file is
///   being rewritten), where no polled record claims their address.
///
/// Records with our node key or our overlay IP never become peers.
pub fn reconcile(me: &NodeRecord, current: &HashMap<NodePublic, NodeRecord>, polled: &[NodeRecord]) -> Vec<Change> {
    let mine = |r: &NodeRecord| r.nodekey == me.nodekey || r.overlay_ip == me.overlay_ip;
    let mut by_key: HashMap<NodePublic, &NodeRecord> = HashMap::new();
    for r in polled {
        offer(me, &mut by_key, r.nodekey, r);
    }
    let mut by_ip: HashMap<IpAddr, &NodeRecord> = HashMap::new();
    for r in by_key.values().filter(|r| !mine(r)) {
        offer(me, &mut by_ip, r.overlay_ip, r);
    }
    let claimed: HashSet<IpAddr> = by_ip.keys().copied().collect();
    for p in current.values() {
        if !by_key.contains_key(&p.nodekey) && !claimed.contains(&p.overlay_ip) && !mine(p) {
            offer(me, &mut by_ip, p.overlay_ip, p);
        }
    }
    let want: HashMap<NodePublic, &NodeRecord> = by_ip.into_values().map(|r| (r.nodekey, r)).collect();

    let mut removed: Vec<NodePublic> = current.keys().filter(|k| !want.contains_key(k)).copied().collect();
    removed.sort();
    let mut upserted: Vec<&NodeRecord> = want.into_values().filter(|r| current.get(&r.nodekey) != Some(*r)).collect();
    upserted.sort_by_key(|r| r.nodekey);
    removed.into_iter().map(Change::Remove).chain(upserted.into_iter().cloned().map(Change::Upsert)).collect()
}

/// Puts `r` under `k` if it's the best record there so far.
fn offer<'a, K: Eq + Hash>(me: &NodeRecord, m: &mut HashMap<K, &'a NodeRecord>, k: K, r: &'a NodeRecord) {
    let best = m.entry(k).or_insert(r);
    if rank(me, r, best).is_lt() {
        *best = r;
    }
}

/// Orders records claiming the same address, best first: records from
/// our own GitHub Actions run, so that concurrent runs, whose default
/// addresses collide, form separate meshes that agree on who is who;
/// then by node key. The record's content breaks ties between records
/// with the same key.
pub fn rank(me: &NodeRecord, a: &NodeRecord, b: &NodeRecord) -> Ordering {
    let foreign = |r: &NodeRecord| me.run_id.is_empty() || r.run_id != me.run_id;
    let json = |r: &NodeRecord| serde_json::to_vec(r).unwrap_or_default();
    foreign(a).cmp(&foreign(b)).then(a.nodekey.cmp(&b.nodekey)).then_with(|| json(a).cmp(&json(b)))
}

/// Applies changes to a peer map, as [`Overlay`](crate::Overlay) does.
pub fn apply(peers: &mut HashMap<NodePublic, NodeRecord>, changes: impl IntoIterator<Item = Change>) {
    for c in changes {
        match c {
            Change::Upsert(r) => {
                peers.insert(r.nodekey, r);
            }
            Change::Remove(k) => {
                peers.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hegel::TestCase;
    use hegel::generators as gs;
    use tailcat::DiscoPublic;

    use super::*;

    /// A deterministic key, so that Hegel can replay and shrink.
    fn key(n: u8) -> NodePublic {
        format!("nodekey:{:064x}", n as u32 + 1).parse().unwrap()
    }

    /// A record with little variety, so that collisions are common: few
    /// keys, few addresses, two runs, and an index to tell versions of
    /// one key's record apart.
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

    fn me() -> NodeRecord {
        record(0, 0, 0, 0)
    }

    fn draw_record(tc: &TestCase) -> NodeRecord {
        record(
            tc.draw(gs::integers::<u8>().max_value(6)),
            tc.draw(gs::integers::<u8>().max_value(4)),
            tc.draw(gs::integers::<u8>().max_value(1)),
            tc.draw(gs::integers::<u32>().max_value(2)),
        )
    }

    fn draw_records(tc: &TestCase) -> Vec<NodeRecord> {
        let n = tc.draw(gs::integers::<usize>().max_value(8));
        (0..n).map(|_| draw_record(tc)).collect()
    }

    /// A valid peer map: reached by reconciling some earlier poll.
    fn draw_current(tc: &TestCase) -> HashMap<NodePublic, NodeRecord> {
        let mut peers = HashMap::new();
        apply(&mut peers, reconcile(&me(), &HashMap::new(), &draw_records(tc)));
        peers
    }

    fn poll(peers: &mut HashMap<NodePublic, NodeRecord>, polled: &[NodeRecord]) {
        let changes = reconcile(&me(), peers, polled);
        apply(peers, changes);
    }

    fn check_valid(peers: &HashMap<NodePublic, NodeRecord>) {
        let me = me();
        let mut ips = HashSet::new();
        for (k, r) in peers {
            assert_eq!(*k, r.nodekey);
            assert!(ips.insert(r.overlay_ip), "two peers at {}: {peers:?}", r.overlay_ip);
            assert_ne!(r.nodekey, me.nodekey, "we are our own peer");
            assert_ne!(r.overlay_ip, me.overlay_ip, "a peer has our address");
        }
    }

    #[hegel::test(test_cases = 500)]
    fn repeated_polls_change_nothing(tc: TestCase) {
        let mut peers = draw_current(&tc);
        let polled = draw_records(&tc);
        poll(&mut peers, &polled);
        assert_eq!(reconcile(&me(), &peers, &polled), [], "second poll of {polled:?}");
    }

    #[hegel::test(test_cases = 500)]
    fn poll_order_does_not_matter(tc: TestCase) {
        let peers = draw_current(&tc);
        let polled = draw_records(&tc);
        let mut shuffled = polled.clone();
        for i in (1..shuffled.len()).rev() {
            shuffled.swap(i, tc.draw(gs::integers::<usize>().max_value(i)));
        }
        assert_eq!(reconcile(&me(), &peers, &polled), reconcile(&me(), &peers, &shuffled));
    }

    #[hegel::test(test_cases = 500)]
    fn peers_have_unique_addresses_and_are_never_us(tc: TestCase) {
        let mut peers = draw_current(&tc);
        check_valid(&peers);
        // One record per key, as sources return them.
        let mut keys = HashSet::new();
        let polled: Vec<NodeRecord> = draw_records(&tc).into_iter().filter(|r| keys.insert(r.nodekey)).collect();
        poll(&mut peers, &polled);
        check_valid(&peers);
        // Every address a polled record claims goes to a polled record.
        for r in polled.iter().filter(|r| r.overlay_ip != me().overlay_ip && r.nodekey != me().nodekey) {
            let holder = peers.values().find(|p| p.overlay_ip == r.overlay_ip).expect("address unclaimed");
            assert!(polled.contains(holder), "{} went to {holder:?}, which wasn't polled", r.overlay_ip);
        }
    }

    #[test]
    fn duplicate_addresses_do_not_flap() {
        let (a, b) = (record(1, 1, 0, 1), record(2, 1, 0, 1));
        let mut peers = HashMap::new();
        for _ in 0..3 {
            poll(&mut peers, &[a.clone(), b.clone()]);
            assert_eq!(peers.values().collect::<Vec<_>>(), [&a], "the lower key wins");
        }
        assert_eq!(reconcile(&me(), &peers, &[b.clone(), a.clone()]), []);
    }

    #[test]
    fn our_own_run_wins_an_address() {
        let ours = record(5, 1, 0, 1);
        let theirs = record(1, 1, 1, 1);
        assert_eq!(reconcile(&me(), &HashMap::new(), &[theirs, ours.clone()]), [Change::Upsert(ours)]);
    }

    #[test]
    fn records_claiming_our_address_are_ignored() {
        let squatter = record(3, 0, 1, 0);
        assert_eq!(reconcile(&me(), &HashMap::new(), &[me(), squatter]), []);
    }

    #[test]
    fn missing_peers_stay_until_their_address_is_claimed() {
        let (a, b) = (record(1, 1, 0, 1), record(2, 2, 0, 2));
        let mut peers = HashMap::new();
        poll(&mut peers, &[a.clone(), b.clone()]);
        assert_eq!(reconcile(&me(), &peers, std::slice::from_ref(&b)), [], "a is kept while its record is missing");
        let a2 = record(3, 1, 0, 1);
        assert_eq!(
            reconcile(&me(), &peers, std::slice::from_ref(&a2)),
            [Change::Remove(a.nodekey), Change::Upsert(a2)]
        );
        let moved = record(2, 3, 0, 2);
        assert_eq!(reconcile(&me(), &peers, std::slice::from_ref(&moved)), [Change::Upsert(moved)]);
    }
}
