//! A state-machine test of an overlay's peers, driven by Hegel: random
//! polls, adds and removals, checking that the overlay, the WireGuard
//! engine and magicsock always know the same peers, one per address.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use hegel::TestCase;
use hegel::generators as gs;
use tailcat::{DerpMap, DerpNode, DerpRegion, DiscoPublic, NodePrivate, NodePublic};
use tailcat_device::{DeviceKey, NodeRecord, Overlay, OverlayConfig};

const KEYS: u8 = 6;

/// A relay that refuses connections: nothing here needs one to work.
fn region(host: &str) -> DerpRegion {
    DerpRegion {
        region_id: 900,
        region_code: "test".into(),
        nodes: vec![DerpNode { name: host.into(), host_name: host.into(), ..Default::default() }],
        ..Default::default()
    }
}

fn key(k: u8) -> NodePublic {
    format!("nodekey:{:064x}", k as u32 + 1).parse().unwrap()
}

struct Mesh {
    rt: tokio::runtime::Runtime,
    overlay: Arc<Overlay>,
    dm: DerpMap,
}

impl Mesh {
    fn new() -> Mesh {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let private = NodePrivate::generate();
        let record =
            NodeRecord { derp: Some(region("127.0.0.1")), ..NodeRecord::new(0, &private, [100, 64, 1, 0].into()) };
        let overlay = rt
            .block_on(Overlay::start(OverlayConfig {
                key: DeviceKey { private, record },
                derp_map: DerpMap::default(),
                listen_port: 0,
                overlay_prefix: "100.64.0.0/16".parse().unwrap(),
                enable_udp: false,
            }))
            .unwrap();
        let dm =
            DerpMap { regions: [(1, DerpRegion { region_id: 1, ..region("127.0.0.1") })].into(), ..Default::default() };
        Mesh { rt, overlay, dm }
    }

    /// A record from a small space, so that collisions are common: its
    /// key, address (0 is ours), home region (embedded, in the map, or
    /// unknown) and run.
    fn draw_record(&self, tc: &TestCase) -> NodeRecord {
        let k = tc.draw(gs::integers::<u8>().max_value(KEYS - 1));
        let ip = tc.draw(gs::integers::<u8>().max_value(3));
        let (derp, derp_region) = match tc.draw(gs::integers::<u8>().max_value(3)) {
            0 => (Some(region("127.0.0.1")), 0),
            1 => (Some(region("127.0.0.2")), 0),
            2 => (None, 1),
            _ => (None, 5),
        };
        NodeRecord {
            index: ip as u32,
            nodekey: key(k),
            discokey: format!("discokey:{:064x}", k as u32 + 1).parse::<DiscoPublic>().unwrap(),
            overlay_ip: IpAddr::from([100, 64, 1, ip]),
            derp_region,
            derp,
            routes: Vec::new(),
            endpoints: Vec::new(),
            os: String::new(),
            arch: String::new(),
            run_id: tc.draw(gs::sampled_from(vec!["", "7", "8"])).into(),
            run_attempt: String::new(),
            jwt: String::new(),
        }
    }

    fn peers(&self) -> Vec<(NodePublic, IpAddr, u32)> {
        self.overlay.status().into_iter().map(|p| (p.nodekey, p.overlay_ip, p.index)).collect()
    }
}

#[hegel::state_machine]
impl Mesh {
    /// A poll returns some records, one per key; the peers are some of
    /// them, whatever came before, and polling them again changes
    /// nothing.
    #[rule]
    fn poll(&mut self, tc: TestCase) {
        let n = tc.draw(gs::integers::<usize>().max_value(6));
        let mut keys = HashSet::new();
        let recs: Vec<NodeRecord> = (0..n).map(|_| self.draw_record(&tc)).filter(|r| keys.insert(r.nodekey)).collect();
        let _rt = self.rt.enter();
        self.overlay.sync(&recs, &self.dm);
        let before = self.peers();
        for (k, ..) in &before {
            assert!(keys.contains(k), "{k} is still a peer, but wasn't polled");
        }
        let mut reversed = recs.clone();
        reversed.reverse();
        self.overlay.sync(&reversed, &self.dm);
        assert_eq!(self.peers(), before, "polling {recs:?} again changed the peers");
    }

    #[rule]
    fn add(&mut self, tc: TestCase) {
        let r = self.draw_record(&tc);
        let _rt = self.rt.enter();
        let _ = self.overlay.add_peer(&r, &self.dm);
    }

    #[rule]
    fn remove(&mut self, tc: TestCase) {
        let k = key(tc.draw(gs::integers::<u8>().max_value(KEYS - 1)));
        let _rt = self.rt.enter();
        self.overlay.remove_peer(&k);
    }

    #[invariant(always_run)]
    fn everyone_agrees_on_the_peers(&self, _: TestCase) {
        let peers: HashSet<NodePublic> = self.overlay.status().iter().map(|p| p.nodekey).collect();
        assert_eq!(peers.len(), self.overlay.peer_count());
        for k in (0..KEYS).map(key) {
            let (overlay, engine, ms) = (
                peers.contains(&k),
                self.overlay.engine().peer_stats(&k).is_some(),
                self.overlay.magicsock().peer_path(&k).is_some(),
            );
            assert!(overlay == engine && engine == ms, "{k}: overlay {overlay}, engine {engine}, magicsock {ms}");
        }
    }

    #[invariant(always_run)]
    fn one_peer_per_address_and_never_ours(&self, _: TestCase) {
        let me = self.overlay.record();
        let mut ips = HashSet::new();
        for p in self.overlay.status() {
            assert!(ips.insert(p.overlay_ip), "two peers at {}", p.overlay_ip);
            assert_ne!(p.overlay_ip, me.overlay_ip);
            assert_ne!(p.nodekey, me.nodekey);
        }
    }
}

#[hegel::test(test_cases = 100)]
fn overlay_peers_state_machine(tc: TestCase) {
    hegel::stateful::machine(Mesh::new()).steps(30).run(tc);
}
