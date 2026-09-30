//! Model-based tests of the engine's peer tables, driven by Hegel. The
//! owner adds, reconfigures and removes peers with overlapping allowed
//! IPs, and sets our own prefixes, while simulated peers send packets
//! from every address, some held in flight across the changes, and the
//! engine sends to every address.
//! Each packet delivered, either way, is checked against the peer that
//! owns its address; the tables are checked against the configuration.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use hegel::TestCase;
use hegel::generators as gs;

use super::*;

const PEERS: usize = 3;

fn prefixes() -> [IpNet; 7] {
    ["10.0.0.1/32", "10.0.0.2/32", "10.0.0.0/30", "10.0.0.0/24", "0.0.0.0/0", "fd00::1/128", "fd00::/64"]
        .map(|p| p.parse().unwrap())
}

fn addrs() -> [IpAddr; 6] {
    ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.1.1", "fd00::1", "fd00::2"].map(|a| a.parse().unwrap())
}

/// A deterministic key, so that Hegel can replay and shrink.
fn private(n: u8) -> NodePrivate {
    NodePrivate::from_bytes([n + 1; 32])
}

/// A minimal IP header from `src` to `dst`, plus a payload.
fn packet(src: IpAddr, dst: IpAddr, payload: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
            p[2..4].copy_from_slice(&(20 + payload.len() as u16).to_be_bytes());
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(payload);
            p
        }
        (s, d) => {
            let v6 = |a: IpAddr| match a {
                IpAddr::V6(a) => a,
                IpAddr::V4(a) => a.to_ipv6_mapped(),
            };
            let mut p = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
            p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            p.extend_from_slice(&v6(s).octets());
            p.extend_from_slice(&v6(d).octets());
            p.extend_from_slice(payload);
            p
        }
    }
}

fn src_of(p: &[u8]) -> IpAddr {
    match p[0] >> 4 {
        4 => IpAddr::from(<[u8; 4]>::try_from(&p[12..16]).unwrap()),
        _ => IpAddr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap()),
    }
}

/// A simulated peer: its tunnel to us, made for one of our sessions.
struct Remote {
    key: NodePrivate,
    tunn: Option<(Tunn, Option<u32>)>,
}

struct Mesh {
    rt: tokio::runtime::Runtime,
    engine: Arc<Engine>,
    key: NodePrivate,
    rx: mpsc::Receiver<InboundPacket>,
    remotes: Vec<Remote>,
    /// The owner's configuration of each peer.
    configs: HashMap<NodePublic, PeerConfig>,
    /// Our own prefixes, as the owner last set them.
    local: Vec<IpNet>,
    /// Packets remotes sent that haven't arrived yet.
    held: Vec<(usize, Vec<u8>)>,
    /// Packets remotes received from us.
    delivered: Vec<(usize, Vec<u8>)>,
    serial: u32,
}

impl Mesh {
    fn new() -> Mesh {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let key = private(100);
        let (engine, rx) = {
            let _rt = rt.enter();
            let (ms, wg_rx) = MagicSock::offline(key.clone(), true);
            Engine::start(&key, ms, wg_rx, None, None)
        };
        let remotes = (0..PEERS as u8).map(|i| Remote { key: private(i), tunn: None }).collect();
        Mesh {
            rt,
            engine,
            key,
            rx,
            remotes,
            configs: HashMap::new(),
            local: Vec::new(),
            held: Vec::new(),
            delivered: Vec::new(),
            serial: 0,
        }
    }

    fn draw_remote(tc: &TestCase) -> usize {
        tc.draw_named("peer", gs::integers::<usize>().max_value(PEERS - 1))
    }

    fn draw_addr(tc: &TestCase) -> IpAddr {
        addrs()[tc.draw_named("addr", gs::integers::<usize>().max_value(addrs().len() - 1))]
    }

    /// The peer that owns `ip`: the most specific match, then the lowest
    /// key; but none if one of our own prefixes matches as specifically.
    fn owner(&self, ip: IpAddr) -> Option<NodePublic> {
        let len = |nets: &[IpNet]| nets.iter().filter(|n| n.contains(&ip)).map(|n| n.prefix_len).max();
        let mut best: Vec<(u8, NodePublic)> =
            self.configs.iter().filter_map(|(k, c)| Some((len(&c.allowed_ips)?, *k))).collect();
        best.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        best.first().filter(|(l, _)| len(&self.local).is_none_or(|ours| ours < *l)).map(|(_, k)| *k)
    }

    fn index_of(&self, k: &NodePublic) -> Option<u32> {
        self.engine.peer(k).map(|p| p.index)
    }

    /// Remote `i`'s tunnel, made anew if our session for it changed.
    fn tunn(&mut self, i: usize) -> &mut Tunn {
        let k = self.remotes[i].key.public();
        let index = self.index_of(&k);
        let psk = self.configs.get(&k).map_or(PresharedKey::default(), |c| c.preshared_key);
        let r = &mut self.remotes[i];
        if r.tunn.as_ref().is_none_or(|(_, at)| *at != index) {
            let t =
                Tunn::new(r.key.x25519(), self.key.public().x25519(), psk.for_wireguard(), None, i as u32 + 1, None);
            r.tunn = Some((t, index));
        }
        &mut r.tunn.as_mut().unwrap().0
    }

    /// Remote `i` encrypts `pkt`, returning what it puts on the wire.
    fn encrypt(&mut self, i: usize, pkt: &[u8]) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; pkt.len() + 148];
        match self.tunn(i).encapsulate(pkt, &mut buf) {
            TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
            _ => None,
        }
    }

    /// Delivers a packet from remote `i` to the engine, then everything
    /// that bounces back and forth until both sides are quiet.
    fn pump(&mut self, i: usize, wire: Vec<u8>) {
        let mut to_engine = vec![(i, wire)];
        let mut rounds = 0;
        while !to_engine.is_empty() {
            rounds += 1;
            assert!(rounds < 20, "packets bounce forever");
            for (i, data) in std::mem::take(&mut to_engine) {
                let pkt = WireguardPacket { peer: Some(self.remotes[i].key.public()), src: PathAddr::Derp(1), data };
                self.rt.block_on(self.engine.handle(pkt));
            }
            to_engine = self.flush_sent();
        }
    }

    /// Hands the engine's sent packets to their remotes, returning their
    /// replies.
    fn flush_sent(&mut self) -> Vec<(usize, Vec<u8>)> {
        let sent = std::mem::take(&mut *self.engine.sent.lock().unwrap());
        let mut replies = Vec::new();
        for (k, data) in sent {
            let i = self.remotes.iter().position(|r| r.key.public() == k).expect("sent to a stranger");
            let mut buf = vec![0u8; 65536];
            let t = self.tunn(i);
            match t.decapsulate(None, &data, &mut buf) {
                TunnResult::WriteToNetwork(b) => {
                    replies.push((i, b.to_vec()));
                    while let TunnResult::WriteToNetwork(b) = t.decapsulate(None, &[], &mut buf) {
                        replies.push((i, b.to_vec()));
                    }
                }
                TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) if !b.is_empty() => {
                    self.delivered.push((i, b.to_vec()))
                }
                _ => {}
            }
        }
        replies
    }

    /// The owner configures remote `i`'s peer.
    fn configure(&mut self, i: usize, cfg: PeerConfig) {
        let k = self.remotes[i].key.public();
        self.engine.upsert_peer(k, cfg.clone());
        self.configs.insert(k, cfg);
    }

    /// The owner sets our own prefixes.
    fn set_local(&mut self, local: Vec<IpNet>) {
        self.engine.set_local_ips(local.clone());
        self.local = local;
    }

    /// Remote `i` sends a packet from `src`, returning what reached us.
    fn send_from_addr(&mut self, i: usize, src: IpAddr) -> Vec<InboundPacket> {
        let payload = self.next_payload();
        let pkt = packet(src, "10.9.9.9".parse().unwrap(), &payload);
        if let Some(wire) = self.encrypt(i, &pkt) {
            self.pump(i, wire);
        }
        let got = self.check_inbound();
        let k = self.remotes[i].key.public();
        if self.owner(src) == Some(k) && self.held.iter().all(|(j, _)| *j != i) {
            assert!(got.iter().any(|p| p.data == pkt), "a packet from owner {} of {src} was lost", k.short_string());
        }
        got
    }

    /// We send a packet to `dst`, returning the remotes it reached.
    fn send_to_addr(&mut self, dst: IpAddr) -> Vec<NodePublic> {
        let src = if dst.is_ipv4() { IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)) } else { IpAddr::V6(Ipv6Addr::LOCALHOST) };
        let payload = self.next_payload();
        let pkt = packet(src, dst, &payload);
        self.delivered.clear();
        self.engine.send_ip(&pkt);
        let owner = self.owner(dst);
        for (k, _) in self.engine.sent.lock().unwrap().iter() {
            assert_eq!(Some(*k), owner, "a packet for {dst} went to {}", k.short_string());
        }
        let replies = self.flush_sent();
        for (i, wire) in replies {
            self.pump(i, wire);
        }
        self.check_inbound();
        let got: Vec<NodePublic> =
            self.delivered.iter().filter(|(_, p)| *p == pkt).map(|(i, _)| self.remotes[*i].key.public()).collect();
        assert_eq!(got, Vec::from_iter(owner), "a packet for {dst}");
        got
    }

    fn next_payload(&mut self) -> Vec<u8> {
        self.serial += 1;
        self.serial.to_be_bytes().to_vec()
    }

    /// Checks what reached us: each packet from the peer that owns its
    /// source address.
    fn check_inbound(&mut self) -> Vec<InboundPacket> {
        let mut got = Vec::new();
        while let Ok(p) = self.rx.try_recv() {
            let src = src_of(&p.data);
            assert_eq!(self.owner(src), Some(p.peer), "a packet from {src} was taken from {}", p.peer.short_string());
            got.push(p);
        }
        got
    }
}

#[hegel::state_machine]
impl Mesh {
    /// The owner adds or reconfigures a peer; a changed pre-shared key
    /// or keepalive gives it a new session.
    #[rule]
    fn upsert(&mut self, tc: TestCase) {
        let i = Self::draw_remote(&tc);
        let mask = tc.draw_named("prefixes", gs::integers::<u8>().max_value((1 << prefixes().len()) - 1));
        let allowed_ips =
            prefixes().into_iter().enumerate().filter(|(b, _)| mask >> b & 1 == 1).map(|(_, p)| p).collect();
        let preshared_key = if tc.draw_named("psk", gs::booleans()) {
            PresharedKey::from_bytes([9; 32])
        } else {
            PresharedKey::default()
        };
        let persistent_keepalive = tc.draw_named("keepalive", gs::booleans()).then_some(25);
        self.configure(i, PeerConfig { allowed_ips, preshared_key, persistent_keepalive });
    }

    /// The owner sets our own prefixes, from the same set as peers'.
    #[rule]
    fn set_local_ips(&mut self, tc: TestCase) {
        let mask = tc.draw_named("local", gs::integers::<u8>().max_value((1 << prefixes().len()) - 1));
        self.set_local(
            prefixes().into_iter().enumerate().filter(|(b, _)| mask >> b & 1 == 1).map(|(_, p)| p).collect(),
        );
    }

    #[rule]
    fn remove(&mut self, tc: TestCase) {
        let k = self.remotes[Self::draw_remote(&tc)].key.public();
        assert_eq!(self.engine.remove_peer(&k), self.configs.remove(&k).is_some());
    }

    /// A remote sends a packet from any address; it arrives if the
    /// remote owns that address, unless it's waiting on a held handshake.
    #[rule]
    fn send_from(&mut self, tc: TestCase) {
        self.send_from_addr(Self::draw_remote(&tc), Self::draw_addr(&tc));
    }

    /// A remote sends a packet that is held up in flight.
    #[rule]
    fn hold(&mut self, tc: TestCase) {
        let i = Self::draw_remote(&tc);
        let src = Self::draw_addr(&tc);
        let payload = self.next_payload();
        if let Some(wire) = self.encrypt(i, &packet(src, "10.9.9.9".parse().unwrap(), &payload)) {
            self.held.push((i, wire));
        }
    }

    #[rule]
    fn release(&mut self, tc: TestCase) {
        if self.held.is_empty() {
            return;
        }
        let j = tc.draw_named("held", gs::integers::<usize>().max_value(self.held.len() - 1));
        let (i, wire) = self.held.remove(j);
        self.pump(i, wire);
        self.check_inbound();
    }

    /// We send to any address; only its owner gets it, and it does.
    #[rule]
    fn send_to(&mut self, tc: TestCase) {
        self.send_to_addr(Self::draw_addr(&tc));
    }

    #[invariant(always_run)]
    fn tables_match_the_configuration(&self, _: TestCase) {
        let peers = self.engine.peers.lock().unwrap();
        assert_eq!(peers.by_key.len(), self.configs.len());
        assert_eq!(peers.by_index.len(), peers.by_key.len(), "stale sessions are indexed");
        for (k, c) in &self.configs {
            let p = peers.by_key.get(k).expect("configured peer missing");
            assert_eq!(p.key, *k);
            assert_eq!(p.cfg.lock().unwrap().allowed_ips, c.allowed_ips);
            assert!(peers.by_index.get(&p.index).is_some_and(|q| Arc::ptr_eq(p, q)), "{k} isn't indexed");
        }
    }
}

#[hegel::test(test_cases = 300)]
fn engine_peers_state_machine(tc: TestCase) {
    hegel::stateful::machine(Mesh::new()).steps(30).run(tc);
}

fn allow(prefixes: &[&str]) -> PeerConfig {
    PeerConfig {
        allowed_ips: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
        preshared_key: PresharedKey::default(),
        persistent_keepalive: None,
    }
}

/// The bug the state machine found, with a wider prefix rather than an
/// equal one: a peer routing a subnet could send from any address in
/// it, such as another peer's overlay IP, which we route to that peer.
#[test]
fn a_peer_cannot_send_from_another_peers_address() {
    let mut m = Mesh::new();
    m.configure(0, allow(&["10.0.0.1/32"]));
    m.configure(1, allow(&["10.0.0.2/32", "10.0.0.0/24"]));
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert!(m.send_from_addr(1, ip("10.0.0.1")).is_empty(), "peer 1 spoofed peer 0");
    assert_eq!(m.send_from_addr(1, ip("10.0.0.3")).len(), 1);
    assert_eq!(m.send_from_addr(0, ip("10.0.0.1")).len(), 1);
}

/// A peer routed a prefix around our address can't send from it, and
/// isn't sent what's for it; nor is one routed our address itself. One
/// routed an address inside one of our prefixes gets that address.
#[test]
fn our_own_prefixes_are_ours() {
    let mut m = Mesh::new();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    m.set_local(vec!["10.0.0.1/32".parse().unwrap(), "fd00::/64".parse().unwrap()]);
    m.configure(0, allow(&["10.0.0.0/24", "0.0.0.0/0"]));
    m.configure(1, allow(&["10.0.0.1/32", "fd00::/64", "fd00::2/128"]));
    for i in [0, 1] {
        assert!(m.send_from_addr(i, ip("10.0.0.1")).is_empty(), "peer {i} sent from our address");
        assert!(m.send_from_addr(i, ip("fd00::1")).is_empty(), "peer {i} sent from our prefix");
    }
    assert_eq!(m.send_to_addr(ip("10.0.0.1")), []);
    assert_eq!(m.send_to_addr(ip("fd00::1")), []);
    assert_eq!(m.send_from_addr(0, ip("10.0.0.3")).len(), 1);
    assert_eq!(m.send_from_addr(1, ip("fd00::2")).len(), 1);
    assert_eq!(m.send_to_addr(ip("fd00::2")), [m.remotes[1].key.public()]);
}

/// Peers routing the same prefix share it by key, not by hash order,
/// which changes as peers come and go; replies go the same way.
#[test]
fn equal_prefixes_go_to_the_lower_key() {
    let mut m = Mesh::new();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let (low, high) = if m.remotes[0].key.public() < m.remotes[1].key.public() { (0, 1) } else { (1, 0) };
    for i in [high, low] {
        m.configure(i, allow(&["10.0.0.0/24"]));
    }
    for _ in 0..4 {
        assert_eq!(m.send_to_addr(ip("10.0.0.7")), [m.remotes[low].key.public()]);
        m.configure(2, allow(&["10.0.1.0/24"]));
        m.engine.remove_peer(&m.remotes[2].key.public());
        m.configs.remove(&m.remotes[2].key.public());
    }
    assert!(m.send_from_addr(high, ip("10.0.0.7")).is_empty());
    assert_eq!(m.send_from_addr(low, ip("10.0.0.7")).len(), 1);
}
