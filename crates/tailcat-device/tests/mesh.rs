//! A three-node mesh in one process: in-memory packet devices, meeting
//! through a local DERP relay.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tailcat::derp::server::DevDerp;
use tailcat::wg::IpNet;
use tailcat::{DerpMap, DerpNode, DerpRegion, NodePrivate};
use tailcat_device::overlay::EMBEDDED_REGION_BASE;
use tailcat_device::{ChannelDevice, DeviceKey, NodeRecord, Overlay, OverlayConfig, PacketDevice};
use tokio::sync::mpsc;

struct Node {
    overlay: Arc<Overlay>,
    inject: mpsc::Sender<Vec<u8>>,
    delivered: mpsc::Receiver<Vec<u8>>,
    ip: IpAddr,
}

/// Node `i` is at 100.64.1.`i`, and also routes 10.42.`i`.0/24.
fn record(i: u32, private: &NodePrivate, dev: &DevDerp) -> NodeRecord {
    NodeRecord {
        derp: Some(dev.region.clone()),
        routes: vec![format!("10.42.{i}.0/24")],
        ..NodeRecord::new(i, private, format!("100.64.1.{i}").parse().unwrap())
    }
}

async fn node(i: u32, dev: &DevDerp) -> Node {
    let private = NodePrivate::generate();
    let record = record(i, &private, dev);
    start(private, record).await
}

async fn start(private: NodePrivate, record: NodeRecord) -> Node {
    let ip = record.overlay_ip;
    let overlay = Overlay::start(OverlayConfig {
        key: DeviceKey { private, record },
        derp_map: DerpMap::default(),
        listen_port: 0,
        overlay_prefix: "100.64.0.0/16".parse().unwrap(),
        enable_udp: true,
    })
    .await
    .unwrap();
    assert!(overlay.wait_derp(Duration::from_secs(10)).await);
    let (d, inject, delivered) = ChannelDevice::new();
    tokio::spawn(overlay.clone().run(d));
    Node { overlay, inject, delivered, ip }
}

fn udp(src: IpAddr, dst: IpAddr, payload: &[u8]) -> Vec<u8> {
    tailcat::netstack::build_udp(SocketAddr::new(src, 4000), SocketAddr::new(dst, 5000), payload).unwrap()
}

#[tokio::test]
async fn three_node_mesh_routes_ipv4() {
    let dev = DevDerp::start_local().await.unwrap();
    let mut nodes = Vec::new();
    for i in 0..3 {
        nodes.push(node(i, &dev).await);
    }
    let records: Vec<NodeRecord> = nodes.iter().map(|n| n.overlay.record().clone()).collect();
    for n in &nodes {
        for r in &records {
            n.overlay.add_peer(r, &DerpMap::default()).unwrap();
        }
        assert_eq!(n.overlay.peer_count(), 2);
    }
    // Every node sends to every other, at its overlay IP or inside its
    // routed prefix; each packet must arrive intact at exactly its
    // destination.
    for (a, b, dst) in [(0, 1, nodes[1].ip), (1, 2, nodes[2].ip), (2, 0, nodes[0].ip), (0, 2, [10, 42, 2, 7].into())] {
        let msg = format!("hello {a}->{b}");
        let pkt = udp(nodes[a].ip, dst, msg.as_bytes());
        let mut got = None;
        for _ in 0..20 {
            nodes[a].inject.send(pkt.clone()).await.unwrap();
            if let Ok(Some(p)) = tokio::time::timeout(Duration::from_millis(500), nodes[b].delivered.recv()).await {
                got = Some(p);
                break;
            }
        }
        let got = got.unwrap_or_else(|| panic!("no packet {a}->{b}"));
        assert_eq!(got, pkt, "packet {a}->{b} altered");
        while let Ok(extra) = nodes[b].delivered.try_recv() {
            assert_eq!(extra, pkt, "unexpected extra packet at {b}");
        }
    }
    // A packet for an address outside the mesh goes nowhere.
    nodes[0].inject.send(udp(nodes[0].ip, "100.64.9.9".parse().unwrap(), b"lost")).await.unwrap();
    for n in nodes.iter_mut().skip(1) {
        assert!(tokio::time::timeout(Duration::from_millis(300), n.delivered.recv()).await.is_err());
    }
    let st = nodes[0].overlay.status();
    assert_eq!(st.len(), 2);
    assert!(st.iter().all(|p| p.handshake_age_secs.is_some()), "{st:?}");
    assert_eq!(st.iter().map(|p| p.index).collect::<Vec<_>>(), [1, 2], "ordered by index");
}

#[tokio::test]
async fn peer_updates() {
    let dev = DevDerp::start_local().await.unwrap();
    let o = node(0, &dev).await.overlay;
    let dm = DerpMap::default();
    assert!(!o.add_peer(o.record(), &dm).unwrap(), "our own record is ignored");
    assert_eq!(o.peer_count(), 0);

    let a = record(1, &NodePrivate::generate(), &dev);
    assert!(o.add_peer(&a, &dm).unwrap(), "new");
    assert!(!o.add_peer(&a, &dm).unwrap(), "unchanged");
    let rerouted = NodeRecord { routes: vec![], ..a.clone() };
    assert!(!o.add_peer(&rerouted, &dm).unwrap(), "updated");
    assert_eq!(o.peer_count(), 1);

    // A new key at a's address takes it over.
    let b = NodeRecord { index: 2, ..record(1, &NodePrivate::generate(), &dev) };
    assert!(o.add_peer(&b, &dm).unwrap());
    assert_eq!(o.peer_count(), 1);
    assert!(o.magicsock().peer_path(&a.nodekey).is_none());
    assert_eq!(o.status()[0].nodekey, b.nodekey);

    // A peer whose home region isn't known is refused, as is one at our
    // address.
    let lost = NodeRecord { derp: None, derp_region: 5, ..record(3, &NodePrivate::generate(), &dev) };
    assert!(o.add_peer(&lost, &dm).is_err());
    let squatter = record(0, &NodePrivate::generate(), &dev);
    assert!(o.add_peer(&squatter, &dm).is_err());
    assert_eq!(o.peer_count(), 1);

    assert!(o.remove_peer(&b.nodekey));
    assert!(!o.remove_peer(&b.nodekey));
    assert_eq!(o.peer_count(), 0);
    assert!(o.magicsock().peer_path(&b.nodekey).is_none());

    // The packet loop is already running.
    tokio::task::yield_now().await;
    let (d, _, _) = ChannelDevice::new();
    let err = o.clone().run(d).await.unwrap_err();
    assert!(err.to_string().contains("called twice"), "{err:#}");
}

/// Repeated polls of records that share an address settle on one peer,
/// and leave it alone.
#[tokio::test]
async fn duplicate_addresses_settle() {
    let dev = DevDerp::start_local().await.unwrap();
    // Node 1 of our run, and of another run: they collide at 100.64.1.1.
    let run = |r: NodeRecord, id: &str| NodeRecord { run_id: id.into(), ..r };
    let private = NodePrivate::generate();
    let me = start(private.clone(), run(record(0, &private, &dev), "7")).await;
    let private = NodePrivate::generate();
    let mut peer = start(private.clone(), run(record(1, &private, &dev), "7")).await;
    let theirs = run(record(1, &NodePrivate::generate(), &dev), "8");
    let squatter = run(record(0, &NodePrivate::generate(), &dev), "8");
    let (ours, dm) = (peer.overlay.record().clone(), DerpMap::default());
    me.overlay.sync(&[theirs.clone(), ours.clone(), squatter.clone()], &dm);
    peer.overlay.sync(&[me.overlay.record().clone()], &dm);
    assert!(exchange(&me, &mut peer).await, "no packet from node 0 to node 1");
    for recs in [[ours.clone(), theirs.clone(), squatter.clone()], [squatter.clone(), theirs.clone(), ours.clone()]] {
        me.overlay.sync(&recs, &dm);
        let st = me.overlay.status();
        assert_eq!(st.iter().map(|p| p.nodekey).collect::<Vec<_>>(), [ours.nodekey], "our own run's node wins");
        assert!(st[0].handshake_age_secs.is_some(), "the session was torn down");
    }
}

/// A node of our run with a lower key at our address takes it from us,
/// and the overlay says so until its record is gone; another run's node
/// there doesn't.
#[tokio::test]
async fn a_lost_address_is_reported() {
    let dev = DevDerp::start_local().await.unwrap();
    let run = |r: NodeRecord, id: &str| NodeRecord { run_id: id.into(), routes: Vec::new(), ..r };
    let private = NodePrivate::generate();
    let me = start(private.clone(), run(record(0, &private, &dev), "7")).await.overlay;
    let mine = me.record().clone();
    let lower = || std::iter::repeat_with(NodePrivate::generate).find(|k| k.public() < mine.nodekey).unwrap();
    let squatter = run(record(0, &lower(), &dev), "7");
    let foreign = run(record(0, &lower(), &dev), "8");
    let dm = DerpMap::default();
    me.sync(&[mine.clone(), foreign.clone()], &dm);
    assert_eq!(me.contested(), []);
    me.sync(&[mine.clone(), squatter.clone(), foreign.clone()], &dm);
    assert_eq!(me.contested(), [(IpNet::host(mine.overlay_ip), squatter.nodekey)]);
    assert_eq!(me.peer_count(), 0, "neither is a peer");
    me.sync(&[mine.clone(), foreign], &dm);
    assert_eq!(me.contested(), []);
}

/// Sends packets from `a` to `b` until one arrives.
async fn exchange(a: &Node, b: &mut Node) -> bool {
    let pkt = udp(a.ip, b.ip, b"hello");
    for _ in 0..20 {
        a.inject.send(pkt.clone()).await.unwrap();
        if let Ok(Some(p)) = tokio::time::timeout(Duration::from_millis(500), b.delivered.recv()).await {
            return p == pkt;
        }
    }
    false
}

/// Relays embedded in records are told apart by content, not by the IDs
/// they carry, which collide.
#[tokio::test]
async fn embedded_regions_get_their_own_ids() {
    let dev = DevDerp::start_local().await.unwrap();
    let o = node(0, &dev).await.overlay;
    let home = o.magicsock().home_region();
    assert!(home >= EMBEDDED_REGION_BASE, "{home}");
    let custom = |host: &str| DerpRegion {
        region_id: 900,
        region_code: "custom".into(),
        nodes: vec![DerpNode { name: host.into(), host_name: host.into(), ..Default::default() }],
        ..Default::default()
    };
    // The public map's region 1, which dev-derp regions also call 1.
    let public = DerpRegion { region_id: 1, region_code: "public".into(), ..custom("127.0.0.4") };
    let dm = DerpMap { regions: [(1, public)].into(), ..Default::default() };
    let peers = [
        NodeRecord { derp: Some(custom("127.0.0.2")), ..record(1, &NodePrivate::generate(), &dev) },
        NodeRecord { derp: Some(custom("127.0.0.3")), ..record(2, &NodePrivate::generate(), &dev) },
        NodeRecord { derp: None, derp_region: 1, ..record(3, &NodePrivate::generate(), &dev) },
        record(4, &NodePrivate::generate(), &dev),
    ];
    o.sync(&peers, &dm);
    let region = |i: usize| o.magicsock().peer_path(&peers[i].nodekey).unwrap().home_region;
    let (a, b, public, same_as_ours) = (region(0), region(1), region(2), region(3));
    assert_eq!(public, 1);
    assert_eq!(same_as_ours, home, "a peer embedding our relay is reached through our connection");
    assert!(a != b && a != home && b != home && a >= EMBEDDED_REGION_BASE && b >= EMBEDDED_REGION_BASE);
}

#[tokio::test]
async fn close_stops_the_packet_loop() {
    let dev = DevDerp::start_local().await.unwrap();
    let private = NodePrivate::generate();
    let o = Overlay::start(OverlayConfig {
        key: DeviceKey { record: record(0, &private, &dev), private },
        derp_map: DerpMap::default(),
        listen_port: 0,
        overlay_prefix: "100.64.0.0/16".parse().unwrap(),
        enable_udp: true,
    })
    .await
    .unwrap();
    let (d, _inject, _delivered) = ChannelDevice::new();
    let run = tokio::spawn(o.clone().run(d));
    tokio::task::yield_now().await;
    o.close();
    let res = tokio::time::timeout(Duration::from_secs(2), run).await.expect("the packet loop kept running");
    assert!(res.unwrap().is_ok());
    let weak = Arc::downgrade(&o);
    drop(o);
    assert!(weak.upgrade().is_none(), "the overlay outlived its last user");
}

/// A device that reads as closed.
struct Closed;

impl PacketDevice for Closed {
    async fn recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
    async fn send(&self, pkt: &[u8]) -> std::io::Result<usize> {
        Ok(pkt.len())
    }
}

#[tokio::test]
async fn a_closed_device_ends_the_packet_loop() {
    let dev = DevDerp::start_local().await.unwrap();
    let private = NodePrivate::generate();
    let o = Overlay::start(OverlayConfig {
        key: DeviceKey { record: record(0, &private, &dev), private },
        derp_map: DerpMap::default(),
        listen_port: 0,
        overlay_prefix: "100.64.0.0/16".parse().unwrap(),
        enable_udp: true,
    })
    .await
    .unwrap();
    let res = tokio::time::timeout(Duration::from_secs(2), o.run(Arc::new(Closed))).await.expect("spinning");
    assert!(format!("{:#}", res.unwrap_err()).contains("closed"));
}
