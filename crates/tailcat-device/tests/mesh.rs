//! A three-node mesh in one process: in-memory packet devices, meeting
//! through a local DERP relay.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tailcat::derp::server::DevDerp;
use tailcat::{DerpMap, NodePrivate};
use tailcat_device::{ChannelDevice, DeviceKey, NodeRecord, Overlay, OverlayConfig};
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
    assert!(!o.magicsock().has_peer(&a.nodekey));
    assert_eq!(o.status()[0].nodekey, b.nodekey);

    // A peer whose home region isn't known is refused.
    let lost = NodeRecord { derp: None, derp_region: 5, ..record(3, &NodePrivate::generate(), &dev) };
    assert!(o.add_peer(&lost, &dm).is_err());

    assert!(o.remove_peer(&b.nodekey));
    assert!(!o.remove_peer(&b.nodekey));
    assert_eq!(o.peer_count(), 0);
    assert!(!o.magicsock().has_peer(&b.nodekey));

    // The packet loop is already running.
    tokio::task::yield_now().await;
    let (d, _, _) = ChannelDevice::new();
    let err = o.clone().run(d).await.unwrap_err();
    assert!(err.to_string().contains("called twice"), "{err:#}");
}
