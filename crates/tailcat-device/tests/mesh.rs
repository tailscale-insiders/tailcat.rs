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

async fn node(i: u32, dev: &DevDerp) -> Node {
    let private = NodePrivate::generate();
    let ip: IpAddr = format!("100.64.1.{i}").parse().unwrap();
    let record = NodeRecord {
        index: i,
        nodekey: private.public(),
        discokey: private.disco_private().public(),
        overlay_ip: ip,
        derp_region: 0,
        derp: Some(dev.region.clone()),
        routes: vec![],
        endpoints: vec![],
        os: String::new(),
        arch: String::new(),
        run_id: String::new(),
        run_attempt: String::new(),
        jwt: String::new(),
    };
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
    // Every node sends to every other; each packet must arrive intact at
    // exactly its destination.
    for (a, b) in [(0, 1), (1, 2), (2, 0), (0, 2)] {
        let msg = format!("hello {a}->{b}");
        let pkt = udp(nodes[a].ip, nodes[b].ip, msg.as_bytes());
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
}
