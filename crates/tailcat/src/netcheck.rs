//! Picking the nearest DERP region by latency: STUN probes to every
//! region's nodes over UDP, falling back to timing HTTPS requests to the
//! relays' `/derp/latency-check` endpoint when UDP is blocked.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::debug;

use crate::Result;
use crate::derpmap::{DerpMap, DerpNode};
use crate::stun;

const STUN_TIMEOUT: Duration = Duration::from_secs(3);
const HTTPS_TIMEOUT: Duration = Duration::from_secs(5);

/// The latency to each region that answered.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub region_latency: HashMap<i32, Duration>,
    /// Our public address as seen by the STUN servers, if any answered.
    pub global_v4: Option<SocketAddr>,
}

/// Measures the latency to every region of `dm`.
pub async fn report(dm: &DerpMap) -> Result<Report> {
    let mut rep = stun_report(dm).await;
    if rep.region_latency.is_empty() {
        debug!("netcheck: no STUN replies; trying HTTPS latency checks");
        rep.region_latency = https_report(dm).await;
    }
    Ok(rep)
}

/// Returns the lowest-latency region of `dm`, or `None` if no region
/// could be measured.
pub async fn pick_best_region(dm: &DerpMap) -> Result<Option<i32>> {
    let rep = report(dm).await?;
    Ok(rep
        .region_latency
        .iter()
        .filter(|(rid, _)| dm.regions.contains_key(rid))
        .min_by_key(|(_, d)| **d)
        .map(|(rid, _)| *rid))
}

fn measurable(dm: &DerpMap) -> impl Iterator<Item = (i32, &DerpNode)> {
    dm.regions
        .values()
        .filter(|r| !r.avoid && !r.no_measure_no_home)
        .flat_map(|r| r.nodes.iter().take(3).map(move |n| (r.region_id, n)))
}

async fn stun_report(dm: &DerpMap) -> Report {
    let mut rep = Report::default();
    let Ok(sock4) = UdpSocket::bind("0.0.0.0:0").await else {
        return rep;
    };
    let sock6 = UdpSocket::bind("[::]:0").await.ok();

    // Resolve every node's STUN address up front.
    let mut targets: Vec<(i32, SocketAddr)> = Vec::new();
    for (rid, n) in measurable(dm) {
        let Some(port) = n.stun_port() else { continue };
        targets.extend(n.resolve_addrs(port).await.into_iter().map(|a| (rid, a)));
    }
    if targets.is_empty() {
        return rep;
    }

    let regions = targets.iter().map(|t| t.0).collect::<HashSet<i32>>().len();
    let mut pending: HashMap<stun::TxId, (i32, Instant)> = HashMap::new();
    let deadline = tokio::time::Instant::now() + STUN_TIMEOUT;
    let mut resend = tokio::time::interval(Duration::from_millis(500));
    let mut buf4 = [0u8; 1500];
    let mut buf6 = [0u8; 1500];
    let mut rounds = 0;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = resend.tick(), if rounds < 3 => {
                rounds += 1;
                for &(rid, a) in &targets {
                    let Some(s) = (if a.is_ipv4() { Some(&sock4) } else { sock6.as_ref() }) else { continue };
                    let tx = stun::new_txid();
                    pending.insert(tx, (rid, Instant::now()));
                    let _ = s.send_to(&stun::request(tx), a).await;
                }
            }
            r = sock4.recv_from(&mut buf4) => {
                if let Ok((n, _)) = r {
                    note_reply(&mut rep, &mut pending, &buf4[..n], true);
                }
            }
            r = async { match &sock6 { Some(s) => s.recv_from(&mut buf6).await, None => std::future::pending().await } } => {
                if let Ok((n, _)) = r {
                    note_reply(&mut rep, &mut pending, &buf6[..n], false);
                }
            }
        }
        // Stop early once every region has answered at least once: only
        // those regions were asked, so that's when all have latencies.
        if rounds >= 2 && rep.region_latency.len() == regions {
            break;
        }
    }
    rep
}

/// Records `d` as the latency to `rid` if it's the lowest seen yet.
fn note_latency(m: &mut HashMap<i32, Duration>, rid: i32, d: Duration) {
    m.entry(rid).and_modify(|e| *e = (*e).min(d)).or_insert(d);
}

fn note_reply(rep: &mut Report, pending: &mut HashMap<stun::TxId, (i32, Instant)>, pkt: &[u8], v4: bool) {
    let Some((tx, addr)) = stun::parse_response(pkt) else { return };
    let Some((rid, sent)) = pending.remove(&tx) else { return };
    note_latency(&mut rep.region_latency, rid, sent.elapsed());
    if v4 && rep.global_v4.is_none() {
        rep.global_v4 = Some(addr);
    }
}

async fn https_report(dm: &DerpMap) -> HashMap<i32, Duration> {
    let mut set = tokio::task::JoinSet::new();
    for (rid, n) in measurable(dm) {
        let n = n.clone();
        set.spawn(async move {
            let d = tokio::time::timeout(HTTPS_TIMEOUT, https_latency(&n)).await.ok().flatten()?;
            Some((rid, d))
        });
    }
    let mut out = HashMap::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some((rid, d))) = r {
            note_latency(&mut out, rid, d);
        }
    }
    out
}

/// Times an HTTPS request to a relay's latency-check endpoint over an
/// already-established TLS connection.
async fn https_latency(n: &DerpNode) -> Option<Duration> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tls = crate::derp::client::dial_tls(n).await.ok()?;
    let host = n.host_name.dialable()?;
    let req = format!("HEAD /derp/latency-check HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let t0 = Instant::now();
    tls.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 12];
    tls.read_exact(&mut buf).await.ok()?;
    buf.starts_with(b"HTTP/1.").then(|| t0.elapsed())
}

#[cfg(test)]
mod tests {
    use tokio::time::sleep;

    use super::*;
    use crate::derpmap::DerpRegion;

    /// Answers STUN binding requests on a loopback port after `delay`.
    async fn stun_server(delay: Duration) -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, src)) = sock.recv_from(&mut buf).await {
                let Some(tx) = stun::parse_binding_request(&buf[..n]) else { continue };
                sleep(delay).await;
                let _ = sock.send_to(&stun::response(tx, src), src).await;
            }
        });
        port
    }

    fn region(region_id: i32, stun_port: u16, avoid: bool) -> (i32, DerpRegion) {
        let node = DerpNode {
            ipv4: "127.0.0.1".into(),
            ipv6: "none".into(),
            stun_port: stun_port.into(),
            ..Default::default()
        };
        (region_id, DerpRegion { region_id, avoid, nodes: vec![node], ..Default::default() })
    }

    #[tokio::test]
    async fn picks_the_fastest_measurable_region() {
        let fast = stun_server(Duration::ZERO).await;
        let slow = stun_server(Duration::from_millis(100)).await;
        let regions = [region(1, slow, false), region(2, fast, false), region(3, fast, true)];
        let dm = DerpMap { regions: regions.into(), ..Default::default() };

        let rep = report(&dm).await.unwrap();

        assert_eq!(rep.region_latency.len(), 2, "{rep:?}");
        assert!(rep.region_latency[&1] > rep.region_latency[&2]);
        assert!(rep.global_v4.unwrap().ip().is_loopback());
        assert_eq!(pick_best_region(&dm).await.unwrap(), Some(2));
    }
}
