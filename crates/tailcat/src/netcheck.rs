//! Picking the nearest DERP region by latency: STUN probes to every
//! region's nodes over UDP, falling back to timing HTTPS requests to the
//! relays' `/derp/latency-check` endpoint when UDP is blocked.

use std::collections::HashMap;
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
        for a in n.resolve_addrs(port).await {
            targets.push((rid, a));
        }
    }
    if targets.is_empty() {
        return rep;
    }

    let mut pending: HashMap<stun::TxId, (i32, Instant)> = HashMap::new();
    let send_all = |pending: &mut HashMap<stun::TxId, (i32, Instant)>| {
        let mut out = Vec::new();
        for &(rid, a) in &targets {
            let tx = stun::new_txid();
            pending.insert(tx, (rid, Instant::now()));
            out.push((a, stun::request(tx)));
        }
        out
    };

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
                for (a, pkt) in send_all(&mut pending) {
                    let s = if a.is_ipv4() { Some(&sock4) } else { sock6.as_ref() };
                    if let Some(s) = s {
                        let _ = s.send_to(&pkt, a).await;
                    }
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
        // Stop early once every region has answered at least once.
        let regions: std::collections::HashSet<i32> = targets.iter().map(|t| t.0).collect();
        if regions.iter().all(|r| rep.region_latency.contains_key(r)) && rounds >= 2 {
            break;
        }
    }
    rep
}

fn note_reply(rep: &mut Report, pending: &mut HashMap<stun::TxId, (i32, Instant)>, pkt: &[u8], v4: bool) {
    let Some((tx, addr)) = stun::parse_response(pkt) else { return };
    let Some((rid, sent)) = pending.remove(&tx) else { return };
    let d = sent.elapsed();
    let e = rep.region_latency.entry(rid).or_insert(d);
    if d < *e {
        *e = d;
    }
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
    let mut out: HashMap<i32, Duration> = HashMap::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some((rid, d))) = r {
            let e = out.entry(rid).or_insert(d);
            if d < *e {
                *e = d;
            }
        }
    }
    out
}

/// Times an HTTPS request to a relay's latency-check endpoint over an
/// already-established TLS connection.
async fn https_latency(n: &DerpNode) -> Option<Duration> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tls = crate::derp::client::dial_tls(n).await.ok()?;
    let req = format!("HEAD /derp/latency-check HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", n.host_name);
    let t0 = Instant::now();
    tls.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 12];
    tls.read_exact(&mut buf).await.ok()?;
    buf.starts_with(b"HTTP/1.").then(|| t0.elapsed())
}
