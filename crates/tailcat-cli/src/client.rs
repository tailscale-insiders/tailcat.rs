//! Client modes: the stdin/stdout pipe and `tailcat ping`.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use tailcat::{Addr, Client, ClientOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cache::DiskDerpMapCache;
use crate::{Global, usagef};

/// A client configured from the global flags, with the on-disk DERP map
/// cache.
pub fn new_client(g: &Global, addr: Addr, key: tailcat::NodePrivate) -> Client {
    Client::with_options(
        addr,
        ClientOptions {
            key: Some(key),
            derp_map_url: Some(g.derpmap_url.clone()),
            derp_map_cache: Some(Arc::new(DiskDerpMapCache)),
            derp_map: None,
        },
    )
}

/// `tailcat <tc-addr> [<port>|<ip:port>]`: pipes stdin and stdout
/// through a TCP connection to the server (port 1 by default).
pub async fn client_mode(g: &Global, addr_arg: &str, dest: Option<&str>) -> Result<ExitCode> {
    let addr = crate::addrarg::tailcat_addr_arg(addr_arg).await?;
    let cl = new_client(g, addr, crate::keys::client_key(g)?);
    enum Dest {
        Port(u16),
        Via(SocketAddr),
    }
    let d = match dest {
        None => Dest::Port(1),
        Some(s) if !s.contains(':') => Dest::Port(s.parse().map_err(|_| usagef!("invalid port number {s:?}"))?),
        Some(s) => Dest::Via(s.parse().map_err(|_| usagef!("invalid IP:port {s:?}"))?),
    };
    let pi = cl.ping().await.map_err(|e| anyhow!("tailcat Ping: {e}"))?;
    tracing::debug!("got ping: {pi:?}");
    let dial = async {
        match d {
            Dest::Port(p) => cl.dial_tcp_port(p).await,
            Dest::Via(a) => cl.dial_tcp(a).await,
        }
    };
    let c = tokio::time::timeout(Duration::from_secs(10), dial)
        .await
        .map_err(|_| anyhow!("Dial: timed out"))?
        .map_err(|e| anyhow!("Dial: {e}"))?;
    let (mut rd, mut wr) = tokio::io::split(c);
    let up = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 32 << 10];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        // Half-close: tell the server we're done sending, netcat style.
        let _ = wr.shutdown().await;
    });
    // Exit once the server finishes sending. Its close also confirms
    // delivery of everything we sent, including our FIN.
    let mut out = tokio::io::stdout();
    tokio::io::copy(&mut rd, &mut out).await?;
    out.flush().await?;
    up.abort();
    // Our ACK of the server's FIN starts in this process; let it drain.
    cl.drain_tcp(Duration::from_secs(5)).await;
    Ok(ExitCode::SUCCESS)
}

/// `tailcat ping [--until-direct] <tc-addr>`.
pub async fn ping_mode(g: &Global, until_direct: bool, timeout: Duration, addr_arg: &str) -> Result<ExitCode> {
    let addr = crate::addrarg::tailcat_addr_arg(addr_arg).await?;
    let cl = new_client(g, addr, crate::keys::client_key(g)?);
    let deadline = Instant::now() + timeout;
    loop {
        let t0 = Instant::now();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let res = match tokio::time::timeout(remaining, cl.disco_ping(remaining.max(Duration::from_millis(1)))).await {
            Ok(Ok(r)) => r,
            Ok(Err(tailcat::Error::Timeout(_))) | Err(_) if until_direct => {
                return Err(anyhow!("no direct path to the server after {}", crate::util::fmt_duration(timeout)));
            }
            Ok(Err(e)) => return Err(anyhow!("ping: {e}")),
            Err(_) => return Err(anyhow!("ping: timed out")),
        };
        let via = match res.endpoint {
            Some(ep) => ep.to_string(),
            None => format!(
                "DERP({})",
                if res.derp_region_code.is_empty() { res.derp_region_id.to_string() } else { res.derp_region_code.clone() }
            ),
        };
        println!("pong in {} via {via}", crate::util::fmt_duration(res.latency));
        let direct = res.endpoint.is_some();
        if direct || !until_direct {
            return Ok(ExitCode::SUCCESS);
        }
        if deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(500) {
            return Err(anyhow!("no direct path to the server after {}", crate::util::fmt_duration(timeout)));
        }
        tokio::time::sleep(Duration::from_secs(1).saturating_sub(t0.elapsed())).await;
    }
}
