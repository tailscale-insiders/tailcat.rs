//! Client modes: the stdin/stdout pipe and `tailcat ping`.

use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use tailcat::{Addr, Client, ClientOptions, DiscoPingResult};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

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
pub async fn client_mode(g: &Global, addr_arg: &str, dest: Option<&str>) -> Result<()> {
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
    let (mut rd, wr) = tokio::io::split(c);
    // Exit once the server finishes sending (its close also confirms
    // delivery of everything we sent, including our FIN), even if stdin
    // is still open, or on a stdin error.
    let mut out = tokio::io::stdout();
    let res: Result<()> = tokio::select! {
        r = tokio::io::copy(&mut rd, &mut out) => r.map(drop).map_err(Into::into),
        Err(e) = upload(read_chunks(std::io::stdin()), wr) => Err(anyhow!("stdin: {e}")),
    };
    // Whatever arrived goes out, even on failure.
    let flushed = out.flush().await;
    res?;
    flushed?;
    // Our ACK of the server's FIN starts in this process; let it drain.
    cl.drain_tcp(Duration::from_secs(5)).await;
    Ok(())
}

/// Reads `r` on a thread of its own, sending each chunk, or the error
/// that ends it, until EOF. Unlike tokio's stdin, whose reads run on
/// the runtime's blocking pool and hold up its shutdown until they
/// return, a read blocked here doesn't keep the process from exiting.
fn read_chunks(mut r: impl Read + Send + 'static) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (tx, rx) = mpsc::channel(1);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 32 << 10];
        loop {
            let chunk = match r.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => Ok(buf[..n].to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => Err(e),
            };
            let last = chunk.is_err();
            if tx.blocking_send(chunk).is_err() || last {
                return;
            }
        }
    });
    rx
}

/// Writes the chunks from `rx` to `wr`, then half-closes it to tell the
/// server we're done sending, netcat style. It fails only if reading
/// does: a write error means the connection is going away, which the
/// other direction reports.
async fn upload(
    mut rx: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    mut wr: impl AsyncWrite + Unpin,
) -> std::io::Result<()> {
    while let Some(chunk) = rx.recv().await {
        if wr.write_all(&chunk?).await.is_err() {
            return Ok(());
        }
    }
    let _ = wr.shutdown().await;
    Ok(())
}

/// The name of the DERP region a pong came through: its code, or else
/// its ID.
pub fn derp_region_name(r: &DiscoPingResult) -> String {
    if r.derp_region_code.is_empty() { r.derp_region_id.to_string() } else { r.derp_region_code.clone() }
}

/// `tailcat ping [--until-direct] <tc-addr>`.
pub async fn ping_mode(g: &Global, until_direct: bool, timeout: Duration, addr_arg: &str) -> Result<()> {
    let addr = crate::addrarg::tailcat_addr_arg(addr_arg).await?;
    let cl = new_client(g, addr, crate::keys::client_key(g)?);
    let no_direct = || anyhow!("no direct path to the server after {}", crate::util::fmt_duration(timeout));
    let deadline = Instant::now() + timeout;
    loop {
        let t0 = Instant::now();
        let remaining = deadline.saturating_duration_since(t0);
        let res = match tokio::time::timeout(remaining, cl.disco_ping(remaining.max(Duration::from_millis(1)))).await {
            Ok(Ok(r)) => r,
            Ok(Err(tailcat::Error::Timeout(_))) | Err(_) if until_direct => return Err(no_direct()),
            Ok(Err(e)) => bail!("ping: {e}"),
            Err(_) => bail!("ping: timed out"),
        };
        let via = res.endpoint.map_or_else(|| format!("DERP({})", derp_region_name(&res)), |ep| ep.to_string());
        println!("pong in {} via {via}", crate::util::fmt_duration(res.latency));
        if res.endpoint.is_some() || !until_direct {
            return Ok(());
        }
        if deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(500) {
            return Err(no_direct());
        }
        tokio::time::sleep(Duration::from_secs(1).saturating_sub(t0.elapsed())).await;
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write, pipe};
    use std::sync::mpsc as std_mpsc;
    use std::thread;

    use tokio::io::{AsyncReadExt, duplex, sink};
    use tokio::runtime::Runtime;
    use tokio::time::timeout;

    use super::*;

    /// A reader whose every read fails.
    struct Broken;

    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }
    }

    /// Drops `rt` on a thread of its own, and reports whether that
    /// finished within `limit`.
    fn shuts_down_within(rt: Runtime, limit: Duration) -> bool {
        let (tx, dropped) = std_mpsc::channel();
        thread::spawn(move || {
            drop(rt);
            let _ = tx.send(());
        });
        dropped.recv_timeout(limit).is_ok()
    }

    #[tokio::test]
    async fn uploads_then_half_closes() {
        let (r, mut w) = pipe().unwrap();
        let (mut server, client) = duplex(64);
        let up = tokio::spawn(upload(read_chunks(r), client));

        w.write_all(b"hello ").unwrap();
        w.write_all(b"world").unwrap();
        drop(w);

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello world");
        up.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn upload_fails_on_read_errors() {
        let e = upload(read_chunks(Broken), sink()).await.unwrap_err();
        assert_eq!(e.to_string(), "broken");
    }

    /// A read blocked on a still-open stdin doesn't keep the runtime, and
    /// so the process, from exiting.
    #[test]
    fn blocked_reads_dont_hold_up_exit() {
        let (r, _w) = pipe().unwrap();
        let rt = Runtime::new().unwrap();
        let recv = rt.block_on(async {
            let mut rx = read_chunks(r);
            timeout(Duration::from_millis(50), rx.recv()).await
        });
        assert!(recv.is_err(), "a read of an open, empty pipe returned");
        let exited = shuts_down_within(rt, Duration::from_secs(10));
        assert!(exited, "runtime shutdown waited for the blocked read");
    }
}
