//! `tailcat forward` and `tailcat browse`: local TCP listeners forwarded
//! to a tailcat server.

use std::net::SocketAddr;

use anyhow::{Result, anyhow};
use tailcat::Client;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::{Global, usagef};

#[derive(Debug, PartialEq)]
pub struct ForwardSpec {
    pub listen_addr: String,
    /// An exit-node target, or else `port` on the server.
    pub target: Option<SocketAddr>,
    pub port: u16,
}

impl ForwardSpec {
    fn remote_target(&self) -> String {
        match self.target {
            Some(t) => t.to_string(),
            None => format!("localhost:{}", self.port),
        }
    }
}

fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| anyhow!("invalid port {s:?}"))
}

/// Parses a mapping: `port`, `local:remote`, or `local:ip:port`.
pub fn parse_forward_spec(bind: &str, spec: &str) -> Result<ForwardSpec> {
    let (local, target, has_colon) = match spec.split_once(':') {
        Some((l, t)) => (l, t, true),
        None => (spec, spec, false),
    };
    let local_port = if has_colon && local == "0" {
        0 // ask the OS for a free port
    } else {
        parse_port(local).map_err(|e| anyhow!("local port: {e}"))?
    };
    let listen_addr = crate::util::join_host_port(bind, local_port);
    if !has_colon {
        return Ok(ForwardSpec {
            listen_addr,
            target: None,
            port: parse_port(target).map_err(|e| anyhow!("remote port: {e}"))?,
        });
    }
    if let Ok(p) = parse_port(target) {
        return Ok(ForwardSpec { listen_addr, target: None, port: p });
    }
    let t: SocketAddr =
        target.parse().map_err(|_| anyhow!("remote target {target:?} is not a port or address:port"))?;
    Ok(ForwardSpec { listen_addr, target: Some(t), port: 0 })
}

/// Opens a web browser to `url` in the background.
pub fn open_browser(url: &str) {
    eprintln!("# Opening {url}");
    let url = url.to_string();
    std::thread::spawn(move || {
        let r = if cfg!(target_os = "macos") {
            std::process::Command::new("open").arg(&url).status()
        } else if cfg!(windows) {
            std::process::Command::new("cmd").args(["/c", "start", "", &url]).status()
        } else {
            std::process::Command::new("xdg-open").arg(&url).status()
        };
        if let Err(e) = r {
            eprintln!("# opening browser failed: {e}");
        }
    });
}

pub async fn run_forward(g: &Global, bind: &str, addr_arg: &str, mappings: &[String], open: bool) -> Result<()> {
    if mappings.is_empty() {
        return Err(usagef!("forward takes a <tc-addr> and at least one port mapping"));
    }
    let addr = crate::addrarg::tailcat_addr_arg(addr_arg).await?;
    let cl = crate::client::new_client(g, addr, crate::keys::client_key(g)?);
    let mut listeners = Vec::new();
    for m in mappings {
        let spec = parse_forward_spec(bind, m).map_err(|e| usagef!("mapping {m:?} is invalid: {e}"))?;
        let ln =
            TcpListener::bind(&spec.listen_addr).await.map_err(|e| anyhow!("listen on {}: {e}", spec.listen_addr))?;
        let la = ln.local_addr()?;
        // Always print: with a local port of 0 it's the only way to learn it.
        eprintln!("# forwarding {la} -> remote {}", spec.remote_target());
        if open {
            let host = if la.ip().is_unspecified() { SocketAddr::from(([127, 0, 0, 1], la.port())) } else { la };
            open_browser(&format!("http://{host}/"));
        }
        listeners.push((ln, spec));
    }
    let mut tasks = Vec::new();
    for (ln, spec) in listeners {
        tasks.push(tokio::spawn(forward_listener(cl.clone(), ln, spec)));
    }
    shutdown_signal().await;
    for t in tasks {
        t.abort();
    }
    Ok(())
}

async fn forward_listener(cl: Client, ln: TcpListener, spec: ForwardSpec) {
    let spec = std::sync::Arc::new(spec);
    loop {
        let Ok((conn, _)) = ln.accept().await else { return };
        let _ = conn.set_nodelay(true);
        let cl = cl.clone();
        let spec = spec.clone();
        tokio::spawn(async move {
            let remote = match spec.target {
                Some(t) => cl.dial_tcp(t).await,
                None => cl.dial_tcp_port(spec.port).await,
            };
            match remote {
                Ok(r) => crate::serve::proxy_and_drain(r, conn).await,
                Err(e) => {
                    tracing::debug!("dial remote target {}: {e}", spec.remote_target());
                    let mut conn = conn;
                    let _ = conn.shutdown().await;
                }
            }
        });
    }
}

/// Waits for Ctrl-C or SIGTERM.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs() {
        let s = parse_forward_spec("127.0.0.1", "8080").unwrap();
        assert_eq!(s, ForwardSpec { listen_addr: "127.0.0.1:8080".into(), target: None, port: 8080 });
        let s = parse_forward_spec("0.0.0.0", "18080:8080").unwrap();
        assert_eq!(s.listen_addr, "0.0.0.0:18080");
        assert_eq!(s.port, 8080);
        let s = parse_forward_spec("127.0.0.1", "0:80").unwrap();
        assert_eq!(s.listen_addr, "127.0.0.1:0");
        let s = parse_forward_spec("127.0.0.1", "13306:192.168.1.10:3306").unwrap();
        assert_eq!(s.target, Some("192.168.1.10:3306".parse().unwrap()));
        assert!(parse_forward_spec("127.0.0.1", "0").is_err());
        assert!(parse_forward_spec("127.0.0.1", "80:nope").is_err());
    }
}
