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
    let local_port = |s| parse_port(s).map_err(|e| anyhow!("local port: {e}"));
    let Some((local, target)) = spec.split_once(':') else {
        let port = local_port(spec)?;
        return Ok(ForwardSpec { listen_addr: crate::util::join_host_port(bind, port), target: None, port });
    };
    // A local port of 0 asks the OS for a free port.
    let listen_addr = crate::util::join_host_port(bind, if local == "0" { 0 } else { local_port(local)? });
    if let Ok(port) = parse_port(target) {
        return Ok(ForwardSpec { listen_addr, target: None, port });
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
        if let Err(e) = browser_command(&url).status() {
            eprintln!("# opening browser failed: {e}");
        }
    });
}

/// The command that opens `url` in the default browser.
#[cfg(target_os = "macos")]
fn browser_command(url: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new("open");
    cmd.arg(url);
    cmd
}

/// The command that opens `url` in the default browser.
#[cfg(windows)]
fn browser_command(url: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new("cmd");
    cmd.args(["/c", "start", "", url]);
    cmd
}

/// The command that opens `url` in the default browser.
#[cfg(not(any(target_os = "macos", windows)))]
fn browser_command(url: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new("xdg-open");
    cmd.arg(url);
    cmd
}

/// Forwards each mapping until Ctrl-C or SIGTERM. `mappings` must not be
/// empty.
pub async fn run_forward(g: &Global, bind: &str, addr_arg: &str, mappings: &[String], open: bool) -> Result<()> {
    let addr = crate::addrarg::tailcat_addr_arg(addr_arg).await?;
    let cl = crate::client::new_client(g, addr, crate::keys::client_key(g)?);
    // Listen on every mapping before forwarding any.
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
    for (ln, spec) in listeners {
        tokio::spawn(forward_listener(cl.clone(), ln, spec));
    }
    shutdown_signal().await;
    Ok(())
}

async fn forward_listener(cl: Client, ln: TcpListener, spec: ForwardSpec) {
    let spec = std::sync::Arc::new(spec);
    loop {
        let (mut conn, _) = crate::util::accept(|| ln.accept()).await;
        let _ = conn.set_nodelay(true);
        let (cl, spec) = (cl.clone(), spec.clone());
        tokio::spawn(async move {
            let remote = match spec.target {
                Some(t) => cl.dial_tcp(t).await,
                None => cl.dial_tcp_port(spec.port).await,
            };
            match remote {
                Ok(r) => crate::serve::proxy_and_drain(r, conn).await,
                Err(e) => {
                    tracing::debug!("dial remote target {}: {e}", spec.remote_target());
                    let _ = conn.shutdown().await;
                }
            }
        });
    }
}

/// Waits for Ctrl-C or SIGTERM.
#[cfg(unix)]
pub async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// Waits for Ctrl-C.
#[cfg(not(unix))]
pub async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a mapping that listens on 127.0.0.1.
    fn local(spec: &str) -> Result<ForwardSpec> {
        parse_forward_spec("127.0.0.1", spec)
    }

    #[test]
    fn specs() {
        let s = local("8080").unwrap();
        assert_eq!(s, ForwardSpec { listen_addr: "127.0.0.1:8080".into(), target: None, port: 8080 });

        let s = parse_forward_spec("0.0.0.0", "18080:8080").unwrap();
        assert_eq!(s.listen_addr, "0.0.0.0:18080");
        assert_eq!(s.port, 8080);

        assert_eq!(local("0:80").unwrap().listen_addr, "127.0.0.1:0");
        assert_eq!(local("1:2").unwrap().remote_target(), "localhost:2");

        let s = local("13306:192.168.1.10:3306").unwrap();
        assert_eq!(s.target, Some("192.168.1.10:3306".parse().unwrap()));

        let s = parse_forward_spec("::1", "8080:[fd7a::1]:80").unwrap();
        assert_eq!(s.listen_addr, "[::1]:8080");
        assert_eq!(s.remote_target(), "[fd7a::1]:80");

        for bad in ["", "0", ":80", "x:80", "65536", "80:0", "80:65536", "80:nope", "80:host:22", "00:80"] {
            assert!(local(bad).is_err(), "{bad:?} parsed");
        }
    }
}
