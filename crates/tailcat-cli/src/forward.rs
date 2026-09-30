//! `tailcat forward` and `tailcat browse`: local TCP listeners forwarded
//! to a tailcat server.

use std::net::SocketAddr;

use anyhow::{Result, anyhow};
use tailcat::Client;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::Global;
use crate::args::{Dest, ForwardArg};

/// What a forward's remote end is called in messages.
fn remote_name(d: Dest) -> String {
    match d {
        Dest::Port(p) => format!("localhost:{p}"),
        Dest::Via(a) => a.to_string(),
    }
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
pub async fn run_forward(g: &Global, bind: &str, addr_arg: &str, mappings: &[ForwardArg], open: bool) -> Result<()> {
    let addr = crate::addrarg::tailcat_addr_arg(addr_arg).await?;
    let cl = crate::client::new_client(g, addr, crate::keys::client_key(g)?);
    // Listen on every mapping before forwarding any.
    let mut listeners = Vec::new();
    for m in mappings {
        let listen = crate::util::join_host_port(bind, m.local);
        let ln = TcpListener::bind(&listen).await.map_err(|e| anyhow!("listen on {listen}: {e}"))?;
        let la = ln.local_addr()?;
        // Always print: with a local port of 0 it's the only way to learn it.
        eprintln!("# forwarding {la} -> remote {}", remote_name(m.remote));
        if open {
            let host = if la.ip().is_unspecified() { SocketAddr::from(([127, 0, 0, 1], la.port())) } else { la };
            open_browser(&format!("http://{host}/"));
        }
        listeners.push((ln, m.remote));
    }
    for (ln, remote) in listeners {
        tokio::spawn(forward_listener(cl.clone(), ln, remote));
    }
    crate::util::shutdown_signal().await;
    Ok(())
}

async fn forward_listener(cl: Client, ln: TcpListener, remote: Dest) {
    loop {
        let (mut conn, _) = crate::util::accept(|| ln.accept()).await;
        let _ = conn.set_nodelay(true);
        let cl = cl.clone();
        tokio::spawn(async move {
            match remote.dial(&cl).await {
                Ok(r) => crate::util::proxy_and_drain(r, conn).await,
                Err(e) => {
                    tracing::debug!("dial remote target {}: {e}", remote_name(remote));
                    let _ = conn.shutdown().await;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_names() {
        assert_eq!(remote_name(Dest::Port(2)), "localhost:2");
        assert_eq!(remote_name(Dest::Via("[fd7a::1]:80".parse().unwrap())), "[fd7a::1]:80");
    }
}
