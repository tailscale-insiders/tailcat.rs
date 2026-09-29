//! Running a command per connection, inetd-style.

use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::warn;

use crate::key::NodePublic;
use crate::netstack::TcpStream;
use crate::server::{Server, TcpHandler, handler};

/// Environment variables describing the peer of an accepted connection,
/// for processes served to it:
///
/// - `TAILCAT_PEER_KEY`: the peer's node key (`nodekey:…`), already
///   authenticated by the tunnel;
/// - `TAILCAT_REMOTE_ADDR`: the peer's tailcat IP:port;
/// - `TAILCAT_LOCAL_ADDR`: the server address:port it connected to.
pub fn peer_env(local: SocketAddr, remote: SocketAddr, key: Option<NodePublic>) -> Vec<(String, String)> {
    let mut env = vec![
        ("TAILCAT_REMOTE_ADDR".to_string(), remote.to_string()),
        ("TAILCAT_LOCAL_ADDR".to_string(), local.to_string()),
    ];
    if let Some(k) = key {
        env.push(("TAILCAT_PEER_KEY".to_string(), k.to_string()));
    }
    env
}

impl Server {
    /// Returns a handler that runs `argv` for each connection, with the
    /// connection as the command's stdin and stdout and the server's
    /// stderr as its stderr. Each direction half-closes independently:
    /// the command's stdin reaches EOF when the client shuts down its
    /// sending side, and the client sees a FIN when the command closes
    /// its stdout.
    pub fn exec_conn_handler(&self, argv: Vec<String>) -> TcpHandler {
        let s = self.clone();
        let argv = Arc::new(argv);
        handler(move |c: TcpStream| {
            let s = s.clone();
            let argv = argv.clone();
            async move {
                if let Err(e) = run_conn_command(&s, c, &argv).await {
                    warn!("exec {}: {e}", argv[0]);
                }
            }
        })
    }
}

async fn run_conn_command(s: &Server, c: TcpStream, argv: &[String]) -> std::io::Result<()> {
    let env = peer_env(c.local_addr(), c.peer_addr(), s.peer_key(c.peer_addr()));
    let mut child = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("piped");
    let mut stdout = child.stdout.take().expect("piped");
    let (mut rd, mut wr) = tokio::io::split(c);
    let status = {
        let to_child = async {
            let mut buf = vec![0u8; 32 << 10];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stdin.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            drop(stdin);
        };
        let from_child = async {
            let mut buf = vec![0u8; 32 << 10];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if wr.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = wr.shutdown().await;
        };
        // Finish once the command's output is flushed and it has exited. The
        // stdin copy may still be blocked reading from a client that hasn't
        // half-closed; its input no longer matters then.
        let finished = async {
            from_child.await;
            child.wait().await
        };
        tokio::pin!(to_child, finished);
        let mut to_done = false;

        loop {
            tokio::select! {
                _ = &mut to_child, if !to_done => to_done = true,
                st = &mut finished => break st?,
            }
        }
    };
    let c = rd.unsplit(wr);
    c.drain(Duration::from_secs(5)).await;
    if !status.success() {
        return Err(std::io::Error::other(format!("{} exited: {status}", argv[0])));
    }
    Ok(())
}
