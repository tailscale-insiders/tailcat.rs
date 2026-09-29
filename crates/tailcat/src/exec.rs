//! Running a command per connection, inetd-style.

use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use crate::key::NodePublic;
use crate::netstack::TcpStream;
use crate::proxy::pipe;
use crate::server::{Server, TcpHandler, handler};

/// Environment variables describing the peer of an accepted connection,
/// for processes served to it:
///
/// - `TAILCAT_PEER_KEY`: the peer's node key (`nodekey:…`), already
///   authenticated by the tunnel;
/// - `TAILCAT_REMOTE_ADDR`: the peer's tailcat IP:port;
/// - `TAILCAT_LOCAL_ADDR`: the server address:port it connected to.
pub fn peer_env(local: SocketAddr, remote: SocketAddr, key: Option<NodePublic>) -> Vec<(String, String)> {
    [("TAILCAT_REMOTE_ADDR", remote.to_string()), ("TAILCAT_LOCAL_ADDR", local.to_string())]
        .into_iter()
        .chain(key.map(|k| ("TAILCAT_PEER_KEY", k.to_string())))
        .map(|(k, v)| (k.to_string(), v))
        .collect()
}

impl Server {
    /// Returns a handler that runs `argv` for each connection, with the
    /// connection as the command's stdin and stdout and the server's
    /// stderr as its stderr. Each direction half-closes independently:
    /// the command's stdin reaches EOF when the client shuts down its
    /// sending side, and the client sees a FIN when the command closes
    /// its stdout.
    pub fn exec_conn_handler(&self, argv: Vec<String>) -> TcpHandler {
        let ctx = Arc::new((self.clone(), argv));
        handler(move |c: TcpStream| {
            let ctx = ctx.clone();
            async move {
                let (s, argv) = &*ctx;
                if let Err(e) = run_conn_command(s, c, argv).await {
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
    let stdin = child.stdin.take().expect("piped");
    let mut stdout = child.stdout.take().expect("piped");
    let (mut rd, mut wr) = tokio::io::split(c);
    let status = {
        // Dropping stdin once the client half-closes gives the command EOF.
        let to_child = async {
            let mut stdin = stdin;
            pipe(&mut rd, &mut stdin).await
        };
        // Finish once the command's output is flushed and it has exited. The
        // stdin copy may still be blocked reading from a client that hasn't
        // half-closed; its input no longer matters then.
        let finished = async {
            pipe(&mut stdout, &mut wr).await;
            child.wait().await
        };
        tokio::pin!(finished);
        tokio::select! {
            st = &mut finished => st,
            _ = to_child => finished.await,
        }?
    };
    rd.unsplit(wr).drain(Duration::from_secs(5)).await;
    if !status.success() {
        return Err(std::io::Error::other(format!("{} exited: {status}", argv[0])));
    }
    Ok(())
}
