//! Running a command per connection, inetd-style.

use std::net::SocketAddr;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
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
pub fn peer_env(
    local: SocketAddr,
    remote: SocketAddr,
    key: Option<NodePublic>,
) -> impl Iterator<Item = (String, String)> {
    [("TAILCAT_REMOTE_ADDR", remote.to_string()), ("TAILCAT_LOCAL_ADDR", local.to_string())]
        .into_iter()
        .chain(key.map(|k| ("TAILCAT_PEER_KEY", k.to_string())))
        .map(|(k, v)| (k.to_string(), v))
}

impl Server {
    /// Returns a handler that runs `argv` for each connection, with the
    /// connection as the command's stdin and stdout and the server's
    /// stderr as its stderr. Each direction half-closes independently:
    /// the command's stdin reaches EOF when the client shuts down its
    /// sending side, and the client sees a FIN when the command closes
    /// its stdout.
    pub fn exec_conn_handler(&self, argv: impl IntoIterator<Item = impl Into<String>>) -> TcpHandler {
        let argv: Vec<String> = argv.into_iter().map(Into::into).collect();
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
    let (mut rd, mut wr) = tokio::io::split(c);
    let status = run_command(argv, env, &mut rd, &mut wr).await?;
    rd.unsplit(wr).drain(Duration::from_secs(5)).await;
    if !status.success() {
        return Err(std::io::Error::other(format!("{} exited: {status}", argv[0])));
    }
    Ok(())
}

/// Runs `argv` with `rd` as its stdin and `wr` as its stdout, returning
/// its exit status once it has exited and its output is flushed.
async fn run_command<R, W>(
    argv: &[String],
    env: impl IntoIterator<Item = (String, String)>,
    rd: &mut R,
    wr: &mut W,
) -> std::io::Result<ExitStatus>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut child = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // If this task is dropped, as when the runtime shuts down.
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child.stdin.take().expect("piped");
    let stdout = child.stdout.take().expect("piped");
    // Dropping stdin once the client half-closes gives the command EOF.
    let to_child = async {
        let mut stdin = stdin;
        pipe(rd, &mut stdin).await
    };
    // Finish once the command's output is flushed and it has exited. The
    // stdin copy may still be blocked reading from a client that hasn't
    // half-closed; its input no longer matters then. If the client goes
    // away, closing stdout lets a command still writing (`yes`, `tail -f`)
    // get SIGPIPE rather than block on a full pipe forever.
    let finished = async {
        let mut stdout = stdout;
        pipe(&mut stdout, wr).await;
        drop(stdout);
        child.wait().await
    };
    tokio::pin!(finished);
    tokio::select! {
        st = &mut finished => st,
        _ = to_child => finished.await,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::process::ExitStatusExt;

    use tokio::io::AsyncReadExt;

    use super::*;

    /// A command still writing when its client goes away ends (with
    /// SIGPIPE) rather than blocking on its full stdout pipe.
    #[tokio::test]
    async fn streaming_command_ends_when_the_client_goes() {
        let (mut client, conn) = tokio::io::duplex(1024);
        let run = tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(conn);
            run_command(&["yes".into()], vec![], &mut rd, &mut wr).await
        });
        let mut buf = [0u8; 8];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"y\ny\ny\ny\n");
        drop(client);
        let st = tokio::time::timeout(Duration::from_secs(10), run).await.expect("still running").unwrap().unwrap();
        assert_eq!(st.signal(), Some(libc::SIGPIPE), "{st}");
    }
}
