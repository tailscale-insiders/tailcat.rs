//! The built-in SSH server: shells and commands, a forced-command mode,
//! and an SFTP file service that can be confined to one directory as
//! read-only, read-write, or write-only drop box.
//!
//! Authentication is by OpenSSH authorized keys, or by nothing at all:
//! with no keys configured, the WireGuard tunnel's client identity is
//! the only gate (the `no-auth-ssh` service).

mod session;
mod sftp;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use russh::keys::PrivateKey;
use tracing::warn;

use crate::key::NodePublic;
use crate::netstack::TcpStream;
use crate::server::{Server, TcpHandler, handler};
use crate::{Error, Result};

/// What an SFTP file service lets clients do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileServeMode {
    /// List, stat and download; no changes.
    ReadOnly,
    /// Anything within the directory.
    ReadWrite,
    /// A flat, write-only drop box: each upload is stored under a new,
    /// server-chosen name, and nothing can be listed or read back.
    WriteOnly,
    /// A recursive write-only drop box: clients may also make and stat
    /// directories, and uploads keep their names when available.
    WriteOnlyTree,
}

/// An SFTP file service rooted in `dir`. Paths are resolved inside it
/// with openat-style confinement, so neither `..` nor symlinks escape.
#[derive(Debug, Clone)]
pub struct FileService {
    pub dir: PathBuf,
    pub mode: FileServeMode,
}

/// Configures [`Server::ssh_conn_handler`].
#[derive(Debug, Clone, Default)]
pub struct SshOptions {
    /// Enables shell and exec sessions.
    pub shell: bool,
    /// If non-empty, every session runs this command instead of a shell
    /// or the client's command (like OpenSSH's `ForceCommand`), with no
    /// SFTP. The client's command arrives in `SSH_ORIGINAL_COMMAND`.
    pub exec: Vec<String>,
    /// OpenSSH authorized_keys text; each element may hold several lines.
    /// If empty, clients need no SSH-level authentication. Key options
    /// are rejected rather than silently ignored.
    pub authorized_keys: Vec<String>,
    /// Serves SFTP rooted here. If `None` and `shell` is set, SFTP gets
    /// the same access as the shell (the whole filesystem).
    pub files: Option<FileService>,
}

/// Looks up the tunnel identity of a connection's remote address.
pub type PeerLookup = Arc<dyn Fn(SocketAddr) -> Option<NodePublic> + Send + Sync>;

pub(crate) struct Shared {
    pub opts: SshOptions,
    /// Allowed keys, as their SSH wire encoding; `None` means no auth.
    pub allowed: Option<HashSet<Vec<u8>>>,
    pub config: Arc<russh::server::Config>,
    pub peer_lookup: PeerLookup,
}

/// Parses authorized_keys texts into a set of allowed keys, rejecting
/// options, trailing garbage, and an empty result.
pub fn parse_authorized_keys(texts: &[String]) -> Result<HashSet<Vec<u8>>> {
    use russh::keys::ssh_key::authorized_keys::Entry;
    let mut allowed = HashSet::new();
    for (ti, text) in texts.iter().enumerate() {
        for (li, line) in text.split('\n').enumerate() {
            let line = line.trim_end_matches('\r').trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let entry: Entry = line
                .parse()
                .map_err(|e| Error::other(format!("authorized keys entry {}, line {}: {e}", ti + 1, li + 1)))?;
            if !entry.config_opts().is_empty() {
                return Err(Error::other(format!(
                    "authorized keys entry {}, line {}: options are not supported",
                    ti + 1,
                    li + 1
                )));
            }
            let wire = entry
                .public_key()
                .to_bytes()
                .map_err(|e| Error::other(format!("authorized keys entry {}, line {}: {e}", ti + 1, li + 1)))?;
            allowed.insert(wire);
        }
    }
    if allowed.is_empty() {
        return Err(Error::other("no SSH public keys found"));
    }
    Ok(allowed)
}

/// Checks that authorized_keys texts are valid and non-empty.
pub fn validate_authorized_keys(texts: &[String]) -> Result<()> {
    parse_authorized_keys(texts).map(|_| ())
}

fn ssh_key_dir() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| Error::other("no user config directory"))?;
    let dir = base.join("tailcat").join("ssh");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Go's `os.UserConfigDir`, where the Go implementation keeps its host
/// key too, so both share one.
pub(crate) fn config_dir() -> Option<PathBuf> {
    let home = || std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        return std::env::var_os("AppData").map(PathBuf::from);
    }
    if cfg!(target_os = "macos") {
        return home().map(|h| h.join("Library/Application Support"));
    }
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|x| !x.is_empty()) {
        return Some(PathBuf::from(x));
    }
    home().map(|h| h.join(".config"))
}

static HOST_KEY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Returns the SSH host key, generating an ed25519 key on first use in
/// `$CONFIG/tailcat/ssh/ssh_host_ed25519_key` (PKCS#8 PEM, like Go's).
pub fn host_key() -> Result<PrivateKey> {
    let _g = HOST_KEY_LOCK.lock().unwrap();
    let path = ssh_key_dir()?.join("ssh_host_ed25519_key");
    match std::fs::read_to_string(&path) {
        Ok(pem) => {
            russh::keys::decode_secret_key(&pem, None).map_err(|e| Error::other(format!("parsing host key: {e}")))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            let pem = pkcs8_ed25519_pem(&seed);
            write_private_file(&path, pem.as_bytes())?;
            russh::keys::decode_secret_key(&pem, None).map_err(|e| Error::other(format!("parsing host key: {e}")))
        }
        Err(e) => Err(e.into()),
    }
}

/// Encodes an ed25519 seed as a PKCS#8 v1 PEM ("PRIVATE KEY").
fn pkcs8_ed25519_pem(seed: &[u8; 32]) -> String {
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
}

fn write_private_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}

/// Returns a handler serving each TCP connection as an SSH server with
/// the capabilities in `opts`. `peer_lookup` maps a connection's remote
/// address to the tunnel-authenticated node key, exported to served
/// processes as `TAILCAT_PEER_KEY`.
pub fn conn_handler_with_lookup(peer_lookup: PeerLookup, mut opts: SshOptions) -> Result<TcpHandler> {
    let allowed =
        if opts.authorized_keys.is_empty() { None } else { Some(parse_authorized_keys(&opts.authorized_keys)?) };
    if !opts.exec.is_empty() {
        opts.shell = false;
        opts.files = None;
    }
    let key = host_key()?;
    let config = Arc::new(russh::server::Config {
        server_id: russh::SshId::Standard(format!("SSH-2.0-tailcat_{}", env!("CARGO_PKG_VERSION")).into()),
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(250),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        nodelay: true,
        methods: if allowed.is_some() {
            russh::MethodSet::from(&[russh::MethodKind::PublicKey][..])
        } else {
            russh::MethodSet::from(&[russh::MethodKind::None, russh::MethodKind::PublicKey][..])
        },
        ..Default::default()
    });
    let shared = Arc::new(Shared { opts, allowed, config, peer_lookup });
    Ok(handler(move |c: TcpStream| {
        let shared = shared.clone();
        async move {
            let local = c.local_addr();
            let remote = c.peer_addr();
            let h = session::ConnHandler::new(shared.clone(), local, remote);
            match russh::server::run_stream(shared.config.clone(), c, h).await {
                Ok(running) => {
                    if let Err(e) = running.await {
                        tracing::debug!("ssh session from {remote}: {e}");
                    }
                }
                Err(e) => warn!("ssh handshake from {remote}: {e}"),
            }
        }
    }))
}

/// Like [`conn_handler_with_lookup`], looking peers up on a server that
/// may not have started yet (as when handlers are built before it).
pub fn conn_handler(server: Arc<std::sync::OnceLock<Server>>, opts: SshOptions) -> Result<TcpHandler> {
    conn_handler_with_lookup(Arc::new(move |a| server.get().and_then(|s| s.peer_key(a))), opts)
}

impl Server {
    /// Returns a handler that serves each incoming TCP connection as an
    /// SSH session with the capabilities in `opts`; see [`SshOptions`].
    /// The host key is generated on first use in the user's config
    /// directory, shared with the Go implementation.
    pub fn ssh_conn_handler(&self, opts: SshOptions) -> Result<TcpHandler> {
        let s = self.clone();
        conn_handler_with_lookup(Arc::new(move |a| s.peer_key(a)), opts)
    }
}

/// Reports whether this platform supports the built-in SSH server.
pub fn supports_ssh_server() -> bool {
    cfg!(any(unix, windows))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE comment";

    #[test]
    fn authorized_keys_parsing() {
        assert_eq!(parse_authorized_keys(&[format!("# c\n\n{KEY}\n")]).unwrap().len(), 1);
        assert!(parse_authorized_keys(&["".into()]).is_err());
        assert!(parse_authorized_keys(&[format!("command=\"x\" {KEY}")]).is_err());
        assert!(parse_authorized_keys(&["not a key".into()]).is_err());
    }

    #[test]
    fn pkcs8_round_trips() {
        let pem = pkcs8_ed25519_pem(&[7u8; 32]);
        let k = russh::keys::decode_secret_key(&pem, None).unwrap();
        assert_eq!(k.algorithm(), russh::keys::Algorithm::Ed25519);
    }
}
