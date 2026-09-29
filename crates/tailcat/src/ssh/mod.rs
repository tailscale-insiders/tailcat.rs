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
    /// With `exec` set, `shell` and `files` are cleared.
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
        for (li, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = |msg: &dyn std::fmt::Display| {
                Error::other(format!("authorized keys entry {}, line {}: {msg}", ti + 1, li + 1))
            };
            let entry: Entry = line.parse().map_err(|e| bad(&e))?;
            if !entry.config_opts().is_empty() {
                return Err(bad(&"options are not supported"));
            }
            allowed.insert(entry.public_key().to_bytes().map_err(|e| bad(&e))?);
        }
    }
    if allowed.is_empty() {
        return Err(Error::other("no SSH public keys found"));
    }
    Ok(allowed)
}

fn ssh_key_dir() -> Result<PathBuf> {
    let dir = config_dir().ok_or_else(|| Error::other("no user config directory"))?.join("tailcat").join("ssh");
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
fn config_dir() -> Option<PathBuf> {
    let var = |k| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        std::env::var_os("AppData").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|h| h.join("Library/Application Support"))
    } else {
        var("XDG_CONFIG_HOME").or_else(|| var("HOME").map(|h| h.join(".config")))
    }
}

static HOST_KEY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Returns the SSH host key, generating an ed25519 key on first use in
/// `$CONFIG/tailcat/ssh/ssh_host_ed25519_key` (PKCS#8 PEM, like Go's).
pub fn host_key() -> Result<PrivateKey> {
    let _g = HOST_KEY_LOCK.lock().unwrap();
    let path = ssh_key_dir()?.join("ssh_host_ed25519_key");
    let pem = match std::fs::read_to_string(&path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            let pem = pkcs8_ed25519_pem(&seed);
            write_private_file(&path, pem.as_bytes())?;
            pem
        }
        Err(e) => return Err(e.into()),
    };
    russh::keys::decode_secret_key(&pem, None).map_err(|e| Error::other(format!("parsing host key: {e}")))
}

/// Encodes an ed25519 seed as a PKCS#8 v1 PEM ("PRIVATE KEY").
fn pkcs8_ed25519_pem(seed: &[u8; 32]) -> String {
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
}

/// Creates `path`, which must not exist, readable only by its owner.
fn write_private_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)?.write_all(data)?;
    Ok(())
}

impl Shared {
    fn new(peer_lookup: PeerLookup, mut opts: SshOptions, key: PrivateKey) -> Result<Self> {
        let allowed =
            (!opts.authorized_keys.is_empty()).then(|| parse_authorized_keys(&opts.authorized_keys)).transpose()?;
        if !opts.exec.is_empty() {
            opts.shell = false;
            opts.files = None;
        }
        use russh::MethodKind::{None as NoAuth, PublicKey};
        let methods: &[_] = if allowed.is_some() { &[PublicKey] } else { &[NoAuth, PublicKey] };
        let config = Arc::new(russh::server::Config {
            server_id: russh::SshId::Standard(format!("SSH-2.0-tailcat_{}", env!("CARGO_PKG_VERSION")).into()),
            keys: vec![key],
            auth_rejection_time: Duration::from_millis(250),
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(30)),
            nodelay: true,
            methods: methods.into(),
            ..Default::default()
        });
        Ok(Shared { opts, allowed, config, peer_lookup })
    }

    /// Serves one SSH connection until it ends.
    async fn serve<S>(self: Arc<Self>, stream: S, local: SocketAddr, remote: SocketAddr)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let h = session::ConnHandler::new(self.clone(), local, remote);
        match russh::server::run_stream(self.config.clone(), stream, h).await {
            Ok(running) => {
                if let Err(e) = running.await {
                    tracing::debug!("ssh session from {remote}: {e}");
                }
            }
            Err(e) => warn!("ssh handshake from {remote}: {e}"),
        }
    }
}

/// Returns a handler serving each TCP connection as an SSH server with
/// the capabilities in `opts`. `peer_lookup` maps a connection's remote
/// address to the tunnel-authenticated node key, exported to served
/// processes as `TAILCAT_PEER_KEY`.
pub fn conn_handler_with_lookup(peer_lookup: PeerLookup, opts: SshOptions) -> Result<TcpHandler> {
    let shared = Arc::new(Shared::new(peer_lookup, opts, host_key()?)?);
    Ok(handler(move |c: TcpStream| {
        let (local, remote) = (c.local_addr(), c.peer_addr());
        shared.clone().serve(c, local, remote)
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

/// Formats the permission bits of a Unix mode as `ls -l` does, like
/// `rwxr-x---`. (Shared with the CLI's `ls`.)
#[doc(hidden)]
pub fn permission_string(mode: u32) -> String {
    (0..9).map(|i| if mode >> (8 - i) & 1 != 0 { b"rwx"[i % 3] as char } else { '-' }).collect()
}

/// Splits a Unix time into its UTC `[year, month, day, hour, minute,
/// second]`. (Shared with the CLI's `ls`.)
#[doc(hidden)]
pub fn utc_civil(secs: i64) -> [i64; 6] {
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    [yoe + era * 400 + i64::from(mo <= 2), mo, d, rem / 3600, rem % 3600 / 60, rem % 60]
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE comment";

    #[test]
    fn authorized_keys_parsing() {
        assert_eq!(parse_authorized_keys(&[format!("# c\r\n\n  {KEY}\r\n")]).unwrap().len(), 1);
        assert_eq!(parse_authorized_keys(&[KEY.into(), KEY.into()]).unwrap().len(), 1);
        assert!(parse_authorized_keys(&["".into()]).is_err());
        assert!(parse_authorized_keys(&[]).is_err());
        let e = parse_authorized_keys(&[KEY.into(), format!("\ncommand=\"x\" {KEY}")]).unwrap_err();
        assert_eq!(e.to_string(), "authorized keys entry 2, line 2: options are not supported");
        assert!(parse_authorized_keys(&["not a key".into()]).is_err());
    }

    #[test]
    fn pkcs8_round_trips() {
        let pem = pkcs8_ed25519_pem(&[7u8; 32]);
        let k = russh::keys::decode_secret_key(&pem, None).unwrap();
        assert_eq!(k.algorithm(), russh::keys::Algorithm::Ed25519);
    }

    #[test]
    fn permission_strings() {
        assert_eq!(permission_string(0o100755), "rwxr-xr-x");
        assert_eq!(permission_string(0o640), "rw-r-----");
        assert_eq!(permission_string(0), "---------");
    }

    #[test]
    fn civil_times() {
        assert_eq!(utc_civil(0), [1970, 1, 1, 0, 0, 0]);
        assert_eq!(utc_civil(951_782_400 + 3661), [2000, 2, 29, 1, 1, 1]);
        assert_eq!(utc_civil(1_735_689_599), [2024, 12, 31, 23, 59, 59]);
        assert_eq!(utc_civil(-1), [1969, 12, 31, 23, 59, 59]);
    }
}
