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
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use std::{env, fmt};

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
            let bad = |msg: &dyn fmt::Display| {
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
    fs::create_dir_all(&dir)?;
    make_private_dir(&dir);
    Ok(dir)
}

/// Makes `dir` accessible only to its owner, if it can.
#[cfg(unix)]
fn make_private_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

/// Does nothing: directories have no Unix mode here.
#[cfg(not(unix))]
fn make_private_dir(_: &Path) {}

/// Go's `os.UserConfigDir`, where the Go implementation keeps its host
/// key too, so both share one: `%AppData%`.
#[cfg(windows)]
fn config_dir() -> Option<PathBuf> {
    env::var_os("AppData").map(PathBuf::from)
}

/// Go's `os.UserConfigDir`, where the Go implementation keeps its host
/// key too, so both share one: `~/Library/Application Support`.
#[cfg(target_os = "macos")]
fn config_dir() -> Option<PathBuf> {
    env_path("HOME").map(|h| h.join("Library/Application Support"))
}

/// Go's `os.UserConfigDir`, where the Go implementation keeps its host
/// key too, so both share one: `$XDG_CONFIG_HOME`, else `~/.config`.
#[cfg(not(any(windows, target_os = "macos")))]
fn config_dir() -> Option<PathBuf> {
    env_path("XDG_CONFIG_HOME").or_else(|| env_path("HOME").map(|h| h.join(".config")))
}

/// The path in the environment variable `k`, unless it's unset or empty.
#[cfg(not(windows))]
fn env_path(k: &str) -> Option<PathBuf> {
    env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Returns the SSH host key, generating an ed25519 key on first use in
/// `$CONFIG/tailcat/ssh/ssh_host_ed25519_key` (PKCS#8 PEM, like Go's).
pub fn host_key() -> Result<PrivateKey> {
    load_or_create_key(&ssh_key_dir()?.join("ssh_host_ed25519_key"))
}

/// Loads the private key at `path`, first generating one if the file is
/// missing or empty (as a crash while writing it could once leave it).
/// A new key is written in full to a temporary file and then linked into
/// place, so processes starting together all end up with the one that
/// got there first, and none reads a partial key.
fn load_or_create_key(path: &Path) -> Result<PrivateKey> {
    // Replacing an empty file can't be made safe by linking alone, so
    // tailcat processes also take turns, by locking the directory.
    with_dir_locked(path.parent().unwrap_or(Path::new(".")), || {
        let pem = match fs::read_to_string(path) {
            Ok(pem) if !pem.trim().is_empty() => pem,
            Ok(_) => install_new_key(path, true)?,
            Err(e) if e.kind() == ErrorKind::NotFound => install_new_key(path, false)?,
            Err(e) => return Err(e.into()),
        };
        russh::keys::decode_secret_key(&pem, None)
            .map_err(|e| Error::other(format!("parsing host key {}: {e}", path.display())))
    })
}

/// Runs `f` holding an exclusive lock on the directory `dir`, waiting
/// for other processes' turns first.
#[cfg(unix)]
fn with_dir_locked<T>(dir: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    use std::io;
    use std::os::fd::AsRawFd;

    let dir = fs::File::open(dir)?;
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    f() // Unlocked when `dir` closes.
}

/// Runs `f`: directories can't be locked here.
#[cfg(not(unix))]
fn with_dir_locked<T>(_: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    f()
}

/// Generates a key and puts it at `path`, replacing what's there only
/// if `replace`, and returns the file's contents afterwards.
fn install_new_key(path: &Path, replace: bool) -> Result<String> {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", hex::encode(rand::random::<[u8; 8]>())));
    let r = write_private_file(&tmp, pkcs8_ed25519_pem(&seed).as_bytes()).and_then(|()| {
        if replace {
            return Ok(fs::rename(&tmp, path)?);
        }
        match fs::hard_link(&tmp, path) {
            // Someone else's key got there first.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
            r => Ok(r?),
        }
    });
    let _ = fs::remove_file(&tmp);
    r?;
    Ok(fs::read_to_string(path)?)
}

/// Encodes an ed25519 seed as a PKCS#8 v1 PEM ("PRIVATE KEY").
fn pkcs8_ed25519_pem(seed: &[u8; 32]) -> String {
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
}

/// Creates `path`, which must not exist, readable only by its owner, and
/// syncs its contents to disk.
fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    owner_only(&mut o);
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Makes `o` create files readable and writable only by their owner.
#[cfg(unix)]
fn owner_only(o: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    o.mode(0o600);
}

/// Does nothing: files have no Unix mode here.
#[cfg(not(unix))]
fn owner_only(_: &mut OpenOptions) {}

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
pub fn conn_handler(server: Arc<OnceLock<Server>>, opts: SshOptions) -> Result<TcpHandler> {
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
    use std::env::temp_dir;
    use std::sync::Barrier;
    use std::thread;

    use hegel::generators as gs;
    use russh::keys::{Algorithm, decode_secret_key};

    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE comment";

    fn key_count(texts: &[String]) -> usize {
        parse_authorized_keys(texts).unwrap().len()
    }

    #[test]
    fn authorized_keys_parsing() {
        assert_eq!(key_count(&[format!("# c\r\n\n  {KEY}\r\n")]), 1);
        assert_eq!(key_count(&[KEY.into(), KEY.into()]), 1);
        assert!(parse_authorized_keys(&["".into()]).is_err());
        assert!(parse_authorized_keys(&[]).is_err());
        assert!(parse_authorized_keys(&["not a key".into()]).is_err());

        let with_options = [KEY.into(), format!("\ncommand=\"x\" {KEY}")];
        let e = parse_authorized_keys(&with_options).unwrap_err();
        assert_eq!(e.to_string(), "authorized keys entry 2, line 2: options are not supported");
    }

    #[test]
    fn pkcs8_round_trips() {
        let pem = pkcs8_ed25519_pem(&[7u8; 32]);
        let k = decode_secret_key(&pem, None).unwrap();
        assert_eq!(k.algorithm(), Algorithm::Ed25519);
    }

    fn fresh_temp_dir() -> PathBuf {
        let dir = temp_dir().join(format!("tailcat-hostkey-{}", hex::encode(rand::random::<[u8; 8]>())));
        fs::create_dir(&dir).unwrap();
        dir
    }

    fn openssh_public(k: &PrivateKey) -> String {
        k.public_key().to_openssh().unwrap()
    }

    /// Runs `n` `load_or_create_key`s at once and returns each one's
    /// public key.
    fn start_concurrently(n: usize, path: &Path) -> Vec<Result<String>> {
        let barrier = Barrier::new(n);
        let start = || {
            barrier.wait();
            load_or_create_key(path).map(|k| openssh_public(&k))
        };
        thread::scope(|s| {
            let starts: Vec<_> = (0..n).map(|_| s.spawn(start)).collect();
            starts.into_iter().map(|t| t.join().unwrap()).collect()
        })
    }

    /// Processes starting at once (threads here, below any in-process
    /// lock) all get the same host key, which is the one on disk; a
    /// usable existing key is kept, and garbage is refused, not replaced.
    #[cfg(unix)] // Elsewhere, replacing an empty file races.
    #[hegel::test(test_cases = 50)]
    fn concurrent_starts_share_one_host_key(tc: hegel::TestCase) {
        let dir = fresh_temp_dir();
        let path = dir.join("ssh_host_ed25519_key");
        let existing = pkcs8_ed25519_pem(&[7; 32]);
        let initial =
            tc.draw(gs::sampled_from(vec![None, Some(""), Some("\n"), Some(existing.as_str()), Some("junk")]));
        if let Some(text) = initial {
            fs::write(&path, text).unwrap();
        }
        let n = tc.draw(gs::integers::<usize>().min_value(1).max_value(8));

        let keys = start_concurrently(n, &path);

        let on_disk = fs::read_to_string(&path).unwrap();
        let leftovers: Vec<_> = fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
        let _ = fs::remove_dir_all(&dir);
        if initial == Some("junk") {
            assert!(keys.iter().all(|k| k.is_err()), "{keys:?}");
            assert_eq!(on_disk, "junk");
            return;
        }
        let keys: Vec<_> = keys.into_iter().map(|k| k.unwrap()).collect();
        let disk_key = openssh_public(&decode_secret_key(&on_disk, None).unwrap());
        assert!(keys.iter().all(|k| *k == disk_key), "{keys:?} vs {disk_key}");
        if initial == Some(existing.as_str()) {
            assert_eq!(on_disk, existing);
        }
        assert_eq!(leftovers, ["ssh_host_ed25519_key"]);
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
