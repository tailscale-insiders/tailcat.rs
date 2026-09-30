//! Small helpers: Go-style duration text, platform directories, loopback
//! dials, atomic private files, accept loops.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Formats a duration roughly the way Go prints it, rounded sensibly.
pub fn fmt_duration(d: Duration) -> String {
    match d.as_micros() {
        us @ ..1000 => format!("{us}µs"),
        us @ 1000..1_000_000 => format!("{}ms", trim_float(us as f64 / 1000.0, 2)),
        _ => format!("{}s", trim_float(d.as_secs_f64(), 3)),
    }
}

fn trim_float(v: f64, digits: usize) -> String {
    format!("{v:.digits$}").trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Go's `os.UserConfigDir`.
pub fn user_config_dir() -> Option<PathBuf> {
    user_dir("AppData", "Library/Application Support", "XDG_CONFIG_HOME", ".config")
}

/// Go's `os.UserCacheDir`.
pub fn user_cache_dir() -> Option<PathBuf> {
    user_dir("LocalAppData", "Library/Caches", "XDG_CACHE_HOME", ".cache")
}

/// A per-user directory: on Windows, the one in `windows_var`.
#[cfg(windows)]
fn user_dir(windows_var: &str, _macos: &str, _xdg_var: &str, _home_rel: &str) -> Option<PathBuf> {
    env_path(windows_var)
}

/// A per-user directory: on macOS, `macos` under the home directory.
#[cfg(target_os = "macos")]
fn user_dir(_windows_var: &str, macos: &str, _xdg_var: &str, _home_rel: &str) -> Option<PathBuf> {
    env_path("HOME").map(|h| h.join(macos))
}

/// A per-user directory: the one in `xdg_var`, or else `home_rel` under
/// the home directory.
#[cfg(not(any(windows, target_os = "macos")))]
fn user_dir(_windows_var: &str, _macos: &str, xdg_var: &str, home_rel: &str) -> Option<PathBuf> {
    env_path(xdg_var).or_else(|| env_path("HOME").map(|h| h.join(home_rel)))
}

/// The path in the environment variable `v`, unless it's unset or empty.
fn env_path(v: &str) -> Option<PathBuf> {
    std::env::var_os(v).filter(|x| !x.is_empty()).map(PathBuf::from)
}

/// Atomically replaces `path` with a file of `data` readable only by its
/// owner. The data goes to a synced temporary file beside it, which is
/// then renamed into place, so readers (like a script polling for the
/// file) see the old contents or the new, never a partial file, and a
/// crash leaves one or the other. The new file is owner-only even when
/// it replaces one that wasn't.
pub fn replace_private(path: impl AsRef<Path>, data: &[u8]) -> std::io::Result<()> {
    let path = path.as_ref();
    let tmp = write_temp_beside(path, data)?;
    std::fs::rename(&tmp, path).inspect_err(|_| _ = std::fs::remove_file(&tmp))
}

/// Like [`replace_private`], but fails with
/// [`std::io::ErrorKind::AlreadyExists`] if `path` exists. The check is
/// atomic: of concurrent calls, exactly one succeeds.
pub fn create_private(path: impl AsRef<Path>, data: &[u8]) -> std::io::Result<()> {
    let path = path.as_ref();
    let tmp = write_temp_beside(path, data)?;
    // Linking, unlike renaming, never replaces an existing file.
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            // A filesystem without hard links: still refuse to replace a
            // file, though a crash can now leave a partial one.
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            owner_only(&mut opts);
            std::io::Write::write_all(&mut opts.open(path)?, data)
        }
        r => r,
    }
}

/// Writes `data` to a new owner-only file in `path`'s directory, synced
/// to disk, and returns its path.
fn write_temp_beside(path: &Path, data: &[u8]) -> std::io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{} is not a file path", path.display()))
    })?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".tmp{}-{:016x}", std::process::id(), rand::random::<u64>()));
    let tmp = path.with_file_name(tmp_name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    owner_only(&mut opts);
    let mut f = opts.open(&tmp)?;
    let written = std::io::Write::write_all(&mut f, data).and_then(|()| f.sync_all());
    written.inspect_err(|_| _ = std::fs::remove_file(&tmp))?;
    Ok(tmp)
}

/// Makes `opts` create files readable and writable only by their owner.
#[cfg(unix)]
fn owner_only(opts: &mut std::fs::OpenOptions) {
    std::os::unix::fs::OpenOptionsExt::mode(opts, 0o600);
}

/// Does nothing: files have no Unix mode here.
#[cfg(not(unix))]
fn owner_only(_: &mut std::fs::OpenOptions) {}

/// Accepts the next connection from `accept` (a listener's accept),
/// riding out errors: the likely ones (too many open files, a
/// connection aborted before it was accepted) pass, and ending the
/// accept loop instead would leave a process that looks alive but
/// serves nothing. Like Go's http.Server, it reports each and backs off
/// up to a second between retries.
pub async fn accept<T, F>(mut accept: impl FnMut() -> F) -> T
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    let mut delay = Duration::from_millis(5);
    loop {
        match accept().await {
            Ok(c) => return c,
            Err(e) => {
                eprintln!("# accept error: {e}; retrying in {}", fmt_duration(delay));
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        }
    }
}

/// Dials a local target "host:port". "localhost" (and "*.localhost")
/// always means loopback: both 127.0.0.1 and ::1 are tried, without
/// asking DNS, so services bound to either answer.
pub async fn dial_local(target: &str) -> std::io::Result<tokio::net::TcpStream> {
    let (host, port) = split_host_port(target)?;
    let lower = host.to_ascii_lowercase();
    let addrs: Vec<SocketAddr> = if lower == "localhost" || lower.ends_with(".localhost") {
        vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))]
    } else if let Ok(ip) = host.parse() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host.as_str(), port)).await?.collect()
    };
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, format!("no addresses for {target}"));
    for a in addrs {
        match tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(a)).await {
            Ok(Ok(c)) => return Ok(c),
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::new(std::io::ErrorKind::TimedOut, format!("dial {a} timed out")),
        }
    }
    Err(last)
}

/// Splits "host:port" or "[v6]:port".
pub fn split_host_port(s: &str) -> std::io::Result<(String, u16)> {
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid host:port {s:?}"));
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => rest.split_once("]:"),
        None => s.rsplit_once(':'),
    }
    .ok_or_else(bad)?;
    Ok((host.to_string(), port.parse().map_err(|_| bad())?))
}

/// Joins host and port, bracketing IPv6 hosts.
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::future::ready;
    use std::io::{self, ErrorKind};
    use std::time::Instant;
    use std::{fs, thread};

    use hegel::TestCase;
    use hegel::generators as gs;
    use tokio::net::TcpListener;

    use super::*;

    /// How far `fmt_duration` rounds `d`: to whole µs, 0.01ms, or 1ms.
    fn rounding(d: Duration) -> Duration {
        if d < Duration::from_millis(1) {
            Duration::from_micros(1)
        } else if d < Duration::from_secs(1) {
            Duration::from_micros(6)
        } else {
            Duration::from_micros(501)
        }
    }

    #[hegel::test]
    fn formatted_durations_parse_back(tc: TestCase) {
        // Up to about 31 years.
        let nanos = tc.draw(gs::integers::<u64>().max_value(1_000_000_000_000_000_000));
        let d = Duration::from_nanos(nanos);
        let s = fmt_duration(d);
        let parsed = tailcat_args::parse_duration(&s).unwrap_or_else(|e| panic!("{s}: {e}"));
        assert!(parsed.abs_diff(d) <= rounding(d), "{d:?} formatted as {s} parsed as {parsed:?}");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(fmt_duration(Duration::from_micros(1234)), "1.23ms");
        assert_eq!(fmt_duration(Duration::from_micros(999)), "999µs");
        assert_eq!(fmt_duration(Duration::from_millis(20)), "20ms");
        assert_eq!(fmt_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(fmt_duration(Duration::from_secs(30)), "30s");
    }

    #[test]
    fn host_port() {
        assert_eq!(split_host_port("[::1]:22").unwrap(), ("::1".into(), 22));
        assert_eq!(split_host_port("localhost:80").unwrap(), ("localhost".into(), 80));
        assert_eq!(split_host_port(":80").unwrap(), ("".into(), 80));
        for bad in ["localhost", "[::1]22", "host:99999"] {
            assert!(split_host_port(bad).is_err(), "{bad:?} split");
        }
        assert_eq!(join_host_port("fd7a::1", 5), "[fd7a::1]:5");
        assert_eq!(join_host_port("example.com", 5), "example.com:5");
    }

    #[tokio::test]
    async fn dials_localhost_without_dns() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        for host in ["localhost", "LocalHost", "app.localhost", "127.0.0.1"] {
            let c = dial_local(&format!("{host}:{}", addr.port())).await.unwrap();
            assert_eq!(c.peer_addr().unwrap(), addr);
        }
        assert!(dial_local("localhost").await.is_err());
    }

    /// `p`'s permission bits.
    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// The names of the files in `dir`, sorted.
    fn file_names(dir: &Path) -> Vec<OsString> {
        let mut names: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        replace_private(&p, b"long contents").unwrap();
        replace_private(&p, b"short").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"short");
        assert_eq!(mode(&p), 0o600);

        // Replacing a world-readable file leaves an owner-only one.
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        replace_private(&p, b"secret").unwrap();
        assert_eq!(mode(&p), 0o600);

        let q = dir.path().join("g");
        create_private(&q, b"new").unwrap();
        assert_eq!(fs::read(&q).unwrap(), b"new");
        assert_eq!(mode(&q), 0o600);

        // No temporary files are left behind.
        assert_eq!(file_names(dir.path()), ["f", "g"]);
    }

    /// Whether a `create_private` created its file, rather than finding one
    /// there already.
    fn created(r: io::Result<()>) -> bool {
        match r {
            Ok(()) => true,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => false,
            Err(e) => panic!("{e}"),
        }
    }

    /// Races `n` threads to create `path`, each with its own contents,
    /// and returns which of them did.
    fn race_to_create(path: &Path, n: u8) -> Vec<bool> {
        thread::scope(|s| {
            let racers: Vec<_> = (0..n).map(|i| s.spawn(move || created(create_private(path, &[i; 4096])))).collect();
            racers.into_iter().map(|r| r.join().unwrap()).collect()
        })
    }

    #[test]
    fn create_private_never_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key");
        // Of racing creators, exactly one wins, and its file is whole.
        let wins = race_to_create(&p, 8);
        assert_eq!(wins.iter().filter(|w| **w).count(), 1, "{wins:?}");
        let winner = wins.iter().position(|w| *w).unwrap() as u8;
        assert_eq!(fs::read(&p).unwrap(), [winner; 4096]);
        assert_eq!(file_names(dir.path()), ["key"]);
    }

    #[tokio::test]
    async fn accept_rides_out_errors() {
        let emfile = io::Error::from_raw_os_error(24);
        let mut results = [Err(emfile), Err(ErrorKind::ConnectionAborted.into()), Ok(7)].into_iter();
        let t0 = Instant::now();
        let accepted = accept(|| ready(results.next().unwrap())).await;
        assert_eq!(accepted, 7);
        // It backed off (5ms, then 10ms) between tries.
        assert!(t0.elapsed() >= Duration::from_millis(15));
    }
}
