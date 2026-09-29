//! Small helpers: Go-style durations, platform directories, loopback
//! dials, private files.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Parses a Go-style duration like "10s", "1m30s", "250ms" or "1.5h".
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    match s {
        "0" => return Ok(Duration::ZERO),
        "" => return Err("empty duration".into()),
        _ => {}
    }
    let is_num = |c: char| c.is_ascii_digit() || c == '.';
    let mut total = 0f64;
    let mut rest = s;
    while !rest.is_empty() {
        let (num, r) = rest.split_at(rest.find(|c| !is_num(c)).unwrap_or(rest.len()));
        let n: f64 = num.parse().map_err(|_| format!("invalid duration {s:?}"))?;
        let (unit, r) = r.split_at(r.find(is_num).unwrap_or(r.len()));
        rest = r;
        total += n * match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "" => return Err(format!("missing unit in duration {s:?}")),
            _ => return Err(format!("unknown unit {unit:?} in duration {s:?}")),
        };
    }
    Ok(Duration::from_secs_f64(total))
}

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

/// A per-user directory: `windows_var` on Windows, `macos` under the
/// home directory on macOS, and elsewhere `xdg_var` or else `home_rel`
/// under the home directory.
fn user_dir(windows_var: &str, macos: &str, xdg_var: &str, home_rel: &str) -> Option<PathBuf> {
    let var = |v| std::env::var_os(v).filter(|x| !x.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        return var(windows_var);
    }
    if cfg!(target_os = "macos") {
        return var("HOME").map(|h| h.join(macos));
    }
    var(xdg_var).or_else(|| var("HOME").map(|h| h.join(home_rel)))
}

/// Writes a file readable only by its owner.
pub fn write_private(path: impl AsRef<Path>, data: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    std::io::Write::write_all(&mut opts.open(path)?, data)
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
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration(" 0 ").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("1h2m3.5s").unwrap(), Duration::from_millis(3_723_500));
        assert_eq!(parse_duration("5us").unwrap(), parse_duration("5µs").unwrap());
        assert_eq!(parse_duration("100ns").unwrap(), Duration::from_nanos(100));
        for bad in ["10", "x", "", "s", ".s", "1.2.3s", "5d", "-1s", "1s 2s"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} parsed");
        }
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
        assert!(split_host_port("localhost").is_err());
        assert!(split_host_port("[::1]22").is_err());
        assert!(split_host_port("host:99999").is_err());
        assert_eq!(join_host_port("fd7a::1", 5), "[fd7a::1]:5");
        assert_eq!(join_host_port("example.com", 5), "example.com:5");
    }

    #[tokio::test]
    async fn dials_localhost_without_dns() {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ln.local_addr().unwrap().port();
        for host in ["localhost", "LocalHost", "app.localhost", "127.0.0.1"] {
            let c = dial_local(&format!("{host}:{port}")).await.unwrap();
            assert_eq!(c.peer_addr().unwrap(), ln.local_addr().unwrap());
        }
        assert!(dial_local("localhost").await.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        write_private(&p, b"long contents").unwrap();
        write_private(&p, b"short").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"short");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
