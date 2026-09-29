//! Small helpers: Go-style durations, platform directories, loopback dials.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Parses a Go-style duration like "10s", "1m30s", "250ms" or "1.5h".
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let mut total = 0f64;
    let mut rest = s;
    if rest.is_empty() {
        return Err("empty duration".into());
    }
    while !rest.is_empty() {
        let num_end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
        if num_end == 0 {
            return Err(format!("invalid duration {s:?}"));
        }
        let n: f64 = rest[..num_end].parse().map_err(|_| format!("invalid duration {s:?}"))?;
        rest = &rest[num_end..];
        let unit_end = rest.find(|c: char| c.is_ascii_digit() || c == '.').unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];
        let mult = match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "" => return Err(format!("missing unit in duration {s:?}")),
            _ => return Err(format!("unknown unit {unit:?} in duration {s:?}")),
        };
        total += n * mult;
    }
    Ok(Duration::from_secs_f64(total))
}

/// Formats a duration roughly the way Go prints it, rounded sensibly.
pub fn fmt_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1000 {
        format!("{us}µs")
    } else if us < 1_000_000 {
        let ms = us as f64 / 1000.0;
        format!("{}ms", trim_float(ms, 2))
    } else {
        format!("{}s", trim_float(d.as_secs_f64(), 3))
    }
}

fn trim_float(v: f64, digits: usize) -> String {
    let s = format!("{v:.digits$}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    s.to_string()
}

/// Go's `os.UserConfigDir`.
pub fn user_config_dir() -> Option<PathBuf> {
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

/// Go's `os.UserCacheDir`.
pub fn user_cache_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        return std::env::var_os("LocalAppData").map(PathBuf::from);
    }
    if cfg!(target_os = "macos") {
        return home().map(|h| h.join("Library/Caches"));
    }
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME").filter(|x| !x.is_empty()) {
        return Some(PathBuf::from(x));
    }
    home().map(|h| h.join(".cache"))
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

/// Dials a local target "host:port". "localhost" (and "*.localhost")
/// always means loopback: both 127.0.0.1 and ::1 are tried, without
/// asking DNS, so services bound to either answer.
pub async fn dial_local(target: &str) -> std::io::Result<tokio::net::TcpStream> {
    let (host, port) = split_host_port(target)?;
    let addrs: Vec<SocketAddr> =
        if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
            vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], port))]
        } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
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
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").ok_or_else(bad)?;
        (h.to_string(), p)
    } else {
        let (h, p) = s.rsplit_once(':').ok_or_else(bad)?;
        (h.to_string(), p)
    };
    Ok((host, port.parse().map_err(|_| bad())?))
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
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("x").is_err());
        assert_eq!(fmt_duration(Duration::from_micros(1234)), "1.23ms");
    }

    #[test]
    fn host_port() {
        assert_eq!(split_host_port("[::1]:22").unwrap(), ("::1".into(), 22));
        assert_eq!(split_host_port("localhost:80").unwrap(), ("localhost".into(), 80));
        assert_eq!(join_host_port("fd7a::1", 5), "[fd7a::1]:5");
    }
}
