//! DERP map types, mirroring the JSON form of Tailscale's
//! `tailcfg.DERPMap`, and fetching the map with a freshness-aware cache.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The default DERP map: Tailscale's free, rate-limited tailcat relays.
pub const DEFAULT_DERP_MAP_URL: &str = "https://tailcat.dev/derpmap.json";

/// How old a cached DERP map may be and still be used without asking the
/// server whether it changed.
pub const DERP_MAP_CACHE_MAX_AGE: Duration = Duration::from_secs(3600);

/// The magic IP address used in disco pongs to mean "via DERP"; the port
/// is the region ID.
pub const DERP_MAGIC_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127, 3, 3, 40);

/// Reports whether `v` is its type's zero value, for omitting fields the
/// way Go's `omitempty` does.
pub(crate) fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// A set of DERP regions, keyed by region ID.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DerpMap {
    #[serde(rename = "HomeParams", default, skip_serializing_if = "Option::is_none")]
    pub home_params: Option<serde_json::Value>,
    #[serde(rename = "Regions", default)]
    pub regions: BTreeMap<i32, DerpRegion>,
    #[serde(rename = "omitDefaultRegions", default, skip_serializing_if = "is_default")]
    pub omit_default_regions: bool,
}

/// A geographic region of DERP relays that are meshed together, so a
/// client may connect to any of its nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DerpRegion {
    #[serde(rename = "RegionID", default)]
    pub region_id: i32,
    #[serde(rename = "RegionCode", default)]
    pub region_code: String,
    #[serde(rename = "RegionName", default)]
    pub region_name: String,
    #[serde(rename = "Latitude", default, skip_serializing_if = "is_default")]
    pub latitude: f64,
    #[serde(rename = "Longitude", default, skip_serializing_if = "is_default")]
    pub longitude: f64,
    #[serde(rename = "Avoid", default, skip_serializing_if = "is_default")]
    pub avoid: bool,
    #[serde(rename = "NoMeasureNoHome", default, skip_serializing_if = "is_default")]
    pub no_measure_no_home: bool,
    #[serde(rename = "Nodes", default)]
    pub nodes: Vec<DerpNode>,
}

/// One DERP relay server.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DerpNode {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "RegionID", default)]
    pub region_id: i32,
    #[serde(rename = "HostName", default)]
    pub host_name: String,
    #[serde(rename = "CertName", default, skip_serializing_if = "is_default")]
    pub cert_name: String,
    #[serde(rename = "IPv4", default, skip_serializing_if = "is_default")]
    pub ipv4: String,
    #[serde(rename = "IPv6", default, skip_serializing_if = "is_default")]
    pub ipv6: String,
    #[serde(rename = "STUNPort", default, skip_serializing_if = "is_default")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly", default, skip_serializing_if = "is_default")]
    pub stun_only: bool,
    #[serde(rename = "DERPPort", default, skip_serializing_if = "is_default")]
    pub derp_port: i32,
    #[serde(rename = "InsecureForTests", default, skip_serializing_if = "is_default")]
    pub insecure_for_tests: bool,
    #[serde(rename = "STUNTestIP", default, skip_serializing_if = "is_default")]
    pub stun_test_ip: String,
    #[serde(rename = "CanPort80", default, skip_serializing_if = "is_default")]
    pub can_port_80: bool,
}

impl DerpNode {
    /// The TCP port DERP is served on (443 unless overridden).
    pub fn derp_port(&self) -> u16 {
        u16::try_from(self.derp_port).ok().filter(|&p| p > 0).unwrap_or(443)
    }

    /// The UDP STUN port, or `None` if STUN is disabled (`-1`).
    pub fn stun_port(&self) -> Option<u16> {
        match self.stun_port {
            0 => Some(3478),
            p => u16::try_from(p).ok(),
        }
    }

    /// The addresses to use for this node: explicit IPs if given
    /// (`"none"` disables a family), else a DNS lookup of the hostname.
    pub async fn resolve_addrs(&self, port: u16) -> Vec<std::net::SocketAddr> {
        use std::net::{IpAddr, SocketAddr};
        let explicit = |s: &str, v4: bool| s.parse::<IpAddr>().ok().filter(|ip| ip.is_ipv4() == v4);
        let mut out: Vec<_> = [explicit(&self.ipv4, true), explicit(&self.ipv6, false)]
            .into_iter()
            .flatten()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        if (self.ipv4.is_empty() || self.ipv6.is_empty())
            && !self.host_name.is_empty()
            && let Ok(addrs) = tokio::net::lookup_host((self.host_name.as_str(), port)).await
        {
            out.extend(addrs.filter(|a| if a.is_ipv4() { self.ipv4.is_empty() } else { self.ipv6.is_empty() }));
        }
        // Prefer IPv4 first: it's the more commonly working family.
        out.sort_by_key(|a| !a.is_ipv4());
        out.dedup();
        out
    }
}

/// A cache for fetched DERP maps. Implementations only store bytes; the
/// freshness policy lives in [`fetch_derp_map`]: an entry younger than
/// [`DERP_MAP_CACHE_MAX_AGE`] is used with no network traffic, an older
/// one is revalidated with `If-None-Match`, and one of any age is used
/// as a fallback if the fetch fails.
pub trait DerpMapCache: Send + Sync {
    /// Returns the stored response for `url`: body, ETag (or empty), and
    /// when it was stored.
    fn get(&self, url: &str) -> Option<CacheEntry>;
    /// Stores the response for `url`, marking it stored now.
    fn put(&self, url: &str, data: &[u8], etag: &str);
}

/// A process-wide in-memory [`DerpMapCache`], used when no other cache
/// is given.
#[derive(Default)]
pub struct MemDerpMapCache {
    m: Mutex<BTreeMap<String, CacheEntry>>,
}

/// A cached response: body, ETag, and when it was stored.
type CacheEntry = (Vec<u8>, String, SystemTime);

impl DerpMapCache for MemDerpMapCache {
    fn get(&self, url: &str) -> Option<CacheEntry> {
        self.m.lock().unwrap().get(url).cloned()
    }
    fn put(&self, url: &str, data: &[u8], etag: &str) {
        self.m.lock().unwrap().insert(url.to_string(), (data.to_vec(), etag.to_string(), SystemTime::now()));
    }
}

fn default_cache() -> &'static MemDerpMapCache {
    static C: OnceLock<MemDerpMapCache> = OnceLock::new();
    C.get_or_init(MemDerpMapCache::default)
}

/// Whether a DERP map is being fetched for a server (which will listen
/// in the chosen region) or a client. It's sent to the map server as the
/// `Tailcat-Mode` hint header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FetchMode {
    #[default]
    Client,
    Server,
}

impl FetchMode {
    fn header(self) -> &'static str {
        match self {
            FetchMode::Client => "client",
            FetchMode::Server => "server",
        }
    }
}

/// Options for fetching a DERP map.
#[derive(Clone, Copy, Default)]
pub struct FetchOptions<'a> {
    /// The map URL; [`DEFAULT_DERP_MAP_URL`] if `None`.
    pub url: Option<&'a str>,
    pub mode: FetchMode,
    /// The cache; a process-wide in-memory one if `None`.
    pub cache: Option<&'a dyn DerpMapCache>,
}

/// A cached map too old to use without revalidating: the decoded map,
/// and the body and ETag it was stored with.
type Stale = (DerpMap, Vec<u8>, String);

/// Fetches and decodes a JSON DERP map, honoring the cache policy
/// documented on [`DerpMapCache`].
pub async fn fetch_derp_map(opts: FetchOptions<'_>) -> Result<DerpMap> {
    let url = opts.url.unwrap_or(DEFAULT_DERP_MAP_URL);
    let cache = opts.cache.unwrap_or(default_cache());
    let mut stale = None;
    if let Some((data, etag, stored)) = cache.get(url)
        && let Ok(dm) = serde_json::from_slice(&data)
    {
        if stored.elapsed().unwrap_or_default() < DERP_MAP_CACHE_MAX_AGE {
            return Ok(dm);
        }
        stale = Some((dm, data, etag));
    }
    let res = fetch_fresh(url, opts.mode, cache, stale.as_ref()).await;
    res.or_else(|e| stale.map(|(dm, ..)| dm).ok_or(e))
}

/// Fetches `url`, revalidating `stale` if given, and caches the result.
async fn fetch_fresh(url: &str, mode: FetchMode, cache: &dyn DerpMapCache, stale: Option<&Stale>) -> Result<DerpMap> {
    let mut req = crate::http::client().get(url).header("Tailcat-Mode", mode.header()).timeout(Duration::from_secs(10));
    if let Some((_, _, etag)) = stale
        && !etag.is_empty()
    {
        req = req.header("If-None-Match", etag.as_str());
    }
    let res = req.send().await.map_err(|e| Error::other(format!("fetching {url}: {e}")))?;
    if res.status() == reqwest::StatusCode::NOT_MODIFIED
        && let Some((dm, data, etag)) = stale
    {
        cache.put(url, data, etag);
        return Ok(dm.clone());
    }
    if !res.status().is_success() {
        return Err(Error::other(format!("fetching {url}: {}", res.status())));
    }
    let etag = res.headers().get("etag").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let body = res.bytes().await.map_err(|e| Error::other(format!("reading {url}: {e}")))?;
    if body.len() > 8 << 20 {
        return Err(Error::other(format!("DERP map from {url} is too large")));
    }
    let dm = serde_json::from_slice(&body).map_err(|_| Error::other(format!("invalid DERP map JSON from {url}")))?;
    cache.put(url, &body, &etag);
    Ok(dm)
}

/// Finds a region by code (case-insensitive) or by a case-insensitive
/// substring of its name.
pub fn find_region(dm: &DerpMap, s: &str) -> Option<i32> {
    if s == "list" {
        return None;
    }
    if let Some(r) = dm.regions.values().find(|r| r.region_code.eq_ignore_ascii_case(s)) {
        return Some(r.region_id);
    }
    let needle = s.to_lowercase();
    dm.regions.values().find(|r| r.region_name.to_lowercase().contains(&needle)).map(|r| r.region_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"Regions":{"302":{"RegionID":302,"RegionCode":"sfo","RegionName":"San Francisco","Latitude":37.7775,"Nodes":[{"Name":"302a","RegionID":302,"HostName":"tc302a.ipn.dev","IPv4":"208.111.39.38","IPv6":"2607:f740:0:3f::720","CanPort80":true}]}}}"#;

    #[test]
    fn parses_tailcat_dev_format() {
        let dm: DerpMap = serde_json::from_str(SAMPLE).unwrap();
        let r = &dm.regions[&302];
        assert_eq!(r.region_code, "sfo");
        assert_eq!(r.nodes[0].host_name, "tc302a.ipn.dev");
        assert_eq!(r.nodes[0].derp_port(), 443);
        assert_eq!(r.nodes[0].stun_port(), Some(3478));
        assert_eq!(find_region(&dm, "SFO"), Some(302));
        assert_eq!(find_region(&dm, "franc"), Some(302));
        assert_eq!(find_region(&dm, "nope"), None);
        let back = serde_json::to_string(&dm).unwrap();
        let again: DerpMap = serde_json::from_str(&back).unwrap();
        assert_eq!(dm, again);
        // Zero-valued optional fields are omitted, like Go's omitempty.
        assert!(!back.contains("Longitude") && !back.contains("STUNPort") && !back.contains("Avoid"));
    }

    #[test]
    fn ports_default_and_disable() {
        let n = |derp_port, stun_port| DerpNode { derp_port, stun_port, ..Default::default() };
        assert_eq!(n(0, 0).derp_port(), 443);
        assert_eq!(n(-1, 0).derp_port(), 443);
        assert_eq!(n(70000, 0).derp_port(), 443);
        assert_eq!(n(8443, 0).derp_port(), 8443);
        assert_eq!(n(0, 0).stun_port(), Some(3478));
        assert_eq!(n(0, -1).stun_port(), None);
        assert_eq!(n(0, 70000).stun_port(), None);
        assert_eq!(n(0, 3479).stun_port(), Some(3479));
    }

    #[tokio::test]
    async fn resolve_addrs_prefers_explicit_ips() {
        let n = DerpNode {
            host_name: "does-not-resolve.invalid".into(),
            ipv4: "192.0.2.1".into(),
            ipv6: "2001:db8::1".into(),
            ..Default::default()
        };
        let got = n.resolve_addrs(443).await;
        assert_eq!(got, ["192.0.2.1:443".parse().unwrap(), "[2001:db8::1]:443".parse().unwrap()]);
        // "none" disables a family; a mismatched family is ignored.
        let n = DerpNode { ipv4: "2001:db8::1".into(), ipv6: "none".into(), ..Default::default() };
        assert!(n.resolve_addrs(443).await.is_empty());
        let n = DerpNode { host_name: "127.0.0.1".into(), ipv6: "none".into(), ..Default::default() };
        assert_eq!(n.resolve_addrs(1).await, ["127.0.0.1:1".parse().unwrap()]);
    }

    /// A cache whose entries are all `age` old.
    struct AgedCache<'a>(&'a MemDerpMapCache, Duration);

    impl DerpMapCache for AgedCache<'_> {
        fn get(&self, url: &str) -> Option<CacheEntry> {
            self.0.get(url).map(|(d, e, t)| (d, e, t - self.1))
        }
        fn put(&self, url: &str, data: &[u8], etag: &str) {
            self.0.put(url, data, etag)
        }
    }

    /// Serves one canned HTTP response per connection, returning the URL
    /// and a channel of the requests received.
    async fn http_server(responses: Vec<String>) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/derpmap.json", ln.local_addr().unwrap());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            for res in responses {
                let (mut c, _) = ln.accept().await.unwrap();
                let mut buf = vec![0; 4096];
                let n = c.read(&mut buf).await.unwrap();
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                c.write_all(res.as_bytes()).await.unwrap();
            }
        });
        (url, rx)
    }

    fn ok_response(body: &str, etag: &str) -> String {
        format!("HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    }

    #[tokio::test]
    async fn fetch_caches_and_revalidates() {
        let (url, mut reqs) = http_server(vec![
            ok_response(SAMPLE, "\"v1\""),
            "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".into(),
            "HTTP/1.1 500 Oops\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        ])
        .await;
        let fresh = MemDerpMapCache::default();
        let opts = FetchOptions { url: Some(&url), mode: FetchMode::Server, cache: Some(&fresh) };
        let dm = fetch_derp_map(opts).await.unwrap();
        assert_eq!(dm.regions[&302].region_code, "sfo");
        let req = reqs.recv().await.unwrap().to_ascii_lowercase();
        assert!(req.contains("tailcat-mode: server") && !req.contains("if-none-match"), "{req}");
        // A fresh entry is used with no request at all.
        assert_eq!(fetch_derp_map(opts).await.unwrap(), dm);

        // A stale entry is revalidated with its ETag...
        let stale = AgedCache(&fresh, DERP_MAP_CACHE_MAX_AGE * 2);
        let opts = FetchOptions { cache: Some(&stale), mode: FetchMode::Client, ..opts };
        assert_eq!(fetch_derp_map(opts).await.unwrap(), dm);
        let req = reqs.recv().await.unwrap().to_ascii_lowercase();
        assert!(req.contains("if-none-match: \"v1\"") && req.contains("tailcat-mode: client"), "{req}");
        // ...and used as a fallback when the server fails.
        assert_eq!(fetch_derp_map(opts).await.unwrap(), dm);
        reqs.recv().await.unwrap();
        // With no cached copy, a failure is an error.
        let empty = MemDerpMapCache::default();
        assert!(fetch_derp_map(FetchOptions { cache: Some(&empty), ..opts }).await.is_err());
    }

    #[tokio::test]
    async fn fetch_rejects_invalid_json() {
        let (url, _reqs) = http_server(vec![ok_response("{not json", "")]).await;
        let cache = MemDerpMapCache::default();
        let e = fetch_derp_map(FetchOptions { url: Some(&url), cache: Some(&cache), ..Default::default() })
            .await
            .unwrap_err();
        assert!(e.to_string().contains("invalid DERP map JSON"), "{e}");
        assert!(cache.get(&url).is_none());
    }
}
