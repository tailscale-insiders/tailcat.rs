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

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}
fn is_false(v: &bool) -> bool {
    !*v
}
fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

/// A set of DERP regions, keyed by region ID.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DerpMap {
    #[serde(rename = "HomeParams", default, skip_serializing_if = "Option::is_none")]
    pub home_params: Option<serde_json::Value>,
    #[serde(rename = "Regions", default)]
    pub regions: BTreeMap<i32, DerpRegion>,
    #[serde(rename = "omitDefaultRegions", default, skip_serializing_if = "is_false")]
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
    #[serde(rename = "Latitude", default, skip_serializing_if = "is_zero_f64")]
    pub latitude: f64,
    #[serde(rename = "Longitude", default, skip_serializing_if = "is_zero_f64")]
    pub longitude: f64,
    #[serde(rename = "Avoid", default, skip_serializing_if = "is_false")]
    pub avoid: bool,
    #[serde(rename = "NoMeasureNoHome", default, skip_serializing_if = "is_false")]
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
    #[serde(rename = "CertName", default, skip_serializing_if = "String::is_empty")]
    pub cert_name: String,
    #[serde(rename = "IPv4", default, skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(rename = "IPv6", default, skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    #[serde(rename = "STUNPort", default, skip_serializing_if = "is_zero_i32")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly", default, skip_serializing_if = "is_false")]
    pub stun_only: bool,
    #[serde(rename = "DERPPort", default, skip_serializing_if = "is_zero_i32")]
    pub derp_port: i32,
    #[serde(rename = "InsecureForTests", default, skip_serializing_if = "is_false")]
    pub insecure_for_tests: bool,
    #[serde(rename = "STUNTestIP", default, skip_serializing_if = "String::is_empty")]
    pub stun_test_ip: String,
    #[serde(rename = "CanPort80", default, skip_serializing_if = "is_false")]
    pub can_port_80: bool,
}

impl DerpNode {
    /// The TCP port DERP is served on (443 unless overridden).
    pub fn derp_port(&self) -> u16 {
        match self.derp_port {
            p if p > 0 && p <= 65535 => p as u16,
            _ => 443,
        }
    }

    /// The UDP STUN port, or `None` if STUN is disabled (`-1`).
    pub fn stun_port(&self) -> Option<u16> {
        match self.stun_port {
            0 => Some(3478),
            p if p > 0 && p <= 65535 => Some(p as u16),
            _ => None,
        }
    }

    /// The addresses to use for this node: explicit IPs if given
    /// (`"none"` disables a family), else a DNS lookup of the hostname.
    pub async fn resolve_addrs(&self, port: u16) -> Vec<std::net::SocketAddr> {
        use std::net::{IpAddr, SocketAddr};
        let mut out = Vec::new();
        let mut need_dns = false;
        for (s, v4) in [(&self.ipv4, true), (&self.ipv6, false)] {
            if s.is_empty() {
                need_dns = true;
            } else if let Ok(ip) = s.parse::<IpAddr>() {
                if ip.is_ipv4() == v4 {
                    out.push(SocketAddr::new(ip, port));
                }
            }
        }
        if need_dns && !self.host_name.is_empty() {
            let explicit_v4 = !self.ipv4.is_empty();
            let explicit_v6 = !self.ipv6.is_empty();
            if let Ok(addrs) = tokio::net::lookup_host((self.host_name.as_str(), port)).await {
                for a in addrs {
                    if (a.is_ipv4() && !explicit_v4) || (a.is_ipv6() && !explicit_v6) {
                        out.push(a);
                    }
                }
            }
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
    fn get(&self, url: &str) -> Option<(Vec<u8>, String, SystemTime)>;
    /// Stores the response for `url`, marking it stored now.
    fn put(&self, url: &str, data: &[u8], etag: &str);
}

/// A process-wide in-memory [`DerpMapCache`], used when no other cache
/// is given.
#[derive(Default)]
pub struct MemDerpMapCache {
    m: Mutex<BTreeMap<String, (Vec<u8>, String, SystemTime)>>,
}

impl DerpMapCache for MemDerpMapCache {
    fn get(&self, url: &str) -> Option<(Vec<u8>, String, SystemTime)> {
        self.m.lock().unwrap().get(url).cloned()
    }
    fn put(&self, url: &str, data: &[u8], etag: &str) {
        self.m
            .lock()
            .unwrap()
            .insert(url.to_string(), (data.to_vec(), etag.to_string(), SystemTime::now()));
    }
}

pub(crate) fn default_cache() -> &'static MemDerpMapCache {
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

fn decode(data: &[u8]) -> Option<DerpMap> {
    if data.is_empty() {
        return None;
    }
    serde_json::from_slice(data).ok()
}

/// Fetches and decodes a JSON DERP map, honoring the cache policy
/// documented on [`DerpMapCache`].
pub async fn fetch_derp_map(opts: FetchOptions<'_>) -> Result<DerpMap> {
    let url = opts.url.unwrap_or(DEFAULT_DERP_MAP_URL);
    let cache: &dyn DerpMapCache = match opts.cache {
        Some(c) => c,
        None => default_cache(),
    };
    let mut stale: Option<(Vec<u8>, String)> = None;
    if let Some((data, etag, stored)) = cache.get(url) {
        if let Some(dm) = decode(&data) {
            let age = SystemTime::now().duration_since(stored).unwrap_or_default();
            if age < DERP_MAP_CACHE_MAX_AGE {
                return Ok(dm);
            }
            stale = Some((data, etag));
        }
    }
    let stale_or = |e: Error| -> Result<DerpMap> {
        if let Some(dm) = stale.as_ref().and_then(|(d, _)| decode(d)) {
            return Ok(dm);
        }
        Err(e)
    };

    let client = crate::http::client();
    let mut req = client
        .get(url)
        .header("Tailcat-Mode", opts.mode.header())
        .timeout(Duration::from_secs(10));
    if let Some((_, etag)) = &stale {
        if !etag.is_empty() {
            req = req.header("If-None-Match", etag.as_str());
        }
    }
    let res = match req.send().await {
        Ok(r) => r,
        Err(e) => return stale_or(Error::other(format!("fetching {url}: {e}"))),
    };
    if res.status() == reqwest::StatusCode::NOT_MODIFIED {
        if let Some((data, etag)) = &stale {
            cache.put(url, data, etag);
            if let Some(dm) = decode(data) {
                return Ok(dm);
            }
        }
    }
    if !res.status().is_success() {
        return stale_or(Error::other(format!("fetching {url}: {}", res.status())));
    }
    let etag = res
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = match res.bytes().await {
        Ok(b) if b.len() <= 8 << 20 => b,
        Ok(_) => return stale_or(Error::other(format!("DERP map from {url} is too large"))),
        Err(e) => return stale_or(Error::other(format!("reading {url}: {e}"))),
    };
    match decode(&body) {
        Some(dm) => {
            cache.put(url, &body, &etag);
            Ok(dm)
        }
        None => stale_or(Error::other(format!("invalid DERP map JSON from {url}"))),
    }
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
    dm.regions
        .values()
        .find(|r| r.region_name.to_lowercase().contains(&needle))
        .map(|r| r.region_id)
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
    }
}
