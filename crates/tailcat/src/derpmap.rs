//! DERP map types, mirroring the JSON form of Tailscale's
//! `tailcfg.DERPMap`, and fetching the map with a freshness-aware cache.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

/// Defines a string type whose well-known values are unit variants, so
/// that copying one allocates nothing, while any other value is kept as
/// it is in `Other`, and the empty string is `Unset`. Values compare,
/// print and serialize as the string.
macro_rules! known_strings {
    ($(#[$m:meta])* $t:ident { $($v:ident => $s:literal),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Default)]
        pub enum $t {
            /// None given: the empty string, as Go leaves it.
            #[default]
            Unset,
            $($v,)*
            Other(String),
        }

        impl $t {
            pub fn as_str(&self) -> &str {
                match self {
                    $t::Unset => "",
                    $($t::$v => $s,)*
                    $t::Other(s) => s,
                }
            }

            pub fn is_empty(&self) -> bool {
                self.as_str().is_empty()
            }
        }

        impl From<&str> for $t {
            fn from(s: &str) -> Self {
                match s {
                    "" => $t::Unset,
                    $($s => $t::$v,)*
                    s => $t::Other(s.into()),
                }
            }
        }

        impl From<String> for $t {
            fn from(s: String) -> Self {
                match s.as_str() {
                    "" => $t::Unset,
                    $($s => $t::$v,)*
                    _ => $t::Other(s),
                }
            }
        }

        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.as_str() == other.as_str()
            }
        }

        impl PartialEq<&str> for $t {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }

        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                String::deserialize(d).map($t::from)
            }
        }
    };
}

known_strings! {
    /// A region's code, like `sfo`: those of the default map's regions
    /// are variants.
    RegionCode {
        Nyc => "nyc",
        Sfo => "sfo",
        Fra => "fra",
        Tok => "tok",
    }
}

known_strings! {
    /// A region's name, like `San Francisco`: those of the default map's
    /// regions are variants.
    RegionName {
        NewYorkCity => "New York City",
        SanFrancisco => "San Francisco",
        Frankfurt => "Frankfurt",
        Tokyo => "Tokyo",
    }
}

known_strings! {
    /// A DERP node's name, like `302a`: those of the default map's nodes
    /// are variants, named for their regions.
    NodeName {
        NycA => "301a",
        SfoA => "302a",
        FraA => "303a",
        TokA => "304a",
    }
}

/// A geographic region of DERP relays that are meshed together, so a
/// client may connect to any of its nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DerpRegion {
    #[serde(rename = "RegionID", default)]
    pub region_id: i32,
    #[serde(rename = "RegionCode", default)]
    pub region_code: RegionCode,
    #[serde(rename = "RegionName", default)]
    pub region_name: RegionName,
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

/// A DERP node's address in one family, as the map gives it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NodeIp {
    /// None given (the empty string): look the hostname up.
    #[default]
    Lookup,
    /// `none`: don't use this family.
    Disabled,
    /// The address to use instead of looking the hostname up. One of the
    /// other family is ignored, and so is the family.
    Addr(std::net::IpAddr),
    /// Anything else, kept as given; the family isn't used, as with
    /// `none`.
    Other(String),
}

impl NodeIp {
    /// The address given, if it's of the family `v4` says.
    pub fn addr(&self, v4: bool) -> Option<std::net::IpAddr> {
        match self {
            NodeIp::Addr(ip) if ip.is_ipv4() == v4 => Some(*ip),
            _ => None,
        }
    }

    /// The text form, as the map has it.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        match self {
            NodeIp::Lookup => "".into(),
            NodeIp::Disabled => "none".into(),
            NodeIp::Addr(ip) => ip.to_string().into(),
            NodeIp::Other(s) => s.as_str().into(),
        }
    }
}

impl From<&str> for NodeIp {
    fn from(s: &str) -> Self {
        match s {
            "" => NodeIp::Lookup,
            "none" => NodeIp::Disabled,
            s => s.parse().map_or_else(|_| NodeIp::Other(s.into()), NodeIp::Addr),
        }
    }
}

impl From<String> for NodeIp {
    fn from(s: String) -> Self {
        match NodeIp::from(s.as_str()) {
            NodeIp::Other(_) => NodeIp::Other(s),
            ip => ip,
        }
    }
}

impl PartialEq<&str> for NodeIp {
    fn eq(&self, other: &&str) -> bool {
        self.text() == *other
    }
}

impl std::fmt::Display for NodeIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

impl Serialize for NodeIp {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NodeIp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(NodeIp::from)
    }
}

/// A DERP node's host, which it's dialed by and, unless its
/// [`CertName`] says otherwise, its certificate is for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Host {
    /// None given (the empty string). The node can't be dialed.
    #[default]
    Unset,
    /// An IP literal.
    Ip(std::net::IpAddr),
    /// A DNS name.
    Dns(String),
}

impl Host {
    /// The text form, as the map has it.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Host::Unset => "".into(),
            Host::Ip(ip) => ip.to_string().into(),
            Host::Dns(n) => n.as_str().into(),
        }
    }

    /// The name to dial, look up and check a certificate for, if any.
    pub fn dialable(&self) -> Option<std::borrow::Cow<'_, str>> {
        (*self != Host::Unset).then(|| self.text())
    }
}

impl From<&str> for Host {
    fn from(s: &str) -> Self {
        match s {
            "" => Host::Unset,
            s => s.parse().map_or_else(|_| Host::Dns(s.into()), Host::Ip),
        }
    }
}

impl From<String> for Host {
    fn from(s: String) -> Self {
        match Host::from(s.as_str()) {
            Host::Dns(_) => Host::Dns(s),
            h => h,
        }
    }
}

impl PartialEq<&str> for Host {
    fn eq(&self, other: &&str) -> bool {
        self.text() == *other
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

impl Serialize for Host {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Host {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(Host::from)
    }
}

/// What a DERP node's TLS certificate is checked against, as the map
/// gives it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CertName {
    /// None given (the empty string): the node's hostname.
    #[default]
    HostName,
    /// `sha256-raw:<hex>`: the SHA-256 of the leaf certificate, whatever
    /// it names.
    Sha256([u8; 32]),
    /// `sha256-raw:` and then something that isn't a SHA-256 in hex, kept
    /// as given. No certificate matches it.
    BadSha256(String),
    /// Another name the certificate is for.
    Name(String),
}

impl CertName {
    const SHA256_PREFIX: &str = "sha256-raw:";

    /// The text form, as the map has it.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        match self {
            CertName::HostName => "".into(),
            CertName::Sha256(hash) => format!("{}{}", CertName::SHA256_PREFIX, hex::encode(hash)).into(),
            CertName::BadSha256(s) => format!("{}{s}", CertName::SHA256_PREFIX).into(),
            CertName::Name(n) => n.as_str().into(),
        }
    }
}

impl From<&str> for CertName {
    fn from(s: &str) -> Self {
        match s.strip_prefix(CertName::SHA256_PREFIX) {
            _ if s.is_empty() => CertName::HostName,
            Some(h) => match hex::decode(h).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                Some(hash) => CertName::Sha256(hash),
                None => CertName::BadSha256(h.into()),
            },
            None => CertName::Name(s.into()),
        }
    }
}

impl From<String> for CertName {
    fn from(s: String) -> Self {
        match CertName::from(s.as_str()) {
            CertName::Name(_) => CertName::Name(s),
            c => c,
        }
    }
}

impl PartialEq<&str> for CertName {
    fn eq(&self, other: &&str) -> bool {
        self.text() == *other
    }
}

impl std::fmt::Display for CertName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

impl Serialize for CertName {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CertName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(CertName::from)
    }
}

/// The address a node's STUN is tested at instead of its own, if any
/// (for Tailscale's tests).
pub type StunTestIp = Option<std::net::IpAddr>;

/// Reads and writes a [`StunTestIp`] as the map does: the address, or
/// the empty string for none. Text that isn't an address reads as none,
/// rather than failing the whole map over a field only tests use.
mod stun_test_ip {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::StunTestIp;

    pub fn serialize<S: Serializer>(ip: &StunTestIp, s: S) -> Result<S::Ok, S::Error> {
        match ip {
            Some(ip) => s.collect_str(ip),
            None => s.serialize_str(""),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<StunTestIp, D::Error> {
        Ok(String::deserialize(d)?.parse().ok())
    }
}

/// One DERP relay server.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DerpNode {
    #[serde(rename = "Name", default)]
    pub name: NodeName,
    #[serde(rename = "RegionID", default)]
    pub region_id: i32,
    #[serde(rename = "HostName", default)]
    pub host_name: Host,
    #[serde(rename = "CertName", default, skip_serializing_if = "is_default")]
    pub cert_name: CertName,
    #[serde(rename = "IPv4", default, skip_serializing_if = "is_default")]
    pub ipv4: NodeIp,
    #[serde(rename = "IPv6", default, skip_serializing_if = "is_default")]
    pub ipv6: NodeIp,
    #[serde(rename = "STUNPort", default, skip_serializing_if = "is_default")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly", default, skip_serializing_if = "is_default")]
    pub stun_only: bool,
    #[serde(rename = "DERPPort", default, skip_serializing_if = "is_default")]
    pub derp_port: i32,
    #[serde(rename = "InsecureForTests", default, skip_serializing_if = "is_default")]
    pub insecure_for_tests: bool,
    #[serde(rename = "STUNTestIP", default, skip_serializing_if = "Option::is_none", with = "stun_test_ip")]
    pub stun_test_ip: StunTestIp,
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
        use std::net::SocketAddr;
        let mut out: Vec<_> = [self.ipv4.addr(true), self.ipv6.addr(false)]
            .into_iter()
            .flatten()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        let looks_up = |v4: bool| if v4 { &self.ipv4 } else { &self.ipv6 } == &NodeIp::Lookup;
        if (looks_up(true) || looks_up(false))
            && let Some(host) = self.host_name.dialable()
            && let Ok(addrs) = tokio::net::lookup_host((&*host, port)).await
        {
            for a in addrs.filter(|a| looks_up(a.is_ipv4())) {
                // A lookup can repeat an address, and not always next to
                // itself, so `dedup` after the sort would miss it.
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        // Prefer IPv4 first: it's the more commonly working family.
        out.sort_by_key(|a| !a.is_ipv4());
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
    if let Some(r) = dm.regions.values().find(|r| r.region_code.as_str().eq_ignore_ascii_case(s)) {
        return Some(r.region_id);
    }
    let needle = s.to_lowercase();
    dm.regions.values().find(|r| r.region_name.as_str().to_lowercase().contains(&needle)).map(|r| r.region_id)
}

/// What a `--region` argument names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionArg {
    /// The lowest-latency region (`auto`).
    Auto,
    /// No region: list them instead (`list`).
    List,
    /// A region ID.
    Id(i32),
    /// A region of one's own DERP servers, by hostname (comma-separated,
    /// each with a dot).
    Hosts(Vec<String>),
    /// A region code, or part of a region's name, as [`find_region`]
    /// takes.
    Name(String),
}

impl std::str::FromStr for RegionArg {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty DERP region".into());
        }
        if s.eq_ignore_ascii_case("auto") {
            return Ok(RegionArg::Auto);
        }
        if s.eq_ignore_ascii_case("list") {
            return Ok(RegionArg::List);
        }
        if let Ok(id) = s.parse() {
            return Ok(RegionArg::Id(id));
        }
        if !s.contains('.') {
            return Ok(RegionArg::Name(s.into()));
        }
        let hosts: Vec<String> = s.split(',').map(|h| h.trim().to_string()).collect();
        if hosts.iter().any(String::is_empty) {
            return Err(format!("empty hostname in DERP region {s:?}"));
        }
        Ok(RegionArg::Hosts(hosts))
    }
}

impl RegionArg {
    /// The region in `dm` this names, by ID or by name. The others name
    /// no one region of a map.
    pub fn find(&self, dm: &DerpMap) -> Option<i32> {
        match self {
            RegionArg::Id(id) => dm.regions.contains_key(id).then_some(*id),
            RegionArg::Name(n) => find_region(dm, n),
            RegionArg::Auto | RegionArg::List | RegionArg::Hosts(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use super::*;

    const SAMPLE: &str = r#"{"Regions":{"302":{"RegionID":302,"RegionCode":"sfo","RegionName":"San Francisco","Latitude":37.7775,"Nodes":[{"Name":"302a","RegionID":302,"HostName":"tc302a.ipn.dev","IPv4":"208.111.39.38","IPv6":"2607:f740:0:3f::720","CanPort80":true}]}}}"#;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn stun_test_ips() {
        let parse = |json: &str| serde_json::from_str::<DerpNode>(json).unwrap().stun_test_ip;
        assert_eq!(parse(r#"{"STUNTestIP":"192.0.2.9"}"#), Some("192.0.2.9".parse().unwrap()));
        assert_eq!(parse(r#"{"STUNTestIP":""}"#), None);
        assert_eq!(parse("{}"), None);
        let n = DerpNode { stun_test_ip: parse(r#"{"STUNTestIP":"192.0.2.9"}"#), ..Default::default() };
        assert!(serde_json::to_string(&n).unwrap().contains(r#""STUNTestIP":"192.0.2.9""#));
        assert!(!serde_json::to_string(&DerpNode::default()).unwrap().contains("STUNTestIP"));
    }

    #[test]
    fn hosts() {
        assert_eq!(Host::from(""), Host::Unset);
        assert_eq!(Host::from("192.0.2.1"), Host::Ip("192.0.2.1".parse().unwrap()));
        assert_eq!(Host::from("tc302a.ipn.dev"), Host::Dns("tc302a.ipn.dev".into()));
        assert_eq!(Host::Unset.dialable(), None);
        assert_eq!(Host::from("derp.example").dialable().as_deref(), Some("derp.example"));
        // The map always has a HostName, empty for none.
        let json = serde_json::to_string(&DerpNode::default()).unwrap();
        assert!(json.contains("\"HostName\":\"\""), "{json}");
        let n: DerpNode = serde_json::from_str("{\"HostName\":\"\"}").unwrap();
        assert_eq!(n.host_name, Host::Unset);
    }

    #[test]
    fn cert_names() {
        let hash = [0xab; 32];
        assert_eq!(CertName::from(""), CertName::HostName);
        assert_eq!(CertName::from("derp.example.com"), CertName::Name("derp.example.com".into()));
        assert_eq!(CertName::from(format!("sha256-raw:{}", hex::encode_upper(hash)).as_str()), CertName::Sha256(hash));
        assert_eq!(CertName::from("sha256-raw:beef"), CertName::BadSha256("beef".into()));
        // A bad pin is kept as given; a good one is written in lowercase.
        assert_eq!(CertName::BadSha256("beef".into()).text(), "sha256-raw:beef");
        assert_eq!(CertName::Sha256(hash).text(), format!("sha256-raw:{}", hex::encode(hash)));
    }

    #[test]
    fn node_ips() {
        let v4: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(NodeIp::from(""), NodeIp::Lookup);
        assert_eq!(NodeIp::from("none"), NodeIp::Disabled);
        assert_eq!(NodeIp::from("192.0.2.1"), NodeIp::Addr(v4));
        assert_eq!(NodeIp::from("bogus"), NodeIp::Other("bogus".into()));
        assert_eq!((NodeIp::Addr(v4).addr(true), NodeIp::Addr(v4).addr(false)), (Some(v4), None));
        for s in ["", "none", "192.0.2.1", "2001:db8::1", "bogus"] {
            let n = DerpNode { ipv4: s.into(), ..Default::default() };
            let back: DerpNode = serde_json::from_str(&serde_json::to_string(&n).unwrap()).unwrap();
            assert_eq!(back.ipv4.text(), s, "{s:?}");
            assert_eq!(back.ipv4, n.ipv4, "{s:?}");
        }
    }

    #[test]
    fn known_region_strings() {
        // The default map's codes and names parse to variants, which cost
        // nothing to copy; any other value is kept exactly.
        let (code, name): (RegionCode, RegionName) = ("sfo".into(), "San Francisco".to_string().into());
        assert!(matches!((&code, &name), (RegionCode::Sfo, RegionName::SanFrancisco)));
        assert!(matches!(RegionCode::from("SFO"), RegionCode::Other(s) if s == "SFO"));
        assert_eq!(RegionCode::Other("sfo".into()), RegionCode::Sfo, "equal as strings");
        assert!(matches!(RegionCode::default(), RegionCode::Unset));
        assert!(matches!(RegionCode::from(""), RegionCode::Unset));
        assert_eq!(RegionCode::Unset.as_str(), "");
        assert_eq!(format!("{code} {name}"), "sfo San Francisco");

        let json = r#"{"RegionCode":"tok","RegionName":"Somewhere Else"}"#;
        let r: DerpRegion = serde_json::from_str(json).unwrap();
        assert!(matches!(r.region_code, RegionCode::Tok));
        assert!(matches!(&r.region_name, RegionName::Other(s) if s == "Somewhere Else"));
        let back = serde_json::to_string(&r).unwrap();
        assert!(back.contains(r#""RegionCode":"tok","RegionName":"Somewhere Else""#), "{back}");
    }

    #[test]
    fn region_args() {
        let arg = |s: &str| s.parse::<RegionArg>();
        assert_eq!(arg("auto"), Ok(RegionArg::Auto));
        assert_eq!(arg(" AUTO "), Ok(RegionArg::Auto));
        assert_eq!(arg("list"), Ok(RegionArg::List));
        assert_eq!(arg("302"), Ok(RegionArg::Id(302)));
        assert_eq!(arg("-1"), Ok(RegionArg::Id(-1)));
        assert_eq!(arg("sfo"), Ok(RegionArg::Name("sfo".into())));
        assert_eq!(arg("San Francisco"), Ok(RegionArg::Name("San Francisco".into())));
        let hosts = RegionArg::Hosts(vec!["a.example".into(), "b.example".into()]);
        assert_eq!(arg("a.example, b.example"), Ok(hosts));
        assert!(arg("").is_err());
        assert!(arg("a.example,").is_err());
    }

    #[test]
    fn parses_tailcat_dev_format() {
        let dm: DerpMap = serde_json::from_str(SAMPLE).unwrap();

        let r = &dm.regions[&302];
        assert_eq!(r.region_code, "sfo");
        assert!(matches!(r.nodes[0].name, NodeName::SfoA));
        assert_eq!(r.nodes[0].host_name, "tc302a.ipn.dev");
        assert_eq!(r.nodes[0].derp_port(), 443);
        assert_eq!(r.nodes[0].stun_port(), Some(3478));
        assert_eq!(find_region(&dm, "SFO"), Some(302));
        assert_eq!(find_region(&dm, "franc"), Some(302));
        assert_eq!(find_region(&dm, "nope"), None);
        let find = |s: &str| s.parse::<RegionArg>().unwrap().find(&dm);
        assert_eq!((find("302"), find("301"), find("sfo"), find("auto")), (Some(302), None, Some(302), None));

        let back = serde_json::to_string(&dm).unwrap();
        let again: DerpMap = serde_json::from_str(&back).unwrap();
        assert_eq!(dm, again);
        // Zero-valued optional fields are omitted, like Go's omitempty.
        assert!(!back.contains("Longitude"), "{back}");
        assert!(!back.contains("STUNPort"), "{back}");
        assert!(!back.contains("Avoid"), "{back}");
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
        let explicit = DerpNode {
            host_name: "does-not-resolve.invalid".into(),
            ipv4: "192.0.2.1".into(),
            ipv6: "2001:db8::1".into(),
            ..Default::default()
        };
        // "none" disables a family; a mismatched family is ignored.
        let mismatched = DerpNode { ipv4: "2001:db8::1".into(), ipv6: "none".into(), ..Default::default() };
        let by_name = DerpNode { host_name: "127.0.0.1".into(), ipv6: "none".into(), ..Default::default() };

        assert_eq!(explicit.resolve_addrs(443).await, [addr("192.0.2.1:443"), addr("[2001:db8::1]:443")]);
        assert!(mismatched.resolve_addrs(443).await.is_empty());
        assert_eq!(by_name.resolve_addrs(1).await, [addr("127.0.0.1:1")]);
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
    async fn http_server(responses: Vec<String>) -> (String, mpsc::UnboundedReceiver<String>) {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/derpmap.json", ln.local_addr().unwrap());
        let (tx, rx) = mpsc::unbounded_channel();
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

    /// The next request the server got, lowercased.
    async fn next_request(reqs: &mut mpsc::UnboundedReceiver<String>) -> String {
        reqs.recv().await.unwrap().to_ascii_lowercase()
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
        let req = next_request(&mut reqs).await;
        assert!(req.contains("tailcat-mode: server"), "{req}");
        assert!(!req.contains("if-none-match"), "{req}");
        // A fresh entry is used with no request at all.
        assert_eq!(fetch_derp_map(opts).await.unwrap(), dm);

        // A stale entry is revalidated with its ETag...
        let stale = AgedCache(&fresh, DERP_MAP_CACHE_MAX_AGE * 2);
        let opts = FetchOptions { cache: Some(&stale), mode: FetchMode::Client, ..opts };
        assert_eq!(fetch_derp_map(opts).await.unwrap(), dm);
        let req = next_request(&mut reqs).await;
        assert!(req.contains("if-none-match: \"v1\""), "{req}");
        assert!(req.contains("tailcat-mode: client"), "{req}");
        // ...and used as a fallback when the server fails.
        assert_eq!(fetch_derp_map(opts).await.unwrap(), dm);
        next_request(&mut reqs).await;
        // With no cached copy, a failure is an error.
        let empty = MemDerpMapCache::default();
        assert!(fetch_derp_map(FetchOptions { cache: Some(&empty), ..opts }).await.is_err());
    }

    #[tokio::test]
    async fn fetch_rejects_invalid_json() {
        let (url, _reqs) = http_server(vec![ok_response("{not json", "")]).await;
        let cache = MemDerpMapCache::default();
        let opts = FetchOptions { url: Some(&url), cache: Some(&cache), ..Default::default() };

        let e = fetch_derp_map(opts).await.unwrap_err();

        assert!(e.to_string().contains("invalid DERP map JSON"), "{e}");
        assert!(cache.get(&url).is_none());
    }
}
