//! Node records: the public half of a mesh node's identity, published
//! (for example as a GitHub Actions run artifact) so that every other
//! node can add it as a peer. The private key never leaves the node.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tailcat::wg::IpNet;
use tailcat::{DerpRegion, DiscoPublic, NodePrivate, NodePublic};

use crate::github::{Attempt, RunId};

/// A GitHub OIDC token, as its compact JWT text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Jwt(String);

impl Jwt {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Jwt {
    fn from(s: String) -> Self {
        Jwt(s)
    }
}

/// A record's OIDC token, if it carries one.
pub type Token = Option<Jwt>;

/// The run a record is from, if it's from GitHub Actions.
pub type Run = Option<RunId>;

/// The attempt at its run a record is from, if it says.
pub type RunAttempt = Option<Attempt>;

/// Reads an optional value from text, taking the empty string for none.
pub(crate) fn nonempty<'de, D: Deserializer<'de>, T: From<String>>(d: D) -> Result<Option<T>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.filter(|s| !s.is_empty()).map(T::from))
}

/// A mesh node's public record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeRecord {
    /// The node's position in the mesh (for example its matrix index).
    pub index: u32,
    /// The WireGuard public key, `nodekey:<hex>`.
    pub nodekey: NodePublic,
    /// The path-discovery key, `discokey:<hex>`.
    pub discokey: DiscoPublic,
    /// The node's address on the overlay, routed to it as a /32 (or /128).
    pub overlay_ip: IpAddr,
    /// The node's home DERP region ID in the DERP map.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub derp_region: i32,
    /// An embedded home region, for relays outside the DERP map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp: Option<DerpRegion>,
    /// Extra prefixes routed to this node (for example a pod CIDR).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<IpNet>,
    /// UDP endpoints known in advance, if any. Endpoints are otherwise
    /// learned at run time over DERP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<SocketAddr>,
    /// The runner OS and architecture (informational).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arch: String,
    /// The GitHub Actions run and attempt that published the record.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "nonempty")]
    pub run_id: Run,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "nonempty")]
    pub run_attempt: RunAttempt,
    /// A GitHub OIDC token binding `nodekey` to the repository, ref and
    /// run: its audience is [`audience_for`] of the node key.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "nonempty")]
    pub jwt: Token,
}

fn is_zero(v: &i32) -> bool {
    *v == 0
}

impl NodeRecord {
    /// A record for `key` at `overlay_ip`, with nothing else set.
    pub fn new(index: u32, key: &NodePrivate, overlay_ip: IpAddr) -> NodeRecord {
        NodeRecord {
            index,
            nodekey: key.public(),
            discokey: key.disco_private().public(),
            overlay_ip,
            derp_region: 0,
            derp: None,
            routes: Vec::new(),
            endpoints: Vec::new(),
            os: String::new(),
            arch: String::new(),
            run_id: None,
            run_attempt: None,
            jwt: None,
        }
    }

    /// Parses and checks a record.
    pub fn from_json(b: &[u8]) -> Result<NodeRecord> {
        let r: NodeRecord = serde_json::from_slice(b).context("parsing node record")?;
        ensure!(!r.nodekey.is_zero() && !r.discokey.is_zero(), "node record {} has a zero key", r.index);
        Ok(r)
    }

    /// The prefixes routed to this node: its overlay IP plus its routes.
    pub fn allowed_ips(&self) -> Vec<IpNet> {
        std::iter::once(IpNet::host(self.overlay_ip)).chain(self.routes.iter().copied()).collect()
    }

    /// The node's home region: embedded, or looked up in `dm`.
    pub fn home_region(&self, dm: &tailcat::DerpMap) -> Option<DerpRegion> {
        self.derp.clone().or_else(|| dm.regions.get(&self.derp_region).cloned())
    }

    /// Writes the record as pretty JSON, atomically: peers polling a
    /// records directory never see it half-written.
    pub fn write(&self, path: &Path) -> Result<()> {
        let mut j = serde_json::to_vec_pretty(self)?;
        j.push(b'\n');
        write_atomic(path, &j)
    }
}

/// The OIDC audience that binds a token to a node key: the prefix, then
/// the hex SHA-256 of the key's 32 raw bytes.
pub fn audience_for(prefix: &str, k: &NodePublic) -> String {
    format!("{prefix}{}", hex::encode(Sha256::digest(k.as_bytes())))
}

/// A node's private identity plus its published record. Keep it private.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKey {
    pub private: NodePrivate,
    pub record: NodeRecord,
}

impl DeviceKey {
    /// Loads a key file.
    pub fn load(path: &Path) -> Result<DeviceKey> {
        let b = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let k: DeviceKey = serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display()))?;
        ensure!(
            k.private.public() == k.record.nodekey && k.private.disco_private().public() == k.record.discokey,
            "{}: the record's keys don't match the private key",
            path.display()
        );
        Ok(k)
    }

    /// Saves the key file, readable only by its owner. An existing file
    /// is an error unless `replace`; either way the file appears whole,
    /// or not at all.
    pub fn save(&self, path: &Path, replace: bool) -> Result<()> {
        let j = serde_json::to_vec_pretty(self)?;
        write_file(path, &j, 0o600, replace).map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => anyhow!("{} already exists; use --force to overwrite", path.display()),
            _ => anyhow::Error::new(e).context(format!("writing {}", path.display())),
        })
    }
}

/// Writes a file atomically, replacing any existing one: readers see the
/// old content or the new, never a partial write.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    write_file(path, data, 0o666, true).with_context(|| format!("writing {}", path.display()))
}

/// Writes `data` to a temporary file created with `mode` (on Unix, less
/// the umask) beside `path`, then moves it into place: renamed over any
/// existing file if `replace`, else linked, which fails if `path` exists.
/// The temporary file is hidden and doesn't end in `.json`, so it never
/// shows up in a records directory.
fn write_file(path: &Path, data: &[u8], mode: u32, replace: bool) -> io::Result<()> {
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a file name"))?;
    let mut tmp = OsString::from(".");
    tmp.push(name);
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(tmp);
    // A leftover from a crash might have other permissions.
    let _ = std::fs::remove_file(&tmp);
    let res = (|| {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        set_mode(&mut o, mode);
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        if replace { std::fs::rename(&tmp, path) } else { std::fs::hard_link(&tmp, path) }
    })();
    if res.is_err() || !replace {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Makes `o` create files with `mode`, less the umask.
#[cfg(unix)]
fn set_mode(o: &mut std::fs::OpenOptions, mode: u32) {
    std::os::unix::fs::OpenOptionsExt::mode(o, mode);
}

/// Does nothing: files have no Unix mode here.
#[cfg(not(unix))]
fn set_mode(_: &mut std::fs::OpenOptions, _: u32) {}

/// The default overlay address for a node: `base + attempt*256 + index`
/// within an IPv4 prefix, so the default `100.64.0.0/16` gives
/// `100.64.<attempt>.<index>`. The index must be below 256, or it would
/// take another attempt's address.
pub fn overlay_ip(prefix: &IpNet, attempt: u32, index: u32) -> Result<IpAddr> {
    let IpAddr::V4(base) = prefix.addr else { bail!("the overlay prefix must be IPv4") };
    ensure!(index < 256, "index {index} is too large for a default overlay IP; pass --ip");
    let host_bits = 32 - prefix.prefix_len.min(32) as u32;
    let offset = attempt as u64 * 256 + index as u64;
    ensure!(offset < 1 << host_bits, "attempt {attempt} index {index} doesn't fit in {prefix}");
    let mask = u32::MAX.checked_shl(host_bits).unwrap_or(0);
    Ok(IpAddr::V4(Ipv4Addr::from((u32::from(base) & mask) + offset as u32)))
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use hegel::TestCase;
    use hegel::generators as gs;
    use serde_json::{Value, json};
    use tailcat::DerpMap;

    use super::*;

    /// A record for a fresh key: node `index`, at `ip`.
    fn fresh(index: u32, ip: &str) -> NodeRecord {
        NodeRecord::new(index, &NodePrivate::generate(), ip.parse().unwrap())
    }

    /// A fresh key, with its record as node 1.
    fn device_key() -> DeviceKey {
        let private = NodePrivate::generate();
        DeviceKey { record: NodeRecord::new(1, &private, "100.64.1.1".parse().unwrap()), private }
    }

    fn file_names(dir: &Path) -> Vec<OsString> {
        fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect()
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn overlay_ips() {
        let ip = |p: &str, attempt, index| overlay_ip(&p.parse().unwrap(), attempt, index).map(|ip| ip.to_string());
        assert_eq!(ip("100.64.0.0/16", 1, 3).unwrap(), "100.64.1.3");
        assert_eq!(ip("100.64.0.0/16", 2, 0).unwrap(), "100.64.2.0");
        // The base is masked to the prefix.
        assert_eq!(ip("100.64.7.7/16", 0, 9).unwrap(), "100.64.0.9");
        assert_eq!(ip("0.0.0.0/0", 1, 1).unwrap(), "0.0.1.1");
        assert_eq!(ip("10.9.8.0/24", 0, 255).unwrap(), "10.9.8.255");
        assert!(ip("10.9.8.0/24", 1, 0).is_err());
        // Index 256 would be attempt 2's index 0.
        assert!(ip("100.64.0.0/16", 1, 256).is_err());
        assert!(ip("10.9.8.7/32", 0, 1).is_err());
        assert!(ip("fd00::/64", 1, 1).is_err());
    }

    #[test]
    fn record_round_trip() {
        let k = NodePrivate::generate();
        let r = NodeRecord {
            derp_region: 302,
            routes: vec!["10.42.3.0/24".parse().unwrap()],
            os: "Linux".into(),
            arch: "X64".into(),
            run_id: RunId::given("123"),
            run_attempt: Attempt::given("1"),
            ..NodeRecord::new(3, &k, "100.64.1.3".parse().unwrap())
        };
        let json = serde_json::to_vec(&r).unwrap();
        assert_eq!(NodeRecord::from_json(&json).unwrap(), r);
        assert_eq!(r.allowed_ips(), ["100.64.1.3/32".parse().unwrap(), "10.42.3.0/24".parse().unwrap()]);
        let aud = audience_for("tailcat-device:", &k.public());
        assert_eq!(aud.len(), "tailcat-device:".len() + 64);
    }

    #[test]
    fn minimal_record_omits_empty_fields() {
        let v = serde_json::to_value(fresh(0, "100.64.1.0")).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["discokey", "index", "nodekey", "overlay_ip"]);
    }

    #[test]
    fn rejects_bad_records() {
        let good = serde_json::to_value(fresh(0, "100.64.1.0")).unwrap();
        // `good`, but with field `k` set to `v`.
        let with = |k: &str, v: Value| {
            let mut j = good.clone();
            j[k] = v;
            NodeRecord::from_json(&serde_json::to_vec(&j).unwrap())
        };
        let zeros = "0".repeat(64);
        assert!(with("index", 7.into()).is_ok());
        assert!(with("nodekey", format!("nodekey:{zeros}").into()).is_err(), "zero node key");
        assert!(with("discokey", format!("discokey:{zeros}").into()).is_err(), "zero disco key");
        assert!(with("routes", json!(["10.0.0.0/8", "bogus"])).is_err(), "bad route");
        assert!(with("overlay_ip", "not-an-ip".into()).is_err());
        assert!(NodeRecord::from_json(b"{\"index\": 1").is_err(), "half-written");
        // An empty token is no token.
        assert_eq!(with("jwt", "".into()).unwrap().jwt, None);
        assert_eq!(with("jwt", "a.b.c".into()).unwrap().jwt, Some(Jwt("a.b.c".into())));
    }

    #[test]
    fn home_region_prefers_embedded() {
        let region = |region_id, code: &str| DerpRegion { region_id, region_code: code.into(), ..Default::default() };
        let mut dm = DerpMap::default();
        dm.regions.insert(5, region(5, "map"));
        let mut r = NodeRecord { derp_region: 5, ..fresh(0, "0.0.0.0") };
        assert_eq!(r.home_region(&dm).unwrap().region_code, "map");
        r.derp = Some(region(900, "own"));
        assert_eq!(r.home_region(&dm).unwrap().region_code, "own");
        r.derp = None;
        r.derp_region = 6;
        assert!(r.home_region(&dm).is_none());
    }

    #[test]
    fn device_key_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let k = device_key();
        k.save(&path, false).unwrap();
        assert_private(&path);
        let back = DeviceKey::load(&path).unwrap();
        assert_eq!(back.private, k.private);
        assert_eq!(back.record, k.record);

        // An existing key is kept unless it's to be replaced.
        let other = DeviceKey { private: NodePrivate::generate(), record: k.record.clone() };
        let err = other.save(&path, false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err:#}");
        assert_eq!(DeviceKey::load(&path).unwrap().private, k.private);

        // A record that isn't the key's is refused.
        other.save(&path, true).unwrap();
        assert!(DeviceKey::load(&path).is_err());
        assert!(DeviceKey::load(&dir.path().join("missing")).is_err());
        assert_eq!(file_names(dir.path()), ["key"], "no temporary files left");
    }

    /// Asserts that only its owner may read or write `p`.
    #[cfg(unix)]
    fn assert_private(p: &Path) {
        assert_eq!(mode(p), 0o600);
    }

    /// Asserts nothing: files have no Unix mode here.
    #[cfg(not(unix))]
    fn assert_private(_: &Path) {}

    /// Replacing a world-readable file doesn't leave the new private key
    /// readable by others.
    #[cfg(unix)]
    #[test]
    fn replaced_key_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let k = device_key();
        k.save(&path, true).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(DeviceKey::load(&path).unwrap().private, k.private);
    }

    #[test]
    fn records_are_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node-1-0.json");
        let r = fresh(0, "100.64.1.0");
        fs::write(&path, b"{\"index\": ").unwrap();
        r.write(&path).unwrap();
        let written = fs::read(&path).unwrap();
        assert_eq!(NodeRecord::from_json(&written).unwrap(), r);
        assert_eq!(file_names(dir.path()), ["node-1-0.json"]);
    }

    /// Distinct attempts and indexes never share a default overlay IP.
    #[hegel::test(test_cases = 500)]
    fn default_overlay_ips_are_distinct(tc: TestCase) {
        let prefix_len = tc.draw(gs::integers::<u8>().min_value(8).max_value(24));
        let prefix = IpNet::new([100, 64, 0, 0].into(), prefix_len);
        let n = || gs::integers::<u32>().max_value(1000);
        let (a, b) = ((tc.draw(n()), tc.draw(n())), (tc.draw(n()), tc.draw(n())));
        tc.assume(a != b);
        let (Ok(x), Ok(y)) = (overlay_ip(&prefix, a.0, a.1), overlay_ip(&prefix, b.0, b.1)) else { return };
        assert_ne!(x, y, "{a:?} and {b:?} both get {x} in {prefix}");
        assert!(prefix.contains(&x), "{x} is outside {prefix}");
        assert!(prefix.contains(&y), "{y} is outside {prefix}");
    }
}
