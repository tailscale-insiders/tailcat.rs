//! Node records: the public half of a mesh node's identity, published
//! (for example as a GitHub Actions run artifact) so that every other
//! node can add it as a peer. The private key never leaves the node.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tailcat::wg::IpNet;
use tailcat::{DerpRegion, DiscoPublic, NodePrivate, NodePublic};

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
    pub routes: Vec<String>,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_attempt: String,
    /// A GitHub OIDC token binding `nodekey` to the repository, ref and
    /// run: its audience is [`audience_for`] of the node key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jwt: String,
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
            run_id: String::new(),
            run_attempt: String::new(),
            jwt: String::new(),
        }
    }

    /// Parses and checks a record.
    pub fn from_json(b: &[u8]) -> Result<NodeRecord> {
        let r: NodeRecord = serde_json::from_slice(b).context("parsing node record")?;
        ensure!(!r.nodekey.is_zero() && !r.discokey.is_zero(), "node record {} has a zero key", r.index);
        for route in &r.routes {
            route.parse::<IpNet>().map_err(|e| anyhow!("node record {}: route {route:?}: {e}", r.index))?;
        }
        Ok(r)
    }

    /// The prefixes routed to this node: its overlay IP plus its routes.
    pub fn allowed_ips(&self) -> Vec<IpNet> {
        std::iter::once(IpNet::host(self.overlay_ip)).chain(self.routes.iter().filter_map(|r| r.parse().ok())).collect()
    }

    /// The node's home region: embedded, or looked up in `dm`.
    pub fn home_region(&self, dm: &tailcat::DerpMap) -> Option<DerpRegion> {
        self.derp.clone().or_else(|| dm.regions.get(&self.derp_region).cloned())
    }

    /// Writes the record as pretty JSON.
    pub fn write(&self, path: &Path) -> Result<()> {
        let mut j = serde_json::to_vec_pretty(self)?;
        j.push(b'\n');
        std::fs::write(path, j).with_context(|| format!("writing {}", path.display()))
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

    /// Saves the key file, readable only by its owner.
    pub fn save(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        let j = serde_json::to_vec_pretty(self)?;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(path).and_then(|mut f| f.write_all(&j)).with_context(|| format!("writing {}", path.display()))
    }
}

/// The default overlay address for a node: `base + attempt*256 + index`
/// within an IPv4 prefix, so the default `100.64.0.0/16` gives
/// `100.64.<attempt>.<index>`.
pub fn overlay_ip(prefix: &IpNet, attempt: u32, index: u32) -> Result<IpAddr> {
    let IpAddr::V4(base) = prefix.addr else { bail!("the overlay prefix must be IPv4") };
    let host_bits = 32 - prefix.prefix_len.min(32) as u32;
    let offset = attempt as u64 * 256 + index as u64;
    ensure!(offset < 1 << host_bits, "attempt {attempt} index {index} doesn't fit in {prefix}");
    let mask = u32::MAX.checked_shl(host_bits).unwrap_or(0);
    Ok(IpAddr::V4(Ipv4Addr::from((u32::from(base) & mask) + offset as u32)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(ip("10.9.8.7/32", 0, 1).is_err());
        assert!(ip("fd00::/64", 1, 1).is_err());
    }

    #[test]
    fn record_round_trip() {
        let k = NodePrivate::generate();
        let r = NodeRecord {
            derp_region: 302,
            routes: vec!["10.42.3.0/24".into()],
            os: "Linux".into(),
            arch: "X64".into(),
            run_id: "123".into(),
            run_attempt: "1".into(),
            ..NodeRecord::new(3, &k, "100.64.1.3".parse().unwrap())
        };
        let j = serde_json::to_vec(&r).unwrap();
        assert_eq!(NodeRecord::from_json(&j).unwrap(), r);
        assert_eq!(r.allowed_ips(), ["100.64.1.3/32".parse().unwrap(), "10.42.3.0/24".parse().unwrap()]);
        let aud = audience_for("tailcat-device:", &k.public());
        assert_eq!(aud.len(), "tailcat-device:".len() + 64);
    }

    #[test]
    fn minimal_record_omits_empty_fields() {
        let r = NodeRecord::new(0, &NodePrivate::generate(), "100.64.1.0".parse().unwrap());
        let v = serde_json::to_value(&r).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["discokey", "index", "nodekey", "overlay_ip"]);
    }

    #[test]
    fn rejects_bad_records() {
        let good =
            serde_json::to_value(NodeRecord::new(0, &NodePrivate::generate(), "100.64.1.0".parse().unwrap())).unwrap();
        let with = |k: &str, v: serde_json::Value| {
            let mut j = good.clone();
            j[k] = v;
            NodeRecord::from_json(&serde_json::to_vec(&j).unwrap())
        };
        assert!(with("index", 7.into()).is_ok());
        assert!(with("nodekey", format!("nodekey:{}", "0".repeat(64)).into()).is_err(), "zero node key");
        assert!(with("discokey", format!("discokey:{}", "0".repeat(64)).into()).is_err(), "zero disco key");
        assert!(with("routes", serde_json::json!(["10.0.0.0/8", "bogus"])).is_err(), "bad route");
        assert!(with("overlay_ip", "not-an-ip".into()).is_err());
        assert!(NodeRecord::from_json(b"{\"index\": 1").is_err(), "half-written");
    }

    #[test]
    fn home_region_prefers_embedded() {
        let mut dm = tailcat::DerpMap::default();
        dm.regions.insert(5, DerpRegion { region_id: 5, region_code: "map".into(), ..Default::default() });
        let mut r = NodeRecord { derp_region: 5, ..NodeRecord::new(0, &NodePrivate::generate(), [0; 4].into()) };
        assert_eq!(r.home_region(&dm).unwrap().region_code, "map");
        r.derp = Some(DerpRegion { region_id: 900, region_code: "own".into(), ..Default::default() });
        assert_eq!(r.home_region(&dm).unwrap().region_code, "own");
        r.derp = None;
        r.derp_region = 6;
        assert!(r.home_region(&dm).is_none());
    }

    #[test]
    fn device_key_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let private = NodePrivate::generate();
        let k = DeviceKey { record: NodeRecord::new(1, &private, "100.64.1.1".parse().unwrap()), private };
        k.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let back = DeviceKey::load(&path).unwrap();
        assert_eq!(back.private, k.private);
        assert_eq!(back.record, k.record);

        // A record that isn't the key's is refused.
        let other = DeviceKey { private: NodePrivate::generate(), record: k.record };
        other.save(&path).unwrap();
        assert!(DeviceKey::load(&path).is_err());
        assert!(DeviceKey::load(&dir.path().join("missing")).is_err());
    }
}
