//! Node records: the public half of a mesh node's identity, published
//! (for example as a GitHub Actions run artifact) so that every other
//! node can add it as a peer. The private key never leaves the node.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, bail};
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
    /// Parses and checks a record.
    pub fn from_json(b: &[u8]) -> Result<NodeRecord> {
        let r: NodeRecord = serde_json::from_slice(b).context("parsing node record")?;
        if r.nodekey.is_zero() || r.discokey.is_zero() {
            bail!("node record {} has a zero key", r.index);
        }
        for route in &r.routes {
            route.parse::<IpNet>().map_err(|e| anyhow::anyhow!("node record {}: route {route:?}: {e}", r.index))?;
        }
        Ok(r)
    }

    /// The prefixes routed to this node: its overlay IP plus its routes.
    pub fn allowed_ips(&self) -> Vec<IpNet> {
        let mut v = vec![IpNet::host(self.overlay_ip)];
        v.extend(self.routes.iter().filter_map(|r| r.parse::<IpNet>().ok()));
        v
    }

    /// The node's home region: embedded, or looked up in `dm`.
    pub fn home_region(&self, dm: &tailcat::DerpMap) -> Option<DerpRegion> {
        if let Some(r) = &self.derp {
            return Some(r.clone());
        }
        dm.regions.get(&self.derp_region).cloned()
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
        if k.private.public() != k.record.nodekey || k.private.disco_private().public() != k.record.discokey {
            bail!("{}: the record's keys don't match the private key", path.display());
        }
        Ok(k)
    }

    /// Saves the key file, readable only by its owner.
    pub fn save(&self, path: &Path) -> Result<()> {
        let j = serde_json::to_vec_pretty(self)?;
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
            f.write_all(&j)?;
        }
        #[cfg(not(unix))]
        std::fs::write(path, j)?;
        Ok(())
    }
}

/// The default overlay address for a node: `base + attempt*256 + index`
/// within an IPv4 prefix, so the default `100.64.0.0/16` gives
/// `100.64.<attempt>.<index>`.
pub fn overlay_ip(prefix: &IpNet, attempt: u32, index: u32) -> Result<IpAddr> {
    let IpAddr::V4(base) = prefix.addr else { bail!("the overlay prefix must be IPv4") };
    let host_bits = 32 - prefix.prefix_len as u32;
    let offset = attempt as u64 * 256 + index as u64;
    if host_bits < 32 && offset >= (1u64 << host_bits) {
        bail!("attempt {attempt} index {index} doesn't fit in {prefix}");
    }
    let mask = if prefix.prefix_len == 0 { 0 } else { u32::MAX << host_bits };
    Ok(IpAddr::V4(Ipv4Addr::from((u32::from(base) & mask) + offset as u32)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_ips() {
        let p: IpNet = "100.64.0.0/16".parse().unwrap();
        assert_eq!(overlay_ip(&p, 1, 3).unwrap().to_string(), "100.64.1.3");
        assert_eq!(overlay_ip(&p, 2, 0).unwrap().to_string(), "100.64.2.0");
        let small: IpNet = "10.9.8.0/24".parse().unwrap();
        assert!(overlay_ip(&small, 1, 0).is_err());
        assert!(overlay_ip(&"fd00::/64".parse().unwrap(), 1, 1).is_err());
    }

    #[test]
    fn record_round_trip() {
        let k = NodePrivate::generate();
        let r = NodeRecord {
            index: 3,
            nodekey: k.public(),
            discokey: k.disco_private().public(),
            overlay_ip: "100.64.1.3".parse().unwrap(),
            derp_region: 302,
            derp: None,
            routes: vec!["10.42.3.0/24".into()],
            endpoints: vec![],
            os: "Linux".into(),
            arch: "X64".into(),
            run_id: "123".into(),
            run_attempt: "1".into(),
            jwt: String::new(),
        };
        let j = serde_json::to_vec(&r).unwrap();
        assert_eq!(NodeRecord::from_json(&j).unwrap(), r);
        assert_eq!(r.allowed_ips().len(), 2);
        let aud = audience_for("tailcat-device:", &k.public());
        assert_eq!(aud.len(), "tailcat-device:".len() + 64);
    }
}
