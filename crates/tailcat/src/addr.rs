//! Tailcat addresses: the compact, URL-safe `tc…` strings a server gives
//! to clients. An address is `"tc"` followed by the unpadded base64url
//! encoding of a CBOR map with single-character keys (the wire format
//! shared with the Go implementation):
//!
//! | key | field                                   |
//! |-----|-----------------------------------------|
//! | `p` | server node public key (32 bytes)        |
//! | `k` | server disco public key (32 bytes)       |
//! | `q` | WireGuard pre-shared key (32 bytes)      |
//! | `r` | embedded DERP regions (array of maps)    |
//! | `i` | DERP region ID in the default DERP map   |
//!
//! Regions use `i` (region ID), `c` (code), `m` (name) and `N` (nodes);
//! nodes use `n` (name), `i`, `h` (hostname), `t` (cert name), `4`, `6`
//! (IPs), `s` (STUN port), `d` (DERP port) and `x` (insecure for tests).

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use ciborium::Value;
use serde::{Deserialize, Serialize};

use crate::derpmap::{DerpMap, DerpNode, DerpRegion, FetchOptions};
use crate::key::{DiscoPublic, NodePrivate, NodePublic, PresharedKey};
use crate::{Error, Result};

/// A tailcat address, like `tcomFwWC…`. It names a server and how to
/// reach it, and normally contains the server's WireGuard pre-shared
/// key, making it a secret bearer capability.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Addr(String);

impl Addr {
    /// Wraps a string without validating it; see [`Addr::parse`].
    pub fn new(s: impl Into<String>) -> Self {
        Addr(s.into())
    }

    /// Returns the address string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the address into a [`ConnInfo`], restoring the fields that
    /// encoding elided (region and node IDs, region codes, node names).
    pub fn parse(&self) -> Result<ConnInfo> {
        let w = WireConnInfo::decode(self)?;
        let mut ci = ConnInfo {
            server_public: w.server_public,
            server_disco_public: w.server_disco_public.unwrap_or_default(),
            preshared_key: w.preshared_key.unwrap_or_default(),
            region: w.region.into_iter().map(WireRegion::into_region).collect(),
            region_id: w.region_id as i32,
        };
        for (ri, r) in ci.region.iter_mut().enumerate() {
            if r.region_id == 0 {
                r.region_id = ri as i32 + 1;
            }
            if r.region_code.is_empty() {
                r.region_code = r.region_id.to_string();
            }
            for n in &mut r.nodes {
                if n.name.is_empty() {
                    n.name = n.host_name.clone();
                }
                if n.region_id == 0 {
                    n.region_id = r.region_id;
                }
            }
        }
        Ok(ci)
    }

    /// Decodes the address to a JSON value showing just the fields it
    /// carries, for display (the CLI's `parse` subcommand).
    pub fn parse_raw_json(&self) -> Result<serde_json::Value> {
        Ok(WireConnInfo::decode(self)?.to_json())
    }

    /// Returns a self-contained equivalent of this address with the DERP
    /// relay details embedded, so that later use needs no DERP map fetch.
    /// An address that already embeds its relay is returned unchanged.
    pub async fn resolve(&self, opts: FetchOptions<'_>) -> Result<Addr> {
        let mut ci = self.parse()?;
        if !ci.region.is_empty() {
            return Ok(self.clone());
        }
        ci.expand(opts, None).await?;
        for r in &mut ci.region {
            r.nodes.truncate(2);
        }
        ci.region_id = 0;
        Ok(ci.addr())
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Addresses are secrets; don't print them whole in debug output.
        let n = self.0.len().min(12);
        write!(f, "Addr({}…)", &self.0[..n])
    }
}

impl FromStr for Addr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let a = Addr::new(s);
        a.parse()?;
        Ok(a)
    }
}

impl From<&str> for Addr {
    fn from(s: &str) -> Self {
        Addr::new(s)
    }
}

impl From<String> for Addr {
    fn from(s: String) -> Self {
        Addr(s)
    }
}

/// How to reach a server: its WireGuard and disco public keys, the
/// WireGuard pre-shared key, and which DERP region to rendezvous in.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ConnInfo {
    #[serde(rename = "ServerPublic")]
    pub server_public: NodePublic,
    /// Deliberately independent from `server_public`: disco packets
    /// carry it in cleartext on direct UDP paths.
    #[serde(rename = "ServerDiscoPublic", default)]
    pub server_disco_public: DiscoPublic,
    /// Mixed into the WireGuard handshake. Zero disables the PSK layer.
    #[serde(rename = "PresharedKey", default)]
    pub preshared_key: PresharedKey,
    /// Embedded DERP regions (at most one today). Either this or
    /// `region_id` must be set.
    #[serde(rename = "Region", default, skip_serializing_if = "Vec::is_empty")]
    pub region: Vec<DerpRegion>,
    /// A region ID in the DERP map, or `-1` to pick the nearest region
    /// at server startup (used in saved keys).
    #[serde(rename = "RegionID", default, skip_serializing_if = "is_zero")]
    pub region_id: i32,
}

fn is_zero(v: &i32) -> bool {
    *v == 0
}

impl ConnInfo {
    /// Serializes to a compact [`Addr`]. Region IDs, codes and names, and
    /// node names redundant with their hostname, are dropped to save
    /// space; [`Addr::parse`] restores them.
    pub fn addr(&self) -> Addr {
        let w = WireConnInfo {
            server_public: self.server_public,
            server_disco_public: (!self.server_disco_public.is_zero()).then_some(self.server_disco_public),
            preshared_key: (!self.preshared_key.is_zero()).then_some(self.preshared_key),
            region: self
                .region
                .iter()
                .map(|r| {
                    let mut w = WireRegion::from_region(r);
                    w.region_id = 0;
                    w.region_code.clear();
                    w.region_name.clear();
                    for n in &mut w.nodes {
                        n.region_id = 0;
                        if !n.host_name.is_empty() {
                            n.name.clear();
                        }
                    }
                    w
                })
                .collect(),
            region_id: self.region_id as i64,
        };
        w.encode()
    }

    /// Populates `region` from a DERP map if only `region_id` is set.
    /// With `region_id == -1`, the nearest region is picked by latency.
    /// If `dm` is given it is used instead of fetching a map.
    pub async fn expand(&mut self, opts: FetchOptions<'_>, dm: Option<&DerpMap>) -> Result<()> {
        for r in &mut self.region {
            if r.region_id == 0 {
                r.region_id = 1;
            }
            let rid = r.region_id;
            for n in &mut r.nodes {
                if n.region_id == 0 {
                    n.region_id = rid;
                }
            }
        }
        if !self.region.is_empty() || self.region_id == 0 {
            return Ok(());
        }
        let fetched;
        let (dm, src) = match dm {
            Some(dm) => (dm, "provided DERP map".to_string()),
            None => {
                fetched = crate::derpmap::fetch_derp_map(opts)
                    .await
                    .map_err(|e| Error::other(format!("fetching DERPMap for region {}: {e}", self.region_id)))?;
                (&fetched, opts.url.unwrap_or(crate::DEFAULT_DERP_MAP_URL).to_string())
            }
        };
        if self.region_id == -1 {
            let mut dm = dm.clone();
            {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                for r in dm.regions.values_mut() {
                    r.nodes.shuffle(&mut rng);
                }
            }
            let picked = crate::netcheck::pick_best_region(&dm).await?;
            let rid = match picked {
                Some(rid) => rid,
                None => {
                    // Netcheck failed; pick a random region, assuming the map
                    // server filtered the map for us when asked as a server.
                    use rand::seq::IteratorRandom;
                    *dm.regions
                        .keys()
                        .choose(&mut rand::thread_rng())
                        .ok_or_else(|| Error::other("failed to auto-detect any regions"))?
                }
            };
            self.region_id = 0;
            self.region = vec![dm.regions[&rid].clone()];
            return Ok(());
        }
        let r = dm.regions.get(&self.region_id).ok_or_else(|| {
            Error::other(format!(
                "tailcat address specified DERP RegionID {} but no such region exists in {src}",
                self.region_id
            ))
        })?;
        self.region.push(r.clone());
        Ok(())
    }
}

/// A node identity: a private key and the connection info to reach this
/// node. Despite the historical field name, `public` contains the secret
/// pre-shared key; the whole value must be kept private. This is the
/// format of `*.private.json` key files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    #[serde(rename = "Private")]
    pub private: NodePrivate,
    #[serde(rename = "Public")]
    pub public: ConnInfo,
}

impl PrivateKey {
    /// Generates a new identity with a fresh node key and pre-shared key,
    /// but no DERP region (the caller populates it).
    pub fn generate() -> Self {
        let private = NodePrivate::generate();
        let public = ConnInfo {
            server_public: private.public(),
            server_disco_public: private.disco_private().public(),
            preshared_key: PresharedKey::generate(),
            ..Default::default()
        };
        PrivateKey { private, public }
    }

    /// Serializes like Go's `json.MarshalIndent(v, "", "\t")`.
    pub fn to_json_pretty(&self) -> String {
        let mut buf = Vec::new();
        let fmt = serde_json::ser::PrettyFormatter::with_indent(b"\t");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
        self.serialize(&mut ser).expect("key serializes");
        String::from_utf8(buf).expect("JSON is UTF-8")
    }
}

// ---------------------------------------------------------------------
// Wire (CBOR) types

#[derive(Debug, Default)]
struct WireConnInfo {
    server_public: NodePublic,
    server_disco_public: Option<DiscoPublic>,
    preshared_key: Option<PresharedKey>,
    region: Vec<WireRegion>,
    region_id: i64,
}

#[derive(Debug, Default, Clone)]
struct WireRegion {
    region_id: i64,
    region_code: String,
    region_name: String,
    nodes: Vec<WireNode>,
}

#[derive(Debug, Default, Clone)]
struct WireNode {
    name: String,
    region_id: i64,
    host_name: String,
    cert_name: String,
    ipv4: String,
    ipv6: String,
    stun_port: i64,
    derp_port: i64,
    insecure_for_tests: bool,
}

fn text(k: &str) -> Value {
    Value::Text(k.to_string())
}

fn push_str(m: &mut Vec<(Value, Value)>, k: &str, v: &str) {
    if !v.is_empty() {
        m.push((text(k), Value::Text(v.to_string())));
    }
}

fn push_int(m: &mut Vec<(Value, Value)>, k: &str, v: i64) {
    if v != 0 {
        m.push((text(k), Value::Integer(v.into())));
    }
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Addr(msg.into())
}

fn as_map(v: Value, what: &str) -> Result<Vec<(Value, Value)>> {
    match v {
        Value::Map(m) => Ok(m),
        Value::Null => Err(bad(format!("invalid tailcat address: {what} is null"))),
        _ => Err(bad(format!("invalid tailcat address: {what} is not a map"))),
    }
}

fn as_int(v: &Value, what: &str) -> Result<i64> {
    match v {
        Value::Integer(i) => i64::try_from(*i).map_err(|_| bad(format!("{what} out of range"))),
        _ => Err(bad(format!("{what} is not an integer"))),
    }
}

fn as_text(v: Value, what: &str) -> Result<String> {
    match v {
        Value::Text(s) => Ok(s),
        _ => Err(bad(format!("{what} is not a string"))),
    }
}

fn as_bytes32(v: Value, what: &str) -> Result<[u8; 32]> {
    match v {
        Value::Bytes(b) => {
            <[u8; 32]>::try_from(b.as_slice()).map_err(|_| bad(format!("invalid {what} length {}, want 32", b.len())))
        }
        _ => Err(bad(format!("{what} is not a byte string"))),
    }
}

impl WireNode {
    fn to_value(&self) -> Value {
        let mut m = Vec::new();
        push_str(&mut m, "n", &self.name);
        push_int(&mut m, "i", self.region_id);
        push_str(&mut m, "h", &self.host_name);
        push_str(&mut m, "t", &self.cert_name);
        push_str(&mut m, "4", &self.ipv4);
        push_str(&mut m, "6", &self.ipv6);
        push_int(&mut m, "s", self.stun_port);
        push_int(&mut m, "d", self.derp_port);
        if self.insecure_for_tests {
            m.push((text("x"), Value::Bool(true)));
        }
        Value::Map(m)
    }

    fn from_value(v: Value, what: &str) -> Result<Self> {
        let mut n = WireNode::default();
        for (k, v) in as_map(v, what)? {
            let Value::Text(k) = k else { continue };
            match k.as_str() {
                "n" => n.name = as_text(v, "node name")?,
                "i" => n.region_id = as_int(&v, "node region ID")?,
                "h" => n.host_name = as_text(v, "node hostname")?,
                "t" => n.cert_name = as_text(v, "node cert name")?,
                "4" => n.ipv4 = as_text(v, "node IPv4")?,
                "6" => n.ipv6 = as_text(v, "node IPv6")?,
                "s" => n.stun_port = as_int(&v, "node STUN port")?,
                "d" => n.derp_port = as_int(&v, "node DERP port")?,
                "x" => n.insecure_for_tests = matches!(v, Value::Bool(true)),
                _ => {}
            }
        }
        Ok(n)
    }

    fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        if !self.name.is_empty() {
            m.insert("Name".into(), self.name.as_str().into());
        }
        if self.region_id != 0 {
            m.insert("RegionID".into(), self.region_id.into());
        }
        for (k, v) in
            [("HostName", &self.host_name), ("CertName", &self.cert_name), ("IPv4", &self.ipv4), ("IPv6", &self.ipv6)]
        {
            if !v.is_empty() {
                m.insert(k.into(), v.as_str().into());
            }
        }
        if self.stun_port != 0 {
            m.insert("STUNPort".into(), self.stun_port.into());
        }
        if self.derp_port != 0 {
            m.insert("DERPPort".into(), self.derp_port.into());
        }
        if self.insecure_for_tests {
            m.insert("InsecureForTests".into(), true.into());
        }
        serde_json::Value::Object(m)
    }
}

impl WireRegion {
    fn from_region(r: &DerpRegion) -> Self {
        WireRegion {
            region_id: r.region_id as i64,
            region_code: r.region_code.clone(),
            region_name: r.region_name.clone(),
            // STUN-only nodes can't relay, which is all an embedded region is for.
            nodes: r
                .nodes
                .iter()
                .filter(|n| !n.stun_only)
                .map(|n| WireNode {
                    name: n.name.clone(),
                    region_id: n.region_id as i64,
                    host_name: n.host_name.clone(),
                    cert_name: n.cert_name.clone(),
                    ipv4: n.ipv4.clone(),
                    ipv6: n.ipv6.clone(),
                    stun_port: n.stun_port as i64,
                    derp_port: n.derp_port as i64,
                    insecure_for_tests: n.insecure_for_tests,
                })
                .collect(),
        }
    }

    fn into_region(self) -> DerpRegion {
        DerpRegion {
            region_id: self.region_id as i32,
            region_code: self.region_code,
            region_name: self.region_name,
            nodes: self
                .nodes
                .into_iter()
                .map(|n| DerpNode {
                    name: n.name,
                    region_id: n.region_id as i32,
                    host_name: n.host_name,
                    cert_name: n.cert_name,
                    ipv4: n.ipv4,
                    ipv6: n.ipv6,
                    stun_port: n.stun_port as i32,
                    derp_port: n.derp_port as i32,
                    insecure_for_tests: n.insecure_for_tests,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    fn to_value(&self) -> Value {
        let mut m = Vec::new();
        push_int(&mut m, "i", self.region_id);
        push_str(&mut m, "c", &self.region_code);
        push_str(&mut m, "m", &self.region_name);
        if !self.nodes.is_empty() {
            m.push((text("N"), Value::Array(self.nodes.iter().map(WireNode::to_value).collect())));
        }
        Value::Map(m)
    }

    fn from_value(v: Value, idx: usize) -> Result<Self> {
        let mut r = WireRegion::default();
        for (k, v) in as_map(v, &format!("region {idx}"))? {
            let Value::Text(k) = k else { continue };
            match k.as_str() {
                "i" => r.region_id = as_int(&v, "region ID")?,
                "c" => r.region_code = as_text(v, "region code")?,
                "m" => r.region_name = as_text(v, "region name")?,
                "N" => match v {
                    Value::Array(a) => {
                        for (j, n) in a.into_iter().enumerate() {
                            r.nodes.push(WireNode::from_value(n, &format!("region {idx} node {j}"))?);
                        }
                    }
                    Value::Null => {}
                    _ => return Err(bad("region nodes is not an array")),
                },
                _ => {}
            }
        }
        Ok(r)
    }

    fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        if self.region_id != 0 {
            m.insert("RegionID".into(), self.region_id.into());
        }
        if !self.region_code.is_empty() {
            m.insert("RegionCode".into(), self.region_code.clone().into());
        }
        if !self.region_name.is_empty() {
            m.insert("RegionName".into(), self.region_name.clone().into());
        }
        if !self.nodes.is_empty() {
            m.insert("Nodes".into(), self.nodes.iter().map(WireNode::to_json).collect());
        }
        serde_json::Value::Object(m)
    }
}

impl WireConnInfo {
    fn encode(&self) -> Addr {
        let mut m = vec![(text("p"), Value::Bytes(self.server_public.as_bytes().to_vec()))];
        if let Some(k) = &self.server_disco_public {
            m.push((text("k"), Value::Bytes(k.as_bytes().to_vec())));
        }
        if let Some(q) = &self.preshared_key {
            m.push((text("q"), Value::Bytes(q.as_bytes().to_vec())));
        }
        if !self.region.is_empty() {
            m.push((text("r"), Value::Array(self.region.iter().map(WireRegion::to_value).collect())));
        }
        push_int(&mut m, "i", self.region_id);
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(m), &mut buf).expect("CBOR encoding to a Vec cannot fail");
        Addr(format!("tc{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)))
    }

    fn decode(addr: &Addr) -> Result<Self> {
        let rest = addr.0.strip_prefix("tc").ok_or_else(|| bad("tailcat address doesn't start with \"tc\""))?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(rest)
            .map_err(|e| bad(format!("base64 decode: {e}")))?;
        let v: Value = ciborium::from_reader(raw.as_slice()).map_err(|e| bad(format!("CBOR unmarshal: {e}")))?;
        let mut w = WireConnInfo::default();
        let mut have_p = false;
        for (k, v) in as_map(v, "address")? {
            let Value::Text(k) = k else { continue };
            match k.as_str() {
                "p" => {
                    w.server_public = NodePublic::from_bytes(as_bytes32(v, "node public key")?);
                    have_p = true;
                }
                "k" => w.server_disco_public = Some(DiscoPublic::from_bytes(as_bytes32(v, "disco public key")?)),
                "q" => w.preshared_key = Some(PresharedKey::from_bytes(as_bytes32(v, "WireGuard pre-shared key")?)),
                "r" => match v {
                    Value::Array(a) => {
                        for (i, r) in a.into_iter().enumerate() {
                            w.region.push(WireRegion::from_value(r, i)?);
                        }
                    }
                    Value::Null => {}
                    _ => return Err(bad("regions is not an array")),
                },
                "i" => w.region_id = as_int(&v, "region ID")?,
                _ => {}
            }
        }
        if !have_p {
            return Err(bad("tailcat address has no server public key"));
        }
        Ok(w)
    }

    fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("ServerPublic".into(), self.server_public.to_string().into());
        if let Some(k) = &self.server_disco_public {
            m.insert("ServerDiscoPublic".into(), k.to_string().into());
        }
        if let Some(q) = &self.preshared_key {
            m.insert("PresharedKey".into(), q.to_string().into());
        }
        if !self.region.is_empty() {
            m.insert("Region".into(), self.region.iter().map(WireRegion::to_json).collect());
        }
        if self.region_id != 0 {
            m.insert("RegionID".into(), self.region_id.into());
        }
        serde_json::Value::Object(m)
    }
}

/// Formats a JSON value the way Go's `json.Encoder` with
/// `SetIndent("", "    ")` does, with a trailing newline.
pub fn to_go_indented_json(v: &serde_json::Value) -> String {
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
    v.serialize(&mut ser).expect("JSON value serializes");
    let mut s = String::from_utf8(buf).expect("JSON is UTF-8");
    s.push('\n');
    s
}

/// Builds the connection info for a node key with the given regions.
pub fn conn_info_for(private: &NodePrivate, psk: PresharedKey, region: Vec<DerpRegion>, region_id: i32) -> ConnInfo {
    ConnInfo {
        server_public: private.public(),
        server_disco_public: private.disco_private().public(),
        preshared_key: psk,
        region,
        region_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Examples from the upstream README (pre-disco-key addresses).
    const SHORT: &str = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu";
    const RESOLVED: &str = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFygaFhToGjYWhudGMzMDJhLmlwbi5kZXZhNG0yMDguMTExLjM5LjM4YTZzMjYwNzpmNzQwOjA6M2Y6OjcyMA";
    const CUSTOM: &str = "tcomFwWCCAIsKOqPUux6ClG2RM4A_vOq4VBzGgHGGjq9OsJuFKSWFygaFhToGhYWhwZGVycC5leGFtcGxlLmNvbQ";

    #[test]
    fn parses_upstream_readme_examples() {
        let ci = Addr::new(SHORT).parse().unwrap();
        assert_eq!(
            ci.server_public.to_string(),
            "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34"
        );
        assert_eq!(ci.region_id, 302);
        assert!(ci.region.is_empty());

        let ci = Addr::new(RESOLVED).parse().unwrap();
        assert_eq!(ci.region.len(), 1);
        let n = &ci.region[0].nodes[0];
        assert_eq!(n.host_name, "tc302a.ipn.dev");
        assert_eq!(n.ipv4, "208.111.39.38");
        assert_eq!(n.ipv6, "2607:f740:0:3f::720");
        // Restored implicit fields:
        assert_eq!(ci.region[0].region_id, 1);
        assert_eq!(n.name, "tc302a.ipn.dev");

        let raw = Addr::new(CUSTOM).parse_raw_json().unwrap();
        assert_eq!(
            raw,
            serde_json::json!({
                "ServerPublic": "nodekey:8022c28ea8f52ec7a0a51b644ce00fef3aae150731a01c61a3abd3ac26e14a49",
                "Region": [{"Nodes": [{"HostName": "derp.example.com"}]}]
            })
        );
    }

    #[test]
    fn short_address_is_byte_identical_to_go() {
        // Re-encoding the Go-produced address gives the same string: same
        // key order, same minimal integer encoding.
        let ci = Addr::new(SHORT).parse().unwrap();
        assert_eq!(ci.addr().as_str(), SHORT);
        let ci = Addr::new(RESOLVED).parse().unwrap();
        assert_eq!(ci.addr().as_str(), RESOLVED);
    }

    #[test]
    fn round_trips_full_info() {
        let k = PrivateKey::generate();
        let mut ci = k.public.clone();
        ci.region = vec![DerpRegion {
            region_id: 7,
            region_code: "x".into(),
            nodes: vec![DerpNode {
                name: "n".into(),
                host_name: "127.0.0.1".into(),
                ipv4: "127.0.0.1".into(),
                ipv6: "none".into(),
                derp_port: 4443,
                stun_port: 3478,
                insecure_for_tests: true,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let a = ci.addr();
        let back = a.parse().unwrap();
        assert_eq!(back.server_public, ci.server_public);
        assert_eq!(back.server_disco_public, ci.server_disco_public);
        assert_eq!(back.preshared_key, ci.preshared_key);
        let n = &back.region[0].nodes[0];
        assert_eq!(n.derp_port, 4443);
        assert!(n.insecure_for_tests);
        assert_eq!(n.ipv6, "none");
    }

    #[test]
    fn rejects_garbage() {
        assert!(Addr::new("nope").parse().is_err());
        assert!(Addr::new("tc!!!").parse().is_err());
        assert!(Addr::new("tcoA").parse().is_err()); // empty map: no key
        // A null region must be rejected, not dereferenced.
        let mut buf = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![(text("p"), Value::Bytes(vec![1; 32])), (text("r"), Value::Array(vec![Value::Null]))]),
            &mut buf,
        )
        .unwrap();
        let a = Addr::new(format!("tc{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)));
        assert!(a.parse().is_err());
    }

    #[test]
    fn private_key_json_matches_go_shape() {
        let k = PrivateKey::generate();
        let j = k.to_json_pretty();
        assert!(j.contains("\t\"Private\": \"privkey:"));
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert!(v["Public"]["ServerPublic"].as_str().unwrap().starts_with("nodekey:"));
        assert!(v["Public"]["PresharedKey"].as_str().unwrap().starts_with("psk:"));
        assert!(v["Public"].get("Region").is_none());
        let back: PrivateKey = serde_json::from_str(&j).unwrap();
        assert_eq!(back.private, k.private);

        // A Go client key file (RegionID omitted, zero disco key allowed).
        let go = format!(
            "{{\"Private\":\"{}\",\"Public\":{{\"ServerPublic\":\"{}\",\"ServerDiscoPublic\":\"discokey:{}\",\"PresharedKey\":\"psk:{}\"}}}}",
            k.private,
            k.private.public(),
            "0".repeat(64),
            "0".repeat(64)
        );
        let back: PrivateKey = serde_json::from_str(&go).unwrap();
        assert!(back.public.preshared_key.is_zero());
    }
}
