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

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value;
use serde::{Deserialize, Serialize};

use crate::derpmap::{
    CertName, DerpMap, DerpNode, DerpRegion, FetchOptions, Host, NodeIp, NodeName, RegionCode, RegionName, is_default,
};
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
        let w = Wire::decode(self)?;
        let mut ci = ConnInfo {
            server_public: w.server_public,
            server_disco_public: w.server_disco_public.unwrap_or_default(),
            preshared_key: w.preshared_key.unwrap_or_default(),
            region: w.region,
            region_id: w.region_id,
        };
        for (ri, r) in ci.region.iter_mut().enumerate() {
            if r.region_id == 0 {
                r.region_id = ri as i32 + 1;
            }
            if r.region_code.is_empty() {
                r.region_code = r.region_id.to_string().into();
            }
            for n in &mut r.nodes {
                if n.name.is_empty() {
                    n.name = n.host_name.text().into_owned().into();
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
        Ok(Wire::decode(self)?.into_json())
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
    #[serde(rename = "RegionID", default, skip_serializing_if = "is_default")]
    pub region_id: i32,
}

impl ConnInfo {
    /// The connection info for a node key with the given regions.
    pub fn for_key(
        private: &NodePrivate,
        psk: PresharedKey,
        region: impl IntoIterator<Item = DerpRegion>,
        region_id: i32,
    ) -> Self {
        ConnInfo {
            server_public: private.public(),
            server_disco_public: private.disco_private().public(),
            preshared_key: psk,
            region: region.into_iter().collect(),
            region_id,
        }
    }

    /// Serializes to a compact [`Addr`]. Region IDs, codes and names, and
    /// node names redundant with their hostname, are dropped to save
    /// space; [`Addr::parse`] restores them.
    pub fn addr(&self) -> Addr {
        let key = |k: &[u8; 32]| Value::Bytes(k.to_vec());
        let mut m = vec![(text("p"), key(self.server_public.as_bytes()))];
        if !self.server_disco_public.is_zero() {
            m.push((text("k"), key(self.server_disco_public.as_bytes())));
        }
        if !self.preshared_key.is_zero() {
            m.push((text("q"), key(self.preshared_key.as_bytes())));
        }
        if !self.region.is_empty() {
            let regions = self.region.iter().map(|r| {
                // STUN-only nodes can't relay, which is all an embedded region is for.
                let nodes: Vec<Value> = r
                    .nodes
                    .iter()
                    .filter(|n| !n.stun_only)
                    .map(|n| {
                        let mut n = n.clone();
                        n.region_id = 0;
                        if n.host_name != Host::Unset {
                            n.name = NodeName::Unset;
                        }
                        Value::Map(cbor_map(node_fields(&mut n)))
                    })
                    .collect();
                Value::Map(if nodes.is_empty() { vec![] } else { vec![(text("N"), Value::Array(nodes))] })
            });
            m.push((text("r"), Value::Array(regions.collect())));
        }
        if self.region_id != 0 {
            m.push((text("i"), Value::Integer(self.region_id.into())));
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(m), &mut buf).expect("CBOR encoding to a Vec cannot fail");
        Addr(format!("tc{}", URL_SAFE_NO_PAD.encode(buf)))
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
        let src = if dm.is_some() { "provided DERP map" } else { opts.url.unwrap_or(crate::DEFAULT_DERP_MAP_URL) };
        let fetched;
        let dm = match dm {
            Some(dm) => dm,
            None => {
                fetched = crate::derpmap::fetch_derp_map(opts)
                    .await
                    .map_err(|e| Error::other(format!("fetching DERPMap for region {}: {e}", self.region_id)))?;
                &fetched
            }
        };
        if self.region_id == -1 {
            use rand::seq::{IteratorRandom, SliceRandom};
            let mut dm = dm.clone();
            for r in dm.regions.values_mut() {
                r.nodes.shuffle(&mut rand::thread_rng());
            }
            let rid = match crate::netcheck::pick_best_region(&dm).await? {
                Some(rid) => rid,
                // Netcheck failed; pick a random region, assuming the map
                // server filtered the map for us when asked as a server.
                None => *dm
                    .regions
                    .keys()
                    .choose(&mut rand::thread_rng())
                    .ok_or_else(|| Error::other("failed to auto-detect any regions"))?,
            };
            self.region_id = 0;
            self.region = dm.regions.remove(&rid).into_iter().collect();
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
        let public = ConnInfo::for_key(&private, PresharedKey::generate(), [], 0);
        PrivateKey { private, public }
    }

    /// Serializes like Go's `json.MarshalIndent(v, "", "\t")`.
    pub fn to_json_pretty(&self) -> String {
        indented_json(self, b"\t")
    }
}

/// Formats a JSON value the way Go's `json.Encoder` with
/// `SetIndent("", "    ")` does, with a trailing newline.
pub fn to_go_indented_json(v: &serde_json::Value) -> String {
    indented_json(v, b"    ") + "\n"
}

fn indented_json(v: &impl Serialize, indent: &[u8]) -> String {
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(indent);
    v.serialize(&mut serde_json::Serializer::with_formatter(&mut buf, fmt)).expect("JSON serializes");
    String::from_utf8(buf).expect("JSON is UTF-8")
}

// ---------------------------------------------------------------------
// Wire (CBOR) form

/// An address as decoded, before [`Addr::parse`] fills in what encoding
/// elided; keys are `None` when absent.
struct Wire {
    server_public: NodePublic,
    server_disco_public: Option<DiscoPublic>,
    preshared_key: Option<PresharedKey>,
    region: Vec<DerpRegion>,
    region_id: i32,
}

/// One field of an embedded region or node, borrowed so that the same
/// table drives decoding, encoding and display. Zero values are omitted
/// when encoding and displaying.
enum Field<'a> {
    Str(&'a mut dyn Text),
    Int(&'a mut i32),
    Bool(&'a mut bool),
}

/// A text field: a plain string, or a typed value written as one.
trait Text {
    fn text(&self) -> Cow<'_, str>;
    fn set_text(&mut self, s: String);
}

impl Text for String {
    fn text(&self) -> Cow<'_, str> {
        self.into()
    }
    fn set_text(&mut self, s: String) {
        *self = s;
    }
}

impl Text for RegionCode {
    fn text(&self) -> Cow<'_, str> {
        self.as_str().into()
    }
    fn set_text(&mut self, s: String) {
        *self = s.into();
    }
}

impl Text for NodeName {
    fn text(&self) -> Cow<'_, str> {
        self.as_str().into()
    }
    fn set_text(&mut self, s: String) {
        *self = s.into();
    }
}

impl Text for RegionName {
    fn text(&self) -> Cow<'_, str> {
        self.as_str().into()
    }
    fn set_text(&mut self, s: String) {
        *self = s.into();
    }
}

impl Text for NodeIp {
    fn text(&self) -> Cow<'_, str> {
        NodeIp::text(self)
    }
    fn set_text(&mut self, s: String) {
        *self = s.into();
    }
}

impl Text for Host {
    fn text(&self) -> Cow<'_, str> {
        Host::text(self)
    }
    fn set_text(&mut self, s: String) {
        *self = s.into();
    }
}

impl Text for CertName {
    fn text(&self) -> Cow<'_, str> {
        CertName::text(self)
    }
    fn set_text(&mut self, s: String) {
        *self = s.into();
    }
}

/// Fields by CBOR key and JSON name, in wire order.
type Fields<'a, const N: usize> = [(&'static str, &'static str, Field<'a>); N];

fn node_fields(n: &mut DerpNode) -> Fields<'_, 9> {
    use Field::*;
    [
        ("n", "Name", Str(&mut n.name)),
        ("i", "RegionID", Int(&mut n.region_id)),
        ("h", "HostName", Str(&mut n.host_name)),
        ("t", "CertName", Str(&mut n.cert_name)),
        ("4", "IPv4", Str(&mut n.ipv4)),
        ("6", "IPv6", Str(&mut n.ipv6)),
        ("s", "STUNPort", Int(&mut n.stun_port)),
        ("d", "DERPPort", Int(&mut n.derp_port)),
        ("x", "InsecureForTests", Bool(&mut n.insecure_for_tests)),
    ]
}

/// A region's fields other than its nodes (`N`).
fn region_fields(r: &mut DerpRegion) -> Fields<'_, 3> {
    use Field::*;
    [
        ("i", "RegionID", Int(&mut r.region_id)),
        ("c", "RegionCode", Str(&mut r.region_code)),
        ("m", "RegionName", Str(&mut r.region_name)),
    ]
}

impl Field<'_> {
    fn is_zero(&self) -> bool {
        match self {
            Field::Str(s) => s.text().is_empty(),
            Field::Int(i) => **i == 0,
            Field::Bool(b) => !**b,
        }
    }

    fn to_cbor(&self) -> Value {
        match self {
            Field::Str(s) => Value::Text(s.text().into_owned()),
            Field::Int(i) => Value::Integer((**i).into()),
            Field::Bool(b) => Value::Bool(**b),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            Field::Str(s) => s.text().into_owned().into(),
            Field::Int(i) => (**i).into(),
            Field::Bool(b) => (**b).into(),
        }
    }

    fn set(&mut self, v: Value, what: &str) -> Result<()> {
        match self {
            Field::Str(s) => s.set_text(v.into_text().map_err(|_| bad(format!("{what} is not a string")))?),
            Field::Int(i) => **i = as_int(v, what)?,
            Field::Bool(b) => **b = matches!(v, Value::Bool(true)),
        }
        Ok(())
    }
}

fn cbor_map<const N: usize>(fields: Fields<'_, N>) -> Vec<(Value, Value)> {
    fields.iter().filter(|f| !f.2.is_zero()).map(|(k, _, v)| (text(k), v.to_cbor())).collect()
}

fn json_map<const N: usize>(fields: Fields<'_, N>) -> serde_json::Map<String, serde_json::Value> {
    fields.iter().filter(|f| !f.2.is_zero()).map(|(_, k, v)| (k.to_string(), v.to_json())).collect()
}

/// Decodes the entry `k: v` of a map into the matching field, if any.
fn set_field(fields: &mut [(&str, &str, Field<'_>)], k: &str, v: Value, what: &str) -> Result<()> {
    match fields.iter_mut().find(|f| f.0 == k) {
        Some((_, name, f)) => f.set(v, &format!("{what} {name}")),
        None => Ok(()),
    }
}

fn text(k: &str) -> Value {
    Value::Text(k.to_string())
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Addr(msg.into())
}

/// The text-keyed entries of a CBOR map; other keys are ignored.
fn entries(v: Value, what: &str) -> Result<impl Iterator<Item = (String, Value)>> {
    match v {
        Value::Map(m) => Ok(m.into_iter().filter_map(|(k, v)| Some((k.into_text().ok()?, v)))),
        Value::Null => Err(bad(format!("invalid tailcat address: {what} is null"))),
        _ => Err(bad(format!("invalid tailcat address: {what} is not a map"))),
    }
}

/// Decodes each element of a CBOR array (or null, for none) with `f`,
/// which is given the element's index.
fn decode_array<T>(v: Value, what: &str, f: impl Fn(Value, usize) -> Result<T>) -> Result<Vec<T>> {
    match v {
        Value::Array(a) => a.into_iter().enumerate().map(|(i, v)| f(v, i)).collect(),
        Value::Null => Ok(Vec::new()),
        _ => Err(bad(format!("{what} is not an array"))),
    }
}

fn as_int(v: Value, what: &str) -> Result<i32> {
    let i = v.into_integer().map_err(|_| bad(format!("{what} is not an integer")))?;
    i32::try_from(i).map_err(|_| bad(format!("{what} out of range")))
}

fn as_bytes32(v: Value, what: &str) -> Result<[u8; 32]> {
    let b = v.into_bytes().map_err(|_| bad(format!("{what} is not a byte string")))?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| bad(format!("invalid {what} length {}, want 32", b.len())))
}

fn decode_node(v: Value, what: &str) -> Result<DerpNode> {
    let mut n = DerpNode::default();
    for (k, v) in entries(v, what)? {
        set_field(&mut node_fields(&mut n), &k, v, what)?;
    }
    Ok(n)
}

fn decode_region(v: Value, idx: usize) -> Result<DerpRegion> {
    let what = format!("region {idx}");
    let mut r = DerpRegion::default();
    for (k, v) in entries(v, &what)? {
        if k == "N" {
            r.nodes = decode_array(v, "region nodes", |n, j| decode_node(n, &format!("{what} node {j}")))?;
        } else {
            set_field(&mut region_fields(&mut r), &k, v, &what)?;
        }
    }
    Ok(r)
}

impl Wire {
    fn decode(addr: &Addr) -> Result<Self> {
        let rest = addr.0.strip_prefix("tc").ok_or_else(|| bad("tailcat address doesn't start with \"tc\""))?;
        let raw = URL_SAFE_NO_PAD.decode(rest)?;
        let v: Value = ciborium::from_reader(raw.as_slice())?;
        let (mut server_public, mut server_disco_public, mut preshared_key) = (None, None, None);
        let (mut region, mut region_id) = (Vec::new(), 0);
        for (k, v) in entries(v, "address")? {
            match k.as_str() {
                "p" => server_public = Some(NodePublic::from_bytes(as_bytes32(v, "node public key")?)),
                "k" => server_disco_public = Some(DiscoPublic::from_bytes(as_bytes32(v, "disco public key")?)),
                "q" => preshared_key = Some(PresharedKey::from_bytes(as_bytes32(v, "WireGuard pre-shared key")?)),
                "r" => region = decode_array(v, "regions", decode_region)?,
                "i" => region_id = as_int(v, "region ID")?,
                _ => {}
            }
        }
        let server_public = server_public.ok_or_else(|| bad("tailcat address has no server public key"))?;
        Ok(Wire { server_public, server_disco_public, preshared_key, region, region_id })
    }

    fn into_json(mut self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("ServerPublic".into(), self.server_public.to_string().into());
        if let Some(k) = self.server_disco_public {
            m.insert("ServerDiscoPublic".into(), k.to_string().into());
        }
        if let Some(q) = self.preshared_key {
            m.insert("PresharedKey".into(), q.to_string().into());
        }
        if !self.region.is_empty() {
            let regions = self.region.iter_mut().map(|r| {
                let mut j = json_map(region_fields(r));
                if !r.nodes.is_empty() {
                    j.insert(
                        "Nodes".into(),
                        r.nodes.iter_mut().map(|n| serde_json::Value::Object(json_map(node_fields(n)))).collect(),
                    );
                }
                serde_json::Value::Object(j)
            });
            m.insert("Region".into(), regions.collect());
        }
        if self.region_id != 0 {
            m.insert("RegionID".into(), self.region_id.into());
        }
        serde_json::Value::Object(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Examples from the upstream README (pre-disco-key addresses).
    const SHORT: &str = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFpGQEu";
    const RESOLVED: &str = "tcomFwWCCcjS5nKNqAod034nWoJZW0LZqDhhC8U_dKdnDRYQ8uNGFygaFhToGjYWhudGMzMDJhLmlwbi5kZXZhNG0yMDguMTExLjM5LjM4YTZzMjYwNzpmNzQwOjA6M2Y6OjcyMA";
    const CUSTOM: &str = "tcomFwWCCAIsKOqPUux6ClG2RM4A_vOq4VBzGgHGGjq9OsJuFKSWFygaFhToGhYWhwZGVycC5leGFtcGxlLmNvbQ";

    type Entries = Vec<(Value, Value)>;

    fn int(i: i64) -> Value {
        Value::Integer(i.into())
    }

    fn array(items: Vec<Value>) -> Value {
        Value::Array(items)
    }

    fn map(entries: Entries) -> Value {
        Value::Map(entries)
    }

    /// Encodes a raw CBOR address, for hand-built test cases.
    fn raw_addr(m: Entries) -> Addr {
        let mut buf = Vec::new();
        ciborium::into_writer(&map(m), &mut buf).unwrap();
        Addr::new(format!("tc{}", URL_SAFE_NO_PAD.encode(buf)))
    }

    /// The top-level CBOR map an address encodes.
    fn cbor_map_of(a: &Addr) -> Entries {
        let bytes = URL_SAFE_NO_PAD.decode(&a.as_str()[2..]).unwrap();
        let v: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        v.into_map().expect("not a map")
    }

    fn keys(m: &[(Value, Value)]) -> Vec<&str> {
        m.iter().map(|(k, _)| k.as_text().unwrap()).collect()
    }

    fn sample_region() -> DerpRegion {
        DerpRegion {
            region_id: 7,
            region_code: "x".into(),
            region_name: "Example".into(),
            nodes: vec![
                DerpNode {
                    name: "n".into(),
                    region_id: 7,
                    host_name: "127.0.0.1".into(),
                    cert_name: "c".into(),
                    ipv4: "127.0.0.1".into(),
                    ipv6: "none".into(),
                    derp_port: 4443,
                    stun_port: -1,
                    insecure_for_tests: true,
                    ..Default::default()
                },
                DerpNode { host_name: "stun.example".into(), stun_only: true, ..Default::default() },
                DerpNode { name: "bare".into(), ..Default::default() },
            ],
            ..Default::default()
        }
    }

    /// A fresh key's connection info, carrying [`sample_region`].
    fn sample_conn_info() -> ConnInfo {
        let mut ci = PrivateKey::generate().public;
        ci.region = vec![sample_region()];
        ci
    }

    #[test]
    fn parses_upstream_readme_examples() {
        let short = Addr::new(SHORT).parse().unwrap();
        let resolved = Addr::new(RESOLVED).parse().unwrap();
        let custom = Addr::new(CUSTOM).parse_raw_json().unwrap();

        let key = "nodekey:9c8d2e6728da80a1dd37e275a82595b42d9a838610bc53f74a7670d1610f2e34";
        assert_eq!(short.server_public.to_string(), key);
        assert_eq!(short.region_id, 302);
        assert!(short.region.is_empty());

        assert_eq!(resolved.region.len(), 1);
        let n = &resolved.region[0].nodes[0];
        assert_eq!(n.host_name, "tc302a.ipn.dev");
        assert_eq!(n.ipv4, "208.111.39.38");
        assert_eq!(n.ipv6, "2607:f740:0:3f::720");
        // Restored implicit fields:
        assert_eq!(resolved.region[0].region_id, 1);
        assert_eq!(n.name, "tc302a.ipn.dev");

        let want = serde_json::json!({
            "ServerPublic": "nodekey:8022c28ea8f52ec7a0a51b644ce00fef3aae150731a01c61a3abd3ac26e14a49",
            "Region": [{"Nodes": [{"HostName": "derp.example.com"}]}]
        });
        assert_eq!(custom, want);
    }

    #[test]
    fn short_address_is_byte_identical_to_go() {
        // Re-encoding the Go-produced address gives the same string: same
        // key order, same minimal integer encoding.
        for s in [SHORT, RESOLVED] {
            let ci = Addr::new(s).parse().unwrap();
            assert_eq!(ci.addr().as_str(), s);
        }
    }

    #[test]
    fn round_trips_full_info() {
        let ci = sample_conn_info();

        let back = ci.addr().parse().unwrap();

        assert_eq!(back.server_public, ci.server_public);
        assert_eq!(back.server_disco_public, ci.server_disco_public);
        assert_eq!(back.preshared_key, ci.preshared_key);
        let r = &back.region[0];
        // Region IDs and codes are restored from position; names are lost.
        assert_eq!((r.region_id, r.region_code.as_str(), r.region_name.as_str()), (1, "1", ""));
        // The STUN-only node is dropped; the others keep their fields.
        assert_eq!(r.nodes.len(), 2);
        let n = &r.nodes[0];
        assert_eq!(n.name, "127.0.0.1", "a name redundant with the hostname becomes the hostname");
        assert_eq!((n.region_id, n.derp_port, n.stun_port), (1, 4443, -1));
        assert_eq!((&n.cert_name, &n.ipv6), (&CertName::Name("c".into()), &NodeIp::Disabled));
        assert!(n.insecure_for_tests);
        assert_eq!(r.nodes[1].name, "bare", "a name with no hostname is kept");
    }

    #[test]
    fn encodes_in_go_key_order() {
        let mut ci = sample_conn_info();
        ci.region_id = -1;

        let m = cbor_map_of(&ci.addr());

        assert_eq!(keys(&m), ["p", "k", "q", "r", "i"]);
        assert_eq!(m[4].1, int(-1));
        let regions = m[3].1.as_array().expect("regions not an array");
        let r = regions[0].as_map().expect("region not a map");
        assert_eq!(r.len(), 1, "only the nodes of a region are encoded");
        let nodes = r[0].1.as_array().expect("nodes not an array");
        let n = nodes[0].as_map().expect("node not a map");
        assert_eq!(keys(n), ["h", "t", "4", "6", "s", "d", "x"]);

        // Zero keys and IDs are omitted entirely.
        let bare = ConnInfo { server_public: NodePublic::from_bytes([1; 32]), ..Default::default() };
        assert_eq!(cbor_map_of(&bare.addr()).len(), 1);
    }

    #[test]
    fn raw_json_shows_carried_fields_in_order() {
        let node = map(vec![(text("x"), Value::Bool(true)), (text("s"), int(-1))]);
        let region = map(vec![(text("m"), text("Name")), (text("i"), int(9)), (text("N"), array(vec![node]))]);
        let a = raw_addr(vec![
            (text("p"), Value::Bytes(vec![1; 32])),
            (text("k"), Value::Bytes(vec![0; 32])),
            (text("r"), array(vec![region])),
            (text("i"), int(3)),
        ]);

        let j = a.parse_raw_json().unwrap();

        // An explicit zero key is shown, since the address carries it.
        assert_eq!(j["ServerDiscoPublic"].as_str().unwrap(), format!("discokey:{}", "0".repeat(64)));
        assert!(j.get("PresharedKey").is_none());
        assert_eq!(j["RegionID"], 3);
        let r = serde_json::to_string(&j["Region"]).unwrap();
        assert_eq!(r, r#"[{"RegionID":9,"RegionName":"Name","Nodes":[{"STUNPort":-1,"InsecureForTests":true}]}]"#);
        // Explicit region fields survive parsing.
        let ci = a.parse().unwrap();
        let r = &ci.region[0];
        assert_eq!((r.region_id, r.region_code.as_str()), (9, "9"));
        assert_eq!(r.nodes[0].region_id, 9);
    }

    /// A valid server key entry.
    fn p() -> (Value, Value) {
        (text("p"), Value::Bytes(vec![1; 32]))
    }

    /// An address whose one region has one node with just `k: v`.
    fn with_node_field(k: &str, v: Value) -> Entries {
        let node = map(vec![(text(k), v)]);
        let region = map(vec![(text("N"), array(vec![node]))]);
        vec![p(), (text("r"), array(vec![region]))]
    }

    #[test]
    fn rejects_garbage() {
        assert!(Addr::new("nope").parse().is_err());
        assert!(Addr::new("tc!!!").parse().is_err());
        assert!(Addr::new("tcoA").parse().is_err()); // empty map: no key
        assert!("tcoA".parse::<Addr>().is_err());

        let cases = [
            // A null region must be rejected, not dereferenced.
            (vec![p(), (text("r"), array(vec![Value::Null]))], "region 0 is null"),
            (vec![(text("p"), Value::Bytes(vec![1; 31]))], "length 31"),
            (vec![p(), (text("i"), text("x"))], "region ID is not an integer"),
            (vec![p(), (text("i"), int(1 << 40))], "out of range"),
            (vec![p(), (text("r"), text("x"))], "regions is not an array"),
            (with_node_field("h", int(1)), "region 0 node 0 HostName is not a string"),
        ];
        for (m, want) in cases {
            let e = raw_addr(m).parse().unwrap_err().to_string();
            assert!(e.contains(want), "{e}");
        }

        // Unknown and non-text keys are ignored, as are null arrays.
        let ok = raw_addr(vec![p(), (int(1), Value::Null), (text("z"), Value::Null), (text("r"), Value::Null)]);
        assert!(ok.parse().unwrap().region.is_empty());
    }

    #[tokio::test]
    async fn expands_from_a_derp_map() {
        let dm = DerpMap { regions: [(7, sample_region())].into(), ..Default::default() };
        let opts = FetchOptions::default();

        let mut ci = ConnInfo { region_id: 7, ..Default::default() };
        ci.expand(opts, Some(&dm)).await.unwrap();
        assert_eq!(ci.region, [sample_region()]);
        // Expanding again is a no-op.
        ci.expand(opts, Some(&dm)).await.unwrap();
        assert_eq!(ci.region.len(), 1);

        let mut missing = ConnInfo { region_id: 8, ..Default::default() };
        let e = missing.expand(opts, Some(&dm)).await.unwrap_err().to_string();
        assert!(e.contains("RegionID 8 but no such region exists in provided DERP map"), "{e}");

        // An embedded region gets default IDs.
        let embedded = DerpRegion { nodes: vec![DerpNode::default()], ..Default::default() };
        let mut ci = ConnInfo { region: vec![embedded], ..Default::default() };
        ci.expand(opts, None).await.unwrap();
        assert_eq!((ci.region[0].region_id, ci.region[0].nodes[0].region_id), (1, 1));

        // An address that already embeds its region resolves to itself.
        let a = Addr::new(RESOLVED);
        assert_eq!(a.resolve(opts).await.unwrap(), a);
    }

    #[test]
    fn debug_hides_the_secret() {
        assert_eq!(format!("{:?}", Addr::new(RESOLVED)), "Addr(tcomFwWCCcjS…)");
        assert_eq!(format!("{:?}", Addr::new("tc")), "Addr(tc…)");
    }

    #[test]
    fn private_key_json_matches_go_shape() {
        let k = PrivateKey::generate();

        let j = k.to_json_pretty();

        assert!(j.contains("\t\"Private\": \"privkey:"));
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let public = &v["Public"];
        assert!(public["ServerPublic"].as_str().unwrap().starts_with("nodekey:"));
        assert!(public["PresharedKey"].as_str().unwrap().starts_with("psk:"));
        assert!(public.get("Region").is_none());
        assert!(public.get("RegionID").is_none());
        let back: PrivateKey = serde_json::from_str(&j).unwrap();
        assert_eq!(back.private, k.private);

        // A Go client key file (RegionID omitted, zero disco key allowed).
        let (private, server_public, zeros) = (&k.private, k.private.public(), "0".repeat(64));
        let go = format!(
            "{{\"Private\":\"{private}\",\"Public\":{{\"ServerPublic\":\"{server_public}\",\"ServerDiscoPublic\":\"discokey:{zeros}\",\"PresharedKey\":\"psk:{zeros}\"}}}}"
        );
        let back: PrivateKey = serde_json::from_str(&go).unwrap();
        assert!(back.public.preshared_key.is_zero());
    }

    #[test]
    fn go_indented_json() {
        let v = serde_json::json!({"a": [1], "b": {}});
        assert_eq!(to_go_indented_json(&v), "{\n    \"a\": [\n        1\n    ],\n    \"b\": {}\n}\n");
    }
}
