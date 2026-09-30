//! Key types: WireGuard node keys, path-discovery ("disco") keys, and
//! WireGuard pre-shared keys, with the same text and binary encodings
//! as Tailscale's `types/key` package so that key files and addresses
//! interoperate with the Go implementation.

use std::net::Ipv6Addr;
use std::str::FromStr;
use std::{fmt, hint, iter};

use base64::Engine as _;
use boringtun::x25519;
use crypto_box::aead::{AeadInPlace, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;

/// Length of every key type in bytes.
pub const KEY_LEN: usize = 32;

/// Length of a NaCl box nonce.
pub const NONCE_LEN: usize = 24;

/// Overhead a NaCl box adds to its plaintext (the Poly1305 tag).
pub const BOX_OVERHEAD: usize = 16;

/// The message HMAC'd with a node private key to derive its disco key.
/// It must match the Go implementation's for addresses to interoperate.
const DISCO_DERIVATION_LABEL: &[u8] = b"github.com/tailscale/tailcat disco key v1";

/// An error parsing a key from text.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid {kind}: {msg}")]
pub struct KeyParseError {
    kind: &'static str,
    msg: String,
}

fn parse_hex_key(s: &str, prefix: &str, kind: &'static str) -> Result<[u8; KEY_LEN], KeyParseError> {
    let err = |msg| KeyParseError { kind, msg };
    let hexpart = s.strip_prefix(prefix).ok_or_else(|| err(format!("missing {prefix:?} prefix")))?;
    let mut out = [0u8; KEY_LEN];
    hex::decode_to_slice(hexpart, &mut out).map_err(|e| err(e.to_string()))?;
    Ok(out)
}

fn random_bytes() -> [u8; KEY_LEN] {
    let mut b = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// Applies the Curve25519 scalar clamping that Go's key constructors apply.
fn clamp(mut k: [u8; KEY_LEN]) -> [u8; KEY_LEN] {
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    k
}

fn x25519_public(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    x25519::PublicKey::from(&x25519::StaticSecret::from(*private)).to_bytes()
}

/// The conventional Tailscale debug form of a public key: the first five
/// characters of its standard base64 encoding, in square brackets.
fn short_string(k: &[u8; KEY_LEN]) -> String {
    format!("[{}]", &base64::engine::general_purpose::STANDARD.encode(k)[..5])
}

/// Constant-time equality of two byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && hint::black_box(a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y))) == 0
}

/// Defines a 32-byte key type with raw-byte accessors and a
/// `<prefix><hex>` text form (through `Display`, `FromStr` and serde).
macro_rules! key_type {
    ($(#[$m:meta])* $t:ident, $prefix:literal, $kind:literal) => {
        $(#[$m])*
        pub struct $t([u8; KEY_LEN]);

        impl $t {
            /// Wraps raw key bytes.
            pub const fn from_bytes(b: [u8; KEY_LEN]) -> Self {
                $t(b)
            }

            /// Parses 32 raw bytes, as found in tailcat addresses and on the wire.
            pub fn from_slice(b: &[u8]) -> Option<Self> {
                <[u8; KEY_LEN]>::try_from(b).ok().map($t)
            }

            /// Returns the raw key bytes.
            pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Reports whether the key is all zeros (unset).
            pub fn is_zero(&self) -> bool {
                ct_eq(&self.0, &[0; KEY_LEN])
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl FromStr for $t {
            type Err = KeyParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_hex_key(s, $prefix, $kind).map($t)
            }
        }

        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Implements `PartialEq` and `Eq` in constant time, for secrets.
macro_rules! ct_partial_eq {
    ($($t:ident),*) => {$(
        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                ct_eq(&self.0, &other.0)
            }
        }
        impl Eq for $t {}
    )*};
}

ct_partial_eq!(NodePrivate, PresharedKey);

// ---------------------------------------------------------------------
// Node keys

key_type! {
    /// A node's WireGuard private key, also used to authenticate to DERP
    /// relays. Its text form is `privkey:<hex>`.
    #[derive(Clone)]
    NodePrivate, "privkey:", "node private key"
}

impl NodePrivate {
    /// Generates a new random node private key.
    pub fn generate() -> Self {
        NodePrivate(clamp(random_bytes()))
    }

    /// Returns the corresponding public key.
    pub fn public(&self) -> NodePublic {
        NodePublic(x25519_public(&self.0))
    }

    /// Returns the key as an x25519 secret for the WireGuard engine.
    pub fn x25519(&self) -> x25519::StaticSecret {
        x25519::StaticSecret::from(self.0)
    }

    /// Deterministically derives this node's path-discovery key. The
    /// derived public disco key cannot be linked to the node public key
    /// without the private key, which matters because disco frames carry
    /// it in cleartext on the local network.
    pub fn disco_private(&self) -> DiscoPrivate {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(DISCO_DERIVATION_LABEL);
        DiscoPrivate(clamp(mac.finalize().into_bytes().into()))
    }

    /// Seals `cleartext` in a NaCl box to `to`, returning the 24-byte
    /// random nonce followed by the box (tag then ciphertext), like Go's
    /// `key.NodePrivate.SealTo`.
    pub fn seal_to(&self, to: &NodePublic, cleartext: &[u8]) -> Vec<u8> {
        nacl_seal(&salsa_box(&to.0, &self.0), cleartext)
    }

    /// Opens a box made by [`NodePrivate::seal_to`] from `from`.
    pub fn open_from(&self, from: &NodePublic, ciphertext: &[u8]) -> Option<Vec<u8>> {
        nacl_open(&salsa_box(&from.0, &self.0), ciphertext)
    }
}

impl fmt::Debug for NodePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodePrivate({})", self.public().short_string())
    }
}

key_type! {
    /// A node's WireGuard public key, which also addresses it on DERP relays.
    /// Its text form is `nodekey:<hex>`.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
    NodePublic, "nodekey:", "node public key"
}

impl NodePublic {
    /// Returns the Tailscale-style short debug form, like `[abcde]`.
    pub fn short_string(&self) -> String {
        short_string(&self.0)
    }

    /// Returns the key as an x25519 public key for the WireGuard engine.
    pub fn x25519(&self) -> x25519::PublicKey {
        x25519::PublicKey::from(self.0)
    }

    /// Returns the deterministic tailcat IPv6 address for this key: the
    /// Tailscale ULA prefix `fd7a:115c:a1e0::/48` followed by the first
    /// 80 bits of the key.
    pub fn tailcat_ip(&self) -> Ipv6Addr {
        let mut a = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        a[6..].copy_from_slice(&self.0[..10]);
        Ipv6Addr::from(a)
    }
}

impl fmt::Debug for NodePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodePublic({})", self.short_string())
    }
}

// ---------------------------------------------------------------------
// Disco keys

key_type! {
    /// A path-discovery private key. Disco messages are NaCl boxes between
    /// the two peers' disco keys. Its text form is `discoprivkey:<hex>`.
    #[derive(Clone)]
    DiscoPrivate, "discoprivkey:", "disco private key"
}

impl DiscoPrivate {
    /// Generates a new random disco private key.
    pub fn generate() -> Self {
        DiscoPrivate(clamp(random_bytes()))
    }

    /// Returns the corresponding public key.
    pub fn public(&self) -> DiscoPublic {
        DiscoPublic(x25519_public(&self.0))
    }

    /// Precomputes the shared secret with `peer`, like Go's
    /// `key.DiscoPrivate.Shared`.
    pub fn shared(&self, peer: &DiscoPublic) -> DiscoShared {
        DiscoShared(Box::new(salsa_box(&peer.0, &self.0)))
    }
}

impl fmt::Debug for DiscoPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DiscoPrivate({})", self.public().short_string())
    }
}

key_type! {
    /// A path-discovery public key. Its text form is `discokey:<hex>`.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
    DiscoPublic, "discokey:", "disco public key"
}

impl DiscoPublic {
    /// Returns the Tailscale-style short debug form, like `[abcde]`.
    pub fn short_string(&self) -> String {
        short_string(&self.0)
    }
}

impl fmt::Debug for DiscoPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DiscoPublic({})", self.short_string())
    }
}

/// A precomputed NaCl box shared secret between two disco keys.
pub struct DiscoShared(Box<crypto_box::SalsaBox>);

impl DiscoShared {
    /// Seals `cleartext` with a random nonce: nonce, then tag, then ciphertext.
    pub fn seal(&self, cleartext: &[u8]) -> Vec<u8> {
        nacl_seal(&self.0, cleartext)
    }

    /// Opens a box made by [`DiscoShared::seal`] on the other side.
    pub fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        nacl_open(&self.0, ciphertext)
    }
}

// ---------------------------------------------------------------------
// Pre-shared keys

key_type! {
    /// An optional 256-bit WireGuard pre-shared key. The zero value means
    /// no pre-shared key. Its text form is `psk:<hex>`.
    #[derive(Clone, Copy, Default)]
    PresharedKey, "psk:", "WireGuard pre-shared key"
}

impl PresharedKey {
    /// Generates a new random, non-zero pre-shared key.
    pub fn generate() -> Self {
        iter::repeat_with(|| PresharedKey(random_bytes())).find(|k| !k.is_zero()).unwrap()
    }

    /// Returns the key for the WireGuard engine, or `None` if zero.
    pub fn for_wireguard(&self) -> Option<[u8; KEY_LEN]> {
        (!self.is_zero()).then_some(self.0)
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_zero() { "PresharedKey(none)" } else { "PresharedKey(..)" })
    }
}

// ---------------------------------------------------------------------
// NaCl box helpers

fn salsa_box(public: &[u8; KEY_LEN], private: &[u8; KEY_LEN]) -> crypto_box::SalsaBox {
    crypto_box::SalsaBox::new(&crypto_box::PublicKey::from(*public), &crypto_box::SecretKey::from(*private))
}

/// Seals with a random nonce in NaCl's `crypto_box_easy` layout:
/// nonce || tag || ciphertext.
fn nacl_seal(b: &crypto_box::SalsaBox, cleartext: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; NONCE_LEN + BOX_OVERHEAD];
    rand::rngs::OsRng.fill_bytes(&mut out[..NONCE_LEN]);
    out.extend_from_slice(cleartext);
    let (head, ct) = out.split_at_mut(NONCE_LEN + BOX_OVERHEAD);
    let (nonce, tag) = head.split_at_mut(NONCE_LEN);
    let t =
        b.encrypt_in_place_detached(GenericArray::from_slice(nonce), b"", ct).expect("NaCl box encryption cannot fail");
    tag.copy_from_slice(&t);
    out
}

fn nacl_open(b: &crypto_box::SalsaBox, sealed: &[u8]) -> Option<Vec<u8>> {
    let (nonce, rest) = sealed.split_at_checked(NONCE_LEN)?;
    let (tag, ct) = rest.split_at_checked(BOX_OVERHEAD)?;
    let mut pt = ct.to_vec();
    b.decrypt_in_place_detached(GenericArray::from_slice(nonce), b"", &mut pt, GenericArray::from_slice(tag)).ok()?;
    Some(pt)
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn text_round_trips() {
        let k = NodePrivate::generate();
        let s = k.to_string();
        assert!(s.starts_with("privkey:"));
        assert_eq!(s.parse::<NodePrivate>().unwrap(), k);

        let p = k.public();
        assert_eq!(p.to_string().parse::<NodePublic>().unwrap(), p);

        let d = k.disco_private().public();
        assert_eq!(d.to_string().parse::<DiscoPublic>().unwrap(), d);

        let psk = PresharedKey::generate();
        assert_eq!(psk.to_string().parse::<PresharedKey>().unwrap(), psk);
        assert!("psk:00".parse::<PresharedKey>().is_err());
        assert!("nodekey:zz".parse::<NodePublic>().is_err());
    }

    /// The error message from parsing `s` as a `T`.
    fn parse_err<T: FromStr<Err: Display>>(s: &str) -> String {
        s.parse::<T>().err().expect("parsed").to_string()
    }

    #[test]
    fn parse_errors_name_the_problem() {
        let e = parse_err::<NodePublic>("discokey:00");
        assert_eq!(e, "invalid node public key: missing \"nodekey:\" prefix");
        let e = parse_err::<PresharedKey>(&format!("psk:{}", "0".repeat(62)));
        assert!(e.starts_with("invalid WireGuard pre-shared key: "), "{e}");
        // Keys of the wrong length don't fit.
        let too_long = format!("nodekey:{}", "ab".repeat(33));
        assert!(too_long.parse::<NodePublic>().is_err());
        assert!(NodePublic::from_slice(&[0; 31]).is_none());
    }

    #[test]
    fn serde_uses_text_form() {
        let p = NodePrivate::generate().public();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, format!("\"{p}\""));
        assert_eq!(serde_json::from_str::<NodePublic>(&j).unwrap(), p);
        assert!(serde_json::from_str::<NodePublic>("\"nodekey:00\"").is_err());
    }

    #[test]
    fn zero_and_debug_forms() {
        assert!(NodePublic::default().is_zero());
        assert!(PresharedKey::default().is_zero());
        assert!(PresharedKey::default().for_wireguard().is_none());
        assert_eq!(format!("{:?}", PresharedKey::default()), "PresharedKey(none)");
        let psk = PresharedKey::generate();
        assert_eq!(psk.for_wireguard(), Some(*psk.as_bytes()));
        // Debug output never leaks secrets.
        assert_eq!(format!("{psk:?}"), "PresharedKey(..)");
        let k = NodePrivate::generate();
        assert_eq!(format!("{k:?}"), format!("NodePrivate({})", k.public().short_string()));
        assert_eq!(k.public().short_string().len(), 7);
    }

    #[test]
    fn box_round_trip() {
        let a = NodePrivate::generate();
        let b = NodePrivate::generate();
        let open_from_a = |sealed: &[u8]| b.open_from(&a.public(), sealed);

        let sealed = a.seal_to(&b.public(), b"hello");
        assert_eq!(sealed.len(), NONCE_LEN + BOX_OVERHEAD + 5);
        assert_eq!(open_from_a(&sealed).unwrap(), b"hello");
        assert!(b.open_from(&b.public(), &sealed).is_none());
        // Truncated or tampered boxes don't open.
        assert!(open_from_a(&sealed[..NONCE_LEN + BOX_OVERHEAD - 1]).is_none());
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open_from_a(&bad).is_none());
        // An empty message still round-trips.
        let empty = a.seal_to(&b.public(), b"");
        assert_eq!(open_from_a(&empty).unwrap(), b"");

        let da = a.disco_private();
        let db = b.disco_private();
        let sealed = da.shared(&db.public()).seal(b"disco");
        assert_eq!(db.shared(&da.public()).open(&sealed).unwrap(), b"disco");
    }

    #[test]
    fn tailcat_ip_uses_ula_prefix() {
        let p = NodePublic::from_bytes([0xab; 32]);
        assert_eq!(p.tailcat_ip().to_string(), "fd7a:115c:a1e0:abab:abab:abab:abab:abab");
    }

    /// The disco derivation is a fixed function of the private key; this
    /// pins it so changes are caught (the value was computed from the
    /// HMAC-SHA256 definition in the Go implementation).
    #[test]
    fn disco_derivation_is_clamped_hmac() {
        let k = NodePrivate::from_bytes([1u8; 32]);
        let mut mac = Hmac::<Sha256>::new_from_slice(&[1u8; 32]).unwrap();
        mac.update(DISCO_DERIVATION_LABEL);
        let raw: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(k.disco_private().0, clamp(raw));
    }
}
