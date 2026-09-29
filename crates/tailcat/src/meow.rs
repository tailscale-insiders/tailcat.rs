//! Meow messages: tailcat's tiny join handshake, sent as raw DERP packets
//! (not disco-framed). A client announces its node and disco keys with a
//! "meow" ping; the server adds it as a peer and acks with "meowed".
//!
//! The format is the 4-byte magic `meow`, a type byte, and for pings the
//! 32-byte node key and 32-byte disco key. The magic is distinct from
//! WireGuard message types (1–4) and disco's `TS💬`.

use crate::key::{DiscoPublic, NodePublic};

const MAGIC: &[u8; 4] = b"meow";
const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;

/// Reports whether `pkt` starts with the meow magic.
pub fn is_meow(pkt: &[u8]) -> bool {
    pkt.starts_with(MAGIC)
}

/// Reports whether `pkt` is a "meowed" acknowledgment.
pub fn is_meowed(pkt: &[u8]) -> bool {
    pkt.strip_prefix(MAGIC).is_some_and(|rest| rest.first() == Some(&TYPE_PONG))
}

/// Encodes a meow ping announcing the sender's keys.
pub fn encode_ping(node: &NodePublic, disco: &DiscoPublic) -> Vec<u8> {
    [MAGIC.as_slice(), &[TYPE_PING], node.as_bytes(), disco.as_bytes()].concat()
}

/// Encodes a meowed acknowledgment.
pub fn encode_meowed() -> Vec<u8> {
    [MAGIC.as_slice(), &[TYPE_PONG]].concat()
}

/// Parses a meow ping, returning the sender's node and disco keys.
pub fn parse_ping(pkt: &[u8]) -> Option<(NodePublic, DiscoPublic)> {
    let [TYPE_PING, rest @ ..] = pkt.strip_prefix(MAGIC)? else { return None };
    let node = NodePublic::from_slice(rest.get(..32)?)?;
    let disco = DiscoPublic::from_slice(rest.get(32..64)?)?;
    (!disco.is_zero()).then_some((node, disco))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let n = NodePublic::from_bytes([1; 32]);
        let d = DiscoPublic::from_bytes([2; 32]);
        let p = encode_ping(&n, &d);
        assert!(is_meow(&p) && !is_meowed(&p));
        assert_eq!(parse_ping(&p), Some((n, d)));
        assert!(is_meowed(&encode_meowed()));
        assert_eq!(parse_ping(&encode_ping(&n, &DiscoPublic::default())), None);
        // Truncated, mistyped, or extended pings.
        assert_eq!(parse_ping(&p[..p.len() - 1]), None);
        assert_eq!(parse_ping(&encode_meowed()), None);
        assert_eq!(parse_ping(&[p.as_slice(), b"more"].concat()), Some((n, d)));
        assert!(!is_meowed(b"meow") && !is_meow(b"meo") && !is_meowed(b"purr\x02"));
    }
}
