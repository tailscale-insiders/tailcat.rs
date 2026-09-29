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
    pkt.len() >= 4 && &pkt[..4] == MAGIC
}

/// Reports whether `pkt` is a "meowed" acknowledgment.
pub fn is_meowed(pkt: &[u8]) -> bool {
    pkt.len() >= 5 && is_meow(pkt) && pkt[4] == TYPE_PONG
}

/// Encodes a meow ping announcing the sender's keys.
pub fn encode_ping(node: &NodePublic, disco: &DiscoPublic) -> Vec<u8> {
    let mut b = Vec::with_capacity(5 + 64);
    b.extend_from_slice(MAGIC);
    b.push(TYPE_PING);
    b.extend_from_slice(node.as_bytes());
    b.extend_from_slice(disco.as_bytes());
    b
}

/// Encodes a meowed acknowledgment.
pub fn encode_meowed() -> Vec<u8> {
    let mut b = MAGIC.to_vec();
    b.push(TYPE_PONG);
    b
}

/// Parses a meow ping, returning the sender's node and disco keys.
pub fn parse_ping(pkt: &[u8]) -> Option<(NodePublic, DiscoPublic)> {
    if pkt.len() < 5 + 64 || !is_meow(pkt) || pkt[4] != TYPE_PING {
        return None;
    }
    let disco = DiscoPublic::from_slice(&pkt[37..69])?;
    if disco.is_zero() {
        return None;
    }
    Some((NodePublic::from_slice(&pkt[5..37])?, disco))
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
    }
}
