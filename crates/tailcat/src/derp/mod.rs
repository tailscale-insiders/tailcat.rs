//! DERP ("Designated Encrypted Relay for Packets"), Tailscale's relay
//! protocol: clients connect over TLS, upgrade the HTTP connection, and
//! exchange frames addressed by node public key.
//!
//! A frame is a one-byte type, a big-endian `u32` length, and a payload.
//! Login: the server sends [`FrameType::ServerKey`], the client sends
//! [`FrameType::ClientInfo`] (its key and a NaCl-boxed JSON blob), and the
//! server answers with [`FrameType::ServerInfo`]. After that the client
//! sends [`FrameType::SendPacket`] frames and receives
//! [`FrameType::RecvPacket`] frames.

pub mod client;
pub mod server;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::key::NodePublic;

/// Sent in the server key frame: `DERP🔑`.
pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";

/// The DERP protocol version we speak (received packets carry their
/// source key).
pub const PROTOCOL_VERSION: i32 = 2;

/// The largest packet DERP carries.
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// The largest frame we accept (packets plus framing, and info frames).
pub const MAX_FRAME_SIZE: usize = 1 << 20;

/// The HTTP header that asks the server to skip its 101 response.
pub const FAST_START_HEADER: &str = "Derp-Fast-Start";

macro_rules! frame_types {
    ($($name:ident = $v:literal,)*) => {
        /// DERP frame types.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum FrameType {
            $($name = $v,)*
        }

        impl FrameType {
            pub fn from_u8(b: u8) -> Option<Self> {
                match b {
                    $($v => Some(FrameType::$name),)*
                    _ => None,
                }
            }
        }
    };
}

frame_types! {
    ServerKey = 0x01,
    ClientInfo = 0x02,
    ServerInfo = 0x03,
    SendPacket = 0x04,
    RecvPacket = 0x05,
    KeepAlive = 0x06,
    NotePreferred = 0x07,
    PeerGone = 0x08,
    PeerPresent = 0x09,
    ForwardPacket = 0x0a,
    WatchConns = 0x10,
    ClosePeer = 0x11,
    Ping = 0x12,
    Pong = 0x13,
    Health = 0x14,
    Restarting = 0x15,
}

/// Why a server has no path to a peer, in [`FrameType::PeerGone`].
pub const PEER_GONE_DISCONNECTED: u8 = 0x00;
pub const PEER_GONE_NOT_HERE: u8 = 0x01;

/// Reads one frame, returning its raw type byte and payload.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr[1..].try_into().unwrap()) as usize;
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("DERP frame of {len} bytes exceeds limit of {max}"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok((hdr[0], payload))
}

/// Encodes a frame whose payload is the concatenation of `parts`.
pub fn frame(t: FrameType, parts: &[&[u8]]) -> Vec<u8> {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(5 + len);
    out.push(t as u8);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// Writes and flushes one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, t: FrameType, parts: &[&[u8]]) -> std::io::Result<()> {
    w.write_all(&frame(t, parts)).await?;
    w.flush().await
}

/// Writes `first` and whatever else is already queued on `rx`, then
/// flushes once, coalescing bursts of frames into few TLS records.
async fn write_queued<W: AsyncWrite + Unpin>(
    w: &mut W,
    first: Vec<u8>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
) -> std::io::Result<()> {
    w.write_all(&first).await?;
    while let Ok(f) = rx.try_recv() {
        w.write_all(&f).await?;
    }
    w.flush().await
}

/// Splits the node key that leads many frame payloads from the rest.
fn split_key(payload: &[u8]) -> Option<(NodePublic, &[u8])> {
    let (k, rest) = payload.split_first_chunk()?;
    Some((NodePublic::from_bytes(*k), rest))
}

/// A packet received from a DERP relay.
#[derive(Debug, Clone)]
pub struct ReceivedPacket {
    /// The region it came through.
    pub region_id: i32,
    /// The sender's node key.
    pub src: NodePublic,
    pub data: Vec<u8>,
}

known_strings! {
    /// What a DERP client says it is, which the relay may log: tailcat's
    /// own are variants.
    AppName {
        Client => "tailcat-client",
        Server => "tailcat-server",
        Device => "tailcat-device",
    }
}

impl AppName {
    /// Whether it's one a relay takes: at most 32 bytes of printable ASCII.
    pub fn is_valid(&self) -> bool {
        valid_app_name(self.as_str())
    }
}

/// The client's self-description, sealed to the server at login.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ClientInfo {
    #[serde(rename = "meshKey", default, skip_serializing_if = "String::is_empty")]
    pub mesh_key: String,
    #[serde(rename = "version", default, skip_serializing_if = "is_zero")]
    pub version: i32,
    #[serde(rename = "CanAckPings", default)]
    pub can_ack_pings: bool,
    #[serde(rename = "IsProber", default, skip_serializing_if = "std::ops::Not::not")]
    pub is_prober: bool,
    #[serde(rename = "AppName", default, skip_serializing_if = "AppName::is_empty")]
    pub app_name: AppName,
}

/// The server's self-description, sealed to the client at login.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ServerInfo {
    #[serde(rename = "version", default, skip_serializing_if = "is_zero")]
    pub version: i32,
    #[serde(rename = "TokenBucketBytesPerSecond", default, skip_serializing_if = "is_zero")]
    pub token_bucket_bytes_per_second: i32,
    #[serde(rename = "TokenBucketBytesBurst", default, skip_serializing_if = "is_zero")]
    pub token_bucket_bytes_burst: i32,
}

fn is_zero(v: &i32) -> bool {
    *v == 0
}

/// Reports whether an app name is valid: at most 32 bytes of printable ASCII.
pub fn valid_app_name(s: &str) -> bool {
    s.len() <= 32 && s.bytes().all(|b| (b' '..=b'~').contains(&b))
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use super::*;

    #[test]
    fn frame_types_round_trip() {
        for b in 0..=u8::MAX {
            if let Some(t) = FrameType::from_u8(b) {
                assert_eq!(t as u8, b);
            }
        }
        assert_eq!(FrameType::from_u8(0x0a), Some(FrameType::ForwardPacket));
        assert_eq!(FrameType::from_u8(0x0b), None);
        assert_eq!(FrameType::from_u8(0), None);
    }

    #[tokio::test]
    async fn frames_round_trip_and_respect_the_limit() {
        let f = frame(FrameType::SendPacket, &[&[1; 32], b"hi"]);
        assert_eq!(&f[..5], &[0x04, 0, 0, 0, 34]);

        let (t, payload) = read_frame(&mut f.as_slice(), 34).await.unwrap();
        assert_eq!(t, FrameType::SendPacket as u8);
        let key = NodePublic::from_bytes([1; 32]);
        assert_eq!(split_key(&payload), Some((key, &b"hi"[..])));

        let err = read_frame(&mut f.as_slice(), 33).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        // A truncated payload is an error, not a short frame.
        assert!(read_frame(&mut &f[..20], 34).await.is_err());
        assert_eq!(frame(FrameType::KeepAlive, &[]), [0x06, 0, 0, 0, 0]);
        assert!(split_key(&[0; 31]).is_none());
    }

    #[test]
    fn app_names() {
        assert!(valid_app_name(""));
        assert!(valid_app_name("tailcat-rs 1.0"));
        assert!(!valid_app_name(&"x".repeat(33)));
        assert!(!valid_app_name("tab\there"));
        assert!(!valid_app_name("caf\u{e9}"));
        assert!(matches!(AppName::from("tailcat-device"), AppName::Device));
        assert!(AppName::Device.is_valid() && !AppName::from("x".repeat(33)).is_valid());
    }
}
