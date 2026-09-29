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

/// DERP frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
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

impl FrameType {
    pub fn from_u8(b: u8) -> Option<Self> {
        use FrameType::*;
        Some(match b {
            0x01 => ServerKey,
            0x02 => ClientInfo,
            0x03 => ServerInfo,
            0x04 => SendPacket,
            0x05 => RecvPacket,
            0x06 => KeepAlive,
            0x07 => NotePreferred,
            0x08 => PeerGone,
            0x09 => PeerPresent,
            0x0a => ForwardPacket,
            0x10 => WatchConns,
            0x11 => ClosePeer,
            0x12 => Ping,
            0x13 => Pong,
            0x14 => Health,
            0x15 => Restarting,
            _ => return None,
        })
    }
}

/// Why a server has no path to a peer, in [`FrameType::PeerGone`].
pub const PEER_GONE_DISCONNECTED: u8 = 0x00;
pub const PEER_GONE_NOT_HERE: u8 = 0x01;

/// Reads one frame, returning its raw type byte and payload.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
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

/// Encodes a frame into `out`.
pub fn encode_frame(out: &mut Vec<u8>, t: FrameType, parts: &[&[u8]]) {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    out.push(t as u8);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    for p in parts {
        out.extend_from_slice(p);
    }
}

/// Writes and flushes one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, t: FrameType, parts: &[&[u8]]) -> std::io::Result<()> {
    let mut buf = Vec::new();
    encode_frame(&mut buf, t, parts);
    w.write_all(&buf).await?;
    w.flush().await
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
    #[serde(rename = "AppName", default, skip_serializing_if = "String::is_empty")]
    pub app_name: String,
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
