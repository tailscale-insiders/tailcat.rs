//! A control-plane-free network pipe built on Tailscale's data plane:
//! WireGuard encryption, DERP relays, and NAT traversal.
//!
//! This crate is a Rust re-implementation of the Go
//! [`github.com/tailscale/tailcat`](https://github.com/tailscale/tailcat)
//! library, and speaks the same wire protocols: a Rust client can dial a
//! Go server and vice versa.
//!
//! A [`Server`] listens for clients through a DERP relay. Clients find
//! it through a compact [`Addr`] (a *tailcat address*) that encodes the
//! server's WireGuard and path-discovery public keys, a WireGuard
//! pre-shared key, and its DERP region. DERP is used to bootstrap; once
//! both sides learn each other's UDP endpoints, traffic upgrades to a
//! direct peer-to-peer path whenever NAT traversal succeeds, with DERP
//! remaining as the fallback.
//!
//! Once connected, the two sides exchange TCP streams and UDP datagrams
//! over the tunnel through a userspace TCP/IP stack; no TUN device, root,
//! or OS network configuration is needed. For a real network interface
//! and a mesh of peers, see the `tailcat-device` crate, which builds on
//! the [`magicsock`] and [`wg`] layers here.
//!
//! ```no_run
//! # async fn demo() -> tailcat::Result<()> {
//! use tokio::io::AsyncWriteExt;
//!
//! let server = tailcat::Server::builder()
//!     .on_tcp(|port| {
//!         Some(tailcat::handler(move |mut c: tailcat::TcpStream| async move {
//!             let _ = c.write_all(format!("hello from port {port}\n").as_bytes()).await;
//!         }))
//!     })
//!     .start()
//!     .await?;
//! println!("{}", server.tailcat_addr());
//! # Ok(()) }
//! ```
//!
//! This crate has no API stability promises, and neither does the wire
//! format it shares with the Go implementation.

#[macro_use]
mod known;

pub mod addr;
pub mod derp;
pub mod derpmap;
pub mod disco;
pub mod key;
pub mod magicsock;
pub mod meow;
pub mod netcheck;
pub mod netstack;
pub mod stun;
pub mod wg;

mod client;
mod exec;
mod http;
mod keyset;
mod proxy;
mod server;
#[cfg(feature = "ssh")]
pub mod ssh;
mod tls;

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
#[cfg(feature = "ssh")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use smoltcp::socket::tcp::{ConnectError, RecvError, SendError};

pub use addr::{Addr, ConnInfo, PrivateKey};
pub use client::{Client, ClientOptions, DiscoPingResult, PingResult, Via};
pub use derpmap::{
    CertName, DEFAULT_DERP_MAP_URL, DerpMap, DerpMapCache, DerpNode, DerpRegion, FetchMode, FetchOptions, Host, NodeIp,
    NodeName, RegionChoice, RegionCode, RegionName, StunTestIp,
};
pub use exec::peer_env;
pub use http::client as shared_client;
pub use key::{DiscoPublic, NodePrivate, NodePublic, PresharedKey};
pub use keyset::KeySet;
pub use netstack::{TcpStream, UdpConn};
pub use proxy::{proxy_conns, proxy_packet_conns};
pub use server::{
    DEFAULT_UDP_IDLE_TIMEOUT, Listener, PeerStatus, PortRange, Server, ServerBuilder, ServerStatus, TcpHandler,
    UdpHandler, handler, udp_handler,
};

/// The largest UDP payload that fits the tunnel's 1280-byte IPv6 MTU
/// without fragmentation (1280 minus the IPv6 and UDP headers).
pub const MAX_UDP_PAYLOAD: usize = 1232;

/// The tunnel's MTU, matching Tailscale's default.
pub const TUNNEL_MTU: usize = 1280;

/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Addr(String),
    #[error("DERP: {0}")]
    Derp(String),
    #[error("timed out: {0}")]
    Timeout(String),
    #[error("{0}")]
    Other(String),
    #[error("connect to {remote}: {error}")]
    Connect { remote: SocketAddr, error: ConnectError },
    #[error("TCP receive: {0}")]
    Recv(RecvError),
    #[error("TCP send: {0}")]
    Send(SendError),
    #[error("DERP: invalid DERP hostname {host:?}: {error}")]
    BadHostname { host: String, error: rustls::pki_types::InvalidDnsNameError },
    #[error("DERP: TLS handshake with {host}: {error}")]
    Handshake { host: String, error: io::Error },
    #[error("DERP: client info: {error}")]
    BadClientInfo { error: serde_json::Error },
    #[error("fetching DERPMap for region {region_id}: {error}")]
    RegionMap { region_id: i32, error: Box<Error> },
    #[error("fetching {url}: {status}")]
    DerpMapStatus { url: String, status: reqwest::StatusCode },
    #[error("DERP map from {url} is too large")]
    DerpMapTooLarge { url: String },
    #[error("invalid DERP map JSON from {url}: {error}")]
    DerpMapJson { url: String, error: serde_json::Error },
    #[error("TLS: {0}")]
    Tls(rustls::Error),
    #[error("TLS verifier: {0}")]
    Verifier(rustls::client::VerifierBuilderError),
    #[error("certificate: {0}")]
    Certificate(rcgen::Error),
    #[error("task failed: {0}")]
    Task(tokio::task::JoinError),
    #[error("HTTP: {0}")]
    Http(reqwest::Error),
    #[error("base64 decode: {0}")]
    Base64(base64::DecodeError),
    #[error("CBOR unmarshal: {0}")]
    Cbor(ciborium::de::Error<io::Error>),
    #[cfg(feature = "ssh")]
    #[error("parsing host key {}: {error}", path.display())]
    HostKey { path: PathBuf, error: russh::keys::Error },
    #[cfg(feature = "ssh")]
    #[error("authorized keys entry {entry}, line {line}: {error}")]
    AuthorizedKey { entry: usize, line: usize, error: russh::keys::ssh_key::Error },
    #[cfg(feature = "ssh")]
    #[error("authorized keys entry {entry}, line {line}: options are not supported")]
    KeyOptions { entry: usize, line: usize },
    /// An SFTP request refused with a status.
    #[cfg(feature = "ssh")]
    #[error("SFTP: {0}")]
    Sftp(russh_sftp::protocol::StatusCode),
}

/// Implements `From` for each arm that wraps another error, so `?` puts
/// the error in its arm. These are written out rather than `#[from]`,
/// which would also make the wrapped error the arm's `source()`, and a
/// cause chain (like anyhow's `{:#}`) would then print it twice.
macro_rules! wraps {
    ($($arm:ident($error:ty)),* $(,)?) => {$(
        impl From<$error> for Error {
            fn from(e: $error) -> Self {
                Error::$arm(e)
            }
        }
    )*};
}

wraps! {
    Tls(rustls::Error),
    Verifier(rustls::client::VerifierBuilderError),
    Certificate(rcgen::Error),
    Task(tokio::task::JoinError),
    Http(reqwest::Error),
    Base64(base64::DecodeError),
    Cbor(ciborium::de::Error<io::Error>),
    Recv(RecvError),
    Send(SendError),
}

#[cfg(feature = "ssh")]
wraps! {
    Sftp(russh_sftp::protocol::StatusCode),
}

impl Error {
    pub(crate) fn other(s: impl Into<String>) -> Self {
        Error::Other(s.into())
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            Error::Timeout(s) => io::Error::new(ErrorKind::TimedOut, s),
            e @ Error::Connect { .. } => io::Error::new(ErrorKind::InvalidInput, e.to_string()),
            e @ Error::Recv(RecvError::Finished) => io::Error::new(ErrorKind::UnexpectedEof, e.to_string()),
            e @ (Error::Recv(_) | Error::Send(_)) => io::Error::new(ErrorKind::NotConnected, e.to_string()),
            e => io::Error::other(e.to_string()),
        }
    }
}

/// A `Result` whose error is this crate's [`Error`] unless it says otherwise.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Sets whether library internals log verbosely (at debug level) about
/// region selection and path discovery. Logging itself goes through the
/// `tracing` crate; this only affects what's emitted.
pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Relaxed);
}

pub(crate) fn verbose() -> bool {
    VERBOSE.load(Relaxed)
}

static VERBOSE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn wrapped_errors_say_themselves_once() {
        let e = Error::from(base64::DecodeError::InvalidLength(3));
        assert_eq!(e.to_string(), "base64 decode: Invalid input length: 3");
        assert!(e.source().is_none(), "a cause chain would print it again");
    }

    #[test]
    fn a_refused_connect_is_invalid_input() {
        let remote = "192.0.2.1:80".parse().unwrap();
        let e = Error::Connect { remote, error: ConnectError::Unaddressable };
        let io = io::Error::from(e);
        assert_eq!(io.kind(), ErrorKind::InvalidInput);
        assert_eq!(io.to_string(), "connect to 192.0.2.1:80: unaddressable destination");
    }

    #[test]
    fn stream_errors_have_their_kinds() {
        let kind = |e: Error| io::Error::from(e).kind();
        assert_eq!(kind(RecvError::Finished.into()), ErrorKind::UnexpectedEof);
        assert_eq!(kind(RecvError::InvalidState.into()), ErrorKind::NotConnected);
        assert_eq!(kind(SendError::InvalidState.into()), ErrorKind::NotConnected);
    }
}
