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

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

pub use addr::{Addr, ConnInfo, PrivateKey};
pub use client::{Client, ClientOptions, DiscoPingResult, PingResult};
pub use derpmap::{
    DEFAULT_DERP_MAP_URL, DerpMap, DerpMapCache, DerpNode, DerpRegion, FetchMode, FetchOptions, RegionArg,
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
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Addr(String),
    #[error("DERP: {0}")]
    Derp(String),
    #[error("timed out: {0}")]
    Timeout(String),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub(crate) fn other(s: impl Into<String>) -> Self {
        Error::Other(s.into())
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            Error::Timeout(s) => std::io::Error::new(std::io::ErrorKind::TimedOut, s),
            e => std::io::Error::other(e.to_string()),
        }
    }
}

/// A `Result` with this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

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
