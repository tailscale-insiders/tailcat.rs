//! A WireGuard mesh overlay on a real network interface, built on the
//! `tailcat` crate's DERP relays, disco NAT traversal and WireGuard
//! engine.
//!
//! Where `tailcat` gives one client a userspace tunnel to one server,
//! `tailcat-device` gives every node of a group (for example each job of
//! a GitHub Actions matrix) a TUN interface with an overlay IP, and
//! routes IP packets to every other node directly or through DERP.
//! Routable node addresses are what systems like Kubernetes need, which
//! port forwarding can't provide.
//!
//! Membership comes from [`record::NodeRecord`]s: each node generates
//! its key locally and publishes only the public half. Within one
//! GitHub Actions run, records are uploaded as run artifacts, which only
//! the run's own jobs can write; records from other runs must carry a
//! GitHub OIDC token binding their key to the repository and ref (see
//! [`github`]). No coordination server, account, or shared secret is
//! involved.

pub mod github;
pub mod overlay;
pub mod record;
pub mod source;

pub use overlay::{ChannelDevice, Overlay, OverlayConfig, PacketDevice, PeerStatus};
pub use record::{DeviceKey, NodeRecord};
