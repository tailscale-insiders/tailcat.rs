//! A shared HTTPS client for DERP map fetches and similar small requests.

use std::sync::OnceLock;

/// Returns the process-wide HTTP client, also for sibling crates that
/// want the same TLS setup (ring provider, platform roots).
pub fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        // reqwest uses the process-wide rustls provider: make that ring,
        // unless something else already installed one.
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder()
            .user_agent(concat!("tailcat-rs/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("building the HTTP client")
    })
}
