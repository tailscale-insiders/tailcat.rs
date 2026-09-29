//! A shared HTTPS client for DERP map fetches and similar small requests.

use std::sync::OnceLock;

/// Returns the process-wide HTTP client.
pub(crate) fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        crate::tls::install_default_provider();
        reqwest::Client::builder()
            .user_agent(concat!("tailcat-rs/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("building the HTTP client")
    })
}

/// Returns the process-wide HTTP client, for sibling crates that want the
/// same TLS setup (ring provider, platform roots).
pub fn shared_client() -> &'static reqwest::Client {
    client()
}
