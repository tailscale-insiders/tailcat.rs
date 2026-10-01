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
        let builder = || reqwest::Client::builder().user_agent(concat!("tailcat-rs/", env!("CARGO_PKG_VERSION")));
        // A system with no CA certificates at all (a minimal container, a
        // build sandbox) verifies with the web PKI roots built in, the
        // ones DERP connections use, as Go's tlsdial falls back to its
        // baked-in roots.
        builder().build().unwrap_or_else(|_| {
            let tls = crate::tls::webpki_client_config().expect("building the TLS configuration");
            builder().tls_backend_preconfigured(tls).build().expect("building the HTTP client")
        })
    })
}
