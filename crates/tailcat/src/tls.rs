//! TLS configuration for DERP connections, using the ring crypto provider.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::derpmap::DerpNode;
use crate::{Error, Result};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn derp_err(e: impl std::fmt::Display) -> Error {
    Error::Derp(e.to_string())
}

fn other_err(e: impl std::fmt::Display) -> Error {
    Error::other(e.to_string())
}

/// Parses a hostname or IP literal as a TLS server name.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|e| derp_err(format!("invalid DERP hostname {host:?}: {e}")))
}

/// Builds the TLS client configuration for a DERP node: standard web PKI
/// verification, or none for `InsecureForTests` nodes, or verification
/// against the node's `CertName` (a DNS name, or `sha256-raw:<hex>` of
/// the leaf certificate) when it differs from the hostname.
pub(crate) fn client_config_for_node(n: &DerpNode) -> Result<rustls::ClientConfig> {
    let check = if n.insecure_for_tests {
        Check::Any
    } else if let Some(hash) = n.cert_name.strip_prefix("sha256-raw:") {
        Check::Hash(hash.to_ascii_lowercase())
    } else {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let webpki =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build().map_err(derp_err)?;
        let name = if n.cert_name.is_empty() { None } else { Some(server_name(&n.cert_name)?) };
        Check::WebPki(webpki, name)
    };
    Ok(rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(derp_err)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier { check, provider: provider() }))
        .with_no_client_auth())
}

/// A self-signed certificate and TLS server configuration for a local
/// development DERP relay.
pub(crate) fn self_signed_server_config(names: &[&str]) -> Result<rustls::ServerConfig> {
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let cert = rcgen::generate_simple_self_signed(names).map_err(other_err)?;
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).map_err(other_err)?;
    rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(other_err)?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .map_err(other_err)
}

/// How a DERP node's certificate is checked.
#[derive(Debug)]
enum Check {
    /// Not at all (`InsecureForTests`).
    Any,
    /// By the SHA-256 of the leaf certificate, in lowercase hex.
    Hash(String),
    /// By web PKI, for the given name instead of the dialed one if set.
    WebPki(Arc<WebPkiServerVerifier>, Option<ServerName<'static>>),
}

#[derive(Debug)]
struct Verifier {
    check: Check,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match &self.check {
            Check::Any => Ok(ServerCertVerified::assertion()),
            Check::Hash(want) => {
                let got = hex::encode(Sha256::digest(end_entity.as_ref()));
                if got == *want {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(format!("DERP certificate hash {got} != expected {want}")))
                }
            }
            Check::WebPki(v, over) => {
                v.verify_server_cert(end_entity, intermediates, over.as_ref().unwrap_or(name), ocsp, now)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    /// Handshakes over an in-memory pipe with a fresh self-signed server
    /// for `localhost`, returning the leaf certificate the client saw.
    async fn handshake(n: &DerpNode) -> Result<CertificateDer<'static>> {
        let (c, s) = duplex(1 << 16);
        let server = TlsAcceptor::from(Arc::new(self_signed_server_config(&["localhost"])?));
        tokio::spawn(async move {
            let _ = server.accept(s).await;
        });
        let client = TlsConnector::from(Arc::new(client_config_for_node(n)?));
        let tls = client.connect(server_name("localhost")?, c).await?;
        let (_, session) = tls.get_ref();
        let leaf = &session.peer_certificates().unwrap()[0];
        Ok(leaf.clone().into_owned())
    }

    fn node(insecure_for_tests: bool, cert_name: &str) -> DerpNode {
        DerpNode {
            host_name: "localhost".into(),
            cert_name: cert_name.into(),
            insecure_for_tests,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn verifies_by_mode() {
        // Web PKI rejects a self-signed certificate, with or without a name override.
        assert!(handshake(&node(false, "")).await.is_err());
        assert!(handshake(&node(false, "derp.example.com")).await.is_err());
        // InsecureForTests accepts anything.
        let cert = handshake(&node(true, "")).await.unwrap();
        // A hash pin accepts only the certificate it names, and each
        // server here has a fresh one.
        let hash = hex::encode_upper(Sha256::digest(cert.as_ref()));
        let pinned = node(false, &format!("sha256-raw:{hash}"));
        assert!(handshake(&pinned).await.is_err());
        let v = Verifier { check: Check::Hash(hash.to_ascii_lowercase()), provider: provider() };
        let name = server_name("localhost").unwrap();
        assert!(v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now()).is_ok());
        assert!(server_name("not a hostname").is_err());
    }
}
