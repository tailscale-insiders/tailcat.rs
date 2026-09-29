//! TLS configuration for DERP connections, using the ring crypto provider.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::derpmap::DerpNode;
use crate::{Error, Result};

pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Installs ring as the process-wide rustls provider, for libraries (like
/// reqwest) that use the default. It's a no-op if one is installed.
pub(crate) fn install_default_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn roots() -> rustls::RootCertStore {
    rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

/// Parses a hostname or IP literal as a TLS server name.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|e| Error::Derp(format!("invalid DERP hostname {host:?}: {e}")))
}

/// Builds the TLS client configuration for a DERP node: standard web PKI
/// verification, or none for `InsecureForTests` nodes, or verification
/// against the node's `CertName` (a DNS name, or `sha256-raw:<hex>` of
/// the leaf certificate) when it differs from the hostname.
pub(crate) fn client_config_for_node(n: &DerpNode) -> Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Derp(e.to_string()))?;
    let verifier: Arc<dyn ServerCertVerifier> = if n.insecure_for_tests {
        Arc::new(NoVerify(provider()))
    } else if let Some(hash) = n.cert_name.strip_prefix("sha256-raw:") {
        Arc::new(HashVerify { hash: hash.to_ascii_lowercase(), provider: provider() })
    } else {
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots()), provider())
            .build()
            .map_err(|e| Error::Derp(e.to_string()))?;
        if n.cert_name.is_empty() {
            inner
        } else {
            Arc::new(NameOverride { inner, name: server_name(&n.cert_name)? })
        }
    };
    Ok(builder.dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth())
}

/// A self-signed certificate and TLS server configuration for a local
/// development DERP relay.
pub(crate) fn self_signed_server_config(names: &[&str]) -> Result<rustls::ServerConfig> {
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let cert = rcgen::generate_simple_self_signed(names).map_err(|e| Error::other(e.to_string()))?;
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).map_err(|e| Error::other(e.to_string()))?;
    rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::other(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .map_err(|e| Error::other(e.to_string()))
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

fn verify12(
    p: &rustls::crypto::CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &p.signature_verification_algorithms)
}

fn verify13(
    p: &rustls::crypto::CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &p.signature_verification_algorithms)
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify12(&self.0, m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify13(&self.0, m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct HashVerify {
    hash: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for HashVerify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let got = hex::encode(Sha256::digest(end_entity.as_ref()));
        if got == self.hash {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!("DERP certificate hash {got} != expected {}", self.hash)))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify12(&self.provider, m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify13(&self.provider, m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct NameOverride {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for NameOverride {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(end_entity, intermediates, &self.name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
