//! Certificate-validating Rustls handshake boundary.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use sugra_core::{PortError, PortErrorKind, TlsCertificate, TlsObservation, TlsPort, TlsRequest};
use sugra_domain::{Target, TargetKind};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// TLS adapter construction failure.
#[derive(Debug, Error)]
pub enum TlsAdapterError {
    /// No usable native trust anchors were loaded.
    #[error("no native TLS trust anchors are available")]
    NoTrustAnchors,
}

/// Rustls client using native trust anchors and mandatory verification.
#[derive(Clone)]
pub struct RustlsTls {
    connector: TlsConnector,
}

impl RustlsTls {
    /// Loads native trust anchors and constructs a client without client authentication.
    ///
    /// # Errors
    ///
    /// Returns `TlsAdapterError::NoTrustAnchors` when no usable native trust
    /// anchor is available.
    pub fn native() -> Result<Self, TlsAdapterError> {
        let loaded = rustls_native_certs::load_native_certs();
        let mut roots = rustls::RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(loaded.certs);
        if added == 0 {
            return Err(TlsAdapterError::NoTrustAnchors);
        }
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

#[async_trait]
impl TlsPort for RustlsTls {
    async fn handshake(&self, request: TlsRequest) -> Result<TlsObservation, PortError> {
        let target = request
            .host
            .parse()
            .map(Target::Ip)
            .or_else(|_| Target::parse(TargetKind::Domain, &request.host))
            .map_err(|_| PortError::new(PortErrorKind::InvalidResponse, "TLS host is invalid"))?;
        if !request.scope.allows(&target) {
            return Err(PortError::new(
                PortErrorKind::OutOfScope,
                "TLS host is outside the declared scope",
            ));
        }
        let server_name = ServerName::try_from(request.host.clone()).map_err(|_| {
            PortError::new(PortErrorKind::InvalidResponse, "TLS server name is invalid")
        })?;
        let started = Instant::now();
        let stream = tokio::time::timeout(
            request.budget.timeout(),
            TcpStream::connect((request.host.as_str(), request.port)),
        )
        .await
        .map_err(|_| PortError::new(PortErrorKind::Timeout, "TLS connect timed out"))?
        .map_err(|_| PortError::new(PortErrorKind::Transport, "TLS connect failed"))?;
        let stream = tokio::time::timeout(
            request.budget.timeout(),
            self.connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| PortError::new(PortErrorKind::Timeout, "TLS handshake timed out"))?
        .map_err(|_| {
            PortError::new(
                PortErrorKind::Transport,
                "TLS certificate validation failed",
            )
        })?;
        let connection = stream.get_ref().1;
        let protocol = connection
            .protocol_version()
            .map_or_else(|| "unknown".into(), |value| format!("{value:?}"));
        let cipher_suite = connection
            .negotiated_cipher_suite()
            .map_or_else(|| "unknown".into(), |value| format!("{:?}", value.suite()));
        let alpn = connection
            .alpn_protocol()
            .map(|value| String::from_utf8_lossy(value).into_owned());
        let certificates = connection
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|certificate| certificate_metadata(certificate.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        let certificate_sha256 = certificates
            .iter()
            .map(|certificate| certificate.sha256.clone())
            .collect();
        Ok(TlsObservation {
            protocol,
            cipher_suite,
            alpn,
            certificate_sha256,
            certificates,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

fn certificate_metadata(der: &[u8]) -> Result<TlsCertificate, PortError> {
    let (_, certificate) = X509Certificate::from_der(der).map_err(|_| {
        PortError::new(
            PortErrorKind::InvalidResponse,
            "TLS peer certificate metadata is invalid",
        )
    })?;
    let dns_names = certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(value) => Some((*value).to_owned()),
                    _ => None,
                })
                .take(256)
                .collect()
        })
        .unwrap_or_default();
    let is_ca = certificate
        .basic_constraints()
        .ok()
        .flatten()
        .map(|extension| extension.value.ca);
    Ok(TlsCertificate {
        sha256: hex::encode(Sha256::digest(der)),
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        serial: certificate.raw_serial_as_string(),
        not_before: certificate.validity().not_before.timestamp(),
        not_after: certificate.validity().not_after.timestamp(),
        dns_names,
        signature_algorithm: certificate.signature_algorithm.algorithm.to_id_string(),
        public_key_algorithm: certificate.public_key().algorithm.algorithm.to_id_string(),
        is_ca,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_certificate_metadata_is_rejected_without_raw_details()
    -> Result<(), Box<dyn std::error::Error>> {
        let Err(error) = certificate_metadata(b"not-a-certificate") else {
            return Err("invalid DER was accepted".into());
        };
        assert_eq!(error.kind, PortErrorKind::InvalidResponse);
        assert_eq!(error.message, "TLS peer certificate metadata is invalid");
        Ok(())
    }

    #[test]
    fn native_certificate_metadata_is_bounded_and_fingerprinted()
    -> Result<(), Box<dyn std::error::Error>> {
        let loaded = rustls_native_certs::load_native_certs();
        let Some(certificate) = loaded.certs.first() else {
            return Ok(());
        };
        let metadata = certificate_metadata(certificate.as_ref())?;
        assert_eq!(metadata.sha256.len(), 64);
        assert!(!metadata.subject.is_empty());
        assert!(!metadata.issuer.is_empty());
        assert!(metadata.dns_names.len() <= 256);
        assert!(metadata.not_after > metadata.not_before);
        Ok(())
    }
}
