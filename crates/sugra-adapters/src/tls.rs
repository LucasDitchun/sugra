//! Certificate-validating Rustls handshake boundary.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use sugra_core::{PortError, PortErrorKind, TlsObservation, TlsPort, TlsRequest};
use sugra_domain::{Target, TargetKind};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
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
        let certificate_sha256 = connection
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|certificate| hex::encode(Sha256::digest(certificate.as_ref())))
            .collect();
        Ok(TlsObservation {
            protocol,
            cipher_suite,
            alpn,
            certificate_sha256,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}
