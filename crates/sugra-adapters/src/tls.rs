//! Certificate-validating Rustls handshake boundary.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use sugra_core::{
    PortError, PortErrorKind, QuicObservation, QuicRequest, TlsCertificate, TlsHandshakeKind,
    TlsObservation, TlsPort, TlsRequest,
};
use sugra_domain::{Target, TargetKind};
use thiserror::Error;
use tokio::net::{TcpStream, lookup_host};
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// TLS adapter construction failure.
#[derive(Debug, Error)]
pub enum TlsAdapterError {
    /// No usable native trust anchors were loaded.
    #[error("no native TLS trust anchors are available")]
    NoTrustAnchors,
    /// Native TLS settings could not be converted into a QUIC client.
    #[error("native TLS settings are incompatible with QUIC")]
    InvalidQuicConfig,
    /// The selected crypto provider could not construct safe protocol defaults.
    #[error("native TLS protocol settings are invalid")]
    InvalidProtocolConfig,
}

/// Rustls client using native trust anchors and mandatory verification.
#[derive(Clone)]
pub struct RustlsTls {
    connector: TlsConnector,
    quic_config: quinn::ClientConfig,
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
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| TlsAdapterError::InvalidProtocolConfig)?
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut quic_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| TlsAdapterError::InvalidProtocolConfig)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        quic_tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_crypto =
            QuicClientConfig::try_from(quic_tls).map_err(|_| TlsAdapterError::InvalidQuicConfig)?;
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            quic_config: quinn::ClientConfig::new(Arc::new(quic_crypto)),
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
        let validation_name = request
            .server_name
            .clone()
            .unwrap_or_else(|| request.host.clone());
        let server_name = ServerName::try_from(validation_name).map_err(|_| {
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
        let handshake_kind = match connection.handshake_kind() {
            Some(rustls::HandshakeKind::Full) => TlsHandshakeKind::Full,
            Some(rustls::HandshakeKind::FullWithHelloRetryRequest) => {
                TlsHandshakeKind::FullWithHelloRetryRequest
            }
            Some(rustls::HandshakeKind::Resumed) => TlsHandshakeKind::Resumed,
            None => TlsHandshakeKind::Unknown,
        };
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
            handshake_kind,
            protocol,
            cipher_suite,
            alpn,
            certificate_sha256,
            certificates,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    async fn handshake_quic(&self, request: QuicRequest) -> Result<QuicObservation, PortError> {
        let target = request
            .host
            .parse()
            .map(Target::Ip)
            .or_else(|_| Target::parse(TargetKind::Domain, &request.host))
            .map_err(|_| PortError::new(PortErrorKind::InvalidResponse, "QUIC host is invalid"))?;
        if !request.scope.allows(&target) {
            return Err(PortError::new(
                PortErrorKind::OutOfScope,
                "QUIC host is outside the declared scope",
            ));
        }
        let validation_name = request
            .server_name
            .clone()
            .unwrap_or_else(|| request.host.clone());
        ServerName::try_from(validation_name.clone()).map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidResponse,
                "QUIC server name is invalid",
            )
        })?;
        let remote = tokio::time::timeout(
            request.budget.timeout(),
            lookup_host((request.host.as_str(), request.port)),
        )
        .await
        .map_err(|_| PortError::new(PortErrorKind::Timeout, "QUIC lookup timed out"))?
        .map_err(|_| PortError::new(PortErrorKind::Transport, "QUIC lookup failed"))?
        .next()
        .ok_or_else(|| PortError::new(PortErrorKind::Transport, "QUIC host has no address"))?;
        let bind_address = match remote {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let mut endpoint = quinn::Endpoint::client(bind_address).map_err(|_| {
            PortError::new(
                PortErrorKind::Unavailable,
                "QUIC client socket is unavailable",
            )
        })?;
        endpoint.set_default_client_config(self.quic_config.clone());
        let started = Instant::now();
        let connecting = endpoint.connect(remote, &validation_name).map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidResponse,
                "QUIC connection request is invalid",
            )
        })?;
        let connection = tokio::time::timeout(request.budget.timeout(), connecting)
            .await
            .map_err(|_| PortError::new(PortErrorKind::Timeout, "QUIC handshake timed out"))?
            .map_err(|_| PortError::new(PortErrorKind::Transport, "QUIC handshake failed"))?;
        let handshake = connection
            .handshake_data()
            .ok_or_else(|| {
                PortError::new(
                    PortErrorKind::InvalidResponse,
                    "QUIC handshake metadata is unavailable",
                )
            })?
            .downcast::<HandshakeData>()
            .map_err(|_| {
                PortError::new(
                    PortErrorKind::InvalidResponse,
                    "QUIC handshake metadata has an unexpected type",
                )
            })?;
        let alpn = handshake
            .protocol
            .map(|protocol| String::from_utf8_lossy(&protocol).into_owned());
        connection.close(0_u32.into(), b"");
        Ok(QuicObservation {
            alpn,
            version: None,
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
    use std::net::UdpSocket;

    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use sugra_domain::{Budget, ScopeGrant};

    use super::*;

    fn request(host: &str, server_name: Option<&str>, scope: ScopeGrant) -> TlsRequest {
        TlsRequest {
            host: host.into(),
            server_name: server_name.map(str::to_owned),
            port: 443,
            budget: Budget::default(),
            scope,
        }
    }

    fn quic_request(
        host: &str,
        server_name: Option<&str>,
        port: u16,
        scope: ScopeGrant,
    ) -> QuicRequest {
        QuicRequest {
            host: host.into(),
            server_name: server_name.map(str::to_owned),
            port,
            budget: Budget {
                timeout_ms: 50,
                ..Budget::default()
            },
            scope,
        }
    }

    #[tokio::test]
    async fn invalid_hosts_scope_and_server_names_fail_before_connecting()
    -> Result<(), Box<dyn std::error::Error>> {
        let tls = match RustlsTls::native() {
            Ok(tls) => tls,
            Err(TlsAdapterError::NoTrustAnchors) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let allowed = Target::parse(TargetKind::Domain, "example.com")?;
        let other = Target::parse(TargetKind::Domain, "other.example")?;

        let Err(invalid_host) = tls
            .handshake(request(
                "bad host",
                None,
                ScopeGrant::exact(&allowed, false, time::OffsetDateTime::UNIX_EPOCH),
            ))
            .await
        else {
            return Err("invalid host was accepted".into());
        };
        assert_eq!(invalid_host.kind, PortErrorKind::InvalidResponse);

        let Err(out_of_scope) = tls
            .handshake(request(
                "example.com",
                None,
                ScopeGrant::exact(&other, false, time::OffsetDateTime::UNIX_EPOCH),
            ))
            .await
        else {
            return Err("out-of-scope host was accepted".into());
        };
        assert_eq!(out_of_scope.kind, PortErrorKind::OutOfScope);

        let Err(invalid_name) = tls
            .handshake(request(
                "example.com",
                Some("bad name"),
                ScopeGrant::exact(&allowed, false, time::OffsetDateTime::UNIX_EPOCH),
            ))
            .await
        else {
            return Err("invalid server name was accepted".into());
        };
        assert_eq!(invalid_name.kind, PortErrorKind::InvalidResponse);
        Ok(())
    }

    #[tokio::test]
    async fn quic_boundary_validates_scope_and_attempts_a_real_udp_handshake()
    -> Result<(), Box<dyn std::error::Error>> {
        let tls = match RustlsTls::native() {
            Ok(tls) => tls,
            Err(TlsAdapterError::NoTrustAnchors) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let target = Target::parse(TargetKind::Ip, "127.0.0.1")?;
        let other = Target::parse(TargetKind::Ip, "127.0.0.2")?;
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        drop(socket);

        let Err(out_of_scope) = tls
            .handshake_quic(quic_request(
                "127.0.0.1",
                Some("localhost"),
                port,
                ScopeGrant::exact(&other, false, time::OffsetDateTime::UNIX_EPOCH),
            ))
            .await
        else {
            return Err("out-of-scope QUIC host was accepted".into());
        };
        assert_eq!(out_of_scope.kind, PortErrorKind::OutOfScope);

        let Err(attempted) = tls
            .handshake_quic(quic_request(
                "127.0.0.1",
                Some("localhost"),
                port,
                ScopeGrant::exact(&target, false, time::OffsetDateTime::UNIX_EPOCH),
            ))
            .await
        else {
            return Err("unused local UDP port unexpectedly completed QUIC".into());
        };
        assert!(matches!(
            attempted.kind,
            PortErrorKind::Timeout | PortErrorKind::Transport
        ));
        Ok(())
    }

    #[tokio::test]
    async fn quic_boundary_completes_a_trusted_handshake_and_negotiates_h3()
    -> Result<(), Box<dyn std::error::Error>> {
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let certificate = certified_key.cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key.into())?;
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_crypto = QuicServerConfig::try_from(server_tls)
            .map_err(|_| std::io::Error::other("test QUIC server TLS configuration is invalid"))?;
        let server_endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )?;
        let server_address = server_endpoint.local_addr()?;
        let server_handshake = tokio::spawn(async move {
            let Some(incoming) = server_endpoint.accept().await else {
                return false;
            };
            incoming.await.is_ok()
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate)?;
        let client_tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        let mut quic_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        quic_tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_crypto = QuicClientConfig::try_from(quic_tls)
            .map_err(|_| std::io::Error::other("test QUIC client TLS configuration is invalid"))?;
        let tls = RustlsTls {
            connector: TlsConnector::from(Arc::new(client_tls)),
            quic_config: quinn::ClientConfig::new(Arc::new(quic_crypto)),
        };

        let target = Target::parse(TargetKind::Ip, "127.0.0.1")?;
        let mut request = quic_request(
            "127.0.0.1",
            Some("localhost"),
            server_address.port(),
            ScopeGrant::exact(&target, false, time::OffsetDateTime::UNIX_EPOCH),
        );
        request.budget.timeout_ms = 2_000;
        let observation = tls.handshake_quic(request).await?;

        assert!(server_handshake.await?);
        assert_eq!(observation.alpn.as_deref(), Some("h3"));
        Ok(())
    }

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
