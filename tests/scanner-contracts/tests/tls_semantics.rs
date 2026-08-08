//! Public end-to-end semantic contracts for certificate-validating TLS scanners.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use sugra_core::{
    PortError, ScanError, ScanErrorKind, TlsCertificate, TlsHandshakeKind, TlsObservation, TlsPort,
    TlsRequest, resolve_options,
};
use sugra_domain::{Confidence, ScanResult, Severity};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

const SECRET_MARKER: &str = "tls-contract-secret-9e42";
const FINGERPRINT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FINGERPRINT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const MODERN_CIPHER: &str = "TLS_AES_256_GCM_SHA384_tls-contract-secret-9e42";
const WEAK_CIPHER: &str = "TLS_RSA_WITH_RC4_128_SHA_tls-contract-secret-9e42";
const WEEK: i64 = 7 * 86_400;
const YEAR: i64 = 365 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureCase {
    PositiveSignal,
    NegativeControl,
    EdgeCase,
    TypedFailure,
}

#[derive(Debug, Clone, Copy)]
enum TlsFixture {
    Chain(FixtureCase),
    Expiry(FixtureCase),
    Cipher(FixtureCase),
    Handshake(FixtureCase),
    Security(FixtureCase),
    Resumption(FixtureCase),
    Inventory(FixtureCase),
}

struct FixtureTls {
    fixture: TlsFixture,
    calls: AtomicUsize,
}

impl FixtureTls {
    fn new(fixture: TlsFixture) -> Self {
        Self {
            fixture,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl TlsPort for FixtureTls {
    async fn handshake(&self, _request: TlsRequest) -> Result<TlsObservation, PortError> {
        let sample = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(observation_for(self.fixture, sample))
    }
}

fn observation_for(fixture: TlsFixture, sample: usize) -> TlsObservation {
    match fixture {
        TlsFixture::Chain(case) => chain_observation(case),
        TlsFixture::Expiry(case) => expiry_observation(case),
        TlsFixture::Cipher(case) => cipher_observation(case),
        TlsFixture::Handshake(case) => handshake_observation(case),
        TlsFixture::Security(case) => security_observation(case),
        TlsFixture::Resumption(case) => resumption_observation(case, sample),
        TlsFixture::Inventory(case) => inventory_observation(case, sample),
    }
}

fn base_observation(fingerprint: &str) -> TlsObservation {
    TlsObservation {
        handshake_kind: TlsHandshakeKind::Full,
        protocol: "TLSv1_3".into(),
        cipher_suite: MODERN_CIPHER.into(),
        alpn: Some("h2".into()),
        certificate_sha256: vec![fingerprint.into()],
        certificates: vec![certificate(
            fingerprint,
            "leaf",
            "issuer",
            -86_400,
            YEAR,
            false,
        )],
        duration_ms: 4,
    }
}

fn certificate(
    fingerprint: &str,
    subject_suffix: &str,
    issuer_suffix: &str,
    not_before: i64,
    not_after: i64,
    is_ca: bool,
) -> TlsCertificate {
    TlsCertificate {
        sha256: fingerprint.into(),
        subject: format!("CN={subject_suffix}-{SECRET_MARKER}"),
        issuer: format!("CN={issuer_suffix}-{SECRET_MARKER}"),
        serial: format!("serial-{SECRET_MARKER}"),
        not_before,
        not_after,
        dns_names: vec![format!("{SECRET_MARKER}.example")],
        signature_algorithm: format!("signature-{SECRET_MARKER}"),
        public_key_algorithm: format!("public-key-{SECRET_MARKER}"),
        is_ca: Some(is_ca),
    }
}

fn malformed_observation() -> TlsObservation {
    let mut observation = base_observation(FINGERPRINT_A);
    observation.certificate_sha256 = vec![format!("malformed-{SECRET_MARKER}")];
    observation.certificates.clear();
    observation
}

fn chain_observation(case: FixtureCase) -> TlsObservation {
    match case {
        FixtureCase::PositiveSignal => {
            let mut observation = base_observation(FINGERPRINT_A);
            observation.certificates[0].is_ca = Some(true);
            observation
        }
        FixtureCase::NegativeControl => base_observation(FINGERPRINT_A),
        FixtureCase::EdgeCase => {
            let mut observation = base_observation(FINGERPRINT_A);
            observation.certificates.clear();
            observation
        }
        FixtureCase::TypedFailure => {
            let mut observation = base_observation(FINGERPRINT_A);
            observation.certificates[0].sha256 = FINGERPRINT_B.into();
            observation
        }
    }
}

fn expiry_observation(case: FixtureCase) -> TlsObservation {
    let mut observation = base_observation(FINGERPRINT_A);
    match case {
        FixtureCase::PositiveSignal => {
            observation.certificates[0].not_before = -YEAR;
            observation.certificates[0].not_after = -1;
        }
        FixtureCase::NegativeControl => {}
        FixtureCase::EdgeCase => observation.certificates[0].not_after = WEEK,
        FixtureCase::TypedFailure => {
            observation.certificates[0].not_before = 10;
            observation.certificates[0].not_after = 10;
        }
    }
    observation
}

fn cipher_observation(case: FixtureCase) -> TlsObservation {
    let mut observation = base_observation(FINGERPRINT_A);
    match case {
        FixtureCase::PositiveSignal => observation.cipher_suite = WEAK_CIPHER.into(),
        FixtureCase::NegativeControl => {}
        FixtureCase::EdgeCase => observation.cipher_suite = " ".into(),
        FixtureCase::TypedFailure => return malformed_observation(),
    }
    observation
}

fn handshake_observation(case: FixtureCase) -> TlsObservation {
    let mut observation = base_observation(FINGERPRINT_A);
    match case {
        FixtureCase::PositiveSignal => observation.handshake_kind = TlsHandshakeKind::Unknown,
        FixtureCase::NegativeControl => {}
        FixtureCase::EdgeCase => {
            observation.handshake_kind = TlsHandshakeKind::FullWithHelloRetryRequest;
        }
        FixtureCase::TypedFailure => return malformed_observation(),
    }
    observation
}

fn security_observation(case: FixtureCase) -> TlsObservation {
    let mut observation = base_observation(FINGERPRINT_A);
    match case {
        FixtureCase::PositiveSignal => {
            observation.protocol = "TLSv1_0".into();
            observation.cipher_suite = WEAK_CIPHER.into();
        }
        FixtureCase::NegativeControl => {}
        FixtureCase::EdgeCase => observation.protocol = "TLSv1_2".into(),
        FixtureCase::TypedFailure => return malformed_observation(),
    }
    observation
}

fn resumption_observation(case: FixtureCase, sample: usize) -> TlsObservation {
    let mut observation = base_observation(FINGERPRINT_A);
    match case {
        FixtureCase::NegativeControl if sample > 0 => {
            observation.handshake_kind = TlsHandshakeKind::Resumed;
        }
        FixtureCase::PositiveSignal | FixtureCase::NegativeControl => {}
        FixtureCase::EdgeCase => observation.handshake_kind = TlsHandshakeKind::Unknown,
        FixtureCase::TypedFailure => return malformed_observation(),
    }
    observation
}

fn inventory_observation(case: FixtureCase, sample: usize) -> TlsObservation {
    match case {
        FixtureCase::PositiveSignal if sample > 0 => base_observation(FINGERPRINT_B),
        FixtureCase::PositiveSignal | FixtureCase::NegativeControl => {
            base_observation(FINGERPRINT_A)
        }
        FixtureCase::EdgeCase => {
            let mut observation = base_observation(FINGERPRINT_A);
            observation.certificate_sha256.clear();
            observation.certificates.clear();
            observation
        }
        FixtureCase::TypedFailure => malformed_observation(),
    }
}

async fn scan(
    id: &str,
    fixture: TlsFixture,
    supplied: BTreeMap<String, String>,
) -> Result<ScanResult, ScanError> {
    let mut services = support::Harness::successful().services();
    services.tls = Arc::new(FixtureTls::new(fixture));
    let Ok(builtins) = build_builtins(&services) else {
        unreachable!("built-in catalog must be valid");
    };
    let Ok(scanner_id) = sugra_domain::ScannerId::new(id) else {
        unreachable!("fixture scanner ID must be valid");
    };
    let Some(scanner) = builtins.registry.get(&scanner_id) else {
        unreachable!("fixture scanner must be registered");
    };
    let Ok(mut request) = support::request_for(scanner.descriptor()) else {
        unreachable!("fixture scanner request must be valid");
    };
    let Ok(options) = resolve_options(&scanner.descriptor().options, &supplied) else {
        unreachable!("fixture options must be valid");
    };
    request.options = options;
    scanner.scan(&request, &support::context(false)).await
}

fn finding_keys(result: &ScanResult) -> Vec<&str> {
    result
        .findings
        .iter()
        .map(|finding| finding.key.as_str())
        .collect()
}

fn finding<'a>(result: &'a ScanResult, key: &str) -> Option<&'a sugra_domain::Finding> {
    result.findings.iter().find(|finding| finding.key == key)
}

fn assert_redacted(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serde_json::to_string(&result.evidence)?;
    for raw in [
        SECRET_MARKER,
        FINGERPRINT_A,
        FINGERPRINT_B,
        MODERN_CIPHER,
        WEAK_CIPHER,
        "TLSv1_3",
    ] {
        assert!(!serialized.contains(raw), "raw TLS material leaked: {raw}");
    }
    Ok(())
}

async fn assert_typed_failure(
    id: &str,
    fixture: TlsFixture,
    supplied: BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Err(error) = scan(id, fixture, supplied).await else {
        return Err(format!("{id} accepted invalid TLS adapter metadata").into());
    };
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);
    assert!(!error.to_string().contains(SECRET_MARKER));
    assert!(!error.to_string().contains(FINGERPRINT_A));
    assert!(!error.to_string().contains(FINGERPRINT_B));
    Ok(())
}

#[tokio::test]
async fn ssl_chain_covers_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan(
        "ssl-chain",
        TlsFixture::Chain(FixtureCase::PositiveSignal),
        BTreeMap::new(),
    )
    .await?;
    assert!(finding(&positive, "tls-leaf-is-ca").is_some());
    assert_redacted(&positive)?;

    let negative = scan(
        "ssl-chain",
        TlsFixture::Chain(FixtureCase::NegativeControl),
        BTreeMap::new(),
    )
    .await?;
    assert!(negative.findings.is_empty());
    assert_redacted(&negative)?;

    let edge = scan(
        "ssl-chain",
        TlsFixture::Chain(FixtureCase::EdgeCase),
        BTreeMap::new(),
    )
    .await?;
    let edge_finding = finding(&edge, "tls-chain-metadata-unavailable")
        .ok_or("missing chain metadata finding was not emitted")?;
    assert_eq!(edge_finding.confidence, Confidence::Unknown);
    assert_redacted(&edge)?;

    assert_typed_failure(
        "ssl-chain",
        TlsFixture::Chain(FixtureCase::TypedFailure),
        BTreeMap::new(),
    )
    .await
}

#[tokio::test]
async fn ssl_expiry_covers_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan(
        "ssl-expiry",
        TlsFixture::Expiry(FixtureCase::PositiveSignal),
        BTreeMap::new(),
    )
    .await?;
    let expired = finding(&positive, "tls-certificate-expired")
        .ok_or("expired certificate finding was not emitted")?;
    assert_eq!(expired.severity, Severity::Critical);
    assert_redacted(&positive)?;

    let negative = scan(
        "ssl-expiry",
        TlsFixture::Expiry(FixtureCase::NegativeControl),
        BTreeMap::new(),
    )
    .await?;
    assert!(negative.findings.is_empty());
    assert_redacted(&negative)?;

    let edge = scan(
        "ssl-expiry",
        TlsFixture::Expiry(FixtureCase::EdgeCase),
        BTreeMap::new(),
    )
    .await?;
    let expiring = finding(&edge, "tls-certificate-expiring")
        .ok_or("seven-day expiry finding was not emitted")?;
    assert_eq!(expiring.severity, Severity::High);
    assert_redacted(&edge)?;

    assert_typed_failure(
        "ssl-expiry",
        TlsFixture::Expiry(FixtureCase::TypedFailure),
        BTreeMap::new(),
    )
    .await
}

#[tokio::test]
async fn tls_cipher_suites_covers_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan(
        "tls-cipher-suites",
        TlsFixture::Cipher(FixtureCase::PositiveSignal),
        BTreeMap::new(),
    )
    .await?;
    assert!(finding(&positive, "tls-weak-cipher").is_some());
    assert_redacted(&positive)?;

    let negative = scan(
        "tls-cipher-suites",
        TlsFixture::Cipher(FixtureCase::NegativeControl),
        BTreeMap::new(),
    )
    .await?;
    assert!(negative.findings.is_empty());
    assert_redacted(&negative)?;

    let edge = scan(
        "tls-cipher-suites",
        TlsFixture::Cipher(FixtureCase::EdgeCase),
        BTreeMap::new(),
    )
    .await?;
    let unavailable = finding(&edge, "tls-cipher-metadata-unavailable")
        .ok_or("missing cipher metadata finding was not emitted")?;
    assert_eq!(unavailable.confidence, Confidence::Unknown);
    assert_redacted(&edge)?;

    assert_typed_failure(
        "tls-cipher-suites",
        TlsFixture::Cipher(FixtureCase::TypedFailure),
        BTreeMap::new(),
    )
    .await
}

#[tokio::test]
async fn tls_handshake_covers_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan(
        "tls-handshake",
        TlsFixture::Handshake(FixtureCase::PositiveSignal),
        BTreeMap::new(),
    )
    .await?;
    let incomplete = finding(&positive, "tls-negotiation-incomplete")
        .ok_or("incomplete handshake finding was not emitted")?;
    assert_eq!(incomplete.confidence, Confidence::Unknown);
    assert_redacted(&positive)?;

    let negative = scan(
        "tls-handshake",
        TlsFixture::Handshake(FixtureCase::NegativeControl),
        BTreeMap::new(),
    )
    .await?;
    assert!(negative.findings.is_empty());
    assert_redacted(&negative)?;

    let edge = scan(
        "tls-handshake",
        TlsFixture::Handshake(FixtureCase::EdgeCase),
        BTreeMap::new(),
    )
    .await?;
    assert!(edge.findings.is_empty());
    assert_eq!(
        edge.evidence[0].observation["observation"]["handshake_kind"],
        "full-with-hello-retry-request"
    );
    assert_redacted(&edge)?;

    assert_typed_failure(
        "tls-handshake",
        TlsFixture::Handshake(FixtureCase::TypedFailure),
        BTreeMap::new(),
    )
    .await
}

#[tokio::test]
async fn tls_security_config_covers_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan(
        "tls-security-config",
        TlsFixture::Security(FixtureCase::PositiveSignal),
        BTreeMap::new(),
    )
    .await?;
    assert_eq!(
        finding_keys(&positive),
        vec!["tls-weak-cipher", "tls-obsolete-protocol"]
    );
    assert_redacted(&positive)?;

    let negative = scan(
        "tls-security-config",
        TlsFixture::Security(FixtureCase::NegativeControl),
        BTreeMap::new(),
    )
    .await?;
    assert!(negative.findings.is_empty());
    assert_redacted(&negative)?;

    let edge = scan(
        "tls-security-config",
        TlsFixture::Security(FixtureCase::EdgeCase),
        BTreeMap::new(),
    )
    .await?;
    assert!(finding(&edge, "tls-modernization").is_some());
    assert_redacted(&edge)?;

    assert_typed_failure(
        "tls-security-config",
        TlsFixture::Security(FixtureCase::TypedFailure),
        BTreeMap::new(),
    )
    .await
}

#[tokio::test]
async fn tls_session_resumption_map_covers_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let options = BTreeMap::from([("samples".into(), "2".into())]);
    let positive = scan(
        "tls-session-resumption-map",
        TlsFixture::Resumption(FixtureCase::PositiveSignal),
        options.clone(),
    )
    .await?;
    assert!(finding(&positive, "tls-resumption-not-observed").is_some());
    assert_redacted(&positive)?;

    let negative = scan(
        "tls-session-resumption-map",
        TlsFixture::Resumption(FixtureCase::NegativeControl),
        options.clone(),
    )
    .await?;
    assert!(negative.findings.is_empty());
    assert_redacted(&negative)?;

    let edge = scan(
        "tls-session-resumption-map",
        TlsFixture::Resumption(FixtureCase::EdgeCase),
        options.clone(),
    )
    .await?;
    let inconclusive = finding(&edge, "tls-resumption-inconclusive")
        .ok_or("inconclusive resumption finding was not emitted")?;
    assert_eq!(inconclusive.confidence, Confidence::Unknown);
    assert_redacted(&edge)?;

    assert_typed_failure(
        "tls-session-resumption-map",
        TlsFixture::Resumption(FixtureCase::TypedFailure),
        options,
    )
    .await
}

#[tokio::test]
async fn network_certificate_inventory_covers_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let options = BTreeMap::from([("ports".into(), "443,8443".into())]);
    let positive = scan(
        "network-certificate-inventory",
        TlsFixture::Inventory(FixtureCase::PositiveSignal),
        options.clone(),
    )
    .await?;
    let positive_summary = positive
        .evidence
        .iter()
        .find(|evidence| evidence.kind.ends_with("certificate-inventory-summary"))
        .ok_or("certificate inventory summary evidence is missing")?;
    assert_eq!(
        positive_summary.observation["observation"]["endpoints-observed"],
        2
    );
    assert_eq!(
        positive_summary.observation["observation"]["unique-leaf-certificates"],
        2
    );
    assert_redacted(&positive)?;

    let negative = scan(
        "network-certificate-inventory",
        TlsFixture::Inventory(FixtureCase::NegativeControl),
        options.clone(),
    )
    .await?;
    let negative_summary = negative
        .evidence
        .iter()
        .find(|evidence| evidence.kind.ends_with("certificate-inventory-summary"))
        .ok_or("certificate inventory summary evidence is missing")?;
    assert_eq!(
        negative_summary.observation["observation"]["unique-leaf-certificates"],
        1
    );
    assert!(negative.findings.is_empty());
    assert_redacted(&negative)?;

    let edge = scan(
        "network-certificate-inventory",
        TlsFixture::Inventory(FixtureCase::EdgeCase),
        options.clone(),
    )
    .await?;
    assert!(finding(&edge, "tls-inventory-leaf-unavailable").is_some());
    assert!(finding(&edge, "tls-chain-metadata-unavailable").is_some());
    assert_redacted(&edge)?;

    assert_typed_failure(
        "network-certificate-inventory",
        TlsFixture::Inventory(FixtureCase::TypedFailure),
        options,
    )
    .await
}
