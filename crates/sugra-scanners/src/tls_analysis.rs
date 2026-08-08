//! Pure analysis for bounded, certificate-validating TLS observations.

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::Serialize;
use sugra_core::{TlsHandshakeKind, TlsObservation};
use sugra_domain::{Confidence, Finding, Severity};

/// Validation failures at the TLS analysis boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsAnalysisError {
    /// Pinning requires an explicit baseline.
    MissingBaseline,
    /// The baseline is not exactly 64 lowercase hexadecimal characters.
    InvalidBaselineSha256,
    /// The TLS adapter returned a malformed certificate fingerprint.
    InvalidObservedSha256,
}

impl Display for TlsAnalysisError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBaseline => formatter.write_str("a TLS pinning baseline is required"),
            Self::InvalidBaselineSha256 => {
                formatter.write_str("the TLS pinning baseline is not a valid lowercase SHA-256")
            }
            Self::InvalidObservedSha256 => {
                formatter.write_str("the TLS adapter returned an invalid certificate SHA-256")
            }
        }
    }
}

impl Error for TlsAnalysisError {}

/// Typed failures shared by the semantic TLS analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsSemanticError {
    /// At least one adapter fingerprint was malformed.
    InvalidCertificateSha256,
    /// A certificate validity interval was empty or reversed.
    InvalidValidityWindow,
    /// Parallel observations and evidence identifiers were not aligned.
    InvalidEvidenceMapping,
    /// Parsed certificates and fingerprint metadata describe different chains.
    InconsistentCertificateMetadata,
}

impl Display for TlsSemanticError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCertificateSha256 => {
                formatter.write_str("the TLS adapter returned invalid certificate metadata")
            }
            Self::InvalidValidityWindow => formatter
                .write_str("the TLS adapter returned an invalid certificate validity window"),
            Self::InvalidEvidenceMapping => {
                formatter.write_str("TLS observations and evidence identifiers are not aligned")
            }
            Self::InconsistentCertificateMetadata => {
                formatter.write_str("the TLS adapter returned inconsistent certificate metadata")
            }
        }
    }
}

impl Error for TlsSemanticError {}

/// A validated SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Sha256Fingerprint([u8; 32]);

/// Non-sensitive counts produced by certificate inventory analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct CertificateInventorySummary {
    /// Number of bounded endpoint observations.
    pub(crate) endpoints_observed: usize,
    /// Number of observations with a leaf fingerprint.
    pub(crate) endpoints_with_leaf: usize,
    /// Number of distinct validated leaf fingerprints, without exposing them.
    pub(crate) unique_leaf_certificates: usize,
}

/// Safe inventory output: aggregate counts plus actionable findings.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CertificateInventoryAnalysis {
    /// Aggregate certificate counts.
    pub(crate) summary: CertificateInventorySummary,
    /// Findings tied to the caller's evidence identifiers.
    pub(crate) findings: Vec<Finding>,
}

/// Classification of the single protocol negotiated by one handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NegotiatedProtocol {
    /// TLS 1.3 was negotiated.
    Tls13,
    /// TLS 1.2 was negotiated.
    Tls12,
    /// An obsolete TLS or SSL version was negotiated.
    Legacy,
    /// The observation did not contain a recognized negotiated protocol.
    Unknown,
}

/// Summary of handshake kinds in a bounded resumption sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ResumptionSummary {
    /// At least one handshake was explicitly reported as resumed.
    ResumedObserved,
    /// Every sampled handshake was explicitly reported as a full handshake.
    FullOnlyObserved,
    /// The sample was empty or contained an unknown handshake kind.
    Inconclusive,
}

/// Conservative classification of the single negotiated cipher name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CipherSummary {
    /// The name contains a recognized weak or legacy suite marker.
    KnownWeak,
    /// A non-empty name was observed; no broader security claim is made.
    Named,
    /// The adapter did not expose a cipher name.
    Unknown,
}

/// Application protocol negotiated by the bounded TLS observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ApplicationProtocolSummary {
    /// HTTP/2 was negotiated.
    Http2,
    /// An HTTP/3 ALPN identifier was observed.
    Http3,
    /// A different non-empty ALPN value was observed.
    Other,
    /// ALPN metadata was absent or explicitly unknown.
    Unknown,
}

/// Redacted evidence suitable for serialization by scanner integration code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct TlsEvidenceSummary {
    /// Full, resumed, retry, or unknown handshake classification.
    pub(crate) handshake_kind: TlsHandshakeKind,
    /// Classified negotiated TLS version.
    pub(crate) protocol: NegotiatedProtocol,
    /// Classified negotiated cipher without retaining its raw name.
    pub(crate) cipher: CipherSummary,
    /// Classified ALPN without retaining its raw value.
    pub(crate) application_protocol: ApplicationProtocolSummary,
    /// Number of validated certificate fingerprints in the peer chain.
    pub(crate) certificate_count: usize,
    /// Number of parsed certificate metadata entries.
    pub(crate) parsed_certificate_count: usize,
    /// Bounded handshake duration.
    pub(crate) duration_ms: u64,
}

/// Parses the canonical lowercase hexadecimal baseline form.
pub(crate) fn parse_baseline_sha256(value: &str) -> Result<Sha256Fingerprint, TlsAnalysisError> {
    parse_sha256(value).ok_or(TlsAnalysisError::InvalidBaselineSha256)
}

/// Validates all certificate fingerprints returned by the TLS adapter.
pub(crate) fn validate_observed_sha256(
    values: &[String],
) -> Result<Vec<Sha256Fingerprint>, TlsAnalysisError> {
    values
        .iter()
        .map(|value| parse_sha256(value).ok_or(TlsAnalysisError::InvalidObservedSha256))
        .collect()
}

/// Classifies the negotiated protocol without inferring broader server support.
#[must_use]
pub(crate) fn negotiated_protocol(observation: &TlsObservation) -> NegotiatedProtocol {
    match observation.protocol.as_str() {
        "TLSv1_3" => NegotiatedProtocol::Tls13,
        "TLSv1_2" => NegotiatedProtocol::Tls12,
        "TLSv1_0" | "TLSv1_1" | "SSLv2" | "SSLv3" => NegotiatedProtocol::Legacy,
        _ => NegotiatedProtocol::Unknown,
    }
}

/// Summarizes only observed handshake kinds without claiming server support.
#[must_use]
pub(crate) fn summarize_resumption(observations: &[TlsObservation]) -> ResumptionSummary {
    if observations
        .iter()
        .any(|observation| observation.handshake_kind == TlsHandshakeKind::Resumed)
    {
        ResumptionSummary::ResumedObserved
    } else if !observations.is_empty()
        && observations.iter().all(|observation| {
            matches!(
                observation.handshake_kind,
                TlsHandshakeKind::Full | TlsHandshakeKind::FullWithHelloRetryRequest
            )
        })
    {
        ResumptionSummary::FullOnlyObserved
    } else {
        ResumptionSummary::Inconclusive
    }
}

/// Classifies the negotiated cipher name without treating an unknown name as safe.
#[must_use]
pub(crate) fn negotiated_cipher(observation: &TlsObservation) -> CipherSummary {
    let cipher = observation.cipher_suite.trim().to_ascii_lowercase();
    if cipher.is_empty() || cipher == "unknown" {
        CipherSummary::Unknown
    } else if ["rc4", "3des", "des_cbc", "null", "export"]
        .iter()
        .any(|marker| cipher.contains(marker))
    {
        CipherSummary::KnownWeak
    } else {
        CipherSummary::Named
    }
}

/// Compares the observed leaf certificate with an explicit SHA-256 baseline.
pub(crate) fn analyze_pinning(
    observation: &TlsObservation,
    baseline_sha256: Option<&str>,
    evidence: usize,
) -> Result<Vec<Finding>, TlsAnalysisError> {
    let baseline = baseline_sha256.ok_or(TlsAnalysisError::MissingBaseline)?;
    let baseline = parse_baseline_sha256(baseline)?;
    let observed = validate_observed_sha256(&observation.certificate_sha256)?;
    let Some(observed_leaf) = observed.first() else {
        return Ok(vec![finding(
            "tls-pinning-material-unavailable",
            "No leaf certificate fingerprint is available for pinning comparison",
            Severity::Medium,
            Confidence::Unknown,
            evidence,
        )]);
    };
    if *observed_leaf == baseline {
        Ok(Vec::new())
    } else {
        Ok(vec![finding(
            "tls-pinning-baseline-mismatch",
            "The observed leaf certificate differs from the explicit pinning baseline",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        )])
    }
}

/// Inspects only the certificate metadata returned for one validated TLS chain.
pub(crate) fn analyze_ssl_chain(
    observation: &TlsObservation,
    evidence: usize,
) -> Result<Vec<Finding>, TlsSemanticError> {
    validate_semantic_fingerprints(observation)?;
    if observation.certificates.is_empty() {
        return Ok(vec![finding(
            "tls-chain-metadata-unavailable",
            "The validated peer certificate chain metadata is unavailable",
            Severity::Medium,
            Confidence::Unknown,
            evidence,
        )]);
    }
    let mut findings = Vec::new();
    let leaf = &observation.certificates[0];
    if leaf.is_ca == Some(true) {
        findings.push(finding(
            "tls-leaf-is-ca",
            "The TLS leaf certificate is marked as a certificate authority",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if leaf.subject == leaf.issuer {
        findings.push(finding(
            "tls-self-issued-leaf",
            "The TLS leaf certificate is self-issued",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if observation
        .certificates
        .windows(2)
        .any(|pair| pair[0].issuer != pair[1].subject)
    {
        findings.push(finding(
            "tls-chain-link-mismatch",
            "Adjacent certificate issuer and subject metadata do not link",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if observation
        .certificates
        .iter()
        .skip(1)
        .any(|certificate| certificate.is_ca == Some(false))
    {
        findings.push(finding(
            "tls-chain-non-ca-issuer",
            "A non-leaf certificate is explicitly marked as not being a certificate authority",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    Ok(findings)
}

/// Evaluates the observed leaf validity window against an explicit Unix time.
pub(crate) fn analyze_ssl_expiry(
    observation: &TlsObservation,
    now: i64,
    evidence: usize,
) -> Result<Vec<Finding>, TlsSemanticError> {
    validate_semantic_fingerprints(observation)?;
    let Some(leaf) = observation.certificates.first() else {
        return Ok(vec![finding(
            "tls-validity-metadata-unavailable",
            "Certificate validity metadata is unavailable",
            Severity::Medium,
            Confidence::Unknown,
            evidence,
        )]);
    };
    if leaf.not_before >= leaf.not_after {
        return Err(TlsSemanticError::InvalidValidityWindow);
    }
    if now < leaf.not_before {
        return Ok(vec![finding(
            "tls-certificate-not-yet-valid",
            "The TLS leaf certificate is not yet valid",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        )]);
    }
    if now >= leaf.not_after {
        return Ok(vec![finding(
            "tls-certificate-expired",
            "The TLS leaf certificate has expired",
            Severity::Critical,
            Confidence::Confirmed,
            evidence,
        )]);
    }
    let remaining = leaf.not_after.saturating_sub(now);
    let risk = if remaining <= 7 * 86_400 {
        Some((
            Severity::High,
            "The TLS leaf certificate expires within 7 days",
        ))
    } else if remaining <= 30 * 86_400 {
        Some((
            Severity::Medium,
            "The TLS leaf certificate expires within 30 days",
        ))
    } else if remaining <= 90 * 86_400 {
        Some((
            Severity::Low,
            "The TLS leaf certificate expires within 90 days",
        ))
    } else {
        None
    };
    Ok(risk.map_or_else(Vec::new, |(severity, title)| {
        vec![finding(
            "tls-certificate-expiring",
            title,
            severity,
            Confidence::Confirmed,
            evidence,
        )]
    }))
}

/// Checks whether one successful handshake exposed complete negotiation metadata.
pub(crate) fn analyze_tls_handshake(
    observation: &TlsObservation,
    evidence: usize,
) -> Result<Vec<Finding>, TlsSemanticError> {
    validate_semantic_fingerprints(observation)?;
    let incomplete = matches!(observation.handshake_kind, TlsHandshakeKind::Unknown)
        || is_unknown_text(&observation.protocol)
        || is_unknown_text(&observation.cipher_suite);
    Ok(if incomplete {
        vec![finding(
            "tls-negotiation-incomplete",
            "TLS negotiation metadata is incomplete",
            Severity::Medium,
            Confidence::Unknown,
            evidence,
        )]
    } else {
        Vec::new()
    })
}

/// Evaluates only the cipher suite negotiated by this observation.
pub(crate) fn analyze_tls_cipher_suites(
    observation: &TlsObservation,
    evidence: usize,
) -> Result<Vec<Finding>, TlsSemanticError> {
    validate_semantic_fingerprints(observation)?;
    Ok(match negotiated_cipher(observation) {
        CipherSummary::KnownWeak => vec![finding(
            "tls-weak-cipher",
            "A known weak TLS cipher suite was negotiated",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        )],
        CipherSummary::Unknown => vec![finding(
            "tls-cipher-metadata-unavailable",
            "The negotiated TLS cipher suite is unavailable",
            Severity::Medium,
            Confidence::Unknown,
            evidence,
        )],
        CipherSummary::Named => Vec::new(),
    })
}

/// Evaluates the negotiated protocol and cipher without inferring unobserved support.
pub(crate) fn analyze_tls_security_config(
    observation: &TlsObservation,
    evidence: usize,
) -> Result<Vec<Finding>, TlsSemanticError> {
    let mut findings = analyze_tls_cipher_suites(observation, evidence)?;
    match negotiated_protocol(observation) {
        NegotiatedProtocol::Legacy => findings.push(finding(
            "tls-obsolete-protocol",
            "An obsolete TLS protocol version was negotiated",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        )),
        NegotiatedProtocol::Tls12 => findings.push(finding(
            "tls-modernization",
            "TLS 1.2 was negotiated; this observation cannot establish TLS 1.3 availability",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )),
        NegotiatedProtocol::Unknown => findings.push(finding(
            "tls-protocol-metadata-unavailable",
            "The negotiated TLS protocol version is unavailable",
            Severity::Medium,
            Confidence::Unknown,
            evidence,
        )),
        NegotiatedProtocol::Tls13 => {}
    }
    Ok(findings)
}

/// Classifies ALPN without treating one negotiation as a server capability matrix.
#[must_use]
pub(crate) fn negotiated_application_protocol(
    observation: &TlsObservation,
) -> ApplicationProtocolSummary {
    match observation.alpn.as_deref().map(str::trim) {
        Some("h2") => ApplicationProtocolSummary::Http2,
        Some(value) if value == "h3" || value.starts_with("h3-") => {
            ApplicationProtocolSummary::Http3
        }
        Some(value) if !is_unknown_text(value) => ApplicationProtocolSummary::Other,
        _ => ApplicationProtocolSummary::Unknown,
    }
}

/// Reports whether HTTP/2 or HTTP/3 was negotiated in this bounded observation.
pub(crate) fn analyze_http2_http3_checker(
    observation: &TlsObservation,
    evidence: usize,
) -> Result<Vec<Finding>, TlsSemanticError> {
    validate_semantic_fingerprints(observation)?;
    Ok(match negotiated_application_protocol(observation) {
        ApplicationProtocolSummary::Http2 => Vec::new(),
        ApplicationProtocolSummary::Http3 => vec![finding(
            "http3-transport-unverified",
            "HTTP/3 ALPN metadata was observed without a QUIC transport verification",
            Severity::Info,
            Confidence::Unknown,
            evidence,
        )],
        ApplicationProtocolSummary::Other => vec![finding(
            "http2-http3-not-negotiated",
            "Neither HTTP/2 nor HTTP/3 was negotiated in this observation",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )],
        ApplicationProtocolSummary::Unknown => vec![finding(
            "http-alpn-metadata-unavailable",
            "Application protocol negotiation metadata is unavailable",
            Severity::Info,
            Confidence::Unknown,
            evidence,
        )],
    })
}

/// Summarizes a bounded set of full/resumed handshakes with aligned evidence.
pub(crate) fn analyze_tls_session_resumption_map(
    observations: &[TlsObservation],
    evidence: &[usize],
) -> Result<Vec<Finding>, TlsSemanticError> {
    if observations.len() != evidence.len() {
        return Err(TlsSemanticError::InvalidEvidenceMapping);
    }
    observations
        .iter()
        .try_for_each(validate_semantic_fingerprints)?;
    Ok(match summarize_resumption(observations) {
        ResumptionSummary::ResumedObserved => Vec::new(),
        ResumptionSummary::FullOnlyObserved => vec![finding_with_evidence(
            "tls-resumption-not-observed",
            "Only full TLS handshakes were observed in the bounded sample",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )],
        ResumptionSummary::Inconclusive => vec![finding_with_evidence(
            "tls-resumption-inconclusive",
            "TLS session resumption could not be determined from the bounded sample",
            Severity::Info,
            Confidence::Unknown,
            evidence,
        )],
    })
}

/// Inventories validated leaf fingerprints as aggregate counts only.
pub(crate) fn analyze_network_certificate_inventory(
    observations: &[TlsObservation],
    evidence: &[usize],
) -> Result<CertificateInventoryAnalysis, TlsSemanticError> {
    if observations.len() != evidence.len() {
        return Err(TlsSemanticError::InvalidEvidenceMapping);
    }
    observations
        .iter()
        .try_for_each(validate_semantic_fingerprints)?;

    let mut unique_leafs = HashSet::new();
    let mut findings = Vec::new();
    let mut endpoints_with_leaf = 0;
    for (observation, evidence) in observations.iter().zip(evidence) {
        match observation
            .certificate_sha256
            .first()
            .and_then(|value| parse_sha256(value))
        {
            Some(leaf) => {
                unique_leafs.insert(leaf);
                endpoints_with_leaf += 1;
            }
            None => findings.push(finding(
                "tls-inventory-leaf-unavailable",
                "No validated leaf certificate fingerprint is available for this observation",
                Severity::Medium,
                Confidence::Unknown,
                *evidence,
            )),
        }
    }
    if observations.is_empty() {
        findings.push(finding_with_evidence(
            "tls-inventory-empty",
            "No bounded TLS endpoint observations were available for inventory",
            Severity::Info,
            Confidence::Unknown,
            evidence,
        ));
    }

    Ok(CertificateInventoryAnalysis {
        summary: CertificateInventorySummary {
            endpoints_observed: observations.len(),
            endpoints_with_leaf,
            unique_leaf_certificates: unique_leafs.len(),
        },
        findings,
    })
}

/// Produces a serialization-safe view of one TLS observation.
pub(crate) fn summarize_tls_evidence(
    observation: &TlsObservation,
) -> Result<TlsEvidenceSummary, TlsSemanticError> {
    validate_semantic_fingerprints(observation)?;
    Ok(TlsEvidenceSummary {
        handshake_kind: observation.handshake_kind,
        protocol: negotiated_protocol(observation),
        cipher: negotiated_cipher(observation),
        application_protocol: negotiated_application_protocol(observation),
        certificate_count: observation.certificate_sha256.len(),
        parsed_certificate_count: observation.certificates.len(),
        duration_ms: observation.duration_ms,
    })
}

fn validate_semantic_fingerprints(observation: &TlsObservation) -> Result<(), TlsSemanticError> {
    let observed = validate_observed_sha256(&observation.certificate_sha256)
        .map_err(|_| TlsSemanticError::InvalidCertificateSha256)?;
    let metadata = observation
        .certificates
        .iter()
        .map(|certificate| {
            parse_sha256(&certificate.sha256).ok_or(TlsSemanticError::InvalidCertificateSha256)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !metadata.is_empty() && metadata != observed {
        return Err(TlsSemanticError::InconsistentCertificateMetadata);
    }
    Ok(())
}

fn is_unknown_text(value: &str) -> bool {
    value.trim().is_empty() || value.eq_ignore_ascii_case("unknown")
}

fn finding(
    key: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    evidence: usize,
) -> Finding {
    Finding {
        key: key.into(),
        title: title.into(),
        severity,
        confidence,
        evidence: vec![evidence],
    }
}

fn finding_with_evidence(
    key: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    evidence: &[usize],
) -> Finding {
    Finding {
        key: key.into(),
        title: title.into(),
        severity,
        confidence,
        evidence: evidence.to_vec(),
    }
}

fn parse_sha256(value: &str) -> Option<Sha256Fingerprint> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(Sha256Fingerprint(bytes))
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use sugra_core::{TlsCertificate, TlsHandshakeKind, TlsObservation};

    use super::*;

    fn observation(leaf_sha256: &str) -> TlsObservation {
        TlsObservation {
            handshake_kind: TlsHandshakeKind::Full,
            protocol: "TLSv1_3".into(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
            alpn: Some("h2".into()),
            certificate_sha256: vec![leaf_sha256.into()],
            certificates: Vec::new(),
            duration_ms: 12,
        }
    }

    fn certificate(
        sha256: &str,
        subject: &str,
        issuer: &str,
        not_before: i64,
        not_after: i64,
        is_ca: Option<bool>,
    ) -> TlsCertificate {
        TlsCertificate {
            sha256: sha256.into(),
            subject: subject.into(),
            issuer: issuer.into(),
            serial: "01".into(),
            not_before,
            not_after,
            dns_names: vec!["example.test".into()],
            signature_algorithm: "1.2.840.113549.1.1.11".into(),
            public_key_algorithm: "1.2.840.113549.1.1.1".into(),
            is_ca,
        }
    }

    #[test]
    fn ssl_chain_accepts_a_linked_leaf_and_intermediate() -> Result<(), Box<dyn Error>> {
        let leaf_sha = "ab".repeat(32);
        let issuer_sha = "cd".repeat(32);
        let mut observed = observation(&leaf_sha);
        observed.certificate_sha256.push(issuer_sha.clone());
        observed.certificates = vec![
            certificate(&leaf_sha, "CN=leaf", "CN=issuer", 10, 20, Some(false)),
            certificate(&issuer_sha, "CN=issuer", "CN=root", 5, 25, Some(true)),
        ];

        assert!(analyze_ssl_chain(&observed, 7)?.is_empty());
        Ok(())
    }

    #[test]
    fn ssl_chain_reports_missing_metadata_as_unknown() -> Result<(), Box<dyn Error>> {
        let mut observed = observation(&"ab".repeat(32));
        observed.certificates.clear();

        let findings = analyze_ssl_chain(&observed, 3)?;

        assert_eq!(findings[0].key, "tls-chain-metadata-unavailable");
        assert_eq!(findings[0].confidence, Confidence::Unknown);
        assert_eq!(findings[0].evidence, vec![3]);
        Ok(())
    }

    #[test]
    fn ssl_chain_reports_leaf_ca_and_broken_issuer_link() -> Result<(), Box<dyn Error>> {
        let leaf_sha = "ab".repeat(32);
        let issuer_sha = "cd".repeat(32);
        let mut observed = observation(&leaf_sha);
        observed.certificate_sha256.push(issuer_sha.clone());
        observed.certificates = vec![
            certificate(&leaf_sha, "CN=leaf", "CN=expected", 10, 20, Some(true)),
            certificate(&issuer_sha, "CN=other", "CN=root", 5, 25, Some(true)),
        ];

        let findings = analyze_ssl_chain(&observed, 12)?;

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.key.as_str())
                .collect::<Vec<_>>(),
            vec!["tls-leaf-is-ca", "tls-chain-link-mismatch"]
        );
        assert!(findings.iter().all(|finding| finding.evidence == vec![12]));
        Ok(())
    }

    #[test]
    fn ssl_expiry_accepts_a_certificate_with_more_than_ninety_days() -> Result<(), Box<dyn Error>> {
        const NOW: i64 = 1_700_000_000;
        let sha = "ab".repeat(32);
        let mut observed = observation(&sha);
        observed.certificates = vec![certificate(
            &sha,
            "CN=leaf",
            "CN=issuer",
            NOW - 60,
            NOW + 91 * 86_400,
            Some(false),
        )];

        assert!(analyze_ssl_expiry(&observed, NOW, 1)?.is_empty());
        Ok(())
    }

    #[test]
    fn tls_handshake_accepts_complete_negotiation_metadata() -> Result<(), Box<dyn Error>> {
        let observed = observation(&"ab".repeat(32));

        assert!(analyze_tls_handshake(&observed, 8)?.is_empty());
        Ok(())
    }

    #[test]
    fn tls_cipher_suites_accepts_a_named_modern_negotiated_suite() -> Result<(), Box<dyn Error>> {
        let observed = observation(&"ab".repeat(32));

        assert!(analyze_tls_cipher_suites(&observed, 9)?.is_empty());
        Ok(())
    }

    #[test]
    fn tls_security_config_accepts_observed_tls13_with_a_named_cipher() -> Result<(), Box<dyn Error>>
    {
        let observed = observation(&"ab".repeat(32));

        assert!(analyze_tls_security_config(&observed, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn http2_http3_checker_accepts_an_observed_h2_negotiation() -> Result<(), Box<dyn Error>> {
        let observed = observation(&"ab".repeat(32));

        assert!(analyze_http2_http3_checker(&observed, 11)?.is_empty());
        Ok(())
    }

    #[test]
    fn session_resumption_map_accepts_a_sample_with_observed_resumption()
    -> Result<(), Box<dyn Error>> {
        let full = observation(&"ab".repeat(32));
        let mut resumed = full.clone();
        resumed.handshake_kind = TlsHandshakeKind::Resumed;

        assert!(analyze_tls_session_resumption_map(&[full, resumed], &[4, 5])?.is_empty());
        Ok(())
    }

    #[test]
    fn certificate_inventory_counts_unique_leafs_without_exposing_them()
    -> Result<(), Box<dyn Error>> {
        let leaf = "ab".repeat(32);
        let observations = vec![observation(&leaf), observation(&leaf)];

        let analysis = analyze_network_certificate_inventory(&observations, &[6, 7])?;

        assert_eq!(analysis.summary.endpoints_observed, 2);
        assert_eq!(analysis.summary.endpoints_with_leaf, 2);
        assert_eq!(analysis.summary.unique_leaf_certificates, 1);
        assert!(analysis.findings.is_empty());
        assert!(!format!("{analysis:?}").contains(&leaf));
        Ok(())
    }

    #[test]
    fn ssl_expiry_classifies_temporal_edges_without_exposing_certificate_data()
    -> Result<(), Box<dyn Error>> {
        const NOW: i64 = 1_700_000_000;
        let sha = "ab".repeat(32);
        let cases = [
            (
                NOW + 1,
                NOW + 100,
                "tls-certificate-not-yet-valid",
                Severity::High,
            ),
            (
                NOW - 100,
                NOW,
                "tls-certificate-expired",
                Severity::Critical,
            ),
            (
                NOW - 100,
                NOW + 7 * 86_400,
                "tls-certificate-expiring",
                Severity::High,
            ),
            (
                NOW - 100,
                NOW + 30 * 86_400,
                "tls-certificate-expiring",
                Severity::Medium,
            ),
            (
                NOW - 100,
                NOW + 90 * 86_400,
                "tls-certificate-expiring",
                Severity::Low,
            ),
        ];

        for (not_before, not_after, key, severity) in cases {
            let mut observed = observation(&sha);
            observed.certificates = vec![certificate(
                &sha,
                "CN=private-name",
                "CN=issuer",
                not_before,
                not_after,
                Some(false),
            )];
            let findings = analyze_ssl_expiry(&observed, NOW, 13)?;
            assert_eq!(findings[0].key, key);
            assert_eq!(findings[0].severity, severity);
            assert!(!findings[0].title.contains("private-name"));
        }
        Ok(())
    }

    #[test]
    fn ssl_expiry_rejects_an_inverted_validity_window_with_a_typed_safe_error()
    -> Result<(), Box<dyn Error>> {
        let sha = "ab".repeat(32);
        let mut observed = observation(&sha);
        observed.certificates = vec![certificate(
            &sha,
            "CN=sensitive",
            "CN=issuer",
            20,
            10,
            Some(false),
        )];

        let Err(error) = analyze_ssl_expiry(&observed, 15, 0) else {
            return Err("an inverted validity window must fail".into());
        };

        assert_eq!(error, TlsSemanticError::InvalidValidityWindow);
        assert!(!error.to_string().contains("sensitive"));
        Ok(())
    }

    #[test]
    fn tls_handshake_marks_unknown_fields_as_inconclusive() -> Result<(), Box<dyn Error>> {
        let mut observed = observation(&"ab".repeat(32));
        observed.handshake_kind = TlsHandshakeKind::Unknown;
        observed.protocol = " ".into();

        let findings = analyze_tls_handshake(&observed, 14)?;

        assert_eq!(findings[0].key, "tls-negotiation-incomplete");
        assert_eq!(findings[0].confidence, Confidence::Unknown);
        Ok(())
    }

    #[test]
    fn tls_cipher_suites_distinguishes_weak_and_missing_negotiated_values()
    -> Result<(), Box<dyn Error>> {
        let mut observed = observation(&"ab".repeat(32));
        observed.cipher_suite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into();
        let weak = analyze_tls_cipher_suites(&observed, 15)?;
        assert_eq!(weak[0].key, "tls-weak-cipher");
        assert_eq!(weak[0].confidence, Confidence::Confirmed);

        observed.cipher_suite = "   ".into();
        let missing = analyze_tls_cipher_suites(&observed, 15)?;
        assert_eq!(missing[0].key, "tls-cipher-metadata-unavailable");
        assert_eq!(missing[0].confidence, Confidence::Unknown);
        Ok(())
    }

    #[test]
    fn tls_security_config_reports_only_observed_legacy_configuration() -> Result<(), Box<dyn Error>>
    {
        let mut observed = observation(&"ab".repeat(32));
        observed.protocol = "TLSv1_0".into();
        observed.cipher_suite = "TLS_RSA_WITH_RC4_128_SHA".into();

        let findings = analyze_tls_security_config(&observed, 16)?;

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.key.as_str())
                .collect::<Vec<_>>(),
            vec!["tls-weak-cipher", "tls-obsolete-protocol"]
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.confidence == Confidence::Confirmed)
        );
        Ok(())
    }

    #[test]
    fn http2_http3_checker_distinguishes_h3_other_and_missing_alpn() -> Result<(), Box<dyn Error>> {
        let mut observed = observation(&"ab".repeat(32));
        observed.alpn = Some("h3-29".into());
        let http3 = analyze_http2_http3_checker(&observed, 17)?;
        assert_eq!(http3[0].key, "http3-transport-unverified");
        assert_eq!(http3[0].confidence, Confidence::Unknown);
        assert_eq!(
            negotiated_application_protocol(&observed),
            ApplicationProtocolSummary::Http3
        );

        observed.alpn = Some("http/1.1".into());
        let other = analyze_http2_http3_checker(&observed, 17)?;
        assert_eq!(other[0].key, "http2-http3-not-negotiated");
        assert_eq!(other[0].confidence, Confidence::Confirmed);

        observed.alpn = None;
        let missing = analyze_http2_http3_checker(&observed, 17)?;
        assert_eq!(missing[0].key, "http-alpn-metadata-unavailable");
        assert_eq!(missing[0].confidence, Confidence::Unknown);
        Ok(())
    }

    #[test]
    fn session_resumption_map_distinguishes_full_empty_and_invalid_mappings()
    -> Result<(), Box<dyn Error>> {
        let full = observation(&"ab".repeat(32));
        let full_only = analyze_tls_session_resumption_map(std::slice::from_ref(&full), &[18])?;
        assert_eq!(full_only[0].key, "tls-resumption-not-observed");
        assert_eq!(full_only[0].confidence, Confidence::Confirmed);

        let empty = analyze_tls_session_resumption_map(&[], &[])?;
        assert_eq!(empty[0].key, "tls-resumption-inconclusive");
        assert_eq!(empty[0].confidence, Confidence::Unknown);

        assert_eq!(
            analyze_tls_session_resumption_map(&[full], &[]),
            Err(TlsSemanticError::InvalidEvidenceMapping)
        );
        Ok(())
    }

    #[test]
    fn certificate_inventory_handles_empty_missing_and_invalid_mappings()
    -> Result<(), Box<dyn Error>> {
        let empty = analyze_network_certificate_inventory(&[], &[])?;
        assert_eq!(empty.summary.endpoints_observed, 0);
        assert_eq!(empty.findings[0].key, "tls-inventory-empty");

        let mut missing = observation(&"ab".repeat(32));
        missing.certificate_sha256.clear();
        let missing = analyze_network_certificate_inventory(&[missing], &[19])?;
        assert_eq!(missing.summary.endpoints_with_leaf, 0);
        assert_eq!(missing.findings[0].key, "tls-inventory-leaf-unavailable");

        assert_eq!(
            analyze_network_certificate_inventory(&[observation(&"ab".repeat(32))], &[]),
            Err(TlsSemanticError::InvalidEvidenceMapping)
        );
        Ok(())
    }

    #[test]
    fn semantic_analyzers_reject_malformed_certificate_values_without_echoing_them()
    -> Result<(), Box<dyn Error>> {
        let marker = "malformed-certificate-value";
        let observed = observation(marker);

        let Err(error) = analyze_tls_handshake(&observed, 0) else {
            return Err("malformed certificate metadata must fail".into());
        };

        assert_eq!(error, TlsSemanticError::InvalidCertificateSha256);
        assert!(!error.to_string().contains(marker));
        Ok(())
    }

    #[test]
    fn semantic_analyzers_reject_mismatched_chain_metadata_without_echoing_it()
    -> Result<(), Box<dyn Error>> {
        let observed_sha = "ab".repeat(32);
        let metadata_sha = "cd".repeat(32);
        let mut observed = observation(&observed_sha);
        observed.certificates = vec![certificate(
            &metadata_sha,
            "CN=sensitive",
            "CN=issuer",
            10,
            20,
            Some(false),
        )];

        let Err(error) = analyze_ssl_chain(&observed, 0) else {
            return Err("mismatched certificate metadata must fail".into());
        };

        assert_eq!(error, TlsSemanticError::InconsistentCertificateMetadata);
        assert!(!error.to_string().contains(&observed_sha));
        assert!(!error.to_string().contains(&metadata_sha));
        Ok(())
    }

    #[test]
    fn safe_tls_evidence_serialization_omits_raw_certificate_and_negotiation_values()
    -> Result<(), Box<dyn Error>> {
        let sha = "ab".repeat(32);
        let mut observed = observation(&sha);
        observed.certificates = vec![certificate(
            &sha,
            "CN=sensitive-subject",
            "CN=sensitive-issuer",
            10,
            20,
            Some(false),
        )];

        let serialized = serde_json::to_string(&summarize_tls_evidence(&observed)?)?;

        for sensitive in [
            sha.as_str(),
            "sensitive-subject",
            "sensitive-issuer",
            "TLS_AES_256_GCM_SHA384",
        ] {
            assert!(!serialized.contains(sensitive));
        }
        assert!(serialized.contains("tls13"));
        assert!(serialized.contains("named"));
        Ok(())
    }

    #[test]
    fn explicit_matching_leaf_baseline_produces_no_finding()
    -> Result<(), Box<dyn std::error::Error>> {
        let fingerprint = "ab".repeat(32);

        let findings = analyze_pinning(&observation(&fingerprint), Some(&fingerprint), 0)?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn leaf_mismatch_produces_a_safe_confirmed_finding() -> Result<(), Box<dyn std::error::Error>> {
        let observed = "ab".repeat(32);
        let baseline = "cd".repeat(32);

        let findings = analyze_pinning(&observation(&observed), Some(&baseline), 4)?;

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.key, "tls-pinning-baseline-mismatch");
        assert_eq!(finding.severity, sugra_domain::Severity::High);
        assert_eq!(finding.confidence, sugra_domain::Confidence::Confirmed);
        assert_eq!(finding.evidence, vec![4]);
        assert!(!finding.title.contains(&observed));
        assert!(!finding.title.contains(&baseline));
        Ok(())
    }

    #[test]
    fn malformed_or_noncanonical_baselines_are_rejected_without_echoing_input()
    -> Result<(), Box<dyn std::error::Error>> {
        for baseline in [
            "short".to_owned(),
            "AB".repeat(32),
            format!("{}g", "ab".repeat(31)),
        ] {
            let Err(error) = analyze_pinning(&observation(&"ab".repeat(32)), Some(&baseline), 0)
            else {
                return Err("invalid baseline must fail".into());
            };

            assert_eq!(error, TlsAnalysisError::InvalidBaselineSha256);
            assert!(!error.to_string().contains(&baseline));
        }
        Ok(())
    }

    #[test]
    fn missing_leaf_material_is_unknown_instead_of_a_false_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut missing = observation(&"ab".repeat(32));
        missing.certificate_sha256.clear();

        let findings = analyze_pinning(&missing, Some(&"cd".repeat(32)), 2)?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].key, "tls-pinning-material-unavailable");
        assert_eq!(findings[0].severity, sugra_domain::Severity::Medium);
        assert_eq!(findings[0].confidence, sugra_domain::Confidence::Unknown);
        assert_eq!(findings[0].evidence, vec![2]);
        Ok(())
    }

    #[test]
    fn malformed_adapter_fingerprint_is_a_typed_failure_without_value_leakage()
    -> Result<(), Box<dyn std::error::Error>> {
        let observed = "malformed-adapter-value";

        let Err(error) = analyze_pinning(&observation(observed), Some(&"cd".repeat(32)), 0) else {
            return Err("malformed observed fingerprint must fail".into());
        };

        assert_eq!(error, TlsAnalysisError::InvalidObservedSha256);
        assert!(!error.to_string().contains(observed));
        Ok(())
    }

    #[test]
    fn protocol_summary_classifies_only_the_negotiated_value() {
        let mut observed = observation(&"ab".repeat(32));
        assert_eq!(negotiated_protocol(&observed), NegotiatedProtocol::Tls13);

        observed.protocol = "TLSv1_2".into();
        assert_eq!(negotiated_protocol(&observed), NegotiatedProtocol::Tls12);

        observed.protocol = "TLSv1_0".into();
        assert_eq!(negotiated_protocol(&observed), NegotiatedProtocol::Legacy);

        observed.protocol = "vendor-specific".into();
        assert_eq!(negotiated_protocol(&observed), NegotiatedProtocol::Unknown);
    }

    #[test]
    fn resumption_summary_distinguishes_observed_full_and_inconclusive_samples() {
        let full = observation(&"ab".repeat(32));
        let mut resumed = full.clone();
        resumed.handshake_kind = TlsHandshakeKind::Resumed;
        let mut unknown = full.clone();
        unknown.handshake_kind = TlsHandshakeKind::Unknown;

        assert_eq!(summarize_resumption(&[]), ResumptionSummary::Inconclusive);
        assert_eq!(
            summarize_resumption(std::slice::from_ref(&full)),
            ResumptionSummary::FullOnlyObserved
        );
        assert_eq!(
            summarize_resumption(&[full.clone(), unknown]),
            ResumptionSummary::Inconclusive
        );
        assert_eq!(
            summarize_resumption(&[full, resumed]),
            ResumptionSummary::ResumedObserved
        );
    }

    #[test]
    fn cipher_summary_flags_known_legacy_markers_without_certifying_other_names() {
        let mut observed = observation(&"ab".repeat(32));
        assert_eq!(negotiated_cipher(&observed), CipherSummary::Named);

        observed.cipher_suite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into();
        assert_eq!(negotiated_cipher(&observed), CipherSummary::KnownWeak);

        observed.cipher_suite = "unknown".into();
        assert_eq!(negotiated_cipher(&observed), CipherSummary::Unknown);
    }

    #[test]
    fn malformed_intermediate_fingerprint_is_also_an_adapter_failure() {
        let baseline = "ab".repeat(32);
        let mut observed = observation(&baseline);
        observed
            .certificate_sha256
            .push("malformed-intermediate".into());

        assert_eq!(
            analyze_pinning(&observed, Some(&baseline), 0),
            Err(TlsAnalysisError::InvalidObservedSha256)
        );
    }

    #[test]
    fn omitted_baseline_is_a_typed_failure() {
        assert_eq!(
            analyze_pinning(&observation(&"ab".repeat(32)), None, 0),
            Err(TlsAnalysisError::MissingBaseline)
        );
    }

    #[test]
    fn matching_intermediate_does_not_hide_a_leaf_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let baseline = "ab".repeat(32);
        let mut observed = observation(&"cd".repeat(32));
        observed.certificate_sha256.push(baseline.clone());

        let findings = analyze_pinning(&observed, Some(&baseline), 0)?;

        assert_eq!(findings[0].key, "tls-pinning-baseline-mismatch");
        Ok(())
    }
}
