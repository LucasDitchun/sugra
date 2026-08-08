//! Pure analysis for bounded, certificate-validating TLS observations.

use std::error::Error;
use std::fmt::{Display, Formatter};

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

/// A validated SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sha256Fingerprint([u8; 32]);

/// Classification of the single protocol negotiated by one handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumptionSummary {
    /// At least one handshake was explicitly reported as resumed.
    ResumedObserved,
    /// Every sampled handshake was explicitly reported as a full handshake.
    FullOnlyObserved,
    /// The sample was empty or contained an unknown handshake kind.
    Inconclusive,
}

/// Conservative classification of the single negotiated cipher name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherSummary {
    /// The name contains a recognized weak or legacy suite marker.
    KnownWeak,
    /// A non-empty name was observed; no broader security claim is made.
    Named,
    /// The adapter did not expose a cipher name.
    Unknown,
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
    let cipher = observation.cipher_suite.to_ascii_lowercase();
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
    use sugra_core::{TlsHandshakeKind, TlsObservation};

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
