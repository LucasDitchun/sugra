//! Pure, scanner-specific analysis for bounded DNS observations.

use sugra_core::{DnsRecord, DnsRecordType};
use sugra_domain::{Confidence, Finding, Severity};
use thiserror::Error;

/// Maximum number of DKIM selectors accepted by one bounded DNS scan.
pub(crate) const MAX_DKIM_SELECTORS: usize = 16;

/// Typed failures raised while constructing bounded DKIM query owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum DkimSelectorError {
    /// No owner could be constructed because the selector list was empty.
    #[error("the DKIM selector list must contain at least one item")]
    EmptySelectors,
    /// The raw input exceeded the declared query budget.
    #[error("the DKIM selector list exceeds the supported item limit")]
    TooManySelectors,
    /// A selector was not a canonical lowercase DNS label.
    #[error("a DKIM selector is not a canonical single DNS label")]
    InvalidSelector,
}

/// Builds the DNS owners queried for the requested DKIM selectors.
///
/// # Errors
///
/// Returns a typed, value-free error when the selector list is empty or too
/// large, or when any selector is not a canonical lowercase DNS label.
pub(crate) fn dkim_selector_owners(
    domain: &str,
    selectors: &[&str],
) -> Result<Vec<String>, DkimSelectorError> {
    if selectors.is_empty() {
        return Err(DkimSelectorError::EmptySelectors);
    }
    if selectors.len() > MAX_DKIM_SELECTORS {
        return Err(DkimSelectorError::TooManySelectors);
    }
    if selectors.iter().any(|selector| {
        selector.is_empty()
            || selector.len() > 63
            || selector.starts_with('-')
            || selector.ends_with('-')
            || !selector
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err(DkimSelectorError::InvalidSelector);
    }
    let domain = canonical_name(domain);
    let mut unique = Vec::new();
    for selector in selectors {
        if !unique.contains(selector) {
            unique.push(*selector);
        }
    }
    Ok(unique
        .into_iter()
        .map(|selector| format!("{selector}._domainkey.{domain}"))
        .collect())
}

/// Evaluates whether both sides of the DNSSEC delegation chain were observed.
pub(crate) fn dnssec_findings(
    domain: &str,
    records: &[DnsRecord],
    evidence: usize,
) -> Vec<Finding> {
    let has_ds = has_record(domain, records, DnsRecordType::Ds);
    let has_dnskey = has_record(domain, records, DnsRecordType::Dnskey);
    match (has_ds, has_dnskey) {
        (true, true) => Vec::new(),
        (false, false) => vec![finding(
            "dnssec-not-observed",
            "DNSSEC delegation and signing material were not observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        )],
        _ => vec![finding(
            "dnssec-material-incomplete",
            "Only one side of the DNSSEC delegation chain was observed",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        )],
    }
}

/// Evaluates SPF, DKIM, DMARC, and CAA publication for a mail domain.
pub(crate) fn email_config_findings(
    domain: &str,
    records: &[DnsRecord],
    evidence: usize,
) -> Vec<Finding> {
    let domain = canonical_name(domain);
    let dmarc_owner = format!("_dmarc.{domain}");
    let dkim_suffix = format!("._domainkey.{domain}");
    let spf = txt_policy(records, &domain, "v=spf1");
    let dkim = records.iter().find_map(|record| {
        let owner = canonical_name(&record.name);
        (record.record_type == DnsRecordType::Txt
            && owner.len() > dkim_suffix.len()
            && owner.ends_with(&dkim_suffix))
        .then(|| normalized_txt(&record.value))
        .filter(|value| value.starts_with("v=dkim1"))
    });
    let dmarc = txt_policy(records, &dmarc_owner, "v=dmarc1");
    let has_caa = has_record(&domain, records, DnsRecordType::Caa);
    let mut findings = Vec::new();

    if spf.is_none() {
        findings.push(finding(
            "spf-not-observed",
            "No SPF policy was observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if dkim.is_none() {
        findings.push(finding(
            "dkim-not-observed",
            "No DKIM public-key policy was observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if dmarc.is_none() {
        findings.push(finding(
            "dmarc-not-observed",
            "No DMARC policy was observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if !has_caa {
        findings.push(finding(
            "caa-not-observed",
            "No CAA policy was observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        ));
    }

    if spf.as_deref().is_some_and(spf_allows_every_sender) {
        findings.push(finding(
            "spf-permissive-all",
            "The SPF policy explicitly permits every sender",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if let Some(dmarc) = dmarc {
        match policy_tag(&dmarc, "p") {
            Some("none") => findings.push(finding(
                "dmarc-monitoring-only",
                "The DMARC policy does not request enforcement",
                Severity::Medium,
                Confidence::Confirmed,
                evidence,
            )),
            Some("quarantine" | "reject") => {}
            _ => findings.push(finding(
                "dmarc-policy-invalid",
                "The DMARC policy has no supported enforcement value",
                Severity::Medium,
                Confidence::Confirmed,
                evidence,
            )),
        }
    }

    findings
}

/// Reports an address-family publication mismatch when at least one family exists.
pub(crate) fn dual_stack_finding(records: &[DnsRecord], evidence: usize) -> Option<Finding> {
    let has_ipv4 = has_nonempty_type(records, DnsRecordType::A);
    let has_ipv6 = has_nonempty_type(records, DnsRecordType::Aaaa);
    (has_ipv4 != has_ipv6).then(|| {
        finding(
            "address-family-asymmetry",
            "IPv4 and IPv6 publication differs",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )
    })
}

/// Reports the shortest observed TTL when it falls below sixty seconds.
pub(crate) fn ttl_finding(records: &[DnsRecord], evidence: usize) -> Option<Finding> {
    records
        .iter()
        .filter_map(|record| record.ttl)
        .min()
        .filter(|ttl| *ttl < 60)
        .map(|_| {
            finding(
                "short-dns-ttl",
                "A DNS record uses a time-to-live below 60 seconds",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            )
        })
}

/// Reports a generated typo candidate only when that exact candidate resolves.
pub(crate) fn typosquat_resolution_finding(
    original: &str,
    candidate: &str,
    records: &[DnsRecord],
    evidence: usize,
) -> Option<Finding> {
    let original = canonical_name(original);
    let candidate = canonical_name(candidate);
    let resolves = original != candidate
        && !candidate.is_empty()
        && records.iter().any(|record| {
            canonical_name(&record.name) == candidate
                && !record.value.trim().is_empty()
                && matches!(
                    record.record_type,
                    DnsRecordType::A
                        | DnsRecordType::Aaaa
                        | DnsRecordType::Cname
                        | DnsRecordType::Mx
                )
        });
    resolves.then(|| {
        finding(
            "resolving-typo-candidate",
            "A generated typo candidate returned public DNS records",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )
    })
}

fn has_record(domain: &str, records: &[DnsRecord], record_type: DnsRecordType) -> bool {
    let domain = canonical_name(domain);
    records.iter().any(|record| {
        record.record_type == record_type
            && canonical_name(&record.name) == domain
            && !record.value.trim().is_empty()
    })
}

fn has_nonempty_type(records: &[DnsRecord], record_type: DnsRecordType) -> bool {
    records
        .iter()
        .any(|record| record.record_type == record_type && !record.value.trim().is_empty())
}

fn txt_policy(records: &[DnsRecord], owner: &str, version: &str) -> Option<String> {
    records.iter().find_map(|record| {
        (record.record_type == DnsRecordType::Txt && canonical_name(&record.name) == owner)
            .then(|| normalized_txt(&record.value))
            .filter(|value| value.starts_with(version))
    })
}

fn normalized_txt(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character != '"')
        .collect::<String>()
        .trim()
        .to_ascii_lowercase()
}

fn spf_allows_every_sender(value: &str) -> bool {
    value
        .split_ascii_whitespace()
        .any(|mechanism| matches!(mechanism, "all" | "+all"))
}

fn policy_tag<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    value.split(';').find_map(|segment| {
        let (key, value) = segment.trim().split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn canonical_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, record_type: DnsRecordType, value: &str, ttl: Option<u32>) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            record_type,
            value: value.into(),
            ttl,
        }
    }

    fn keys(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.key.as_str())
            .collect()
    }

    #[test]
    fn dkim_selector_owners_build_canonical_dns_names() {
        assert_eq!(
            dkim_selector_owners("EXAMPLE.COM.", &["default"]),
            Ok(vec!["default._domainkey.example.com".into()])
        );
    }

    #[test]
    fn dkim_selector_owners_deduplicate_without_reordering() {
        assert_eq!(
            dkim_selector_owners("example.com", &["google", "default", "google"]),
            Ok(vec![
                "google._domainkey.example.com".into(),
                "default._domainkey.example.com".into(),
            ])
        );
    }

    #[test]
    fn dkim_selector_owners_enforce_the_small_list_boundary() {
        let values = (0..=MAX_DKIM_SELECTORS)
            .map(|index| format!("s{index}"))
            .collect::<Vec<_>>();
        let at_limit = values[..MAX_DKIM_SELECTORS]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            dkim_selector_owners("example.com", &at_limit).map(|owners| owners.len()),
            Ok(MAX_DKIM_SELECTORS)
        );

        let above_limit = values.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            dkim_selector_owners("example.com", &above_limit),
            Err(DkimSelectorError::TooManySelectors)
        );
    }

    #[test]
    fn dkim_selector_owners_require_at_least_one_selector() {
        assert_eq!(
            dkim_selector_owners("example.com", &[]),
            Err(DkimSelectorError::EmptySelectors)
        );
    }

    #[test]
    fn dkim_selector_owners_reject_noncanonical_labels_without_echoing_them() {
        let oversized = "a".repeat(64);
        let invalid = [
            "",
            "Default",
            "two.labels",
            "under_score",
            "-leading",
            "trailing-",
            "não-ascii",
            oversized.as_str(),
            "sensitive-token.example",
        ];

        for selector in invalid {
            let Err(error) = dkim_selector_owners("example.com", &[selector]) else {
                unreachable!("a noncanonical selector must be rejected");
            };
            assert_eq!(error, DkimSelectorError::InvalidSelector);
            assert_eq!(
                error.to_string(),
                "a DKIM selector is not a canonical single DNS label"
            );
        }
    }

    #[test]
    fn dnssec_accepts_a_complete_chain_and_classifies_missing_material() {
        let complete = vec![
            record("example.com.", DnsRecordType::Ds, "12345 13 2 digest", None),
            record(
                "EXAMPLE.COM",
                DnsRecordType::Dnskey,
                "257 3 13 public-key",
                None,
            ),
        ];
        assert!(dnssec_findings("example.com", &complete, 4).is_empty());

        let absent = dnssec_findings("example.com", &[], 4);
        assert_eq!(keys(&absent), vec!["dnssec-not-observed"]);
        assert_eq!(absent[0].severity, Severity::Low);
        assert_eq!(absent[0].evidence, vec![4]);

        let incomplete = dnssec_findings("example.com", &complete[..1], 7);
        assert_eq!(keys(&incomplete), vec!["dnssec-material-incomplete"]);
        assert_eq!(incomplete[0].severity, Severity::Medium);
    }

    #[test]
    fn dnssec_ignores_empty_and_different_owner_records() {
        let records = vec![
            record("other.example", DnsRecordType::Ds, "material", None),
            record("example.com", DnsRecordType::Dnskey, "", None),
        ];
        assert_eq!(
            keys(&dnssec_findings("example.com", &records, 0)),
            vec!["dnssec-not-observed"]
        );
    }

    #[test]
    fn email_config_accepts_enforced_sender_and_issuance_policies() {
        let records = vec![
            record("example.com", DnsRecordType::Txt, "\"v=spf1 -all\"", None),
            record(
                "selector._domainkey.example.com.",
                DnsRecordType::Txt,
                "v=DKIM1; p=public-key",
                None,
            ),
            record(
                "_dmarc.example.com",
                DnsRecordType::Txt,
                "v=DMARC1; p=reject",
                None,
            ),
            record(
                "example.com",
                DnsRecordType::Caa,
                "0 issue \"letsencrypt.org\"",
                None,
            ),
        ];

        assert!(email_config_findings("EXAMPLE.COM.", &records, 2).is_empty());
    }

    #[test]
    fn email_config_reports_each_missing_policy_independently() {
        let findings = email_config_findings("example.com", &[], 3);
        assert_eq!(
            keys(&findings),
            vec![
                "spf-not-observed",
                "dkim-not-observed",
                "dmarc-not-observed",
                "caa-not-observed"
            ]
        );
        assert!(findings.iter().all(|finding| {
            finding.confidence == Confidence::Confirmed && finding.evidence == vec![3]
        }));
    }

    #[test]
    fn email_config_rejects_wrong_owners_versions_and_weak_enforcement() {
        let malformed = vec![
            record("other.example", DnsRecordType::Txt, "v=spf1 -all", None),
            record(
                "_domainkey.example.com",
                DnsRecordType::Txt,
                "v=DKIM2; p=value",
                None,
            ),
            record(
                "_dmarc.example.com",
                DnsRecordType::Txt,
                "v=DMARC2; p=reject",
                None,
            ),
            record("other.example", DnsRecordType::Caa, "0 issue value", None),
        ];
        assert_eq!(
            keys(&email_config_findings("example.com", &malformed, 0)),
            vec![
                "spf-not-observed",
                "dkim-not-observed",
                "dmarc-not-observed",
                "caa-not-observed"
            ]
        );

        let weak = vec![
            record("example.com", DnsRecordType::Txt, "v=spf1 +all", None),
            record(
                "default._domainkey.example.com",
                DnsRecordType::Txt,
                "v=DKIM1; p=value",
                None,
            ),
            record(
                "_dmarc.example.com",
                DnsRecordType::Txt,
                "v=DMARC1; p=none",
                None,
            ),
            record("example.com", DnsRecordType::Caa, "0 issue value", None),
        ];
        assert_eq!(
            keys(&email_config_findings("example.com", &weak, 0)),
            vec!["spf-permissive-all", "dmarc-monitoring-only"]
        );
    }

    #[test]
    fn ttl_analysis_observes_the_exclusive_sixty_second_boundary() {
        let short = [record(
            "example.com",
            DnsRecordType::A,
            "192.0.2.1",
            Some(59),
        )];
        assert_eq!(
            ttl_finding(&short, 5).map(|finding| finding.key),
            Some("short-dns-ttl".into())
        );
        let boundary = [record(
            "example.com",
            DnsRecordType::A,
            "192.0.2.1",
            Some(60),
        )];
        assert!(ttl_finding(&boundary, 5).is_none());
        let unknown = [record("example.com", DnsRecordType::A, "192.0.2.1", None)];
        assert!(ttl_finding(&unknown, 5).is_none());
    }

    #[test]
    fn ttl_analysis_uses_the_shortest_observed_value() {
        let records = [
            record("example.com", DnsRecordType::A, "192.0.2.1", Some(300)),
            record("example.com", DnsRecordType::Aaaa, "2001:db8::1", Some(0)),
        ];
        assert!(ttl_finding(&records, 0).is_some());
    }

    #[test]
    fn dual_stack_analysis_reports_only_one_sided_publication() {
        let ipv4 = record("example.com", DnsRecordType::A, "192.0.2.1", None);
        let ipv6 = record("example.com", DnsRecordType::Aaaa, "2001:db8::1", None);
        assert!(dual_stack_finding(&[ipv4.clone(), ipv6.clone()], 0).is_none());
        assert_eq!(
            dual_stack_finding(&[ipv4], 6).map(|finding| finding.key),
            Some("address-family-asymmetry".into())
        );
        assert_eq!(
            dual_stack_finding(&[ipv6], 6).map(|finding| finding.key),
            Some("address-family-asymmetry".into())
        );
        assert!(dual_stack_finding(&[], 0).is_none());
        assert!(
            dual_stack_finding(&[record("example.com", DnsRecordType::A, "", None)], 0).is_none()
        );
    }

    #[test]
    fn typosquat_analysis_requires_an_exact_resolving_candidate() {
        let records = [record(
            "EXAMPLLE.COM.",
            DnsRecordType::A,
            "192.0.2.20",
            Some(300),
        )];
        let finding = typosquat_resolution_finding("example.com", "examplle.com", &records, 9)
            .unwrap_or_else(|| unreachable!("resolving candidate should produce a finding"));
        assert_eq!(finding.key, "resolving-typo-candidate");
        assert_eq!(finding.evidence, vec![9]);

        assert!(typosquat_resolution_finding("example.com", "example.com", &records, 0).is_none());
        assert!(
            typosquat_resolution_finding("example.com", "other.example", &records, 0).is_none()
        );
        assert!(typosquat_resolution_finding("example.com", "", &records, 0).is_none());
        assert!(typosquat_resolution_finding("example.com", "examplle.com", &[], 0).is_none());
        let txt_only = [record("examplle.com", DnsRecordType::Txt, "metadata", None)];
        assert!(
            typosquat_resolution_finding("example.com", "examplle.com", &txt_only, 0).is_none()
        );
    }
}
