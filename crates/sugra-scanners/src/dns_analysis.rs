//! Pure, scanner-specific analysis for bounded DNS observations.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde_json::{Value, json};
use sugra_core::{DnsRecord, DnsRecordType, DnsRecursionObservation};
use sugra_domain::{Confidence, Finding, Severity};
use thiserror::Error;

/// Maximum number of DKIM selectors accepted by one bounded DNS scan.
pub(crate) const MAX_DKIM_SELECTORS: usize = 16;

/// Builds a bounded, value-free summary suitable for persisted DNS evidence.
///
/// DNS record values may contain verification tokens, mail policy material, or
/// internal names. Only structural counts and TTL bounds cross the evidence
/// boundary; raw owners and values remain local to analysis.
pub(crate) fn summarize_dns_evidence(
    query_name: &str,
    requested_types: &[DnsRecordType],
    records: &[DnsRecord],
) -> Value {
    let owner = canonical_name(query_name);
    let mut requested = requested_types
        .iter()
        .map(|record_type| record_type.as_str())
        .collect::<Vec<_>>();
    requested.sort_unstable();
    requested.dedup();

    let mut type_counts = BTreeMap::<&'static str, usize>::new();
    let mut matching_owner_records = 0usize;
    let mut usable_records = 0usize;
    let mut minimum_ttl = None::<u32>;
    let mut maximum_ttl = None::<u32>;
    for record in records {
        *type_counts.entry(record.record_type.as_str()).or_default() += 1;
        if canonical_name(&record.name) == owner {
            matching_owner_records += 1;
            if !record.value.trim().is_empty() {
                usable_records += 1;
            }
        }
        if let Some(ttl) = record.ttl {
            minimum_ttl = Some(minimum_ttl.map_or(ttl, |current| current.min(ttl)));
            maximum_ttl = Some(maximum_ttl.map_or(ttl, |current| current.max(ttl)));
        }
    }

    json!({
        "requested_types": requested,
        "response_record_count": records.len(),
        "matching_owner_record_count": matching_owner_records,
        "usable_record_count": usable_records,
        "record_type_counts": type_counts,
        "minimum_ttl": minimum_ttl,
        "maximum_ttl": maximum_ttl,
    })
}

/// Reports recursion exposure only when a complete response both echoes RD
/// and advertises RA with a successful or negative recursive resolution.
#[must_use]
pub(crate) fn dns_recursion_findings(
    observation: &DnsRecursionObservation,
    evidence: usize,
) -> Vec<Finding> {
    let recursive_response = observation.recursion_desired.is_set()
        && observation.recursion_available.is_set()
        && !observation.authoritative.is_set()
        && !observation.truncated.is_set()
        && matches!(observation.response_code, 0 | 3);
    if recursive_response {
        vec![finding(
            "dns-recursion-exposed",
            "The selected DNS server completed a recursive query",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        )]
    } else {
        Vec::new()
    }
}

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

/// Summarizes whether every planned DNS SLA sample produced a response.
///
/// Individual sample latency remains in bounded evidence observations. The
/// finding references every successful sample without claiming a latency
/// threshold that the public scanner contract does not define.
pub(crate) fn dns_sla_availability_finding(
    successful_samples: usize,
    attempted_samples: usize,
) -> Finding {
    let complete = successful_samples == attempted_samples;
    let (key, title, severity) = if complete {
        (
            "dns-sla-availability-observed",
            "Every bounded DNS SLA sample returned a response",
            Severity::Info,
        )
    } else {
        (
            "dns-sla-availability-degraded",
            "At least one bounded DNS SLA sample did not return a response",
            Severity::Medium,
        )
    };
    Finding {
        key: key.into(),
        title: title.into(),
        severity,
        confidence: Confidence::Confirmed,
        evidence: (0..successful_samples).collect(),
    }
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

/// Derives scanner-specific findings from one bounded DNS answer set.
pub(crate) fn scanner_findings(
    scanner_id: &str,
    query_name: &str,
    records: &[DnsRecord],
    evidence: usize,
) -> Vec<Finding> {
    let usable = |record: &&DnsRecord| {
        canonical_name(&record.name) == canonical_name(query_name)
            && !record.value.trim().is_empty()
    };
    let records_for_owner = records.iter().filter(usable).collect::<Vec<_>>();
    match scanner_id {
        "cdn-detection" => cdn_dns_findings(&records_for_owner, evidence),
        "dns-caa-checker" => type_presence_findings(
            &records_for_owner,
            DnsRecordType::Caa,
            "caa-policy-observed",
            "A public CAA policy was observed",
            "caa-not-observed",
            "No CAA policy was observed",
            Severity::Low,
            evidence,
        ),
        "dns-records" => any_presence_findings(
            &records_for_owner,
            "dns-records-observed",
            "Public DNS records were observed",
            "dns-records-not-observed",
            "No public DNS records were observed",
            evidence,
        ),
        "domain-info" => domain_info_findings(&records_for_owner, evidence),
        "geo-dns-footprint" => geo_dns_findings(&records_for_owner, evidence),
        "reverse-dns-scan" => type_presence_findings(
            &records_for_owner,
            DnsRecordType::Ptr,
            "ptr-observed",
            "A reverse DNS record was observed",
            "ptr-not-observed",
            "No reverse DNS record was observed",
            Severity::Info,
            evidence,
        ),
        "rogue-subdomain-resolver" if query_name.starts_with("_sugra-scope-probe.") => {
            let resolves = records_for_owner
                .iter()
                .any(|record| is_usable_resolution_answer(record));
            resolves
                .then(|| {
                    finding(
                        "unexpected-probe-answer",
                        "A deterministic nonexistent-label probe returned DNS data",
                        Severity::Low,
                        Confidence::Inferred,
                        evidence,
                    )
                })
                .into_iter()
                .collect()
        }
        "decoy-dns-beacon" if query_name.starts_with("_sugra-decoy-beacon.") => {
            let resolves = records_for_owner
                .iter()
                .any(|record| is_usable_resolution_answer(record));
            resolves
                .then(|| {
                    finding(
                        "decoy-probe-answer-observed",
                        "A deterministic decoy-label probe returned DNS resolution data",
                        Severity::Low,
                        Confidence::Inferred,
                        evidence,
                    )
                })
                .into_iter()
                .collect()
        }
        "spf-network-extractor" => spf_network_findings(&records_for_owner, evidence),
        "txt-records" => type_presence_findings(
            &records_for_owner,
            DnsRecordType::Txt,
            "txt-records-observed",
            "Public TXT records were observed",
            "txt-records-not-observed",
            "No public TXT records were observed",
            Severity::Info,
            evidence,
        ),
        "subdomain-takeover" => takeover_findings(&records_for_owner, evidence),
        _ => Vec::new(),
    }
}

fn cdn_dns_findings(records: &[&DnsRecord], evidence: usize) -> Vec<Finding> {
    const CDN_SUFFIXES: &[&str] = &[
        "akamai.net",
        "akamaiedge.net",
        "cloudflare.net",
        "cloudfront.net",
        "edgesuite.net",
        "fastly.net",
        "fastlylb.net",
        "azureedge.net",
        "azurefd.net",
    ];
    let observed = records.iter().any(|record| {
        matches!(record.record_type, DnsRecordType::Cname | DnsRecordType::Ns) && {
            let value = canonical_name(&record.value);
            CDN_SUFFIXES
                .iter()
                .any(|suffix| value == *suffix || value.ends_with(&format!(".{suffix}")))
        }
    });
    observed
        .then(|| {
            finding(
                "cdn-dns-signal-observed",
                "A public DNS alias indicates a known delivery network",
                Severity::Info,
                Confidence::Inferred,
                evidence,
            )
        })
        .into_iter()
        .collect()
}

fn any_presence_findings(
    records: &[&DnsRecord],
    observed_key: &str,
    observed_title: &str,
    missing_key: &str,
    missing_title: &str,
    evidence: usize,
) -> Vec<Finding> {
    let (key, title) = if records.is_empty() {
        (missing_key, missing_title)
    } else {
        (observed_key, observed_title)
    };
    vec![finding(
        key,
        title,
        Severity::Info,
        Confidence::Confirmed,
        evidence,
    )]
}

#[allow(clippy::too_many_arguments)]
fn type_presence_findings(
    records: &[&DnsRecord],
    record_type: DnsRecordType,
    observed_key: &str,
    observed_title: &str,
    missing_key: &str,
    missing_title: &str,
    missing_severity: Severity,
    evidence: usize,
) -> Vec<Finding> {
    let observed = records
        .iter()
        .any(|record| record.record_type == record_type);
    let (key, title, severity) = if observed {
        (observed_key, observed_title, Severity::Info)
    } else {
        (missing_key, missing_title, missing_severity)
    };
    vec![finding(
        key,
        title,
        severity,
        Confidence::Confirmed,
        evidence,
    )]
}

fn domain_info_findings(records: &[&DnsRecord], evidence: usize) -> Vec<Finding> {
    let has_address = records.iter().any(|record| {
        matches!(
            record.record_type,
            DnsRecordType::A | DnsRecordType::Aaaa | DnsRecordType::Cname
        )
    });
    let has_authority = records
        .iter()
        .any(|record| matches!(record.record_type, DnsRecordType::Ns | DnsRecordType::Soa));
    let mut findings = Vec::new();
    if has_address {
        findings.push(finding(
            "domain-address-observed",
            "A public address or canonical-name record was observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ));
    } else {
        findings.push(finding(
            "domain-address-not-observed",
            "No public address or canonical-name record was observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if has_authority {
        findings.push(finding(
            "domain-authority-observed",
            "Public authoritative DNS metadata was observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ));
    } else {
        findings.push(finding(
            "domain-authority-not-observed",
            "No authoritative DNS metadata was observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ));
    }
    findings
}

fn geo_dns_findings(records: &[&DnsRecord], evidence: usize) -> Vec<Finding> {
    let observed = records.iter().any(|record| is_usable_geo_endpoint(record));
    let (key, title) = if observed {
        (
            "geo-dns-footprint-observed",
            "DNS endpoints suitable for downstream geographic enrichment were observed",
        )
    } else {
        (
            "geo-dns-footprint-not-observed",
            "No DNS endpoint suitable for downstream geographic enrichment was observed",
        )
    };
    vec![finding(
        key,
        title,
        Severity::Info,
        Confidence::Confirmed,
        evidence,
    )]
}

fn spf_network_findings(records: &[&DnsRecord], evidence: usize) -> Vec<Finding> {
    let policies = records
        .iter()
        .filter(|record| record.record_type == DnsRecordType::Txt)
        .map(|record| normalized_txt(&record.value))
        .filter(|value| value.split_ascii_whitespace().next() == Some("v=spf1"))
        .collect::<Vec<_>>();
    if policies.is_empty() {
        return vec![finding(
            "spf-not-observed",
            "No SPF policy was observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        )];
    }
    let exposes_network_source = policies.iter().any(|policy| {
        policy.split_ascii_whitespace().any(|mechanism| {
            let mechanism = mechanism.trim_start_matches(['+', '-', '~', '?']);
            mechanism == "a"
                || mechanism.starts_with("a:")
                || mechanism == "mx"
                || mechanism.starts_with("mx:")
                || mechanism.starts_with("ip4:")
                || mechanism.starts_with("ip6:")
                || mechanism.starts_with("include:")
                || mechanism.starts_with("redirect=")
        })
    });
    if exposes_network_source {
        vec![finding(
            "spf-network-sources-observed",
            "The SPF policy exposes network sources for extraction",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )]
    } else {
        vec![finding(
            "spf-network-sources-not-observed",
            "The SPF policy exposes no network source for extraction",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )]
    }
}

fn is_usable_resolution_answer(record: &DnsRecord) -> bool {
    let value = record.value.trim().trim_end_matches('.');
    match record.record_type {
        DnsRecordType::A => value.parse::<Ipv4Addr>().is_ok(),
        DnsRecordType::Aaaa => value.parse::<Ipv6Addr>().is_ok(),
        DnsRecordType::Cname => is_valid_dns_name(value),
        _ => false,
    }
}

fn is_usable_geo_endpoint(record: &DnsRecord) -> bool {
    let value = record.value.trim().trim_end_matches('.');
    match record.record_type {
        DnsRecordType::A => value.parse::<Ipv4Addr>().is_ok(),
        DnsRecordType::Aaaa => value.parse::<Ipv6Addr>().is_ok(),
        DnsRecordType::Ns => is_valid_dns_name(value),
        _ => false,
    }
}

fn is_valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        })
}

fn takeover_findings(records: &[&DnsRecord], evidence: usize) -> Vec<Finding> {
    let external_alias = records.iter().any(|record| {
        record.record_type == DnsRecordType::Cname
            && [
                "github.io",
                "herokuapp.com",
                "azurewebsites.net",
                "cloudfront.net",
                "s3.amazonaws.com",
            ]
            .iter()
            .any(|suffix| {
                let alias = canonical_name(&record.value);
                alias == *suffix || alias.ends_with(&format!(".{suffix}"))
            })
    });
    external_alias
        .then(|| {
            finding(
                "external-service-alias",
                "A DNS alias points to an external service and requires ownership review",
                Severity::Medium,
                Confidence::Inferred,
                evidence,
            )
        })
        .into_iter()
        .collect()
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

    #[test]
    fn cdn_detection_requires_an_exact_known_dns_suffix() {
        let cloudfront = [record(
            "example.com",
            DnsRecordType::Cname,
            "distribution.cloudfront.net.",
            None,
        )];
        assert_eq!(
            keys(&scanner_findings(
                "cdn-detection",
                "example.com",
                &cloudfront,
                4,
            )),
            vec!["cdn-dns-signal-observed"]
        );

        let deceptive = [record(
            "example.com",
            DnsRecordType::Cname,
            "cloudfront.net.attacker.example",
            None,
        )];
        assert!(scanner_findings("cdn-detection", "example.com", &deceptive, 4).is_empty());
        let wrong_owner = [record(
            "other.example",
            DnsRecordType::Cname,
            "distribution.cloudfront.net",
            None,
        )];
        assert!(scanner_findings("cdn-detection", "example.com", &wrong_owner, 4).is_empty());
    }

    #[test]
    fn record_collectors_distinguish_usable_missing_and_wrong_type_answers() {
        for (id, record_type, observed_key, missing_key) in [
            (
                "dns-caa-checker",
                DnsRecordType::Caa,
                "caa-policy-observed",
                "caa-not-observed",
            ),
            (
                "reverse-dns-scan",
                DnsRecordType::Ptr,
                "ptr-observed",
                "ptr-not-observed",
            ),
            (
                "txt-records",
                DnsRecordType::Txt,
                "txt-records-observed",
                "txt-records-not-observed",
            ),
        ] {
            let present = [record("example.com", record_type, "usable", None)];
            assert_eq!(
                keys(&scanner_findings(id, "example.com", &present, 2)),
                vec![observed_key]
            );
            assert_eq!(
                keys(&scanner_findings(id, "example.com", &[], 2)),
                vec![missing_key]
            );
            let wrong_owner = [record("other.example", record_type, "usable", None)];
            assert_eq!(
                keys(&scanner_findings(id, "example.com", &wrong_owner, 2)),
                vec![missing_key]
            );
            let empty = [record("example.com", record_type, " ", None)];
            assert_eq!(
                keys(&scanner_findings(id, "example.com", &empty, 2)),
                vec![missing_key]
            );
        }

        let address = [record("example.com", DnsRecordType::A, "192.0.2.1", None)];
        assert_eq!(
            keys(&scanner_findings("dns-records", "example.com", &address, 3)),
            vec!["dns-records-observed"]
        );
        assert_eq!(
            keys(&scanner_findings("dns-records", "example.com", &[], 3)),
            vec!["dns-records-not-observed"]
        );
    }

    #[test]
    fn domain_info_reports_address_and_authority_gaps_independently() {
        let complete = [
            record("example.com", DnsRecordType::A, "192.0.2.1", None),
            record("example.com", DnsRecordType::Ns, "ns.example.net", None),
        ];
        assert_eq!(
            keys(&scanner_findings(
                "domain-info",
                "example.com",
                &complete,
                0
            )),
            vec!["domain-address-observed", "domain-authority-observed"]
        );

        let address_only = [record(
            "example.com",
            DnsRecordType::Aaaa,
            "2001:db8::1",
            None,
        )];
        assert_eq!(
            keys(&scanner_findings(
                "domain-info",
                "example.com",
                &address_only,
                4
            )),
            vec!["domain-address-observed", "domain-authority-not-observed"]
        );
        assert_eq!(
            keys(&scanner_findings("domain-info", "example.com", &[], 4)),
            vec![
                "domain-address-not-observed",
                "domain-authority-not-observed"
            ]
        );
    }

    #[test]
    fn rogue_probe_requires_an_exact_usable_address_answer() {
        let probe = "_sugra-scope-probe.example.com";
        let exact = [record(probe, DnsRecordType::A, "192.0.2.20", None)];
        assert_eq!(
            keys(&scanner_findings(
                "rogue-subdomain-resolver",
                probe,
                &exact,
                6
            )),
            vec!["unexpected-probe-answer"]
        );
        let wrong_owner = [record("example.com", DnsRecordType::A, "192.0.2.20", None)];
        assert!(scanner_findings("rogue-subdomain-resolver", probe, &wrong_owner, 6).is_empty());
        let metadata = [record(probe, DnsRecordType::Txt, "metadata", None)];
        assert!(scanner_findings("rogue-subdomain-resolver", probe, &metadata, 6).is_empty());
        let malformed_address = [record(probe, DnsRecordType::A, "not-an-address", None)];
        assert!(
            scanner_findings("rogue-subdomain-resolver", probe, &malformed_address, 6).is_empty()
        );
    }

    #[test]
    fn decoy_beacon_requires_exact_owner_resolution_type_and_value() {
        let probe = "_sugra-decoy-beacon.example.com";
        for answer in [
            record(probe, DnsRecordType::A, "192.0.2.20", None),
            record(probe, DnsRecordType::Aaaa, "2001:db8::20", None),
            record(probe, DnsRecordType::Cname, "alias.example.net.", None),
        ] {
            assert_eq!(
                keys(&scanner_findings("decoy-dns-beacon", probe, &[answer], 7)),
                vec!["decoy-probe-answer-observed"]
            );
        }

        for ignored in [
            record("other.example", DnsRecordType::A, "192.0.2.20", None),
            record(probe, DnsRecordType::Txt, "192.0.2.20", None),
            record(probe, DnsRecordType::A, "not-an-address", None),
            record(probe, DnsRecordType::Aaaa, "not-an-address", None),
            record(probe, DnsRecordType::Cname, "invalid..name", None),
            record(probe, DnsRecordType::Cname, " ", None),
        ] {
            assert!(scanner_findings("decoy-dns-beacon", probe, &[ignored], 7).is_empty());
        }
    }

    #[test]
    fn spf_network_extractor_requires_a_policy_and_network_mechanism() {
        let with_network = [record(
            "example.com",
            DnsRecordType::Txt,
            "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all",
            None,
        )];
        assert_eq!(
            keys(&scanner_findings(
                "spf-network-extractor",
                "example.com",
                &with_network,
                0
            )),
            vec!["spf-network-sources-observed"]
        );
        let no_network = [record(
            "example.com",
            DnsRecordType::Txt,
            "v=spf1 -all",
            None,
        )];
        assert_eq!(
            keys(&scanner_findings(
                "spf-network-extractor",
                "example.com",
                &no_network,
                0
            )),
            vec!["spf-network-sources-not-observed"]
        );
        assert_eq!(
            keys(&scanner_findings(
                "spf-network-extractor",
                "example.com",
                &[],
                0
            )),
            vec!["spf-not-observed"]
        );
    }

    #[test]
    fn takeover_analysis_requires_an_exact_external_cname_suffix() {
        let alias = [record(
            "app.example.com",
            DnsRecordType::Cname,
            "tenant.github.io.",
            None,
        )];
        assert_eq!(
            keys(&scanner_findings(
                "subdomain-takeover",
                "app.example.com",
                &alias,
                8
            )),
            vec!["external-service-alias"]
        );
        let deceptive = [record(
            "app.example.com",
            DnsRecordType::Cname,
            "github.io.attacker.example",
            None,
        )];
        assert!(
            scanner_findings("subdomain-takeover", "app.example.com", &deceptive, 8).is_empty()
        );
        let deceptive_prefix = [record(
            "app.example.com",
            DnsRecordType::Cname,
            "tenant.evilgithub.io",
            None,
        )];
        assert!(
            scanner_findings(
                "subdomain-takeover",
                "app.example.com",
                &deceptive_prefix,
                8
            )
            .is_empty()
        );
        let txt = [record(
            "app.example.com",
            DnsRecordType::Txt,
            "tenant.github.io",
            None,
        )];
        assert!(scanner_findings("subdomain-takeover", "app.example.com", &txt, 8).is_empty());
    }

    #[test]
    fn dns_evidence_summary_is_value_free_and_structurally_bounded() -> Result<(), serde_json::Error>
    {
        let marker = "fixture-private-dns-token";
        let records = (0_u32..512)
            .map(|index| {
                record(
                    if index % 2 == 0 {
                        "example.com"
                    } else {
                        "other.example"
                    },
                    if index % 3 == 0 {
                        DnsRecordType::Txt
                    } else {
                        DnsRecordType::A
                    },
                    marker,
                    Some(index % 600),
                )
            })
            .collect::<Vec<_>>();
        let summary = summarize_dns_evidence(
            "example.com",
            &[DnsRecordType::Txt, DnsRecordType::Txt, DnsRecordType::A],
            &records,
        );
        let serialized = serde_json::to_string(&summary)?;
        assert!(!serialized.contains(marker));
        assert!(serialized.len() < 512);
        assert_eq!(summary["response_record_count"], 512);
        assert_eq!(summary["matching_owner_record_count"], 256);
        assert_eq!(summary["requested_types"], json!(["A", "TXT"]));
        assert_eq!(summary["record_type_counts"]["TXT"], 171);
        Ok(())
    }
}
