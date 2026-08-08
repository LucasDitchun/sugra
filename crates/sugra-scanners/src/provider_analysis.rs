//! Pure, bounded projections of third-party provider responses.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;
use sugra_domain::{Confidence, Severity};

/// Optional operator-owned reference data used by a provider analyzer.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ProviderBaseline<'a> {
    /// No comparison baseline is available.
    None,
    /// Certificate issuer names approved for the target.
    CertificateIssuers(&'a [&'a str]),
}

/// Privacy-preserving projection of one provider response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProviderAnalysis {
    /// Bounded aggregate without raw provider records.
    pub(crate) summary: ProviderSummary,
    /// Security-relevant conclusions derived from the aggregate.
    pub(crate) findings: Vec<ProviderFinding>,
}

/// Supported aggregate response shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum ProviderSummary {
    /// Certificate-transparency counts.
    CertificateTransparency {
        /// Provider records with the expected shape.
        records: usize,
        /// Unique DNS names across all valid records.
        unique_names: usize,
        /// Unique certificate issuers across all valid records.
        unique_issuers: usize,
        /// Names containing a wildcard label.
        wildcard_names: usize,
    },
    /// `URLScan` result counts suitable for passive history and asset summaries.
    UrlScan {
        /// Provider records with a page object.
        records: usize,
        /// Distinct domain values across valid records.
        unique_domains: usize,
        /// Distinct IP address values across valid records.
        unique_ips: usize,
        /// Records explicitly marked malicious by the provider.
        malicious_records: usize,
    },
    /// Routing and route-origin aggregate counts.
    Routing {
        /// Prefixes returned by the provider.
        prefixes: usize,
        /// Autonomous-system origins returned by the provider.
        origins: usize,
        /// Routes with a valid status.
        valid_routes: usize,
        /// Routes with an invalid status.
        invalid_routes: usize,
        /// Routes without a recognized validity status.
        unknown_routes: usize,
    },
    /// `PageSpeed` metrics reduced to bounded numeric values.
    PageSpeed {
        /// Lighthouse performance score from 0 through 100.
        performance_score: Option<u8>,
        /// Largest Contentful Paint in milliseconds.
        largest_contentful_paint_ms: Option<u64>,
        /// Cumulative Layout Shift multiplied by 1,000.
        cumulative_layout_shift_milli: Option<u64>,
        /// Audits explicitly scoring below 0.5.
        failed_audits: usize,
    },
    /// Reputation-engine aggregate counts.
    Reputation {
        /// Engines or sources returning a malicious verdict.
        malicious: u64,
        /// Engines or sources returning a suspicious verdict.
        suspicious: u64,
        /// Engines or sources returning a harmless verdict.
        harmless: u64,
        /// Engines without a verdict.
        undetected: u64,
        /// Abuse confidence score from 0 through 100.
        abuse_confidence: Option<u8>,
    },
}

/// Finding independent of result evidence indexing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProviderFinding {
    /// Stable finding identity.
    pub(crate) key: &'static str,
    /// Safe user-facing title.
    pub(crate) title: &'static str,
    /// Finding severity.
    pub(crate) severity: Severity,
    /// Evidence confidence.
    pub(crate) confidence: Confidence,
}

/// Analyzes a supported provider response without retaining raw records.
#[must_use]
pub(crate) fn analyze_provider_response(
    scanner_id: &str,
    provider: &str,
    response: &Value,
    baseline: ProviderBaseline<'_>,
) -> Option<ProviderAnalysis> {
    match provider {
        "crtsh" => Some(analyze_certificate_transparency(
            scanner_id, response, baseline,
        )),
        "urlscan" => Some(analyze_urlscan(scanner_id, response)),
        "ripestat" => Some(analyze_ripestat(scanner_id, response)),
        "pagespeed" => Some(analyze_pagespeed(scanner_id, response)),
        "virustotal" | "abuseipdb" | "urlhaus" | "otx" => {
            Some(analyze_reputation(scanner_id, response))
        }
        _ => None,
    }
}

fn analyze_ripestat(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let data = response.get("data").unwrap_or(response);
    let prefixes = array_len(data, &["prefixes", "announced_space"]);
    let origins = array_len(data, &["asns", "origins"]);
    let statuses = data
        .get("routes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|route| route.get("status").and_then(Value::as_str))
        .chain(data.get("status").and_then(Value::as_str));
    let mut valid_routes = 0_usize;
    let mut invalid_routes = 0_usize;
    let mut unknown_routes = 0_usize;
    for status in statuses.take(10_000) {
        if status.eq_ignore_ascii_case("valid") {
            valid_routes += 1;
        } else if status.to_ascii_lowercase().starts_with("invalid") {
            invalid_routes += 1;
        } else {
            unknown_routes += 1;
        }
    }
    let findings = if scanner_id == "rpki-route-validity-check" && invalid_routes > 0 {
        vec![ProviderFinding {
            key: "rpki-route-invalid",
            title: "The route origin is invalid under the observed RPKI state",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::Routing {
            prefixes,
            origins,
            valid_routes,
            invalid_routes,
            unknown_routes,
        },
        findings,
    }
}

fn array_len(data: &Value, keys: &[&str]) -> usize {
    keys.iter()
        .filter_map(|key| data.get(key).and_then(Value::as_array))
        .map(Vec::len)
        .sum::<usize>()
        .min(10_000)
}

fn analyze_pagespeed(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let raw_score = response
        .get("performance_score")
        .and_then(Value::as_f64)
        .or_else(|| {
            response
                .pointer("/lighthouseResult/categories/performance/score")
                .and_then(Value::as_f64)
        });
    let performance_score = raw_score.and_then(percent);
    let largest_contentful_paint_ms = metric(
        response,
        "/metrics/largest_contentful_paint_ms",
        "/lighthouseResult/audits/largest-contentful-paint/numericValue",
        1.0,
    );
    let cumulative_layout_shift_milli = metric(
        response,
        "/metrics/cumulative_layout_shift",
        "/lighthouseResult/audits/cumulative-layout-shift/numericValue",
        1_000.0,
    );
    let failed_audits = response
        .pointer("/lighthouseResult/audits")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|audits| audits.values())
        .filter(|audit| {
            audit
                .get("score")
                .and_then(Value::as_f64)
                .is_some_and(|score| score < 0.5)
        })
        .take(10_000)
        .count();
    let findings = if matches!(scanner_id, "performance-monitoring" | "quality-metrics")
        && performance_score.is_some_and(|score| score < 50)
    {
        vec![ProviderFinding {
            key: "low-performance-score",
            title: "The external performance assessment reported a low score",
            severity: Severity::Medium,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::PageSpeed {
            performance_score,
            largest_contentful_paint_ms,
            cumulative_layout_shift_milli,
            failed_audits,
        },
        findings,
    }
}

fn percent(value: f64) -> Option<u8> {
    let scaled = if value <= 1.0 { value * 100.0 } else { value };
    finite_u64(scaled).and_then(|value| u8::try_from(value.min(100)).ok())
}

fn metric(response: &Value, normalized: &str, raw: &str, scale: f64) -> Option<u64> {
    response
        .pointer(normalized)
        .and_then(Value::as_f64)
        .or_else(|| response.pointer(raw).and_then(Value::as_f64))
        .and_then(|value| finite_u64(value * scale))
}

fn finite_u64(value: f64) -> Option<u64> {
    (value.is_finite() && value >= 0.0)
        .then(|| value.round().to_string().parse().ok())
        .flatten()
}

fn analyze_reputation(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let stats = response
        .pointer("/data/attributes/last_analysis_stats")
        .or_else(|| response.get("stats"))
        .unwrap_or(response);
    let malicious = count(stats, "malicious");
    let suspicious = count(stats, "suspicious");
    let harmless = count(stats, "harmless");
    let undetected = count(stats, "undetected");
    let abuse_confidence = response
        .pointer("/data/abuseConfidenceScore")
        .or_else(|| response.get("abuseConfidenceScore"))
        .and_then(Value::as_u64)
        .and_then(|score| u8::try_from(score.min(100)).ok());
    let risky =
        malicious > 0 || suspicious > 0 || abuse_confidence.is_some_and(|score| score >= 50);
    let findings = if risky
        && matches!(
            scanner_id,
            "domain-reputation-check"
                | "ip-reputation-check"
                | "ip-reputation-trending"
                | "malware-phishing"
                | "threat-feed-correlator"
                | "virustotal-scan"
        ) {
        vec![ProviderFinding {
            key: "provider-reputation-risk",
            title: "A configured reputation source returned a material risk signal",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::Reputation {
            malicious,
            suspicious,
            harmless,
            undetected,
            abuse_confidence,
        },
        findings,
    }
}

fn count(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

fn analyze_urlscan(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let mut domains = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut records = 0_usize;
    let mut malicious_records = 0_usize;
    for record in response
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(10_000)
    {
        let Some(page) = record.get("page").and_then(Value::as_object) else {
            continue;
        };
        records += 1;
        if let Some(domain) = page.get("domain").and_then(Value::as_str) {
            domains.insert(domain.to_ascii_lowercase());
        }
        if let Some(ip) = page.get("ip").and_then(Value::as_str) {
            ips.insert(ip.to_owned());
        }
        malicious_records += usize::from(
            record
                .pointer("/verdicts/overall/malicious")
                .and_then(Value::as_bool)
                == Some(true),
        );
    }
    let findings = if scanner_id == "passive-dns-history" && records > 0 {
        vec![ProviderFinding {
            key: "historical-dns-observations",
            title: "The provider returned historical domain or address observations",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }]
    } else if malicious_records > 0 {
        vec![ProviderFinding {
            key: "malicious-urlscan-observation",
            title: "URLScan marked one or more observations as malicious",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::UrlScan {
            records,
            unique_domains: domains.len(),
            unique_ips: ips.len(),
            malicious_records,
        },
        findings,
    }
}

fn analyze_certificate_transparency(
    scanner_id: &str,
    response: &Value,
    baseline: ProviderBaseline<'_>,
) -> ProviderAnalysis {
    let mut names = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut records = 0_usize;
    for record in response.as_array().into_iter().flatten().take(10_000) {
        let Some(object) = record.as_object() else {
            continue;
        };
        let Some(issuer) = object.get("issuer_name").and_then(Value::as_str) else {
            continue;
        };
        records += 1;
        issuers.insert(issuer.to_owned());
        if let Some(values) = object.get("name_value").and_then(Value::as_str) {
            names.extend(
                values
                    .lines()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .take(1_000)
                    .map(str::to_ascii_lowercase),
            );
        }
    }
    let unexpected = match baseline {
        ProviderBaseline::CertificateIssuers(expected) => issuers.iter().any(|issuer| {
            !expected
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(issuer))
        }),
        ProviderBaseline::None => false,
    };
    let findings = if scanner_id == "rogue-certificate-check" && unexpected {
        vec![ProviderFinding {
            key: "unexpected-certificate-issuer",
            title: "Certificate transparency contains an unexpected issuer",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::CertificateTransparency {
            records,
            unique_names: names.len(),
            unique_issuers: issuers.len(),
            wildcard_names: names.iter().filter(|name| name.starts_with("*.")).count(),
        },
        findings,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sugra_domain::Severity;

    use super::*;

    #[test]
    fn rogue_certificate_check_flags_unexpected_issuers_without_retaining_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!([
            {"name_value": "example.com\nwww.example.com", "issuer_name": "Unexpected CA"},
            {"name_value": "*.example.com", "issuer_name": "Expected CA"}
        ]);

        let analysis = analyze_provider_response(
            "rogue-certificate-check",
            "crtsh",
            &response,
            ProviderBaseline::CertificateIssuers(&["Expected CA"]),
        )
        .ok_or("crt.sh response must be supported")?;

        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].key, "unexpected-certificate-issuer");
        assert_eq!(analysis.findings[0].severity, Severity::High);
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("www.example.com"));
        assert!(!serialized.contains("Unexpected CA"));
        Ok(())
    }

    #[test]
    fn passive_dns_history_summarizes_urlscan_results_without_retaining_hosts()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({"results": [
            {"page": {"domain": "one.example.com", "ip": "192.0.2.1"}},
            {"page": {"domain": "two.example.com", "ip": "192.0.2.1"}}
        ]});

        let analysis = analyze_provider_response(
            "passive-dns-history",
            "urlscan",
            &response,
            ProviderBaseline::None,
        )
        .ok_or("URLScan response must be supported")?;

        assert_eq!(analysis.findings[0].key, "historical-dns-observations");
        assert_eq!(
            analysis.summary,
            ProviderSummary::UrlScan {
                records: 2,
                unique_domains: 2,
                unique_ips: 1,
                malicious_records: 0,
            }
        );
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("one.example.com"));
        assert!(!serialized.contains("192.0.2.1"));
        Ok(())
    }

    #[test]
    fn certificate_transparency_expected_issuer_is_a_negative_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "rogue-certificate-check",
            "crtsh",
            &json!([{"name_value": "example.com", "issuer_name": "Expected CA"}]),
            ProviderBaseline::CertificateIssuers(&["expected ca"]),
        )
        .ok_or("crt.sh response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert_eq!(
            analysis.summary,
            ProviderSummary::CertificateTransparency {
                records: 1,
                unique_names: 1,
                unique_issuers: 1,
                wildcard_names: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn certificate_transparency_ignores_malformed_records() -> Result<(), Box<dyn std::error::Error>>
    {
        let analysis = analyze_provider_response(
            "ct-log-query",
            "crtsh",
            &json!([null, "raw", {"name_value": "secret.example"}]),
            ProviderBaseline::None,
        )
        .ok_or("crt.sh response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert_eq!(
            analysis.summary,
            ProviderSummary::CertificateTransparency {
                records: 0,
                unique_names: 0,
                unique_issuers: 0,
                wildcard_names: 0,
            }
        );
        assert!(!serde_json::to_string(&analysis)?.contains("secret.example"));
        Ok(())
    }

    #[test]
    fn urlscan_empty_results_are_a_negative_control() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "passive-dns-history",
            "urlscan",
            &json!({"results": []}),
            ProviderBaseline::None,
        )
        .ok_or("URLScan response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert_eq!(
            analysis.summary,
            ProviderSummary::UrlScan {
                records: 0,
                unique_domains: 0,
                unique_ips: 0,
                malicious_records: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn urlscan_malformed_results_do_not_leak_nested_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "reverse-ip-lookup",
            "urlscan",
            &json!({"results": [null, {"page": "invalid", "token": "private-value"}]}),
            ProviderBaseline::None,
        )
        .ok_or("URLScan response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(!serde_json::to_string(&analysis)?.contains("private-value"));
        Ok(())
    }

    #[test]
    fn rpki_route_validity_flags_invalid_origins() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "rpki-route-validity-check",
            "ripestat",
            &json!({"data": {"status": "invalid_asn", "prefixes": ["192.0.2.0/24"]}}),
            ProviderBaseline::None,
        )
        .ok_or("RIPEstat response must be supported")?;

        assert_eq!(analysis.findings[0].key, "rpki-route-invalid");
        assert_eq!(
            analysis.summary,
            ProviderSummary::Routing {
                prefixes: 1,
                origins: 0,
                valid_routes: 0,
                invalid_routes: 1,
                unknown_routes: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn rpki_valid_route_is_a_negative_control() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "rpki-route-validity-check",
            "ripestat",
            &json!({"data": {"status": "valid", "asns": [64496]}}),
            ProviderBaseline::None,
        )
        .ok_or("RIPEstat response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::Routing {
                valid_routes: 1,
                invalid_routes: 0,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn ripestat_malformed_routes_are_counted_without_retaining_resources()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "bgp-route-analysis",
            "ripestat",
            &json!({"data": {"routes": [null, {"status": "mystery"}], "resource": "private"}}),
            ProviderBaseline::None,
        )
        .ok_or("RIPEstat response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::Routing {
                unknown_routes: 1,
                ..
            }
        ));
        assert!(!serde_json::to_string(&analysis)?.contains("private"));
        Ok(())
    }

    #[test]
    fn performance_monitoring_flags_a_low_pagespeed_score() -> Result<(), Box<dyn std::error::Error>>
    {
        let analysis = analyze_provider_response(
            "performance-monitoring",
            "pagespeed",
            &json!({
                "performance_score": 0.42,
                "metrics": {"largest_contentful_paint_ms": 3100.0, "cumulative_layout_shift": 0.2}
            }),
            ProviderBaseline::None,
        )
        .ok_or("PageSpeed response must be supported")?;

        assert_eq!(analysis.findings[0].key, "low-performance-score");
        assert_eq!(
            analysis.summary,
            ProviderSummary::PageSpeed {
                performance_score: Some(42),
                largest_contentful_paint_ms: Some(3100),
                cumulative_layout_shift_milli: Some(200),
                failed_audits: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn healthy_pagespeed_score_is_a_negative_control() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "quality-metrics",
            "pagespeed",
            &json!({"lighthouseResult": {"categories": {"performance": {"score": 0.95}}}}),
            ProviderBaseline::None,
        )
        .ok_or("PageSpeed response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::PageSpeed {
                performance_score: Some(95),
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn pagespeed_malformed_metrics_are_omitted_without_retaining_urls()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "performance-monitoring",
            "pagespeed",
            &json!({"performance_score": "fast", "id": "https://private.example/?token=secret"}),
            ProviderBaseline::None,
        )
        .ok_or("PageSpeed response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::PageSpeed {
                performance_score: None,
                largest_contentful_paint_ms: None,
                cumulative_layout_shift_milli: None,
                ..
            }
        ));
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("private.example"));
        assert!(!serialized.contains("secret"));
        Ok(())
    }

    #[test]
    fn domain_reputation_flags_malicious_engine_results() -> Result<(), Box<dyn std::error::Error>>
    {
        let analysis = analyze_provider_response(
            "domain-reputation-check",
            "virustotal",
            &json!({"data": {"attributes": {"last_analysis_stats": {
                "malicious": 3, "suspicious": 1, "harmless": 40, "undetected": 5
            }}}}),
            ProviderBaseline::None,
        )
        .ok_or("reputation response must be supported")?;

        assert_eq!(analysis.findings[0].key, "provider-reputation-risk");
        assert!(matches!(
            analysis.summary,
            ProviderSummary::Reputation {
                malicious: 3,
                suspicious: 1,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn harmless_reputation_result_is_a_negative_control() -> Result<(), Box<dyn std::error::Error>>
    {
        let analysis = analyze_provider_response(
            "virustotal-scan",
            "virustotal",
            &json!({"data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 52, "undetected": 4
            }}}}),
            ProviderBaseline::None,
        )
        .ok_or("reputation response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::Reputation { harmless: 52, .. }
        ));
        Ok(())
    }

    #[test]
    fn malformed_reputation_values_are_zeroed_without_retaining_attributes()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "ip-reputation-check",
            "abuseipdb",
            &json!({"data": {"abuseConfidenceScore": "high", "ipAddress": "192.0.2.44"}}),
            ProviderBaseline::None,
        )
        .ok_or("reputation response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert_eq!(
            analysis.summary,
            ProviderSummary::Reputation {
                malicious: 0,
                suspicious: 0,
                harmless: 0,
                undetected: 0,
                abuse_confidence: None,
            }
        );
        assert!(!serde_json::to_string(&analysis)?.contains("192.0.2.44"));
        Ok(())
    }
}
