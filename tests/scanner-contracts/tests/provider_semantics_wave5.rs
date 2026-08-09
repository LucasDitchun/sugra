//! Public offline contracts for the fifth provider-analysis wave.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};
use sugra_core::{
    PortError, PortErrorKind, ProviderPort, ProviderRequest, ProviderResponse, ScanErrorKind,
};
use sugra_domain::{Confidence, ExecutionStatus, ScanResult, Severity, TargetKind};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

const SECRET: &str = "wave5-provider-secret-9d71";

const SCANNERS: [&str; 16] = [
    "breached-credentials-lookup",
    "censys",
    "dark-web-monitoring",
    "data-leak",
    "dns-over-https",
    "domain-shadowing-detector",
    "geo-ip-spoof-detection",
    "global-ranking",
    "ip-reputation-trending",
    "js-malware-scanner",
    "malware-phishing",
    "pastebin-monitoring",
    "shodan",
    "ssl-labs-report",
    "threat-feed-correlator",
    "virustotal-scan",
];

#[derive(Clone)]
struct RecordingProvider {
    requests: Arc<Mutex<Vec<ProviderRequest>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureCase {
    Positive,
    Negative,
    Edge,
}

struct FixtureProvider {
    scanner_id: &'static str,
    case: FixtureCase,
    requests: Arc<Mutex<Vec<ProviderRequest>>>,
}

struct FailingProvider {
    kind: PortErrorKind,
}

struct PartialProvider {
    scanner_id: &'static str,
    failed_provider: &'static str,
    requests: Arc<Mutex<Vec<ProviderRequest>>>,
}

struct CancellingProvider {
    cancellation: tokio_util::sync::CancellationToken,
    requests: Arc<Mutex<Vec<ProviderRequest>>>,
}

#[async_trait]
impl ProviderPort for RecordingProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.clone());
        Ok(ProviderResponse {
            provider: request.provider,
            data: json!({}),
            duration_ms: 1,
        })
    }
}

#[async_trait]
impl ProviderPort for FixtureProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.clone());
        Ok(ProviderResponse {
            provider: request.provider.clone(),
            data: fixture_data(self.scanner_id, self.case, &request),
            duration_ms: 3,
        })
    }
}

#[async_trait]
impl ProviderPort for FailingProvider {
    async fn query(&self, _request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        Err(PortError::new(
            self.kind,
            format!("wave5 provider boundary failure {SECRET}"),
        ))
    }
}

#[async_trait]
impl ProviderPort for PartialProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        self.requests
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "fixture lock failure"))?
            .push(request.clone());
        if request.provider == self.failed_provider {
            return Err(PortError::new(
                PortErrorKind::RateLimited,
                format!("one provider is temporarily unavailable {SECRET}"),
            ));
        }
        Ok(ProviderResponse {
            provider: request.provider.clone(),
            data: fixture_data(self.scanner_id, FixtureCase::Negative, &request),
            duration_ms: 3,
        })
    }
}

#[async_trait]
impl ProviderPort for CancellingProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        self.requests
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "fixture lock failure"))?
            .push(request.clone());
        self.cancellation.cancel();
        Ok(ProviderResponse {
            provider: request.provider.clone(),
            data: fixture_data("threat-feed-correlator", FixtureCase::Negative, &request),
            duration_ms: 1,
        })
    }
}

fn fixture_data(scanner_id: &str, case: FixtureCase, request: &ProviderRequest) -> Value {
    match scanner_id {
        "breached-credentials-lookup" | "data-leak" => breach_data(case),
        "dark-web-monitoring" => stealer_log_data(case),
        "pastebin-monitoring" => paste_data(case),
        "censys" => censys_data(case),
        "shodan" => shodan_data(case),
        "global-ranking" => ranking_data(case),
        "ssl-labs-report" => ssl_labs_data(case),
        "domain-shadowing-detector"
        | "ip-reputation-trending"
        | "js-malware-scanner"
        | "malware-phishing"
        | "threat-feed-correlator"
        | "virustotal-scan" => threat_data(case, request),
        "dns-over-https" => doh_data(case),
        "geo-ip-spoof-detection" => geo_data(case, request),
        _ => match (request.provider.as_str(), case) {
            (_, FixtureCase::Negative) => json!({}),
            _ => json!({"fixture": SECRET}),
        },
    }
}

fn doh_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "Status": 0, "TC": false, "AD": true,
            "Answer": [{"name": SECRET, "type": 1, "data": "192.0.2.10"}, {"type": 1}]
        }),
        FixtureCase::Negative => json!({"Status": 3, "TC": false, "AD": false}),
        FixtureCase::Edge => json!({
            "Status": 0, "TC": true, "AD": false,
            "Answer": (0..10_005).map(|_| json!({"name": SECRET, "data": SECRET})).collect::<Vec<_>>()
        }),
    }
}

fn geo_data(case: FixtureCase, request: &ProviderRequest) -> Value {
    let country = match (case, request.provider.as_str()) {
        (FixtureCase::Positive, "ipinfo") | (FixtureCase::Negative, _) => "BR",
        (FixtureCase::Positive, _) => "US",
        (FixtureCase::Edge, _) => SECRET,
    };
    if request.provider == "ipinfo" {
        json!({
            "geo": {"country_code": country, "latitude": -23.5, "longitude": -46.6},
            "private": SECRET
        })
    } else {
        json!({
            "data": {"located_resources": [{"location": country, "resource": SECRET}]}
        })
    }
}

fn threat_data(case: FixtureCase, request: &ProviderRequest) -> Value {
    match request.provider.as_str() {
        "virustotal" => match case {
            FixtureCase::Positive => json!({
                "data": {"attributes": {"last_analysis_stats": {
                    "malicious": 2, "suspicious": 1, "harmless": 4, "undetected": 3
                }, "private": SECRET}}
            }),
            FixtureCase::Negative => json!({
                "data": {"attributes": {"last_analysis_stats": {
                    "malicious": 0, "suspicious": 0, "harmless": 8, "undetected": 2
                }}}
            }),
            FixtureCase::Edge => json!({
                "data": {"attributes": {"last_analysis_stats": {
                    "malicious": u64::MAX, "suspicious": u64::MAX,
                    "harmless": u64::MAX, "undetected": u64::MAX
                }, "private": SECRET}}
            }),
        },
        "urlscan" => match case {
            FixtureCase::Positive => json!({"results": [{
                "page": {"domain": "private.example.test", "ip": "192.0.2.10"},
                "verdicts": {"overall": {"malicious": true}}, "raw": SECRET
            }]}),
            FixtureCase::Negative => json!({"results": []}),
            FixtureCase::Edge => json!({
                "results": (0..10_005).map(|_| json!({
                    "page": {"domain": format!("{SECRET}.example.test"), "ip": "192.0.2.10"},
                    "verdicts": {"overall": {"malicious": true}}
                })).collect::<Vec<_>>()
            }),
        },
        "urlhaus" => match case {
            FixtureCase::Positive => json!({
                "query_status": "ok", "urls": [{"url_status": "online", "url": SECRET}]
            }),
            FixtureCase::Negative => json!({"query_status": "no_results", "urls": []}),
            FixtureCase::Edge => json!({
                "query_status": "ok",
                "urls": (0..10_005).map(|_| json!({"url_status": "online", "url": SECRET})).collect::<Vec<_>>()
            }),
        },
        "otx" => match case {
            FixtureCase::Positive => json!({"pulse_info": {"count": 2, "pulses": [SECRET]}}),
            FixtureCase::Negative => json!({"pulse_info": {"count": 0, "pulses": []}}),
            FixtureCase::Edge => json!({"pulse_info": {"count": u64::MAX, "pulses": [SECRET]}}),
        },
        "ripestat" => match case {
            FixtureCase::Positive => json!({
                "data": {"blocklists": [{"name": "blocklist-a", "listed": true, "raw": SECRET}]}
            }),
            FixtureCase::Negative => json!({"data": {"blocklists": []}}),
            FixtureCase::Edge => json!({
                "data": {"blocklists": (0..10_005).map(|_| json!({
                    "name": SECRET, "listed": true
                })).collect::<Vec<_>>()}
            }),
        },
        "crtsh" => match case {
            FixtureCase::Negative => json!([]),
            _ => json!([{
                "issuer_name": "Public CA", "name_value": format!("*.{SECRET}.example.test")
            }]),
        },
        _ => json!({}),
    }
}

fn ranking_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "result": {"details_0": {"rank": 42, "bucket": "top_100", "categories": [{"id": 1}]}}
        }),
        FixtureCase::Negative => json!({"result": {"details_0": {}}}),
        FixtureCase::Edge => json!({
            "result": {"details_0": {
                "rank": 1, "bucket": SECRET,
                "categories": (0..10_005).map(|index| json!({"id": index, "name": SECRET})).collect::<Vec<_>>()
            }}
        }),
    }
}

fn ssl_labs_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "status": "READY", "host": format!("{SECRET}.example.test"),
            "endpoints": [{"grade": "A"}, {"grade": "C", "details": SECRET}]
        }),
        FixtureCase::Negative => json!({"status": "READY", "endpoints": [{"grade": "A+"}]}),
        FixtureCase::Edge => json!({
            "status": "READY",
            "endpoints": (0..10_005).map(|_| json!({"grade": "F", "details": SECRET})).collect::<Vec<_>>()
        }),
    }
}

fn censys_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "web": {
                "hostname": "private.example.test",
                "port": 443,
                "endpoints": [{"path": format!("/{SECRET}")}, {"path": "/health"}]
            }
        }),
        FixtureCase::Negative => json!({}),
        FixtureCase::Edge => json!({
            "web": {
                "hostname": format!("{SECRET}.example.test"),
                "port": 443,
                "endpoints": (0..10_005)
                    .map(|index| json!({"path": format!("/{SECRET}/{index}")}))
                    .collect::<Vec<_>>()
            }
        }),
    }
}

fn shodan_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "matches": [
                {"ip_str": "192.0.2.10", "port": 443, "hostnames": ["a.example.test"]},
                {"ip_str": "192.0.2.11", "port": 8443, "hostnames": ["b.example.test"]}
            ],
            "total": 2
        }),
        FixtureCase::Negative => json!({"matches": [], "total": 0}),
        FixtureCase::Edge => json!({
            "matches": (0..10_005).map(|_| json!({
                "ip_str": "192.0.2.10", "port": 443,
                "hostnames": [format!("{SECRET}.example.test")], "data": SECRET
            })).collect::<Vec<_>>(),
            "total": u64::MAX
        }),
    }
}

fn breach_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "alice": ["Breach-A", "Breach-B"],
            "bob": ["Breach-A"]
        }),
        FixtureCase::Negative => json!({}),
        FixtureCase::Edge => Value::Object(
            (0..10_005)
                .map(|index| (format!("alias-{index}-{SECRET}"), json!(["Breach-A"])))
                .collect(),
        ),
    }
}

fn stealer_log_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!(["alice@example.test", "bob@example.test"]),
        FixtureCase::Negative => json!([]),
        FixtureCase::Edge => Value::Array(
            (0..10_005)
                .map(|index| json!(format!("account-{index}-{SECRET}@example.test")))
                .collect(),
        ),
    }
}

fn paste_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!([
            {"Source": "Pastebin", "Id": "private-a", "Title": SECRET, "EmailCount": 3},
            {"Source": "Pastie", "Id": "private-b", "EmailCount": 2}
        ]),
        FixtureCase::Negative => json!([]),
        FixtureCase::Edge => Value::Array(
            (0..10_005)
                .map(|index| {
                    json!({
                        "Source": "Pastebin", "Id": format!("{SECRET}-{index}"),
                        "EmailCount": u64::MAX
                    })
                })
                .collect(),
        ),
    }
}

fn expected_calls(id: &str) -> &'static [(&'static str, &'static str, Option<&'static str>)] {
    match id {
        "breached-credentials-lookup" | "data-leak" => &[("hibp", "domain", Some("HIBP_API_KEY"))],
        "censys" => &[("censys", "webproperty", Some("CENSYS_API_TOKEN"))],
        "dark-web-monitoring" => &[("hibp", "stealer-logs-domain", Some("HIBP_API_KEY"))],
        "dns-over-https" => &[
            ("cloudflare-doh", "resolve", None),
            ("google-doh", "resolve", None),
        ],
        "domain-shadowing-detector" => &[("crtsh", "query", None), ("urlscan", "search", None)],
        "geo-ip-spoof-detection" => &[
            ("ipinfo", "lookup", Some("IPINFO_API_KEY")),
            ("ripestat", "rir-geo", None),
        ],
        "global-ranking" => &[(
            "cloudflare-radar",
            "domain-ranking",
            Some("CLOUDFLARE_API_TOKEN"),
        )],
        "ip-reputation-trending" => &[("ripestat", "dns-blocklists", None)],
        "js-malware-scanner" | "malware-phishing" => &[
            ("virustotal", "domain", Some("VIRUSTOTAL_API_KEY")),
            ("urlscan", "search", None),
            ("urlhaus", "host", Some("URLHAUS_AUTH_KEY")),
        ],
        "pastebin-monitoring" => &[("hibp", "paste-account", Some("HIBP_API_KEY"))],
        "shodan" => &[("shodan", "search", Some("SHODAN_API_KEY"))],
        "ssl-labs-report" => &[("ssllabs", "analyze", None)],
        "threat-feed-correlator" => &[
            ("virustotal", "domain", Some("VIRUSTOTAL_API_KEY")),
            ("otx", "domain", Some("OTX_API_KEY")),
            ("urlhaus", "host", Some("URLHAUS_AUTH_KEY")),
        ],
        "virustotal-scan" => &[("virustotal", "domain", Some("VIRUSTOTAL_API_KEY"))],
        _ => &[],
    }
}

fn expected_descriptor(id: &str) -> Option<(Vec<TargetKind>, &'static [&'static str])> {
    match id {
        "breached-credentials-lookup" => {
            Some((vec![TargetKind::Domain, TargetKind::Email], &["timeout"]))
        }
        "censys" => Some((vec![TargetKind::Domain, TargetKind::Ip], &["concurrency"])),
        "dark-web-monitoring" => Some((vec![TargetKind::Domain, TargetKind::Url], &["hibp_key"])),
        "data-leak" | "ssl-labs-report" => Some((vec![TargetKind::Domain], &[])),
        "dns-over-https" => Some((vec![TargetKind::Domain], &["providers", "qtype", "timeout"])),
        "domain-shadowing-detector" => Some((vec![TargetKind::Domain], &["days", "timeout"])),
        "geo-ip-spoof-detection" => Some((vec![TargetKind::Ip, TargetKind::Domain], &[])),
        "global-ranking" => Some((vec![TargetKind::Domain], &["timeout"])),
        "ip-reputation-trending" => Some((
            vec![TargetKind::Domain, TargetKind::Ip, TargetKind::Cidr],
            &["long_window", "short_window"],
        )),
        "js-malware-scanner" => Some((vec![TargetKind::Domain, TargetKind::Url], &["timeout"])),
        "malware-phishing" => Some((vec![TargetKind::Domain, TargetKind::Url], &[])),
        "pastebin-monitoring" => Some((vec![TargetKind::Email], &["hibp_key"])),
        "shodan" | "threat-feed-correlator" => {
            Some((vec![TargetKind::Domain, TargetKind::Ip], &[]))
        }
        "virustotal-scan" => Some((
            vec![TargetKind::Domain, TargetKind::Ip, TargetKind::Url],
            &[],
        )),
        _ => None,
    }
}

#[tokio::test]
async fn provider_catalog_and_calls_match_real_allowlisted_operations()
-> Result<(), Box<dyn std::error::Error>> {
    for id in SCANNERS {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut services = support::Harness::successful().services();
        services.provider = Arc::new(RecordingProvider {
            requests: requests.clone(),
        });
        let builtins = build_builtins(&services)?;
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("scanner is missing")?;
        let descriptor = scanner.descriptor();
        let (target_kinds, option_keys) = expected_descriptor(id).ok_or("descriptor is missing")?;
        assert_eq!(descriptor.target_kinds, target_kinds, "{id}");
        assert_eq!(
            descriptor
                .options
                .iter()
                .map(|option| option.key.as_str())
                .collect::<Vec<_>>(),
            option_keys,
            "{id}"
        );

        let request = support::request_for(descriptor)?;
        let budget = request.budget;
        let result = scanner.scan(&request, &support::context(false)).await?;
        assert!(!result.evidence.is_empty(), "{id}");
        let recorded = requests
            .lock()
            .map_err(|_| "provider request lock poisoned")?;
        let actual = recorded
            .iter()
            .map(|request| {
                (
                    request.provider.as_str(),
                    request.operation.as_str(),
                    request.secret_env.as_deref(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected_calls(id), "{id}");
        assert!(recorded.iter().all(|provider_request| {
            provider_request.budget == budget
                && !provider_request.query.values().any(|value| value == SECRET)
                && provider_request
                    .secret_env
                    .as_deref()
                    .is_none_or(valid_env_reference)
        }));
    }
    Ok(())
}

fn valid_env_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

async fn scan_case(
    id: &'static str,
    case: FixtureCase,
) -> Result<(ScanResult, Vec<ProviderRequest>), Box<dyn std::error::Error>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.provider = Arc::new(FixtureProvider {
        scanner_id: id,
        case,
        requests: requests.clone(),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner is missing")?;
    let request = support::request_for(scanner.descriptor())?;
    let result = scanner.scan(&request, &support::context(false)).await?;
    let recorded = requests
        .lock()
        .map_err(|_| "provider request lock poisoned")?
        .clone();
    Ok((result, recorded))
}

fn summary(result: &ScanResult, index: usize) -> &Value {
    &result.evidence[index].observation["observation"]
}

fn assert_finding(result: &ScanResult, key: &str, severity: Severity, evidence: usize) {
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.key == key)
        .collect();
    assert_eq!(findings.len(), 1, "{key}");
    assert_eq!(findings[0].severity, severity);
    assert_eq!(findings[0].confidence, Confidence::Confirmed);
    assert_eq!(findings[0].evidence, [evidence]);
}

fn assert_finding_at(result: &ScanResult, key: &str, evidence: usize) {
    assert!(
        result.findings.iter().any(|finding| finding.key == key
            && finding.confidence == Confidence::Confirmed
            && finding.evidence == [evidence]),
        "missing {key} at evidence {evidence}"
    );
}

fn assert_redacted(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serde_json::to_string(result)?;
    assert!(!serialized.contains(SECRET));
    assert!(!serialized.contains("alice@example.test"));
    assert!(!serialized.contains("private-a"));
    Ok(())
}

#[tokio::test]
async fn hibp_scanners_project_bounded_counts_without_account_or_paste_identifiers()
-> Result<(), Box<dyn std::error::Error>> {
    for (id, kind, key, positive, edge) in [
        (
            "breached-credentials-lookup",
            "hibp-breaches",
            "breach-observations-present",
            json!({"affected_accounts": 2, "records": 3}),
            json!({"affected_accounts": 10_000, "records": 10_000}),
        ),
        (
            "data-leak",
            "hibp-breaches",
            "breach-observations-present",
            json!({"affected_accounts": 2, "records": 3}),
            json!({"affected_accounts": 10_000, "records": 10_000}),
        ),
        (
            "dark-web-monitoring",
            "hibp-stealer-logs",
            "stealer-log-accounts-present",
            json!({"exposed_accounts": 2}),
            json!({"exposed_accounts": 10_000}),
        ),
        (
            "pastebin-monitoring",
            "hibp-pastes",
            "paste-observations-present",
            json!({"email_mentions": 5, "pastes": 2}),
            json!({"email_mentions": 10_000, "pastes": 10_000}),
        ),
    ] {
        let (positive_result, _) = scan_case(id, FixtureCase::Positive).await?;
        assert_eq!(positive_result.status, ExecutionStatus::Completed, "{id}");
        assert_eq!(summary(&positive_result, 0)["kind"], kind, "{id}");
        for (name, value) in positive
            .as_object()
            .ok_or("positive summary is not an object")?
        {
            assert_eq!(summary(&positive_result, 0)[name], *value, "{id}: {name}");
        }
        assert_finding(&positive_result, key, Severity::High, 0);
        assert_redacted(&positive_result)?;

        let (negative_result, _) = scan_case(id, FixtureCase::Negative).await?;
        assert!(negative_result.findings.is_empty(), "{id}: negative");

        let (edge_result, _) = scan_case(id, FixtureCase::Edge).await?;
        for (name, value) in edge.as_object().ok_or("edge summary is not an object")? {
            assert_eq!(summary(&edge_result, 0)[name], *value, "{id}: {name}");
        }
        assert_finding(&edge_result, key, Severity::High, 0);
        assert_redacted(&edge_result)?;
    }
    Ok(())
}

#[tokio::test]
async fn censys_and_shodan_project_only_bounded_asset_counts()
-> Result<(), Box<dyn std::error::Error>> {
    for (id, positive, edge) in [
        (
            "censys",
            json!({
                "records": 2, "unique_hostnames": 1, "unique_domains": 0,
                "unique_ips": 0, "open_ports": 1
            }),
            json!({
                "records": 10_000, "unique_hostnames": 1, "unique_domains": 0,
                "unique_ips": 0, "open_ports": 1
            }),
        ),
        (
            "shodan",
            json!({
                "records": 2, "unique_hostnames": 2, "unique_domains": 0,
                "unique_ips": 2, "open_ports": 2
            }),
            json!({
                "records": 10_000, "unique_hostnames": 1, "unique_domains": 0,
                "unique_ips": 1, "open_ports": 1
            }),
        ),
    ] {
        let (positive_result, _) = scan_case(id, FixtureCase::Positive).await?;
        assert_eq!(summary(&positive_result, 0)["kind"], "host-intelligence");
        for (name, value) in positive
            .as_object()
            .ok_or("asset summary is not an object")?
        {
            assert_eq!(summary(&positive_result, 0)[name], *value, "{id}: {name}");
        }
        assert_finding(
            &positive_result,
            "host-intelligence-observed",
            Severity::Info,
            0,
        );
        assert_redacted(&positive_result)?;

        let (negative_result, _) = scan_case(id, FixtureCase::Negative).await?;
        assert!(negative_result.findings.is_empty(), "{id}: negative");

        let (edge_result, _) = scan_case(id, FixtureCase::Edge).await?;
        for (name, value) in edge.as_object().ok_or("asset edge is not an object")? {
            assert_eq!(summary(&edge_result, 0)[name], *value, "{id}: {name}");
        }
        assert_finding(
            &edge_result,
            "host-intelligence-observed",
            Severity::Info,
            0,
        );
        assert_redacted(&edge_result)?;
    }
    Ok(())
}

#[tokio::test]
async fn ranking_and_tls_assessment_use_structured_bounded_provider_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let (ranking, _) = scan_case("global-ranking", FixtureCase::Positive).await?;
    assert_eq!(
        summary(&ranking, 0),
        &json!({
            "kind": "domain-ranking", "rank": 42, "bucket_present": true,
            "categories": 1
        })
    );
    assert_finding(&ranking, "domain-ranking-observed", Severity::Info, 0);
    let (unranked, _) = scan_case("global-ranking", FixtureCase::Negative).await?;
    assert!(unranked.findings.is_empty());
    let (ranking_edge, _) = scan_case("global-ranking", FixtureCase::Edge).await?;
    assert_eq!(summary(&ranking_edge, 0)["categories"], 10_000);
    assert_redacted(&ranking_edge)?;

    let (tls, _) = scan_case("ssl-labs-report", FixtureCase::Positive).await?;
    assert_eq!(
        summary(&tls, 0),
        &json!({
            "kind": "external-tls-assessment", "ready": true, "endpoints": 2,
            "strong_endpoints": 1, "weak_endpoints": 1
        })
    );
    assert_finding(&tls, "external-tls-grade-risk", Severity::Medium, 0);
    let (strong_tls, _) = scan_case("ssl-labs-report", FixtureCase::Negative).await?;
    assert!(strong_tls.findings.is_empty());
    let (tls_edge, _) = scan_case("ssl-labs-report", FixtureCase::Edge).await?;
    assert_eq!(summary(&tls_edge, 0)["endpoints"], 10_000);
    assert_eq!(summary(&tls_edge, 0)["weak_endpoints"], 10_000);
    assert_redacted(&tls_edge)?;
    Ok(())
}

#[tokio::test]
async fn threat_scanners_correlate_only_structured_provider_risk_signals()
-> Result<(), Box<dyn std::error::Error>> {
    for (id, expected_evidence, expected_findings) in [
        (
            "domain-shadowing-detector",
            2,
            vec![("malicious-urlscan-observation", 1)],
        ),
        (
            "ip-reputation-trending",
            1,
            vec![("provider-reputation-risk", 0)],
        ),
        (
            "js-malware-scanner",
            3,
            vec![
                ("provider-reputation-risk", 0),
                ("malicious-urlscan-observation", 1),
                ("provider-reputation-risk", 2),
            ],
        ),
        (
            "malware-phishing",
            3,
            vec![
                ("provider-reputation-risk", 0),
                ("malicious-urlscan-observation", 1),
                ("provider-reputation-risk", 2),
            ],
        ),
        (
            "threat-feed-correlator",
            3,
            vec![
                ("provider-reputation-risk", 0),
                ("provider-reputation-risk", 1),
                ("provider-reputation-risk", 2),
            ],
        ),
        ("virustotal-scan", 1, vec![("provider-reputation-risk", 0)]),
    ] {
        let (positive, _) = scan_case(id, FixtureCase::Positive).await?;
        assert_eq!(positive.status, ExecutionStatus::Completed, "{id}");
        assert_eq!(positive.evidence.len(), expected_evidence, "{id}");
        for (key, evidence) in expected_findings {
            assert_finding_at(&positive, key, evidence);
        }
        assert_redacted(&positive)?;

        let (negative, _) = scan_case(id, FixtureCase::Negative).await?;
        assert!(negative.findings.is_empty(), "{id}: negative");

        let (edge, _) = scan_case(id, FixtureCase::Edge).await?;
        assert_eq!(edge.evidence.len(), expected_evidence, "{id}: edge");
        assert!(serde_json::to_string(&edge)?.len() < 100_000, "{id}: edge");
        assert_redacted(&edge)?;
    }
    Ok(())
}

#[tokio::test]
async fn doh_and_geo_scanners_project_counts_and_correlate_two_real_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let (doh, requests) = scan_case("dns-over-https", FixtureCase::Positive).await?;
    assert_eq!(doh.evidence.len(), 2);
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| {
        request.operation == "resolve"
            && request.query.get("name") == Some(&json!("example.com"))
            && request.query.get("type") == Some(&json!("A"))
    }));
    for observation in &doh.evidence {
        assert_eq!(
            observation.observation["observation"],
            json!({
                "kind": "dns-over-https", "status": 0, "answers": 2,
                "truncated": false, "authenticated_data": true
            })
        );
    }
    assert!(doh.findings.is_empty());
    assert_redacted(&doh)?;
    let (doh_negative, _) = scan_case("dns-over-https", FixtureCase::Negative).await?;
    assert!(doh_negative.findings.is_empty());
    let (doh_edge, _) = scan_case("dns-over-https", FixtureCase::Edge).await?;
    assert!(doh_edge.evidence.iter().all(|evidence| {
        evidence.observation["observation"]["answers"] == 10_000
            && evidence.observation["observation"]["truncated"] == true
    }));
    assert_redacted(&doh_edge)?;

    let (mismatch, _) = scan_case("geo-ip-spoof-detection", FixtureCase::Positive).await?;
    assert_eq!(mismatch.evidence.len(), 2);
    assert!(mismatch.evidence.iter().all(|evidence| {
        let summary = &evidence.observation["observation"];
        summary["kind"] == "geolocation-source"
            && summary["country_sha256"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64)
    }));
    let finding = mismatch
        .findings
        .iter()
        .find(|finding| finding.key == "geolocation-source-mismatch")
        .ok_or("missing geolocation mismatch")?;
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    assert_eq!(finding.evidence, [0, 1]);
    assert_redacted(&mismatch)?;
    let (same_country, _) = scan_case("geo-ip-spoof-detection", FixtureCase::Negative).await?;
    assert!(same_country.findings.is_empty());
    let (geo_edge, _) = scan_case("geo-ip-spoof-detection", FixtureCase::Edge).await?;
    assert!(geo_edge.findings.is_empty());
    assert_redacted(&geo_edge)?;
    Ok(())
}

#[tokio::test]
async fn every_wave5_scanner_preserves_all_typed_provider_failures()
-> Result<(), Box<dyn std::error::Error>> {
    for kind in [
        PortErrorKind::Internal,
        PortErrorKind::Unavailable,
        PortErrorKind::Timeout,
        PortErrorKind::InvalidResponse,
        PortErrorKind::RateLimited,
        PortErrorKind::Transport,
        PortErrorKind::OutOfScope,
        PortErrorKind::TooLarge,
    ] {
        let mut services = support::Harness::successful().services();
        services.provider = Arc::new(FailingProvider { kind });
        let builtins = build_builtins(&services)?;
        for id in SCANNERS {
            let scanner_id = sugra_domain::ScannerId::new(id)?;
            let scanner = builtins
                .registry
                .get(&scanner_id)
                .ok_or("failure scanner is missing")?;
            let request = support::request_for(scanner.descriptor())?;
            let Err(error) = scanner.scan(&request, &support::context(false)).await else {
                return Err(format!("{id} {kind:?} all-provider failure became success").into());
            };
            assert_eq!(
                error.kind,
                ScanErrorKind::DependencyUnavailable,
                "{id} {kind:?}"
            );
            assert!(!error.message.contains(SECRET), "{id} {kind:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn multi_source_scanners_return_bounded_partial_results()
-> Result<(), Box<dyn std::error::Error>> {
    for id in [
        "dns-over-https",
        "domain-shadowing-detector",
        "geo-ip-spoof-detection",
        "js-malware-scanner",
        "malware-phishing",
        "threat-feed-correlator",
    ] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let failed_provider = expected_calls(id)
            .first()
            .ok_or("multi-source call plan is missing")?
            .0;
        let mut services = support::Harness::successful().services();
        services.provider = Arc::new(PartialProvider {
            scanner_id: id,
            failed_provider,
            requests: requests.clone(),
        });
        let builtins = build_builtins(&services)?;
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("partial scanner is missing")?;
        let request = support::request_for(scanner.descriptor())?;
        let result = scanner.scan(&request, &support::context(false)).await?;
        assert_eq!(result.status, ExecutionStatus::Partial, "{id}");
        assert_eq!(result.evidence.len(), expected_calls(id).len() - 1, "{id}");
        assert!(!result.diagnostics.is_empty(), "{id}");
        assert_redacted(&result)?;
        assert_eq!(
            requests
                .lock()
                .map_err(|_| "partial request lock poisoned")?
                .len(),
            expected_calls(id).len(),
            "{id}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn provider_request_budget_is_enforced_for_all_wave5_scanners()
-> Result<(), Box<dyn std::error::Error>> {
    for id in SCANNERS {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut services = support::Harness::successful().services();
        services.provider = Arc::new(RecordingProvider {
            requests: requests.clone(),
        });
        let builtins = build_builtins(&services)?;
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("budget scanner is missing")?;
        let mut request = support::request_for(scanner.descriptor())?;
        request.budget.max_requests = 1;
        let result = scanner.scan(&request, &support::context(false)).await?;
        assert_eq!(result.evidence.len(), 1, "{id}");
        let requests = requests
            .lock()
            .map_err(|_| "budget request lock poisoned")?;
        assert_eq!(requests.len(), 1, "{id}");
        assert_eq!(requests[0].budget.max_requests, 1, "{id}");
    }
    Ok(())
}

#[tokio::test]
async fn provider_scanners_recheck_cancellation_between_external_calls()
-> Result<(), Box<dyn std::error::Error>> {
    let context = support::context(false);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.provider = Arc::new(CancellingProvider {
        cancellation: context.cancellation.clone(),
        requests: Arc::clone(&requests),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("threat-feed-correlator")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let request = support::request_for(scanner.descriptor())?;

    let result = scanner.scan(&request, &context).await?;

    assert_eq!(result.status, ExecutionStatus::Cancelled);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(
        requests
            .lock()
            .map_err(|_| "request log unavailable")?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn doh_provider_options_are_validated_and_deduplicated()
-> Result<(), Box<dyn std::error::Error>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.provider = Arc::new(RecordingProvider {
        requests: requests.clone(),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("dns-over-https")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("DoH scanner is missing")?;

    let mut request = support::request_for(scanner.descriptor())?;
    request
        .options
        .insert("providers".into(), json!(["google", "google-doh"]));
    scanner.scan(&request, &support::context(false)).await?;
    {
        let recorded = requests.lock().map_err(|_| "DoH request lock poisoned")?;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].provider, "google-doh");
    }

    request
        .options
        .insert("providers".into(), json!(["unsupported-resolver"]));
    let Err(error) = scanner.scan(&request, &support::context(false)).await else {
        return Err("unsupported DoH provider became success".into());
    };
    assert_eq!(error.kind, ScanErrorKind::InvalidInput);
    Ok(())
}
