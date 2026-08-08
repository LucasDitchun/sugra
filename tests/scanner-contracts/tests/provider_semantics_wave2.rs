//! Public runtime contracts for the second provider-analysis wave.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use sugra_core::{PortError, ProviderPort, ProviderRequest, ProviderResponse, ScanErrorKind};
use sugra_domain::{
    Confidence, ExecutionStatus, ScanResult, ScopeGrant, Severity, Target, TargetKind,
};
use sugra_scanners::build_builtins;
use time::OffsetDateTime;

#[allow(dead_code)]
mod support;

const PROVIDER_LIMIT: usize = 10_000;
const OVER_LIMIT: usize = PROVIDER_LIMIT + 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureCase {
    Positive,
    Negative,
    Edge,
    WildcardOnly,
    TargetOnly,
}

struct FixtureProvider {
    scanner_id: &'static str,
    case: FixtureCase,
}

#[async_trait]
impl ProviderPort for FixtureProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        Ok(ProviderResponse {
            provider: request.provider.clone(),
            data: provider_data(self.scanner_id, &request.provider, self.case),
            duration_ms: 1,
        })
    }
}

fn provider_data(scanner_id: &str, provider: &str, case: FixtureCase) -> Value {
    match (scanner_id, provider, case) {
        ("archive-history", "wayback", FixtureCase::Positive) => json!([[
            "20200102030405",
            "https://private.example/a",
            "200",
            "private-digest"
        ]]),
        ("archive-history", "wayback", FixtureCase::Edge) => edge_wayback(),
        ("asn-lookup" | "rdap-lookup", "rdap", FixtureCase::Positive) => json!({
            "handle": "PRIVATE-HANDLE",
            "startAutnum": 64500,
            "entities": [{"handle": "PRIVATE-CONTACT", "roles": ["registrant"]}]
        }),
        ("asn-lookup" | "rdap-lookup", "rdap", FixtureCase::Edge) => edge_rdap(),
        ("asn-lookup" | "bgp-route-analysis", "ripestat", FixtureCase::Positive) => {
            json!({"data": {"asns": [64500], "routes": [{"status": "valid"}]}})
        }
        ("asn-lookup" | "bgp-route-analysis", "ripestat", FixtureCase::Edge) => edge_ripestat(),
        ("associated-hosts" | "reverse-ip-lookup", "urlscan", FixtureCase::Positive) => {
            json!({
                "results": [{"page": {"domain": "private.example", "ip": "192.0.2.10"}}]
            })
        }
        ("associated-hosts" | "reverse-ip-lookup", "urlscan", FixtureCase::Edge) => edge_urlscan(),
        (
            "associated-hosts" | "ct-log-query" | "subdomain-enum",
            "crtsh",
            FixtureCase::Positive,
        ) => json!([{
            "issuer_name": "Private CA",
            "name_value": "host.private.example"
        }]),
        ("associated-hosts" | "ct-log-query" | "subdomain-enum", "crtsh", FixtureCase::Edge) => {
            edge_crtsh()
        }
        ("associated-hosts", "crtsh", FixtureCase::WildcardOnly) => json!([{
            "issuer_name": "Private CA",
            "name_value": "*.private.example"
        }]),
        ("associated-hosts", "shodan", FixtureCase::Positive) => json!({
            "hostnames": ["private.example"],
            "ip_str": "192.0.2.10",
            "data": [{"port": 443}]
        }),
        ("associated-hosts", "shodan", FixtureCase::Edge) => edge_shodan(),
        ("associated-hosts", "shodan", FixtureCase::TargetOnly) => json!({
            "ip_str": "192.0.2.10",
            "data": [{"port": 443, "banner": support::SECRET_MARKER}]
        }),
        _ => json!({}),
    }
}

fn edge_wayback() -> Value {
    Value::Array(
        (0..OVER_LIMIT)
            .map(|_| {
                json!([
                    "20240203040506",
                    "https://private.example/archive",
                    "200",
                    support::SECRET_MARKER
                ])
            })
            .collect(),
    )
}

fn edge_rdap() -> Value {
    let entities: Vec<_> = (0..OVER_LIMIT)
        .map(|_| {
            json!({
                "handle": "PRIVATE-CONTACT",
                "roles": ["registrant", "REGISTRANT"],
                "email": support::SECRET_MARKER
            })
        })
        .collect();
    json!({
        "handle": "PRIVATE-HANDLE",
        "startAddress": "192.0.2.0",
        "startAutnum": 64500,
        "endAutnum": 64500,
        "entities": entities,
        "notices": [{"description": [support::SECRET_MARKER]}]
    })
}

fn edge_ripestat() -> Value {
    let origins = vec![json!(64500); OVER_LIMIT];
    let routes = vec![json!({"status": "valid", "resource": support::SECRET_MARKER}); OVER_LIMIT];
    json!({"data": {"asns": origins, "routes": routes}})
}

fn edge_urlscan() -> Value {
    let results = vec![
        json!({
            "page": {"domain": "Private.Example", "ip": "192.0.2.10"},
            "raw": support::SECRET_MARKER
        });
        OVER_LIMIT
    ];
    json!({"results": results})
}

fn edge_crtsh() -> Value {
    Value::Array(
        (0..OVER_LIMIT)
            .map(|_| {
                json!({
                    "issuer_name": "Private CA",
                    "name_value": "*.private.example\nhost.private.example",
                    "raw": support::SECRET_MARKER
                })
            })
            .collect(),
    )
}

fn edge_shodan() -> Value {
    let services = vec![
        json!({
            "port": 443,
            "ip_str": "192.0.2.10",
            "banner": support::SECRET_MARKER
        });
        OVER_LIMIT
    ];
    json!({
        "hostnames": ["Private.Example", "private.example"],
        "domains": ["private.example", "PRIVATE.EXAMPLE"],
        "ip_str": "192.0.2.10",
        "data": services
    })
}

async fn scan(
    id: &'static str,
    case: FixtureCase,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    scan_with(id, case, None, &[]).await
}

async fn scan_with(
    id: &'static str,
    case: FixtureCase,
    target: Option<Target>,
    options: &[(&str, Value)],
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.provider = Arc::new(FixtureProvider {
        scanner_id: id,
        case,
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("fixture scanner is missing from the registry")?;
    let mut request = support::request_for(scanner.descriptor())?;
    if let Some(target) = target {
        request.scope = ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH);
        request.target = target;
    }
    for (key, value) in options {
        request.options.insert((*key).into(), value.clone());
    }
    let result = scanner.scan(&request, &support::context(false)).await?;
    assert_eq!(result.status, ExecutionStatus::Completed, "{id}");
    assert!(result.diagnostics.is_empty(), "{id}");
    let expected_kind = format!("{id}-provider-observation");
    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| evidence.kind == expected_kind),
        "{id} emitted a non-specific provider evidence kind"
    );
    Ok(result)
}

fn assert_completed(result: &ScanResult) {
    assert_eq!(result.status, ExecutionStatus::Completed);
    assert!(result.diagnostics.is_empty());
}

fn assert_observation(result: &ScanResult, index: usize, source: &str, expected: impl Into<Value>) {
    let evidence = result.evidence.get(index);
    assert!(evidence.is_some(), "missing evidence {index}");
    let Some(evidence) = evidence else {
        return;
    };
    let scanner_id = evidence.kind.strip_suffix("-provider-observation");
    assert!(
        scanner_id.is_some(),
        "provider evidence kind must identify its scanner"
    );
    let Some(scanner_id) = scanner_id else {
        return;
    };
    let envelope = semantic_envelope(scanner_id);
    assert!(
        envelope.is_some(),
        "unexpected provider scanner {scanner_id}"
    );
    let Some((analysis, purpose)) = envelope else {
        return;
    };
    assert_eq!(evidence.source, source);
    assert_eq!(
        evidence.observation,
        json!({
            "scanner_id": scanner_id,
            "analysis": analysis,
            "purpose": purpose,
            "observation": expected.into()
        })
    );
}

fn semantic_envelope(scanner_id: &str) -> Option<(&'static str, &'static str)> {
    let envelope = match scanner_id {
        "archive-history" => (
            "historical-source-analysis",
            "Collect historical URLs and snapshots.",
        ),
        "asn-lookup" => (
            "registration-source-analysis",
            "Resolve autonomous-system ownership and registration data.",
        ),
        "associated-hosts" => (
            "asset-source-analysis",
            "Correlate hosts associated with a domain or address.",
        ),
        "bgp-route-analysis" => (
            "routing-source-analysis",
            "Inspect announced prefixes and route-origin context.",
        ),
        "ct-log-query" => (
            "certificate-source-analysis",
            "Query certificate-transparency observations.",
        ),
        "rdap-lookup" => (
            "registration-source-analysis",
            "Retrieve structured registration data through RDAP.",
        ),
        "reverse-ip-lookup" => (
            "asset-source-analysis",
            "Correlate hostnames observed on an address.",
        ),
        "subdomain-enum" => (
            "asset-source-analysis",
            "Enumerate public subdomain observations.",
        ),
        _ => return None,
    };
    Some(envelope)
}

fn assert_findings(result: &ScanResult, key: &str, evidence_indexes: &[usize]) {
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.key == key)
        .collect();
    assert_eq!(findings.len(), evidence_indexes.len(), "{key}");
    for (finding, evidence) in findings.into_iter().zip(evidence_indexes) {
        assert_eq!(finding.severity, Severity::Info, "{key}");
        assert_eq!(finding.confidence, Confidence::Confirmed, "{key}");
        assert_eq!(finding.evidence, vec![*evidence], "{key}");
    }
}

fn assert_no_finding(result: &ScanResult, key: &str) {
    assert!(
        result.findings.iter().all(|finding| finding.key != key),
        "unexpected {key}"
    );
}

fn assert_redacted(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serde_json::to_string(result)?;
    for forbidden in [
        support::SECRET_MARKER,
        "private.example",
        "Private.Example",
        "PRIVATE-HANDLE",
        "PRIVATE-CONTACT",
        "Private CA",
        "192.0.2.10",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
    Ok(())
}

async fn assert_typed_failure(id: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    let harness = support::Harness::failing();
    let builtins = build_builtins(&harness.services())?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("failure scanner is missing from the registry")?;
    let request = support::request_for(scanner.descriptor())?;
    let Err(error) = scanner.scan(&request, &support::context(false)).await else {
        return Err(format!("{id} converted provider failure into success").into());
    };
    assert_eq!(error.kind, ScanErrorKind::DependencyUnavailable, "{id}");
    assert_eq!(error.message, "offline fixture boundary failure", "{id}");
    assert!(!error.message.contains(support::SECRET_MARKER));
    Ok(())
}

#[tokio::test]
async fn archive_history_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "archive-history";
    const KEY: &str = "archived-snapshots-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_completed(&positive);
    assert_observation(
        &positive,
        0,
        "wayback",
        json!({
            "kind": "archive-history",
            "snapshots": 1,
            "unique_urls": 1,
            "unique_statuses": 1,
            "unique_digests": 1,
            "earliest_year": 2020,
            "latest_year": 2020
        }),
    );
    assert_findings(&positive, KEY, &[0]);

    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_observation(
        &negative,
        0,
        "wayback",
        json!({
            "kind": "archive-history",
            "snapshots": 0,
            "unique_urls": 0,
            "unique_statuses": 0,
            "unique_digests": 0,
            "earliest_year": null,
            "latest_year": null
        }),
    );
    assert_no_finding(&negative, KEY);

    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_observation(
        &edge,
        0,
        "wayback",
        json!({
            "kind": "archive-history",
            "snapshots": PROVIDER_LIMIT,
            "unique_urls": 1,
            "unique_statuses": 1,
            "unique_digests": 1,
            "earliest_year": 2024,
            "latest_year": 2024
        }),
    );
    assert_findings(&edge, KEY, &[0]);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn asn_lookup_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "asn-lookup";
    const KEY: &str = "autonomous-system-context-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_observation(
        &positive,
        0,
        "rdap",
        json!({
            "kind": "registration",
            "handles": 2,
            "entities": 1,
            "roles": 1,
            "networks": 0,
            "autonomous_systems": 1,
            "notices": 0
        }),
    );
    assert_findings(&positive, KEY, &[0]);

    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_observation(
        &negative,
        0,
        "rdap",
        json!({
            "kind": "registration",
            "handles": 0,
            "entities": 0,
            "roles": 0,
            "networks": 0,
            "autonomous_systems": 0,
            "notices": 0
        }),
    );
    assert_no_finding(&negative, KEY);

    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_observation(
        &edge,
        0,
        "rdap",
        json!({
            "kind": "registration",
            "handles": 2,
            "entities": PROVIDER_LIMIT,
            "roles": 1,
            "networks": 1,
            "autonomous_systems": 1,
            "notices": 1
        }),
    );
    assert_findings(&edge, KEY, &[0]);
    assert_redacted(&edge)?;

    let ripe = scan_with(
        ID,
        FixtureCase::Positive,
        Some(Target::parse(TargetKind::Ip, "192.0.2.10")?),
        &[("provider", json!("ripestat"))],
    )
    .await?;
    assert_observation(
        &ripe,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "routing",
            "prefixes": 0,
            "origins": 1,
            "valid_routes": 1,
            "invalid_routes": 0,
            "unknown_routes": 0
        }),
    );
    assert_findings(&ripe, KEY, &[0]);
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn associated_hosts_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    assert_associated_default_sources().await?;
    assert_associated_wildcard_is_not_concrete().await?;
    assert_associated_shodan_semantics().await?;
    assert_typed_failure("associated-hosts").await
}

async fn assert_associated_default_sources() -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("associated-hosts", FixtureCase::Positive).await?;
    assert_completed(&positive);
    assert_observation(&positive, 0, "crtsh", ct_summary(1, 1, 1, 0));
    assert_observation(
        &positive,
        1,
        "urlscan.io (https://urlscan.io/)",
        urlscan_summary(1, 1, 1),
    );
    assert_findings(&positive, "associated-hosts-observed", &[0, 1]);

    let negative = scan("associated-hosts", FixtureCase::Negative).await?;
    assert_observation(&negative, 0, "crtsh", ct_summary(0, 0, 0, 0));
    assert_observation(
        &negative,
        1,
        "urlscan.io (https://urlscan.io/)",
        urlscan_summary(0, 0, 0),
    );
    assert_no_finding(&negative, "associated-hosts-observed");

    let edge = scan("associated-hosts", FixtureCase::Edge).await?;
    assert_observation(&edge, 0, "crtsh", ct_summary(PROVIDER_LIMIT, 2, 1, 1));
    assert_observation(
        &edge,
        1,
        "urlscan.io (https://urlscan.io/)",
        urlscan_summary(PROVIDER_LIMIT, 1, 1),
    );
    assert_findings(&edge, "associated-hosts-observed", &[0, 1]);
    assert_redacted(&edge)?;
    Ok(())
}

async fn assert_associated_wildcard_is_not_concrete() -> Result<(), Box<dyn std::error::Error>> {
    let wildcard_only = scan_with(
        "associated-hosts",
        FixtureCase::WildcardOnly,
        None,
        &[("sources", json!(["crtsh"]))],
    )
    .await?;
    assert_observation(&wildcard_only, 0, "crtsh", ct_summary(1, 1, 1, 1));
    assert_no_finding(&wildcard_only, "associated-hosts-observed");
    Ok(())
}

async fn assert_associated_shodan_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let ip = Target::parse(TargetKind::Ip, "192.0.2.10")?;
    let shodan = scan_with(
        "associated-hosts",
        FixtureCase::Positive,
        Some(ip.clone()),
        &[("sources", json!(["shodan"]))],
    )
    .await?;
    assert_observation(&shodan, 0, "shodan", host_summary(1, 1, 0, 1, 1));
    assert_findings(&shodan, "associated-hosts-observed", &[0]);

    let shodan_target_only = scan_with(
        "associated-hosts",
        FixtureCase::TargetOnly,
        Some(ip.clone()),
        &[("sources", json!(["shodan"]))],
    )
    .await?;
    assert_observation(
        &shodan_target_only,
        0,
        "shodan",
        host_summary(1, 0, 0, 1, 1),
    );
    assert_no_finding(&shodan_target_only, "associated-hosts-observed");
    assert_redacted(&shodan_target_only)?;

    let shodan_edge = scan_with(
        "associated-hosts",
        FixtureCase::Edge,
        Some(ip),
        &[("sources", json!(["shodan"]))],
    )
    .await?;
    assert_observation(
        &shodan_edge,
        0,
        "shodan",
        host_summary(PROVIDER_LIMIT, 1, 1, 1, 1),
    );
    assert_findings(&shodan_edge, "associated-hosts-observed", &[0]);
    assert_redacted(&shodan_edge)?;
    Ok(())
}

fn ct_summary(records: usize, names: usize, issuers: usize, wildcards: usize) -> Value {
    json!({
        "kind": "certificate-transparency",
        "records": records,
        "unique_names": names,
        "unique_issuers": issuers,
        "wildcard_names": wildcards
    })
}

fn urlscan_summary(records: usize, domains: usize, ips: usize) -> Value {
    json!({
        "kind": "url-scan",
        "records": records,
        "unique_domains": domains,
        "unique_ips": ips,
        "malicious_records": 0
    })
}

fn host_summary(
    records: usize,
    hostnames: usize,
    domains: usize,
    ips: usize,
    ports: usize,
) -> Value {
    json!({
        "kind": "host-intelligence",
        "records": records,
        "unique_hostnames": hostnames,
        "unique_domains": domains,
        "unique_ips": ips,
        "open_ports": ports
    })
}

#[tokio::test]
async fn bgp_route_analysis_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "bgp-route-analysis";
    const KEY: &str = "routing-observations-present";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_observation(
        &positive,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "routing",
            "prefixes": 0,
            "origins": 1,
            "valid_routes": 1,
            "invalid_routes": 0,
            "unknown_routes": 0
        }),
    );
    assert_findings(&positive, KEY, &[0]);

    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_observation(
        &negative,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "routing",
            "prefixes": 0,
            "origins": 0,
            "valid_routes": 0,
            "invalid_routes": 0,
            "unknown_routes": 0
        }),
    );
    assert_no_finding(&negative, KEY);

    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_observation(
        &edge,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "routing",
            "prefixes": 0,
            "origins": PROVIDER_LIMIT,
            "valid_routes": PROVIDER_LIMIT,
            "invalid_routes": 0,
            "unknown_routes": 0
        }),
    );
    assert_findings(&edge, KEY, &[0]);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn ct_log_query_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "ct-log-query";
    const KEY: &str = "certificate-transparency-record-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_observation(
        &positive,
        0,
        "crtsh",
        json!({
            "kind": "certificate-transparency",
            "records": 1,
            "unique_names": 1,
            "unique_issuers": 1,
            "wildcard_names": 0
        }),
    );
    assert_findings(&positive, KEY, &[0]);

    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_observation(
        &negative,
        0,
        "crtsh",
        json!({
            "kind": "certificate-transparency",
            "records": 0,
            "unique_names": 0,
            "unique_issuers": 0,
            "wildcard_names": 0
        }),
    );
    assert_no_finding(&negative, KEY);

    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_observation(
        &edge,
        0,
        "crtsh",
        json!({
            "kind": "certificate-transparency",
            "records": PROVIDER_LIMIT,
            "unique_names": 2,
            "unique_issuers": 1,
            "wildcard_names": 1
        }),
    );
    assert_findings(&edge, KEY, &[0]);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn rdap_lookup_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "rdap-lookup";
    const KEY: &str = "registration-data-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_observation(
        &positive,
        0,
        "rdap",
        json!({
            "kind": "registration",
            "handles": 2,
            "entities": 1,
            "roles": 1,
            "networks": 0,
            "autonomous_systems": 1,
            "notices": 0
        }),
    );
    assert_findings(&positive, KEY, &[0]);

    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_observation(
        &negative,
        0,
        "rdap",
        json!({
            "kind": "registration",
            "handles": 0,
            "entities": 0,
            "roles": 0,
            "networks": 0,
            "autonomous_systems": 0,
            "notices": 0
        }),
    );
    assert_no_finding(&negative, KEY);

    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_observation(
        &edge,
        0,
        "rdap",
        json!({
            "kind": "registration",
            "handles": 2,
            "entities": PROVIDER_LIMIT,
            "roles": 1,
            "networks": 1,
            "autonomous_systems": 1,
            "notices": 1
        }),
    );
    assert_findings(&edge, KEY, &[0]);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn reverse_ip_lookup_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "reverse-ip-lookup";
    const KEY: &str = "reverse-ip-host-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_observation(
        &positive,
        0,
        "urlscan.io (https://urlscan.io/)",
        json!({
            "kind": "url-scan",
            "records": 1,
            "unique_domains": 1,
            "unique_ips": 1,
            "malicious_records": 0
        }),
    );
    assert_findings(&positive, KEY, &[0]);

    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_observation(
        &negative,
        0,
        "urlscan.io (https://urlscan.io/)",
        json!({
            "kind": "url-scan",
            "records": 0,
            "unique_domains": 0,
            "unique_ips": 0,
            "malicious_records": 0
        }),
    );
    assert_no_finding(&negative, KEY);

    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_observation(
        &edge,
        0,
        "urlscan.io (https://urlscan.io/)",
        json!({
            "kind": "url-scan",
            "records": PROVIDER_LIMIT,
            "unique_domains": 1,
            "unique_ips": 1,
            "malicious_records": 0
        }),
    );
    assert_findings(&edge, KEY, &[0]);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn subdomain_enum_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "subdomain-enum";
    const KEY: &str = "subdomain-observations-present";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_observation(
        &positive,
        0,
        "crtsh",
        json!({
            "kind": "certificate-transparency",
            "records": 1,
            "unique_names": 1,
            "unique_issuers": 1,
            "wildcard_names": 0
        }),
    );
    assert_findings(&positive, KEY, &[0]);

    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_observation(
        &negative,
        0,
        "crtsh",
        json!({
            "kind": "certificate-transparency",
            "records": 0,
            "unique_names": 0,
            "unique_issuers": 0,
            "wildcard_names": 0
        }),
    );
    assert_no_finding(&negative, KEY);

    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_observation(
        &edge,
        0,
        "crtsh",
        json!({
            "kind": "certificate-transparency",
            "records": PROVIDER_LIMIT,
            "unique_names": 2,
            "unique_issuers": 1,
            "wildcard_names": 1
        }),
    );
    assert_findings(&edge, KEY, &[0]);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}
