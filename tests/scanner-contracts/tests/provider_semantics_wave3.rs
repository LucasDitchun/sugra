//! Public runtime contracts for the third provider-analysis wave.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};
use sugra_core::{
    PortError, PortErrorKind, ProviderPort, ProviderRequest, ProviderResponse, ScanError,
    ScanErrorKind,
};
use sugra_domain::{
    Confidence, ExecutionStatus, ScanResult, ScopeGrant, Severity, Target, TargetKind,
};
use sugra_scanners::build_builtins;
use time::OffsetDateTime;

#[allow(dead_code)]
mod support;

const PROVIDER_LIMIT: usize = 10_000;
const OVER_LIMIT: usize = PROVIDER_LIMIT + 5;

#[test]
fn provider_catalog_targets_match_real_operation_inputs() -> Result<(), Box<dyn std::error::Error>>
{
    let services = support::Harness::successful().services();
    let builtins = build_builtins(&services)?;
    for (id, expected) in [
        ("autonomous-neighbor-peering-map", vec![TargetKind::Asn]),
        (
            "ip-allocation-history-tracker",
            vec![TargetKind::Cidr, TargetKind::Asn],
        ),
        ("network-timezone-detection", vec![TargetKind::Ip]),
        ("server-location", vec![TargetKind::Ip]),
        (
            "irr-routing-registry-analyzer",
            vec![TargetKind::Asn, TargetKind::Ip],
        ),
    ] {
        let descriptor = builtins
            .catalog
            .iter()
            .find(|descriptor| descriptor.id.as_str() == id)
            .ok_or("provider scanner descriptor is missing")?;
        assert_eq!(descriptor.target_kinds, expected, "{id}");
    }
    Ok(())
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
}

struct FailingProvider {
    kind: PortErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainFixtureCase {
    Positive,
    NoAddress,
    EnricherFailure,
    MultipleAddresses,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DomainCall {
    provider: String,
    operation: String,
    address: Option<String>,
}

struct DomainFixtureProvider {
    case: DomainFixtureCase,
    calls: Arc<Mutex<Vec<DomainCall>>>,
}

#[async_trait]
impl ProviderPort for FailingProvider {
    async fn query(&self, _request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        Err(PortError::new(self.kind, "provider boundary failure"))
    }
}

#[async_trait]
impl ProviderPort for FixtureProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        assert!(
            expected_call(self.scanner_id, &request.provider, &request.operation),
            "unexpected {} call: {}/{}",
            self.scanner_id,
            request.provider,
            request.operation
        );
        Ok(ProviderResponse {
            provider: request.provider.clone(),
            data: provider_data(self.scanner_id, self.case, &request),
            duration_ms: 1,
        })
    }
}

#[async_trait]
impl ProviderPort for DomainFixtureProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        let address = (request.operation != "dns-chain")
            .then(|| {
                request
                    .query
                    .get("resource")
                    .or_else(|| request.query.get("target"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten();
        self.calls
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "fixture call lock failed"))?
            .push(DomainCall {
                provider: request.provider.clone(),
                operation: request.operation.clone(),
                address,
            });
        let data = domain_fixture_data(self.case, &request)?;
        Ok(ProviderResponse {
            provider: request.provider,
            data,
            duration_ms: 1,
        })
    }
}

fn domain_fixture_data(
    case: DomainFixtureCase,
    request: &ProviderRequest,
) -> Result<Value, PortError> {
    match (request.provider.as_str(), request.operation.as_str(), case) {
        ("ripestat", "dns-chain", DomainFixtureCase::NoAddress) => Ok(json!({
            "data": {"forward_nodes": {"example.com": ["not-an-address", "alias.example"]}}
        })),
        ("ripestat", "dns-chain", DomainFixtureCase::MultipleAddresses) => Ok(json!({
            "data": {"forward_nodes": {"example.com": [
                "192.0.2.12", "192.0.2.10", "192.0.2.11", "192.0.2.10"
            ]}}
        })),
        ("ripestat", "dns-chain", _) => Ok(json!({
            "data": {"forward_nodes": {"example.com": ["192.0.2.10"]}}
        })),
        ("ripestat", "network-info", DomainFixtureCase::EnricherFailure) => Err(PortError::new(
            PortErrorKind::RateLimited,
            format!("network enricher rejected {}", support::SECRET_MARKER),
        )),
        ("ripestat", "network-info", _) => Ok(json!({
            "data": {"prefix": "192.0.2.0/24", "asns": [64500, 64501]}
        })),
        ("ipinfo", "lookup", DomainFixtureCase::EnricherFailure) => Ok(json!({
            "geo": {"country_code": "BR", "timezone": "America/Sao_Paulo"}
        })),
        ("ipinfo", "lookup", _) => Ok(json!({
            "geo": {
                "city": "Sao Paulo", "region": "SP", "country_code": "BR",
                "timezone": "America/Sao_Paulo", "latitude": -23.5, "longitude": -46.6
            },
            "as": {"asn": "AS64500"}
        })),
        _ => Err(PortError::new(
            PortErrorKind::Internal,
            "unexpected domain fixture provider call",
        )),
    }
}

fn expected_call(scanner_id: &str, provider: &str, operation: &str) -> bool {
    matches!(
        (scanner_id, provider, operation),
        (
            "autonomous-neighbor-peering-map",
            "ripestat",
            "asn-neighbours"
        ) | (
            "ip-allocation-history-tracker",
            "ripestat",
            "historical-whois"
        ) | (
            "ip-info" | "ns-geo-asn-diversity-analyzer",
            "ripestat",
            "dns-chain" | "network-info"
        ) | (
            "ip-info"
                | "network-timezone-detection"
                | "server-location"
                | "ns-geo-asn-diversity-analyzer",
            "ipinfo",
            "lookup"
        ) | ("certificate-authority-recon", "crtsh", "query")
            | ("irr-routing-registry-analyzer", "ripestat", "whois")
    )
}

fn provider_data(scanner_id: &str, case: FixtureCase, request: &ProviderRequest) -> Value {
    match scanner_id {
        "autonomous-neighbor-peering-map" => autonomous_neighbor_data(case),
        "ip-allocation-history-tracker" => allocation_history_data(case),
        "ip-info" => ip_info_data(case, request),
        "network-timezone-detection" => timezone_data(case),
        "ns-geo-asn-diversity-analyzer" => nameserver_data(case, request),
        "server-location" => server_location_data(case),
        "certificate-authority-recon" => certificate_authority_data(case),
        "irr-routing-registry-analyzer" => irr_registry_data(case),
        _ => json!({}),
    }
}

fn autonomous_neighbor_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "data": {
                "neighbours": [
                    {"asn": 64500, "type": "left"},
                    {"asn": 64501, "type": "right"},
                    {"asn": 64502, "type": "uncertain"}
                ]
            }
        }),
        FixtureCase::Edge => json!({
            "data": {"neighbours": (0..OVER_LIMIT).map(|_| json!({
                "asn": "AS64500", "position": "left", "raw": support::SECRET_MARKER
            })).collect::<Vec<_>>()}
        }),
        FixtureCase::Negative => json!({}),
    }
}

fn allocation_history_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "data": {
                "num_versions": 2,
                "objects": [{"type": "inetnum", "value": "private allocation"}],
                "referencing": [{"type": "route"}],
                "referenced_by": [{"type": "mntner"}],
                "suggestions": [{"type": "inet6num"}]
            }
        }),
        FixtureCase::Edge => json!({
            "data": {
                "num_versions": u64::MAX,
                "objects": (0..OVER_LIMIT).map(|_| json!({
                    "type": "inetnum", "raw": support::SECRET_MARKER
                })).collect::<Vec<_>>(),
                "referencing": (0..OVER_LIMIT).map(|_| json!({"type": "route"})).collect::<Vec<_>>(),
                "referenced_by": (0..OVER_LIMIT).map(|_| json!({"type": "mntner"})).collect::<Vec<_>>(),
                "suggestions": (0..OVER_LIMIT).map(|_| json!({"type": "inet6num"})).collect::<Vec<_>>()
            }
        }),
        FixtureCase::Negative => json!({}),
    }
}

fn ip_info_data(case: FixtureCase, request: &ProviderRequest) -> Value {
    match (request.provider.as_str(), request.operation.as_str(), case) {
        ("ripestat", "dns-chain", FixtureCase::Positive) => {
            json!({"data": {"forward_nodes": {"example.com": ["192.0.2.10"]}}})
        }
        ("ripestat", "network-info", FixtureCase::Positive) => {
            json!({"data": {"prefix": "192.0.2.0/24", "asns": [64500, 64501]}})
        }
        ("ripestat", "network-info", FixtureCase::Edge) => json!({
            "data": {"prefix": support::SECRET_MARKER, "asns": vec![json!(64500); OVER_LIMIT],
                "raw": support::SECRET_MARKER}
        }),
        ("ipinfo", _, FixtureCase::Positive) => json!({
            "geo": {"city": "Sao Paulo", "region": "SP", "country_code": "BR",
                "timezone": "America/Sao_Paulo", "latitude": -23.5, "longitude": -46.6},
            "as": {"asn": "AS64500"}
        }),
        ("ipinfo", _, FixtureCase::Edge) => json!({
            "city": support::SECRET_MARKER, "country": support::SECRET_MARKER,
            "timezone": support::SECRET_MARKER, "loc": "invalid", "asn": "AS64500"
        }),
        _ => json!({}),
    }
}

fn timezone_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "geo": {
                "country_code": "BR", "timezone": "America/Sao_Paulo",
                "latitude": -23.5, "longitude": -46.6
            }
        }),
        FixtureCase::Edge => json!({
            "country": support::SECRET_MARKER,
            "timezone": support::SECRET_MARKER,
            "loc": "invalid",
            "raw": support::SECRET_MARKER
        }),
        FixtureCase::Negative => json!({}),
    }
}

fn nameserver_data(case: FixtureCase, request: &ProviderRequest) -> Value {
    match (request.provider.as_str(), request.operation.as_str(), case) {
        ("ripestat", "dns-chain", FixtureCase::Positive) => {
            json!({
                "data": {
                    "forward_nodes": {
                        "private.example": ["192.0.2.10", "192.0.2.11"],
                        "ns1.private.example": ["192.0.2.10"],
                        "ns2.private.example": ["192.0.2.11"]
                    },
                    "reverse_nodes": {"192.0.2.10": ["ns1.private.example"]},
                    "nameservers": ["192.0.2.53", "192.0.2.54"],
                    "authoritative_nameservers": ["ns1.private.example", "ns2.private.example."]
                }
            })
        }
        ("ripestat", "network-info", FixtureCase::Positive) => {
            let resource = request.query.get("resource").and_then(Value::as_str);
            json!({"data": {"asns": [if resource == Some("192.0.2.10") {64500} else {64501}]}})
        }
        ("ipinfo", "lookup", FixtureCase::Positive) => {
            let target = request.query.get("target").and_then(Value::as_str);
            json!({"geo": {"country_code": if target == Some("192.0.2.10") {"BR"} else {"US"}}})
        }
        ("ripestat", "dns-chain", FixtureCase::Edge) => json!({
            "data": {
                "forward_nodes": {"private.example": vec![support::SECRET_MARKER; OVER_LIMIT]},
                "reverse_nodes": {"192.0.2.10": vec![support::SECRET_MARKER; OVER_LIMIT]},
                "nameservers": vec![support::SECRET_MARKER; OVER_LIMIT],
                "authoritative_nameservers": vec!["192.0.2.10"; OVER_LIMIT],
                "raw": support::SECRET_MARKER
            }
        }),
        ("ripestat", "network-info", FixtureCase::Edge) => {
            json!({"data": {"asns": [64500], "raw": support::SECRET_MARKER}})
        }
        ("ipinfo", "lookup", FixtureCase::Edge) => {
            json!({"geo": {"country_code": "BR"}, "raw": support::SECRET_MARKER})
        }
        _ => json!({}),
    }
}

fn server_location_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "geo": {
                "city": "Sao Paulo", "region": "SP", "country_code": "BR",
                "latitude": -23.5, "longitude": -46.6
            }
        }),
        FixtureCase::Edge => json!({
            "city": support::SECRET_MARKER, "region": support::SECRET_MARKER,
            "country": support::SECRET_MARKER, "loc": "invalid"
        }),
        FixtureCase::Negative => json!({}),
    }
}

fn certificate_authority_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!([
            {"issuer_name": "Private CA", "name_value": "a.private.example\n*.private.example"}
        ]),
        FixtureCase::Edge => Value::Array(
            (0..OVER_LIMIT)
                .map(|_| {
                    json!({
                        "issuer_name": "Private CA",
                        "name_value": "a.private.example\n*.private.example",
                        "raw": support::SECRET_MARKER
                    })
                })
                .collect(),
        ),
        FixtureCase::Negative => json!({}),
    }
}

fn irr_registry_data(case: FixtureCase) -> Value {
    match case {
        FixtureCase::Positive => json!({
            "data": {
                "authorities": ["ripe", "radb"],
                "records": [[{"key": "aut-num", "value": "AS64500"}]],
                "irr_records": [[
                    {"key": "route", "value": "192.0.2.0/24"},
                    {"key": "origin", "value": "AS64500"},
                    {"key": "source", "value": "RADB"}
                ]]
            }
        }),
        FixtureCase::Edge => json!({
            "data": {
                "authorities": vec![support::SECRET_MARKER; OVER_LIMIT],
                "records": vec![json!([{"key": "aut-num", "value": support::SECRET_MARKER}]); OVER_LIMIT],
                "irr_records": vec![json!([
                    {"key": "route6", "value": support::SECRET_MARKER},
                    {"key": "origin", "value": "AS64500"},
                    {"key": "source", "value": "RADB"}
                ]); OVER_LIMIT]
            }
        }),
        FixtureCase::Negative => json!({}),
    }
}

async fn scan(
    id: &'static str,
    case: FixtureCase,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    scan_with_max_requests(id, case, 8).await
}

async fn scan_with_max_requests(
    id: &'static str,
    case: FixtureCase,
    max_requests: usize,
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
    request.budget.max_requests = max_requests;
    Ok(scanner.scan(&request, &support::context(false)).await?)
}

async fn scan_domain_case(
    case: DomainFixtureCase,
    max_requests: usize,
) -> Result<(Result<ScanResult, ScanError>, Vec<DomainCall>), Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    let calls = Arc::new(Mutex::new(Vec::new()));
    services.provider = Arc::new(DomainFixtureProvider {
        case,
        calls: Arc::clone(&calls),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("ip-info")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("IP info scanner is missing from the registry")?;
    let target = Target::parse(TargetKind::Domain, "example.com")?;
    let mut request = support::request_for(scanner.descriptor())?;
    request.scope = ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH);
    request.target = target;
    request.budget.max_requests = max_requests;
    let result = scanner.scan(&request, &support::context(false)).await;
    let recorded = calls
        .lock()
        .map_err(|_| "fixture call lock failed")?
        .clone();
    Ok((result, recorded))
}

fn assert_summary(result: &ScanResult, expected: Value) {
    assert_eq!(result.status, ExecutionStatus::Completed);
    assert!(result.diagnostics.is_empty());
    assert_eq!(result.evidence.len(), 1);
    let scanner_id = result.evidence[0]
        .kind
        .strip_suffix("-provider-observation")
        .unwrap_or_default();
    let source = match scanner_id {
        "network-timezone-detection" | "server-location" => "IPinfo (https://ipinfo.io/)",
        "ns-geo-asn-diversity-analyzer" => "RIPEstat + IPinfo",
        "certificate-authority-recon" => "crtsh",
        _ => "RIPEstat (https://stat.ripe.net/)",
    };
    assert_observation(result, 0, source, expected);
}

fn assert_observation(result: &ScanResult, index: usize, source: &str, expected: Value) {
    let evidence = &result.evidence[index];
    let scanner_id = evidence
        .kind
        .strip_suffix("-provider-observation")
        .unwrap_or_default();
    let (analysis, purpose) = semantic_envelope(scanner_id).unwrap_or_default();
    assert!(
        !analysis.is_empty(),
        "missing semantic envelope for {scanner_id}"
    );
    let expected_envelope = json!({
        "scanner_id": scanner_id,
        "analysis": analysis,
        "purpose": purpose,
        "observation": expected
    });
    drop(expected);
    assert_eq!(evidence.source, source);
    assert_eq!(evidence.observation, expected_envelope);
}

fn semantic_envelope(scanner_id: &str) -> Option<(&'static str, &'static str)> {
    match scanner_id {
        "autonomous-neighbor-peering-map" => Some((
            "routing-source-analysis",
            "Map upstream, downstream, and peer autonomous systems.",
        )),
        "ip-allocation-history-tracker" => Some((
            "historical-source-analysis",
            "Inspect historical address-allocation observations.",
        )),
        "ip-info" => Some((
            "geolocation-source-analysis",
            "Summarize public network and location metadata for an address.",
        )),
        "network-timezone-detection" => Some((
            "geolocation-source-analysis",
            "Correlate public location and timezone metadata.",
        )),
        "ns-geo-asn-diversity-analyzer" => Some((
            "routing-source-analysis",
            "Assess nameserver network and geographic diversity.",
        )),
        "server-location" => Some((
            "geolocation-source-analysis",
            "Resolve public server location metadata.",
        )),
        "certificate-authority-recon" => Some((
            "certificate-source-analysis",
            "Correlate public certificate authority observations.",
        )),
        "irr-routing-registry-analyzer" => Some((
            "routing-source-analysis",
            "Inspect Internet Routing Registry route objects.",
        )),
        _ => None,
    }
}

fn assert_finding(result: &ScanResult, key: &str) {
    assert_finding_at(result, key, 0);
}

fn assert_finding_at(result: &ScanResult, key: &str, evidence_index: usize) {
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.key == key)
        .collect();
    assert_eq!(findings.len(), 1, "{key}");
    for finding in findings {
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.evidence, vec![evidence_index]);
    }
}

fn assert_no_finding(result: &ScanResult, key: &str) {
    assert!(result.findings.iter().all(|finding| finding.key != key));
}

fn assert_redacted(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serde_json::to_string(result)?;
    for forbidden in [
        support::SECRET_MARKER,
        "private.example",
        "Private CA",
        "192.0.2.10",
        "AS64500",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
    Ok(())
}

async fn assert_typed_failure(id: &'static str) -> Result<(), Box<dyn std::error::Error>> {
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
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("failure scanner is missing from the registry")?;
        let request = support::request_for(scanner.descriptor())?;
        let Err(error) = scanner.scan(&request, &support::context(false)).await else {
            return Err(format!("{id} converted {kind:?} into success").into());
        };
        assert_eq!(
            error.kind,
            ScanErrorKind::DependencyUnavailable,
            "{id} {kind:?}"
        );
        assert_eq!(error.message, "provider boundary failure", "{id} {kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn autonomous_neighbor_peering_map_projects_directional_counts()
-> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "autonomous-neighbor-peering-map";
    const KEY: &str = "autonomous-neighbors-observed";
    let result = scan(ID, FixtureCase::Positive).await?;

    assert_summary(
        &result,
        json!({
            "kind": "autonomous-neighbor-peering-map",
            "records": 3,
            "unique_autonomous_systems": 3,
            "left_neighbors": 1,
            "right_neighbors": 1,
            "uncertain_neighbors": 1
        }),
    );
    assert_finding(&result, KEY);
    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_summary(&negative, neighbor_summary(0, 0, 0, 0, 0));
    assert_no_finding(&negative, KEY);
    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_summary(
        &edge,
        neighbor_summary(PROVIDER_LIMIT, 1, PROVIDER_LIMIT, 0, 0),
    );
    assert_finding(&edge, KEY);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

fn neighbor_summary(
    records: usize,
    unique: usize,
    left: usize,
    right: usize,
    uncertain: usize,
) -> Value {
    json!({
        "kind": "autonomous-neighbor-peering-map",
        "records": records,
        "unique_autonomous_systems": unique,
        "left_neighbors": left,
        "right_neighbors": right,
        "uncertain_neighbors": uncertain
    })
}

#[tokio::test]
async fn ip_allocation_history_projects_versioned_object_counts()
-> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "ip-allocation-history-tracker";
    const KEY: &str = "allocation-history-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_summary(
        &positive,
        json!({
            "kind": "ip-allocation-history",
            "versions": 2,
            "objects": 1,
            "referencing_objects": 1,
            "referenced_objects": 1,
            "suggestions": 1,
            "unique_object_types": 4
        }),
    );
    assert_finding(&positive, KEY);
    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_summary(
        &negative,
        json!({
            "kind": "ip-allocation-history", "versions": 0, "objects": 0,
            "referencing_objects": 0, "referenced_objects": 0, "suggestions": 0,
            "unique_object_types": 0
        }),
    );
    assert_no_finding(&negative, KEY);
    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_summary(
        &edge,
        json!({
            "kind": "ip-allocation-history", "versions": PROVIDER_LIMIT,
            "objects": PROVIDER_LIMIT, "referencing_objects": PROVIDER_LIMIT,
            "referenced_objects": PROVIDER_LIMIT, "suggestions": PROVIDER_LIMIT,
            "unique_object_types": 4
        }),
    );
    assert_finding(&edge, KEY);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn ip_info_combines_network_identity_and_location_without_raw_values()
-> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "ip-info";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_eq!(positive.status, ExecutionStatus::Completed);
    assert!(positive.diagnostics.is_empty());
    assert_eq!(positive.evidence.len(), 2);
    assert_observation(
        &positive,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "ip-network-info", "prefix_present": true, "autonomous_systems": 2
        }),
    );
    assert_observation(
        &positive,
        1,
        "IPinfo (https://ipinfo.io/)",
        json!({
            "kind": "ip-location-info", "city_present": true, "region_present": true,
            "country_present": true, "timezone_present": true,
            "coordinates_present": true, "autonomous_system_present": true
        }),
    );
    assert_finding(&positive, "network-information-observed");
    assert_finding_at(&positive, "ip-location-observed", 1);
    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_eq!(negative.evidence.len(), 2);
    assert_observation(
        &negative,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "ip-network-info", "prefix_present": false, "autonomous_systems": 0
        }),
    );
    assert_observation(
        &negative,
        1,
        "IPinfo (https://ipinfo.io/)",
        json!({
            "kind": "ip-location-info", "city_present": false, "region_present": false,
            "country_present": false, "timezone_present": false,
            "coordinates_present": false, "autonomous_system_present": false
        }),
    );
    assert_no_finding(&negative, "network-information-observed");
    assert_no_finding(&negative, "ip-location-observed");
    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_eq!(edge.evidence.len(), 2);
    assert_observation(
        &edge,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "ip-network-info", "prefix_present": true, "autonomous_systems": 1
        }),
    );
    assert_observation(
        &edge,
        1,
        "IPinfo (https://ipinfo.io/)",
        json!({
            "kind": "ip-location-info", "city_present": true, "region_present": false,
            "country_present": true, "timezone_present": true,
            "coordinates_present": false, "autonomous_system_present": true
        }),
    );
    assert_finding(&edge, "network-information-observed");
    assert_finding_at(&edge, "ip-location-observed", 1);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn ip_info_reports_incomplete_provider_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let result = scan_with_max_requests("ip-info", FixtureCase::Positive, 1).await?;
    assert_eq!(result.status, ExecutionStatus::Partial);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].kind, "provider-coverage-gap");
    assert_observation(
        &result,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "ip-network-info", "prefix_present": true, "autonomous_systems": 2
        }),
    );
    assert_no_finding(&result, "ip-location-observed");
    Ok(())
}

#[tokio::test]
async fn ip_info_preserves_domain_support_through_real_address_discovery()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, calls) = scan_domain_case(DomainFixtureCase::Positive, 8).await?;
    let result = result?;
    assert_eq!(result.status, ExecutionStatus::Completed);
    assert!(result.diagnostics.is_empty());
    assert_eq!(result.evidence.len(), 2);
    assert_observation(
        &result,
        0,
        "RIPEstat (https://stat.ripe.net/)",
        json!({
            "kind": "ip-network-info", "prefix_present": true, "autonomous_systems": 2
        }),
    );
    assert_observation(
        &result,
        1,
        "IPinfo (https://ipinfo.io/)",
        json!({
            "kind": "ip-location-info", "city_present": true, "region_present": true,
            "country_present": true, "timezone_present": true,
            "coordinates_present": true, "autonomous_system_present": true
        }),
    );
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].operation, "dns-chain");
    assert_eq!(calls[1].operation, "network-info");
    assert_eq!(calls[2].operation, "lookup");
    assert!(
        calls[1..]
            .iter()
            .all(|call| call.address.as_deref() == Some("192.0.2.10"))
    );
    Ok(())
}

#[tokio::test]
async fn domain_ip_info_rejects_dns_chains_without_an_ip() -> Result<(), Box<dyn std::error::Error>>
{
    let (result, calls) = scan_domain_case(DomainFixtureCase::NoAddress, 8).await?;
    let Err(error) = result else {
        return Err("a DNS chain without an IP produced evidence".into());
    };

    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);
    assert_eq!(
        error.message,
        "domain address discovery returned no enrichable addresses"
    );
    assert_eq!(
        calls,
        vec![DomainCall {
            provider: "ripestat".into(),
            operation: "dns-chain".into(),
            address: None,
        }]
    );
    assert!(!error.message.contains(support::SECRET_MARKER));
    Ok(())
}

#[tokio::test]
async fn domain_ip_info_redacts_one_enricher_failure_as_typed_partial()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, calls) = scan_domain_case(DomainFixtureCase::EnricherFailure, 8).await?;
    let result = result?;

    assert_eq!(result.status, ExecutionStatus::Partial);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].kind, "ratelimited");
    assert_eq!(
        result.diagnostics[0].message,
        "domain address provider enrichment failed"
    );
    assert_observation(
        &result,
        0,
        "IPinfo (https://ipinfo.io/)",
        json!({
            "kind": "ip-location-info", "city_present": false, "region_present": false,
            "country_present": true, "timezone_present": true,
            "coordinates_present": false, "autonomous_system_present": false
        }),
    );
    assert_finding_at(&result, "ip-location-observed", 0);
    assert_no_finding(&result, "network-information-observed");
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].address.as_deref(), Some("192.0.2.10"));
    assert_eq!(calls[2].address.as_deref(), Some("192.0.2.10"));
    assert_redacted(&result)
}

#[tokio::test]
async fn domain_ip_info_truncates_multiple_addresses_to_the_request_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, calls) = scan_domain_case(DomainFixtureCase::MultipleAddresses, 3).await?;
    let result = result?;

    assert_eq!(result.status, ExecutionStatus::Partial);
    assert_eq!(result.evidence.len(), 2);
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].kind, "provider-coverage-gap");
    assert_eq!(
        result.diagnostics[0].message,
        "domain address enrichment was limited by the request budget"
    );
    assert_eq!(calls.len(), 3, "one discovery plus two enrichers");
    assert_eq!(calls[0].operation, "dns-chain");
    assert!(
        calls[1..]
            .iter()
            .all(|call| call.address.as_deref() == Some("192.0.2.10"))
    );
    assert!(
        calls
            .iter()
            .all(|call| call.address.as_deref() != Some("192.0.2.11")
                && call.address.as_deref() != Some("192.0.2.12"))
    );
    assert_redacted(&result)
}

#[tokio::test]
async fn network_timezone_projects_only_location_presence() -> Result<(), Box<dyn std::error::Error>>
{
    const ID: &str = "network-timezone-detection";
    const KEY: &str = "network-timezone-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_summary(
        &positive,
        json!({
            "kind": "network-timezone", "timezone_present": true,
            "country_present": true, "coordinates_present": true
        }),
    );
    assert_finding(&positive, KEY);
    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_summary(
        &negative,
        json!({
            "kind": "network-timezone", "timezone_present": false,
            "country_present": false, "coordinates_present": false
        }),
    );
    assert_no_finding(&negative, KEY);
    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_summary(
        &edge,
        json!({
            "kind": "network-timezone", "timezone_present": true,
            "country_present": true, "coordinates_present": false
        }),
    );
    assert_finding(&edge, KEY);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn nameserver_diversity_enriches_dns_chain_with_real_geo_and_asn_providers()
-> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "ns-geo-asn-diversity-analyzer";
    const KEY: &str = "nameserver-diversity-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_summary(
        &positive,
        json!({
            "kind": "nameserver-diversity", "forward_nodes": 3, "reverse_nodes": 1,
            "resolver_nameservers": 2, "authoritative_nameservers": 2,
            "unique_chain_targets": 3, "enriched_nameservers": 2,
            "unique_countries": 2, "unique_autonomous_systems": 2
        }),
    );
    assert_finding(&positive, KEY);
    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_summary(
        &negative,
        json!({
            "kind": "nameserver-diversity", "forward_nodes": 0, "reverse_nodes": 0,
            "resolver_nameservers": 0, "authoritative_nameservers": 0,
            "unique_chain_targets": 0, "enriched_nameservers": 0,
            "unique_countries": 0, "unique_autonomous_systems": 0
        }),
    );
    assert_no_finding(&negative, KEY);
    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_summary(
        &edge,
        json!({
            "kind": "nameserver-diversity", "forward_nodes": 1, "reverse_nodes": 1,
            "resolver_nameservers": 1, "authoritative_nameservers": 1,
            "unique_chain_targets": 1, "enriched_nameservers": 1,
            "unique_countries": 1, "unique_autonomous_systems": 1
        }),
    );
    assert_no_finding(&edge, KEY);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn nameserver_diversity_reports_a_structural_budget_blocker()
-> Result<(), Box<dyn std::error::Error>> {
    let result =
        scan_with_max_requests("ns-geo-asn-diversity-analyzer", FixtureCase::Positive, 1).await?;
    assert_eq!(result.status, ExecutionStatus::Partial);
    assert_eq!(result.diagnostics.len(), 2);
    assert!(
        result
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind == "nameserver-enrichment-gap")
    );
    assert_observation(
        &result,
        0,
        "RIPEstat + IPinfo",
        json!({
            "kind": "nameserver-diversity", "forward_nodes": 3, "reverse_nodes": 1,
            "resolver_nameservers": 2, "authoritative_nameservers": 2,
            "unique_chain_targets": 3, "enriched_nameservers": 0,
            "unique_countries": 0, "unique_autonomous_systems": 0
        }),
    );
    assert_no_finding(&result, "nameserver-diversity-observed");
    Ok(())
}

#[tokio::test]
async fn server_location_projects_presence_without_location_values()
-> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "server-location";
    const KEY: &str = "server-location-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_summary(
        &positive,
        json!({
            "kind": "server-location", "city_present": true, "region_present": true,
            "country_present": true, "coordinates_present": true
        }),
    );
    assert_finding(&positive, KEY);
    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_summary(
        &negative,
        json!({
            "kind": "server-location", "city_present": false, "region_present": false,
            "country_present": false, "coordinates_present": false
        }),
    );
    assert_no_finding(&negative, KEY);
    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_summary(
        &edge,
        json!({
            "kind": "server-location", "city_present": true, "region_present": true,
            "country_present": true, "coordinates_present": false
        }),
    );
    assert_finding(&edge, KEY);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

#[tokio::test]
async fn certificate_authority_recon_projects_distinct_authorities()
-> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "certificate-authority-recon";
    const KEY: &str = "certificate-authority-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_summary(&positive, ca_summary(1, 1, 2, 1));
    assert_finding(&positive, KEY);
    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_summary(&negative, ca_summary(0, 0, 0, 0));
    assert_no_finding(&negative, KEY);
    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_summary(&edge, ca_summary(PROVIDER_LIMIT, 1, 2, 1));
    assert_finding(&edge, KEY);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}

fn ca_summary(records: usize, authorities: usize, names: usize, wildcards: usize) -> Value {
    json!({
        "kind": "certificate-authority-recon", "records": records,
        "unique_authorities": authorities, "unique_names": names,
        "wildcard_names": wildcards
    })
}

#[tokio::test]
async fn irr_registry_projects_route_object_counts() -> Result<(), Box<dyn std::error::Error>> {
    const ID: &str = "irr-routing-registry-analyzer";
    const KEY: &str = "irr-route-objects-observed";
    let positive = scan(ID, FixtureCase::Positive).await?;
    assert_summary(
        &positive,
        json!({
            "kind": "irr-routing-registry", "records": 1, "irr_records": 1,
            "authorities": 2, "route_objects": 1, "route6_objects": 0,
            "unique_origins": 1, "unique_sources": 1
        }),
    );
    assert_finding(&positive, KEY);
    let negative = scan(ID, FixtureCase::Negative).await?;
    assert_summary(
        &negative,
        json!({
            "kind": "irr-routing-registry", "records": 0, "irr_records": 0,
            "authorities": 0, "route_objects": 0, "route6_objects": 0,
            "unique_origins": 0, "unique_sources": 0
        }),
    );
    assert_no_finding(&negative, KEY);
    let edge = scan(ID, FixtureCase::Edge).await?;
    assert_summary(
        &edge,
        json!({
            "kind": "irr-routing-registry", "records": PROVIDER_LIMIT,
            "irr_records": PROVIDER_LIMIT, "authorities": 1, "route_objects": 0,
            "route6_objects": PROVIDER_LIMIT, "unique_origins": 1, "unique_sources": 1
        }),
    );
    assert_finding(&edge, KEY);
    assert_redacted(&edge)?;
    assert_typed_failure(ID).await
}
