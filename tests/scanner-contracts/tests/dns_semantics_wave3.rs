//! Public semantic contracts for the third DNS-analysis wave.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use sugra_core::{
    DnsPort, DnsQuery, DnsRecord, DnsRecordType, PortError, PortErrorKind, ScanError, ScanErrorKind,
};
use sugra_domain::{Confidence, ExecutionStatus, ScanResult, Severity};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

#[derive(Debug, Clone, Copy)]
enum FixtureCase {
    Positive,
    Negative,
    Edge,
}

struct FixtureDns {
    scanner_id: &'static str,
    case: FixtureCase,
}

#[async_trait]
impl DnsPort for FixtureDns {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        let expected_types = match self.scanner_id {
            "geo-dns-footprint" => &[DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Ns][..],
            "decoy-dns-beacon" => {
                &[DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname][..]
            }
            _ => &[],
        };
        assert_eq!(query.record_types, expected_types, "queried DNS types");
        let record = |name: &str, record_type, value: &str| DnsRecord {
            name: name.into(),
            record_type,
            value: value.into(),
            ttl: Some(300),
        };
        let records = match (self.scanner_id, self.case) {
            ("geo-dns-footprint", FixtureCase::Positive) => vec![
                record(&query.name, DnsRecordType::A, "203.0.113.10"),
                record(&query.name, DnsRecordType::Aaaa, "2001:db8::10"),
                record(&query.name, DnsRecordType::Ns, "ns1.example.net."),
            ],
            ("geo-dns-footprint", FixtureCase::Edge) => vec![
                record("other.example", DnsRecordType::A, "203.0.113.10"),
                record(&query.name, DnsRecordType::Txt, "203.0.113.10"),
                record(&query.name, DnsRecordType::A, "not-an-address"),
                record(&query.name, DnsRecordType::Aaaa, "not-an-address"),
                record(&query.name, DnsRecordType::Ns, "invalid..name"),
                record("secret.invalid", DnsRecordType::Txt, support::SECRET_MARKER),
            ],
            ("decoy-dns-beacon", FixtureCase::Positive)
                if query.name.starts_with("_sugra-decoy-beacon.") =>
            {
                vec![record(&query.name, DnsRecordType::A, "203.0.113.20")]
            }
            ("decoy-dns-beacon", FixtureCase::Edge) => vec![
                record("other.example", DnsRecordType::A, "203.0.113.20"),
                record(&query.name, DnsRecordType::Txt, "203.0.113.20"),
                record(&query.name, DnsRecordType::A, "not-an-address"),
                record(&query.name, DnsRecordType::Aaaa, "not-an-address"),
                record(&query.name, DnsRecordType::Cname, "invalid..name"),
                record("secret.invalid", DnsRecordType::Txt, support::SECRET_MARKER),
            ],
            _ => Vec::new(),
        };
        Ok(records)
    }
}

struct FailingDns(PortErrorKind);

#[async_trait]
impl DnsPort for FailingDns {
    async fn query(&self, _query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        Err(PortError::new(self.0, "typed DNS fixture failure"))
    }
}

#[derive(Debug, Clone, Copy)]
enum SlaMode {
    Complete,
    Partial,
    Edge,
}

struct SlaDns {
    mode: SlaMode,
    calls: AtomicUsize,
}

#[async_trait]
impl DnsPort for SlaDns {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        assert_eq!(
            query.record_types,
            [DnsRecordType::A, DnsRecordType::Aaaa],
            "queried DNS SLA types"
        );
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(10)).await;
        if matches!(self.mode, SlaMode::Partial) && call == 1 {
            return Err(PortError::new(
                PortErrorKind::InvalidResponse,
                "one SLA sample returned an invalid response",
            ));
        }
        if matches!(self.mode, SlaMode::Edge) {
            return Ok((0..256)
                .map(|index| DnsRecord {
                    name: format!("unrelated-{index}.invalid"),
                    record_type: DnsRecordType::Txt,
                    value: format!("{}-{index}", support::SECRET_MARKER),
                    ttl: None,
                })
                .collect());
        }
        Ok(vec![DnsRecord {
            name: query.name,
            record_type: DnsRecordType::A,
            value: "203.0.113.30".into(),
            ttl: Some(300),
        }])
    }
}

async fn scan(
    scanner_id: &'static str,
    case: FixtureCase,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    scan_with_dns(scanner_id, Arc::new(FixtureDns { scanner_id, case })).await
}

async fn scan_with_dns(
    scanner_id: &str,
    dns: Arc<dyn DnsPort>,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    scan_with_dns_config(scanner_id, dns, |_| {}).await
}

async fn scan_with_dns_config(
    scanner_id: &str,
    dns: Arc<dyn DnsPort>,
    configure: impl FnOnce(&mut sugra_domain::ScanRequest),
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.dns = dns;
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new(scanner_id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("fixture scanner is missing from the registry")?;
    let mut request = support::request_for(scanner.descriptor())?;
    configure(&mut request);
    Ok(scanner.scan(&request, &support::context(false)).await?)
}

async fn assert_all_typed_failures(scanner_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    for (port_kind, expected) in [
        (PortErrorKind::Internal, ScanErrorKind::Internal),
        (
            PortErrorKind::Unavailable,
            ScanErrorKind::DependencyUnavailable,
        ),
        (PortErrorKind::Timeout, ScanErrorKind::Timeout),
        (
            PortErrorKind::InvalidResponse,
            ScanErrorKind::InvalidResponse,
        ),
        (PortErrorKind::RateLimited, ScanErrorKind::Timeout),
        (PortErrorKind::Transport, ScanErrorKind::Transport),
        (PortErrorKind::OutOfScope, ScanErrorKind::PolicyDenied),
        (PortErrorKind::TooLarge, ScanErrorKind::InvalidResponse),
    ] {
        let result = scan_with_dns(scanner_id, Arc::new(FailingDns(port_kind))).await;
        let error = match result {
            Err(error) => error
                .downcast::<ScanError>()
                .map_err(|error| format!("{scanner_id}: unexpected error type: {error}"))?,
            Ok(_) => return Err(format!("{scanner_id}: DNS failure became success").into()),
        };
        assert_eq!(error.kind, expected, "{scanner_id}: {port_kind:?}");
        assert!(!error.message.contains(support::SECRET_MARKER));
    }
    Ok(())
}

fn finding_keys(result: &ScanResult) -> BTreeSet<&str> {
    result
        .findings
        .iter()
        .map(|finding| finding.key.as_str())
        .collect()
}

fn assert_safe_bounded(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serde_json::to_string(result)?;
    assert!(!serialized.contains(support::SECRET_MARKER));
    assert!(serialized.len() < 4_096, "DNS evidence was not bounded");
    assert!(result.evidence.len() <= 10);
    assert!(result.findings.iter().all(|finding| {
        !finding.evidence.is_empty()
            && finding
                .evidence
                .iter()
                .all(|index| *index < result.evidence.len())
    }));
    Ok(())
}

#[tokio::test]
async fn geo_dns_footprint_requires_exact_owner_type_and_value()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("geo-dns-footprint", FixtureCase::Positive).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["geo-dns-footprint-observed"])
    );
    assert_eq!(positive.findings[0].severity, Severity::Info);
    assert_eq!(positive.findings[0].confidence, Confidence::Confirmed);
    assert_safe_bounded(&positive)?;

    let negative = scan("geo-dns-footprint", FixtureCase::Negative).await?;
    assert_eq!(
        finding_keys(&negative),
        BTreeSet::from(["geo-dns-footprint-not-observed"])
    );
    assert_safe_bounded(&negative)?;

    let edge = scan("geo-dns-footprint", FixtureCase::Edge).await?;
    assert_eq!(
        finding_keys(&edge),
        BTreeSet::from(["geo-dns-footprint-not-observed"])
    );
    assert_safe_bounded(&edge)?;
    assert_all_typed_failures("geo-dns-footprint").await?;
    Ok(())
}

#[tokio::test]
async fn decoy_dns_beacon_uses_one_exact_bounded_probe() -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("decoy-dns-beacon", FixtureCase::Positive).await?;
    assert_eq!(positive.status, ExecutionStatus::Completed);
    assert_eq!(positive.evidence.len(), 1);
    assert_eq!(
        positive.evidence[0].source,
        "_sugra-decoy-beacon.example.com"
    );
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["decoy-probe-answer-observed"])
    );
    let finding = &positive.findings[0];
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.confidence, Confidence::Inferred);
    assert_safe_bounded(&positive)?;

    let negative = scan("decoy-dns-beacon", FixtureCase::Negative).await?;
    assert!(negative.findings.is_empty());
    assert_safe_bounded(&negative)?;

    let edge = scan("decoy-dns-beacon", FixtureCase::Edge).await?;
    assert!(edge.findings.is_empty());
    assert_safe_bounded(&edge)?;
    assert_all_typed_failures("decoy-dns-beacon").await?;
    Ok(())
}

#[tokio::test]
async fn dns_sla_reports_bounded_latency_and_sample_availability()
-> Result<(), Box<dyn std::error::Error>> {
    let partial = scan_with_dns(
        "dns-sla-latency-monitor",
        Arc::new(SlaDns {
            mode: SlaMode::Partial,
            calls: AtomicUsize::new(0),
        }),
    )
    .await?;
    assert_eq!(partial.status, ExecutionStatus::Partial);
    assert_eq!(partial.evidence.len(), 2);
    assert_eq!(
        finding_keys(&partial),
        BTreeSet::from(["dns-sla-availability-degraded"])
    );
    assert_eq!(partial.findings[0].evidence, [0, 1]);
    assert_eq!(partial.findings[0].severity, Severity::Medium);
    assert_eq!(partial.findings[0].confidence, Confidence::Confirmed);
    assert_safe_bounded(&partial)?;

    let complete = scan_with_dns(
        "dns-sla-latency-monitor",
        Arc::new(SlaDns {
            mode: SlaMode::Complete,
            calls: AtomicUsize::new(0),
        }),
    )
    .await?;
    assert_eq!(complete.status, ExecutionStatus::Completed);
    assert_eq!(complete.evidence.len(), 3);
    assert_eq!(
        finding_keys(&complete),
        BTreeSet::from(["dns-sla-availability-observed"])
    );
    assert_eq!(complete.findings[0].severity, Severity::Info);
    assert_eq!(complete.findings[0].confidence, Confidence::Confirmed);
    for evidence in &complete.evidence {
        assert_eq!(evidence.source, "example.com");
        let duration = evidence.observation["observation"]["duration_ms"]
            .as_u64()
            .ok_or("DNS SLA duration was not persisted as an integer")?;
        assert!(duration >= 5, "DNS SLA duration omitted elapsed time");
    }
    assert_safe_bounded(&complete)?;

    let edge = scan_with_dns_config(
        "dns-sla-latency-monitor",
        Arc::new(SlaDns {
            mode: SlaMode::Edge,
            calls: AtomicUsize::new(0),
        }),
        |request| {
            request
                .options
                .insert("samples".into(), serde_json::json!(100_000));
            request.budget.max_requests = 4;
        },
    )
    .await?;
    assert_eq!(edge.evidence.len(), 4);
    assert_eq!(
        finding_keys(&edge),
        BTreeSet::from(["dns-sla-availability-observed"])
    );
    assert_safe_bounded(&edge)?;

    let unsupported_resolver = scan_with_dns_config(
        "dns-sla-latency-monitor",
        Arc::new(SlaDns {
            mode: SlaMode::Complete,
            calls: AtomicUsize::new(0),
        }),
        |request| {
            request
                .options
                .insert("resolvers".into(), serde_json::json!(["203.0.113.53"]));
        },
    )
    .await;
    let error = match unsupported_resolver {
        Err(error) => error
            .downcast::<ScanError>()
            .map_err(|error| format!("unexpected resolver error type: {error}"))?,
        Ok(_) => return Err("custom resolvers were silently ignored".into()),
    };
    assert_eq!(error.kind, ScanErrorKind::DependencyUnavailable);
    assert!(!error.message.contains("203.0.113.53"));

    assert_all_typed_failures("dns-sla-latency-monitor").await?;
    Ok(())
}
