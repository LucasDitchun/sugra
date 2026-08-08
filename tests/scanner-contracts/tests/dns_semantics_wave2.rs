//! Public semantic contracts for the second DNS-analysis wave.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use sugra_core::{
    DnsPort, DnsQuery, DnsRecord, DnsRecordType, PortError, PortErrorKind, ScanError, ScanErrorKind,
};
use sugra_domain::ScanResult;
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        Ok(records_for(self.scanner_id, self.case, &query))
    }
}

struct FailingDns {
    kind: PortErrorKind,
}

#[async_trait]
impl DnsPort for FailingDns {
    async fn query(&self, _query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        Err(PortError::new(self.kind, "typed DNS fixture failure"))
    }
}

struct SequencedFailingDns {
    calls: AtomicUsize,
}

#[async_trait]
impl DnsPort for SequencedFailingDns {
    async fn query(&self, _query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            Err(PortError::new(
                PortErrorKind::InvalidResponse,
                "first DNS response was invalid",
            ))
        } else {
            Err(PortError::new(
                PortErrorKind::Transport,
                "later DNS transport failure",
            ))
        }
    }
}

fn record(query: &DnsQuery, record_type: DnsRecordType, value: &str) -> DnsRecord {
    DnsRecord {
        name: query.name.clone(),
        record_type,
        value: value.into(),
        ttl: Some(300),
    }
}

fn records_for(id: &str, case: FixtureCase, query: &DnsQuery) -> Vec<DnsRecord> {
    let mut records = match (id, case) {
        ("dns-caa-checker", FixtureCase::Positive) => {
            vec![record(query, DnsRecordType::Caa, "0 issue letsencrypt.org")]
        }
        ("dns-caa-checker", FixtureCase::Edge) => vec![DnsRecord {
            name: "other.example".into(),
            record_type: DnsRecordType::Caa,
            value: "0 issue ignored.example".into(),
            ttl: None,
        }],
        ("dns-records", FixtureCase::Positive) => {
            vec![record(query, DnsRecordType::A, "192.0.2.10")]
        }
        ("dns-records", FixtureCase::Edge) => vec![record(query, DnsRecordType::A, " ")],
        ("domain-info", FixtureCase::Positive) => vec![
            record(query, DnsRecordType::A, "192.0.2.10"),
            record(query, DnsRecordType::Ns, "ns.example.net"),
        ],
        ("domain-info", FixtureCase::Edge) => {
            vec![record(query, DnsRecordType::Aaaa, "2001:db8::10")]
        }
        ("reverse-dns-scan", FixtureCase::Positive) => {
            vec![record(query, DnsRecordType::Ptr, "host.example")]
        }
        ("reverse-dns-scan", FixtureCase::Edge) => vec![DnsRecord {
            name: "wrong.in-addr.arpa".into(),
            record_type: DnsRecordType::Ptr,
            value: "ignored.example".into(),
            ttl: None,
        }],
        ("rogue-subdomain-resolver", FixtureCase::Positive)
            if query.name.starts_with("_sugra-scope-probe.") =>
        {
            vec![record(query, DnsRecordType::A, "192.0.2.20")]
        }
        ("rogue-subdomain-resolver", FixtureCase::Edge)
            if query.name.starts_with("_sugra-scope-probe.") =>
        {
            vec![record(query, DnsRecordType::Txt, "public metadata")]
        }
        ("spf-network-extractor", FixtureCase::Positive) => vec![record(
            query,
            DnsRecordType::Txt,
            "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all",
        )],
        ("spf-network-extractor", FixtureCase::Edge) => {
            vec![record(query, DnsRecordType::Txt, "v=spf1 -all")]
        }
        ("subdomain-takeover", FixtureCase::Positive)
            if !query.name.starts_with("_sugra-scope-probe.") =>
        {
            vec![record(query, DnsRecordType::Cname, "tenant.github.io.")]
        }
        ("subdomain-takeover", FixtureCase::Negative)
            if !query.name.starts_with("_sugra-scope-probe.") =>
        {
            vec![record(query, DnsRecordType::Cname, "owned.example.net.")]
        }
        ("subdomain-takeover", FixtureCase::Edge)
            if !query.name.starts_with("_sugra-scope-probe.") =>
        {
            vec![record(
                query,
                DnsRecordType::Cname,
                "github.io.attacker.example.",
            )]
        }
        ("txt-records", FixtureCase::Positive) => {
            vec![record(query, DnsRecordType::Txt, "public metadata")]
        }
        ("txt-records", FixtureCase::Edge) => vec![record(query, DnsRecordType::Txt, " ")],
        _ => Vec::new(),
    };

    // Irrelevant authority/additional-style records must neither create a
    // signal nor leak their values through persisted evidence. Edge fixtures
    // deliberately make the raw answer large to prove bounded summaries.
    let irrelevant_count = if case == FixtureCase::Edge { 256 } else { 1 };
    records.extend((0..irrelevant_count).map(|index| DnsRecord {
        name: format!("unrelated-{index}.invalid"),
        record_type: DnsRecordType::Txt,
        value: format!("{}-{index}", support::SECRET_MARKER),
        ttl: Some(60),
    }));
    records
}

async fn scan(
    id: &'static str,
    case: FixtureCase,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.dns = Arc::new(FixtureDns {
        scanner_id: id,
        case,
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("fixture scanner is missing from the registry")?;
    let request = support::request_for(scanner.descriptor())?;
    Ok(scanner.scan(&request, &support::context(false)).await?)
}

async fn assert_typed_failure(
    id: &str,
    port_kind: PortErrorKind,
    expected: ScanErrorKind,
) -> Result<(), Box<dyn std::error::Error>> {
    let error = scan_failure(id, Arc::new(FailingDns { kind: port_kind })).await?;
    assert_eq!(error.kind, expected, "{id}: {port_kind:?}");
    assert!(!error.message.contains(support::SECRET_MARKER));
    Ok(())
}

async fn scan_failure(
    id: &str,
    dns: Arc<dyn DnsPort>,
) -> Result<ScanError, Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.dns = dns;
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("failure scanner is missing from the registry")?;
    let request = support::request_for(scanner.descriptor())?;
    let Err(error) = scanner.scan(&request, &support::context(false)).await else {
        return Err(format!("{id} converted DNS failure into success").into());
    };
    Ok(error)
}

async fn assert_typed_failures(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    for (port_kind, expected) in [
        (PortErrorKind::Transport, ScanErrorKind::Transport),
        (
            PortErrorKind::InvalidResponse,
            ScanErrorKind::InvalidResponse,
        ),
        (
            PortErrorKind::Unavailable,
            ScanErrorKind::DependencyUnavailable,
        ),
        (PortErrorKind::Timeout, ScanErrorKind::Timeout),
    ] {
        assert_typed_failure(id, port_kind, expected).await?;
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
    assert!(serialized.len() < 8_192, "DNS evidence was not bounded");
    assert!(result.evidence.len() <= 2);
    for finding in &result.findings {
        assert!(!finding.evidence.is_empty(), "{}", finding.key);
        assert!(
            finding
                .evidence
                .iter()
                .all(|index| *index < result.evidence.len()),
            "{}",
            finding.key
        );
    }
    Ok(())
}

async fn assert_presence_contract(
    id: &'static str,
    observed_key: &str,
    missing_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan(id, FixtureCase::Positive).await?;
    assert_eq!(finding_keys(&positive), BTreeSet::from([observed_key]));
    assert_safe_bounded(&positive)?;

    let negative = scan(id, FixtureCase::Negative).await?;
    assert_eq!(finding_keys(&negative), BTreeSet::from([missing_key]));
    assert_safe_bounded(&negative)?;

    let edge = scan(id, FixtureCase::Edge).await?;
    assert_eq!(finding_keys(&edge), BTreeSet::from([missing_key]));
    assert_safe_bounded(&edge)?;

    assert_typed_failures(id).await
}

#[tokio::test]
async fn caa_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    assert_presence_contract("dns-caa-checker", "caa-policy-observed", "caa-not-observed").await
}

#[tokio::test]
async fn dns_records_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    assert_presence_contract(
        "dns-records",
        "dns-records-observed",
        "dns-records-not-observed",
    )
    .await
}

#[tokio::test]
async fn reverse_dns_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    assert_presence_contract("reverse-dns-scan", "ptr-observed", "ptr-not-observed").await
}

#[tokio::test]
async fn txt_records_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    assert_presence_contract(
        "txt-records",
        "txt-records-observed",
        "txt-records-not-observed",
    )
    .await
}

#[tokio::test]
async fn domain_info_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("domain-info", FixtureCase::Positive).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["domain-address-observed", "domain-authority-observed"])
    );
    assert_safe_bounded(&positive)?;

    let negative = scan("domain-info", FixtureCase::Negative).await?;
    assert_eq!(
        finding_keys(&negative),
        BTreeSet::from([
            "domain-address-not-observed",
            "domain-authority-not-observed"
        ])
    );
    assert_safe_bounded(&negative)?;

    let edge = scan("domain-info", FixtureCase::Edge).await?;
    assert_eq!(
        finding_keys(&edge),
        BTreeSet::from(["domain-address-observed", "domain-authority-not-observed"])
    );
    assert_safe_bounded(&edge)?;

    assert_typed_failures("domain-info").await
}

#[tokio::test]
async fn rogue_subdomain_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("rogue-subdomain-resolver", FixtureCase::Positive).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["unexpected-probe-answer"])
    );
    assert_safe_bounded(&positive)?;

    let negative = scan("rogue-subdomain-resolver", FixtureCase::Negative).await?;
    assert!(negative.findings.is_empty());
    assert_safe_bounded(&negative)?;

    let edge = scan("rogue-subdomain-resolver", FixtureCase::Edge).await?;
    assert!(edge.findings.is_empty());
    assert_safe_bounded(&edge)?;

    assert_typed_failures("rogue-subdomain-resolver").await
}

#[tokio::test]
async fn spf_network_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("spf-network-extractor", FixtureCase::Positive).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["spf-network-sources-observed"])
    );
    assert_safe_bounded(&positive)?;

    let negative = scan("spf-network-extractor", FixtureCase::Negative).await?;
    assert_eq!(
        finding_keys(&negative),
        BTreeSet::from(["spf-not-observed"])
    );
    assert_safe_bounded(&negative)?;

    let edge = scan("spf-network-extractor", FixtureCase::Edge).await?;
    assert_eq!(
        finding_keys(&edge),
        BTreeSet::from(["spf-network-sources-not-observed"])
    );
    assert_safe_bounded(&edge)?;

    assert_typed_failures("spf-network-extractor").await
}

#[tokio::test]
async fn subdomain_takeover_public_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("subdomain-takeover", FixtureCase::Positive).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["external-service-alias"])
    );
    assert_safe_bounded(&positive)?;

    let negative = scan("subdomain-takeover", FixtureCase::Negative).await?;
    assert!(negative.findings.is_empty());
    assert_safe_bounded(&negative)?;

    let edge = scan("subdomain-takeover", FixtureCase::Edge).await?;
    assert!(edge.findings.is_empty());
    assert_safe_bounded(&edge)?;

    assert_typed_failures("subdomain-takeover").await
}

#[tokio::test]
async fn all_failed_dns_plan_preserves_the_first_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let error = scan_failure(
        "rogue-subdomain-resolver",
        Arc::new(SequencedFailingDns {
            calls: AtomicUsize::new(0),
        }),
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);
    assert_eq!(error.message, "first DNS response was invalid");
    Ok(())
}
