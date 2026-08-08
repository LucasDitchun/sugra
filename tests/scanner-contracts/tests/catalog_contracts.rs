//! Cross-crate offline contracts for the complete built-in scanner set.

use std::collections::BTreeSet;

use serde_json::json;
use sugra_core::{LocalInputRequest, ScanErrorKind};
use sugra_domain::{
    Budget, ExecutionStatus, ScanRequest, ScanResult, ScopeGrant, Target, TargetKind,
};
use sugra_scanner_contracts::{Boundary, MissingFixture, contracts, semantic_gaps};
use sugra_scanners::build_builtins;

mod support;

const VERIFIED_SEMANTIC_SCANNERS: &[&str] = &[
    "dnssec",
    "dual-stack-behavior-profiler",
    "dual-stack-diff",
    "email-config",
    "spf-dkim-dmarc-validator",
    "ttl-analysis",
    "typosquat-domain-checker",
    "http-headers",
    "http-security",
    "clickjacking-test",
    "cors-misconfiguration-scanner",
    "security-txt",
    "security-contact-gap-finder",
    "cookies",
    "session-cookie-lifetime-checker",
    "ssl-pinning-check",
    "ipv6-reachability-test",
    "ntp-info-leak-checker",
    "snmp-public-community-checker",
    "udp-service-sampler",
    "netbios-name-query",
    "snmp-bulk-walk",
    "passive-dns-history",
    "rpki-route-validity-check",
    "rogue-certificate-check",
    "performance-monitoring",
    "domain-reputation-check",
    "ip-reputation-check",
    "ssl-chain",
    "ssl-expiry",
    "tls-cipher-suites",
    "tls-handshake",
    "tls-security-config",
    "tls-session-resumption-map",
    "network-certificate-inventory",
    "dns-caa-checker",
    "dns-records",
    "domain-info",
    "reverse-dns-scan",
    "rogue-subdomain-resolver",
    "spf-network-extractor",
    "subdomain-takeover",
    "txt-records",
    "archive-history",
    "asn-lookup",
    "associated-hosts",
    "bgp-route-analysis",
    "ct-log-query",
    "rdap-lookup",
    "reverse-ip-lookup",
    "subdomain-enum",
    "api-schema-grabber",
    "broken-links",
    "cache-behavior-analyzer",
    "captcha-presence-checker",
    "cms-detection",
    "crawl-rules",
    "crawler",
    "csp-deep-analyzer",
    "decoy-dns-beacon",
    "dns-sla-latency-monitor",
    "geo-dns-footprint",
    "autonomous-neighbor-peering-map",
    "ip-allocation-history-tracker",
    "ip-info",
    "network-timezone-detection",
    "ns-geo-asn-diversity-analyzer",
    "server-location",
    "certificate-authority-recon",
    "irr-routing-registry-analyzer",
    "open-ports",
    "ip-range-scanner",
    "zonetransfer",
    "icmp-reachability-matrix",
    "ssh-banner-key-fingerprinter",
    "traceroute",
    "whois-lookup",
    "custom-wordlist-generator",
    "jwt-token-analyzer",
    "cdn-detection",
    "server-info",
    "autocomplete-vulnerability-checker",
    "content-discovery",
    "cookie-scope-diff",
    "dependency-js-cdn-scanner",
    "dom-sink-scanner",
    "embedded-object-hunter",
    "form-grabber",
    "graphql-introspection-probe",
    "http-method-enumerator",
    "websocket-endpoint-sniffer",
    "html-comments-extractor",
    "third-party-integrations",
    "sitemap",
    "social-media",
    "favicon-hashing",
    "technology-stack",
    "exposed-env-files",
    "git-repo-exposure-check",
    "open-redirect-finder",
    "javascript-obfuscation-detector",
    "security-changelog-diff",
];

#[test]
fn matrix_matches_the_complete_catalog_identity_set() -> Result<(), Box<dyn std::error::Error>> {
    let harness = support::Harness::successful();
    let builtins = build_builtins(&harness.services())?;
    let catalog_ids = builtins
        .catalog
        .iter()
        .map(|descriptor| descriptor.id.as_str())
        .collect::<BTreeSet<_>>();
    let matrix_ids = contracts()
        .iter()
        .map(|contract| contract.id)
        .collect::<BTreeSet<_>>();

    assert_eq!(contracts().len(), 147, "matrix must contain 147 rows");
    assert_eq!(matrix_ids.len(), 147, "matrix IDs must be unique");
    assert_eq!(matrix_ids, catalog_ids);
    Ok(())
}

#[test]
fn scanner_specific_semantic_gaps_are_complete_and_explicit() {
    let contract_ids = contracts()
        .into_iter()
        .map(|contract| contract.id)
        .collect::<BTreeSet<_>>();
    let gaps = semantic_gaps();
    let gap_ids = gaps.iter().map(|gap| gap.id).collect::<BTreeSet<_>>();

    assert!(gap_ids.is_subset(&contract_ids));
    assert_eq!(contracts().len(), 147);
    assert_eq!(gaps.len(), 45);
    assert_eq!(gaps.iter().map(|gap| gap.missing.len()).sum::<usize>(), 135);

    for covered in VERIFIED_SEMANTIC_SCANNERS {
        assert!(!gap_ids.contains(covered), "{covered} still has a gap");
    }

    for gap in &gaps {
        assert_eq!(
            gap.missing,
            &[
                MissingFixture::PositiveSignal,
                MissingFixture::NegativeControl,
                MissingFixture::EdgeCase,
            ],
            "{} must retain every unproven fixture class",
            gap.id
        );
    }

    let untouched = gaps
        .iter()
        .find(|gap| gap.id == "recursive-nameserver-leak-test")
        .unwrap_or_else(|| unreachable!("untested scanner gap must remain"));
    assert_eq!(
        untouched.missing,
        &[
            MissingFixture::PositiveSignal,
            MissingFixture::NegativeControl,
            MissingFixture::EdgeCase,
        ]
    );
}

async fn scan_fixture(
    id: &str,
    fixture: support::Fixture,
    configure: impl FnOnce(&mut ScanRequest),
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let harness = support::Harness::fixture(fixture);
    let builtins = build_builtins(&harness.services())?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("fixture scanner is missing from the registry")?;
    let mut request = contract_request_for(scanner.descriptor())?;
    configure(&mut request);
    Ok(scanner.scan(&request, &support::context(false)).await?)
}

fn contract_request_for(
    descriptor: &sugra_domain::ScannerDescriptor,
) -> Result<ScanRequest, Box<dyn std::error::Error>> {
    let mut descriptor = descriptor.clone();
    if descriptor.id.as_str() == "ssl-pinning-check" {
        let baseline = descriptor
            .options
            .iter_mut()
            .find(|option| option.key == "baseline_sha256")
            .ok_or("TLS pinning descriptor is missing its baseline option")?;
        baseline.default = Some("00".repeat(32));
    }
    let mut request = support::request_for(&descriptor)?;
    if descriptor.id.as_str() == "ipv6-reachability-test" {
        let target = Target::parse(TargetKind::Ip, "2001:db8::1")?;
        request.scope = ScopeGrant::exact(&target, true, time::OffsetDateTime::UNIX_EPOCH);
        request.target = target;
    }
    Ok(request)
}

fn has_finding(result: &ScanResult, key: &str) -> bool {
    result.findings.iter().any(|finding| finding.key == key)
}

fn assert_redacted(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
    assert!(!serde_json::to_string(result)?.contains(support::SECRET_MARKER));
    Ok(())
}

#[tokio::test]
async fn dnssec_public_contract_covers_complete_missing_and_partial_material()
-> Result<(), Box<dyn std::error::Error>> {
    let complete = scan_fixture("dnssec", support::Fixture::DnssecComplete, |_| {}).await?;
    assert!(complete.findings.is_empty());

    let missing = scan_fixture("dnssec", support::Fixture::DnssecMissing, |_| {}).await?;
    assert!(has_finding(&missing, "dnssec-not-observed"));

    let incomplete = scan_fixture("dnssec", support::Fixture::DnssecIncomplete, |_| {}).await?;
    assert!(has_finding(&incomplete, "dnssec-material-incomplete"));
    assert_redacted(&incomplete)
}

#[tokio::test]
async fn email_config_public_contract_covers_missing_and_weak_policies()
-> Result<(), Box<dyn std::error::Error>> {
    let missing = scan_fixture("email-config", support::Fixture::EmailMissing, |_| {}).await?;
    for key in [
        "spf-not-observed",
        "dkim-not-observed",
        "dmarc-not-observed",
        "caa-not-observed",
    ] {
        assert!(has_finding(&missing, key), "missing {key}");
    }

    let weak = scan_fixture("email-config", support::Fixture::EmailWeak, |_| {}).await?;
    assert!(has_finding(&weak, "spf-permissive-all"));
    assert!(has_finding(&weak, "dmarc-monitoring-only"));
    assert!(has_finding(&weak, "dkim-not-observed"));
    assert!(!has_finding(&weak, "caa-not-observed"));
    assert_redacted(&weak)
}

#[tokio::test]
async fn dual_stack_public_contract_covers_symmetric_asymmetric_and_empty_answers()
-> Result<(), Box<dyn std::error::Error>> {
    for id in ["dual-stack-behavior-profiler", "dual-stack-diff"] {
        let complete = scan_fixture(id, support::Fixture::DualStackComplete, |_| {}).await?;
        assert!(!has_finding(&complete, "address-family-asymmetry"));

        let asymmetric = scan_fixture(id, support::Fixture::DualStackIpv4Only, |_| {}).await?;
        assert!(has_finding(&asymmetric, "address-family-asymmetry"));

        let empty = scan_fixture(id, support::Fixture::DualStackEmpty, |_| {}).await?;
        assert!(!has_finding(&empty, "address-family-asymmetry"));
    }
    Ok(())
}

#[tokio::test]
async fn ttl_public_contract_covers_short_boundary_and_zero_values()
-> Result<(), Box<dyn std::error::Error>> {
    let healthy = scan_fixture("ttl-analysis", support::Fixture::TtlHealthy, |_| {}).await?;
    assert!(!has_finding(&healthy, "short-dns-ttl"));

    let short = scan_fixture("ttl-analysis", support::Fixture::TtlShort, |_| {}).await?;
    assert!(has_finding(&short, "short-dns-ttl"));

    let zero = scan_fixture("ttl-analysis", support::Fixture::TtlZero, |_| {}).await?;
    assert!(has_finding(&zero, "short-dns-ttl"));
    assert_redacted(&zero)
}

#[tokio::test]
async fn typosquat_public_contract_requires_the_exact_candidate_to_resolve()
-> Result<(), Box<dyn std::error::Error>> {
    let resolved = scan_fixture(
        "typosquat-domain-checker",
        support::Fixture::TyposquatResolved,
        |_| {},
    )
    .await?;
    assert!(has_finding(&resolved, "resolving-typo-candidate"));

    let empty = scan_fixture(
        "typosquat-domain-checker",
        support::Fixture::TyposquatEmpty,
        |_| {},
    )
    .await?;
    assert!(!has_finding(&empty, "resolving-typo-candidate"));

    let wrong_owner = scan_fixture(
        "typosquat-domain-checker",
        support::Fixture::TyposquatWrongOwner,
        |_| {},
    )
    .await?;
    assert!(!has_finding(&wrong_owner, "resolving-typo-candidate"));
    assert_redacted(&wrong_owner)
}

#[tokio::test]
async fn passive_dns_history_public_contract_is_bounded_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    let present = scan_fixture(
        "passive-dns-history",
        support::Fixture::PassiveDnsHistoryPresent,
        |_| {},
    )
    .await?;
    assert!(has_finding(&present, "historical-dns-observations"));

    let empty = scan_fixture(
        "passive-dns-history",
        support::Fixture::PassiveDnsHistoryEmpty,
        |_| {},
    )
    .await?;
    assert!(empty.findings.is_empty());

    let malformed = scan_fixture(
        "passive-dns-history",
        support::Fixture::PassiveDnsHistoryMalformed,
        |_| {},
    )
    .await?;
    assert!(malformed.findings.is_empty());
    assert_redacted(&malformed)
}

#[tokio::test]
async fn rpki_public_contract_distinguishes_invalid_valid_and_unknown_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let invalid = scan_fixture(
        "rpki-route-validity-check",
        support::Fixture::RpkiInvalid,
        |_| {},
    )
    .await?;
    assert!(has_finding(&invalid, "rpki-route-invalid"));

    let valid = scan_fixture(
        "rpki-route-validity-check",
        support::Fixture::RpkiValid,
        |_| {},
    )
    .await?;
    assert!(!has_finding(&valid, "rpki-route-invalid"));

    let malformed = scan_fixture(
        "rpki-route-validity-check",
        support::Fixture::RpkiMalformed,
        |_| {},
    )
    .await?;
    assert!(!has_finding(&malformed, "rpki-route-invalid"));
    assert_redacted(&malformed)
}

#[tokio::test]
async fn rogue_certificate_public_contract_uses_the_operator_issuer_baseline()
-> Result<(), Box<dyn std::error::Error>> {
    let configure = |request: &mut ScanRequest| {
        request
            .options
            .insert("expected_issuers".into(), json!(["Expected CA"]));
    };
    let unexpected = scan_fixture(
        "rogue-certificate-check",
        support::Fixture::RogueCertificateUnexpected,
        configure,
    )
    .await?;
    assert!(has_finding(&unexpected, "unexpected-certificate-issuer"));

    let expected = scan_fixture(
        "rogue-certificate-check",
        support::Fixture::RogueCertificateExpected,
        configure,
    )
    .await?;
    assert!(!has_finding(&expected, "unexpected-certificate-issuer"));

    let malformed = scan_fixture(
        "rogue-certificate-check",
        support::Fixture::RogueCertificateMalformed,
        configure,
    )
    .await?;
    assert!(malformed.findings.is_empty());
    assert_redacted(&malformed)
}

#[tokio::test]
async fn performance_monitoring_public_contract_covers_http_and_pagespeed_signals()
-> Result<(), Box<dyn std::error::Error>> {
    let slow = scan_fixture(
        "performance-monitoring",
        support::Fixture::PerformanceSlow,
        |_| {},
    )
    .await?;
    assert!(has_finding(&slow, "slow-response-observed"));
    assert!(has_finding(&slow, "low-performance-score"));

    let healthy = scan_fixture(
        "performance-monitoring",
        support::Fixture::PerformanceHealthy,
        |_| {},
    )
    .await?;
    assert!(healthy.findings.is_empty());

    let malformed = scan_fixture(
        "performance-monitoring",
        support::Fixture::PerformanceMalformed,
        |_| {},
    )
    .await?;
    assert!(malformed.findings.is_empty());
    assert_redacted(&malformed)?;

    let harness = support::Harness::fixture(support::Fixture::PerformanceHealthy);
    let builtins = build_builtins(&harness.services())?;
    let id = sugra_domain::ScannerId::new("performance-monitoring")?;
    let scanner = builtins.registry.get(&id).ok_or("scanner is missing")?;
    let mut request = contract_request_for(scanner.descriptor())?;
    request
        .options
        .insert("strategies".into(), json!(["tablet"]));
    let Err(error) = scanner.scan(&request, &support::context(false)).await else {
        return Err("invalid PageSpeed strategy was accepted".into());
    };
    assert_eq!(error.kind, ScanErrorKind::InvalidInput);
    Ok(())
}

#[tokio::test]
async fn reputation_public_contract_handles_risky_clean_and_malformed_sources()
-> Result<(), Box<dyn std::error::Error>> {
    for id in ["domain-reputation-check", "ip-reputation-check"] {
        let risky = scan_fixture(id, support::Fixture::ReputationRisk, |_| {}).await?;
        assert!(has_finding(&risky, "provider-reputation-risk"));

        let clean = scan_fixture(id, support::Fixture::ReputationClean, |_| {}).await?;
        assert!(!has_finding(&clean, "provider-reputation-risk"));

        let malformed = scan_fixture(id, support::Fixture::ReputationMalformed, |_| {}).await?;
        assert!(!has_finding(&malformed, "provider-reputation-risk"));
        assert_redacted(&malformed)?;
    }
    Ok(())
}

#[tokio::test]
async fn scanner_specific_boundary_failures_keep_their_public_error_kinds()
-> Result<(), Box<dyn std::error::Error>> {
    for (id, expected) in [
        ("dnssec", ScanErrorKind::Transport),
        ("email-config", ScanErrorKind::Transport),
        ("dual-stack-behavior-profiler", ScanErrorKind::Transport),
        ("dual-stack-diff", ScanErrorKind::Transport),
        ("ttl-analysis", ScanErrorKind::Transport),
        ("typosquat-domain-checker", ScanErrorKind::Transport),
        ("passive-dns-history", ScanErrorKind::DependencyUnavailable),
        (
            "rpki-route-validity-check",
            ScanErrorKind::DependencyUnavailable,
        ),
        (
            "rogue-certificate-check",
            ScanErrorKind::DependencyUnavailable,
        ),
        ("performance-monitoring", ScanErrorKind::Transport),
        (
            "domain-reputation-check",
            ScanErrorKind::DependencyUnavailable,
        ),
        ("ip-reputation-check", ScanErrorKind::DependencyUnavailable),
    ] {
        let harness = support::Harness::failing();
        let builtins = build_builtins(&harness.services())?;
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("scanner is missing")?;
        let request = contract_request_for(scanner.descriptor())?;
        let Err(error) = scanner.scan(&request, &support::context(false)).await else {
            return Err(format!("{id} converted a boundary failure into success").into());
        };
        assert_eq!(error.kind, expected, "{id}");
        assert!(!error.message.contains(support::SECRET_MARKER), "{id}");
    }
    Ok(())
}

#[tokio::test]
async fn local_input_fake_supports_configured_and_empty_lines()
-> Result<(), Box<dyn std::error::Error>> {
    let request = LocalInputRequest {
        path: "/fixture/input.txt".into(),
        budget: Budget::default(),
    };
    let configured = support::Harness::successful()
        .with_local_input_lines(vec!["one".into(), "two".into()])
        .services()
        .local_input
        .read_lines(request.clone())
        .await?;
    assert_eq!(configured.lines, ["one", "two"]);

    let empty = support::Harness::successful()
        .services()
        .local_input
        .read_lines(request)
        .await?;
    assert!(empty.lines.is_empty());
    Ok(())
}

#[test]
fn catalog_descriptors_expose_complete_non_ambiguous_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::Harness::successful();
    let builtins = build_builtins(&harness.services())?;
    let mut legacy_ids = BTreeSet::new();

    for descriptor in builtins.catalog.iter() {
        assert!(!descriptor.name.trim().is_empty(), "{} name", descriptor.id);
        assert!(
            !descriptor.description.trim().is_empty(),
            "{} description",
            descriptor.id
        );
        assert!(
            !descriptor.track.trim().is_empty(),
            "{} track",
            descriptor.id
        );
        assert!(
            !descriptor.version.trim().is_empty(),
            "{} version",
            descriptor.id
        );
        assert!(
            !descriptor.target_kinds.is_empty(),
            "{} target kinds",
            descriptor.id
        );
        assert!(
            !descriptor.capabilities.is_empty(),
            "{} capabilities",
            descriptor.id
        );
        assert_eq!(
            descriptor
                .target_kinds
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            descriptor.target_kinds.len(),
            "{} duplicate target kind",
            descriptor.id
        );
        assert_eq!(
            descriptor
                .options
                .iter()
                .map(|option| option.key.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            descriptor.options.len(),
            "{} duplicate option key",
            descriptor.id
        );
        let legacy = serde_json::to_string(&descriptor.legacy_id)?;
        assert!(
            legacy_ids.insert(legacy),
            "{} duplicate legacy ID",
            descriptor.id
        );
        assert!(
            builtins.registry.get(&descriptor.id).is_some(),
            "{} missing implementation",
            descriptor.id
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_scanner_obeys_its_offline_runtime_contract() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = support::Harness::successful();
    let builtins = build_builtins(&harness.services())?;

    for contract in contracts() {
        harness.reset();
        let scanner_id = sugra_domain::ScannerId::new(contract.id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("matrix scanner is missing from the registry")?;
        let request = contract_request_for(scanner.descriptor())?;
        let result = scanner.scan(&request, &support::context(false)).await?;
        let calls = harness.observed_boundaries();
        assert_success_contract(&contract, &result, &calls, request.budget.max_requests)?;
    }
    Ok(())
}

fn assert_success_contract(
    contract: &sugra_scanner_contracts::ScannerContract,
    result: &ScanResult,
    calls: &std::collections::BTreeMap<Boundary, usize>,
    max_requests: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let total_calls: usize = calls.values().sum();
    assert_eq!(
        result.status,
        ExecutionStatus::Completed,
        "{} did not complete against a successful fixture",
        contract.id
    );
    assert!(
        !result.evidence.is_empty(),
        "{} returned no observation",
        contract.id
    );
    assert!(
        total_calls <= max_requests,
        "{} exceeded its request budget: {calls:?}",
        contract.id
    );
    for (boundary, count) in calls {
        let expected =
            usize::from(contract.boundary == *boundary || contract.supplements.contains(boundary));
        assert_eq!(
            usize::from(*count > 0),
            expected,
            "{} used an unexpected boundary: {calls:?}",
            contract.id
        );
    }
    if contract.boundary == Boundary::Local {
        assert_eq!(total_calls, 0, "{} performed external I/O", contract.id);
    } else {
        assert!(
            total_calls > 0,
            "{} did not exercise its boundary",
            contract.id
        );
    }
    for evidence in &result.evidence {
        assert!(
            evidence.kind.starts_with(&format!("{}-", contract.id)),
            "{} emitted unowned evidence kind {}",
            contract.id,
            evidence.kind
        );
        assert!(!evidence.source.trim().is_empty(), "{} source", contract.id);
        assert_eq!(evidence.observed_at, time::OffsetDateTime::UNIX_EPOCH);
        assert_eq!(
            evidence.observation["scanner_id"].as_str(),
            Some(contract.id),
            "{} evidence identity",
            contract.id
        );
        for field in ["analysis", "purpose"] {
            assert!(
                evidence.observation[field]
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
                "{} evidence {field}",
                contract.id
            );
        }
        assert!(
            evidence.observation.get("observation").is_some(),
            "{} missing structured observation",
            contract.id
        );
    }
    for finding in &result.findings {
        assert!(
            !finding.key.trim().is_empty(),
            "{} finding key",
            contract.id
        );
        assert!(
            !finding.evidence.is_empty()
                && finding
                    .evidence
                    .iter()
                    .all(|index| *index < result.evidence.len()),
            "{} finding {} has invalid evidence references",
            contract.id,
            finding.key
        );
    }
    assert!(
        !serde_json::to_string(result)?.contains(support::SECRET_MARKER),
        "{} leaked sensitive fixture material",
        contract.id
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_prevents_all_scanner_boundary_calls() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = support::Harness::successful();
    let builtins = build_builtins(&harness.services())?;

    for descriptor in builtins.catalog.iter() {
        harness.reset();
        let scanner = builtins
            .registry
            .get(&descriptor.id)
            .ok_or("catalog scanner is missing from the registry")?;
        let request = contract_request_for(descriptor)?;
        let Err(error) = scanner.scan(&request, &support::context(true)).await else {
            return Err(std::io::Error::other(format!(
                "{} completed after pre-cancellation",
                descriptor.id
            ))
            .into());
        };
        assert_eq!(error.kind, sugra_core::ScanErrorKind::Cancelled);
        assert_eq!(
            harness.observed_boundaries().values().sum::<usize>(),
            0,
            "{} contacted a boundary after cancellation",
            descriptor.id
        );
    }
    Ok(())
}

#[tokio::test]
async fn boundary_failures_are_typed_and_never_become_empty_successes()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::Harness::failing();
    let builtins = build_builtins(&harness.services())?;

    for contract in contracts() {
        if contract.boundary == Boundary::Local {
            continue;
        }
        harness.reset();
        let scanner_id = sugra_domain::ScannerId::new(contract.id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("matrix scanner is missing from the registry")?;
        let request = contract_request_for(scanner.descriptor())?;
        let outcome = scanner.scan(&request, &support::context(false)).await;

        match outcome {
            Err(error) => {
                assert_ne!(
                    error.kind,
                    sugra_core::ScanErrorKind::Internal,
                    "{}",
                    contract.id
                );
                assert!(
                    !error.message.trim().is_empty(),
                    "{} error message",
                    contract.id
                );
                assert!(!error.message.contains(support::SECRET_MARKER));
            }
            Ok(result) => {
                assert!(
                    !result.evidence.is_empty() || !result.diagnostics.is_empty(),
                    "{} converted a boundary failure into an empty result",
                    contract.id
                );
                assert!(
                    result.status != ExecutionStatus::Completed || !result.evidence.is_empty(),
                    "{} converted a boundary failure into empty success",
                    contract.id
                );
                assert!(!serde_json::to_string(&result)?.contains(support::SECRET_MARKER));
            }
        }
        let calls = harness.observed_boundaries();
        for expected in std::iter::once(&contract.boundary).chain(contract.supplements) {
            assert!(
                calls.get(expected).copied().unwrap_or_default() > 0,
                "{} did not exercise failure boundary {expected:?}: {calls:?}",
                contract.id
            );
        }
        assert!(
            calls.iter().all(|(boundary, count)| {
                *boundary == contract.boundary
                    || contract.supplements.contains(boundary)
                    || *count == 0
            }),
            "{} used an unexpected failure boundary: {calls:?}",
            contract.id
        );
    }
    Ok(())
}
