//! Public runtime contracts for the third HTTP semantic wave.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use sugra_core::{
    DnsPort, DnsQuery, DnsRecord, DnsRecordType, HttpCookie, HttpPort, HttpRequest, HttpResponse,
    PortError, PortErrorKind, ScanErrorKind,
};
use sugra_domain::{Confidence, ExecutionStatus, ScanResult, ScopeRule, Severity};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

#[derive(Debug, Clone, Copy)]
enum Scenario {
    Positive,
    Negative,
    Edge,
    PartialFailure,
}

struct FixtureHttp {
    id: String,
    scenario: Scenario,
    calls: AtomicUsize,
}

#[async_trait]
impl HttpPort for FixtureHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.scenario, Scenario::PartialFailure) && call > 0 {
            return Err(PortError::new(
                PortErrorKind::Timeout,
                "bounded discovered probe timed out",
            ));
        }
        Ok(fixture_response(&self.id, self.scenario, call, &request))
    }
}

struct FixtureDns(Scenario);

#[async_trait]
impl DnsPort for FixtureDns {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        if matches!(self.0, Scenario::Edge) {
            Ok(vec![DnsRecord {
                name: query.name,
                record_type: DnsRecordType::Cname,
                value: "distribution.cloudfront.net".into(),
                ttl: Some(60),
            }])
        } else {
            Ok(Vec::new())
        }
    }
}

struct ErrorHttp(PortErrorKind);

#[async_trait]
impl HttpPort for ErrorHttp {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        Err(PortError::new(self.0, "bounded HTTP fixture failure"))
    }
}

struct ErrorDns(PortErrorKind);

#[async_trait]
impl DnsPort for ErrorDns {
    async fn query(&self, _query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        Err(PortError::new(
            self.0,
            format!("bounded DNS fixture failure {}", support::SECRET_MARKER),
        ))
    }
}

fn fixture_response(
    id: &str,
    scenario: Scenario,
    call: usize,
    request: &HttpRequest,
) -> HttpResponse {
    let mut response = HttpResponse {
        final_url: request.url.clone(),
        status: 200,
        headers: BTreeMap::from([("content-type".into(), "text/html; charset=utf-8".into())]),
        cookies: Vec::new(),
        redirects: Vec::new(),
        body: b"<p>fixture</p>".to_vec(),
        duration_ms: 2,
    };
    apply_header_fixture(&mut response, id, scenario);
    apply_stateful_fixture(&mut response, id, scenario, call, request);
    apply_content_fixture(&mut response, id, scenario);
    response
}

fn apply_header_fixture(response: &mut HttpResponse, id: &str, scenario: Scenario) {
    match (id, scenario) {
        ("cdn-detection", Scenario::Positive) => {
            response
                .headers
                .insert("cf-ray".into(), support::SECRET_MARKER.into());
        }
        ("cdn-detection", Scenario::Negative) => {
            response.headers.insert("x-cache".into(), "hit".into());
        }
        ("server-info", Scenario::Positive) => {
            response
                .headers
                .insert("server".into(), support::SECRET_MARKER.into());
        }
        ("server-info", Scenario::Edge) => {
            response.headers.insert("server".into(), String::new());
        }
        _ => {}
    }
}

fn apply_stateful_fixture(
    response: &mut HttpResponse,
    id: &str,
    scenario: Scenario,
    call: usize,
    request: &HttpRequest,
) {
    if id == "cookie-scope-diff" && call == 0 {
        html(
            response,
            r#"<a href="https://shop8.example.com/">scoped host</a>"#,
        );
    }
    match (id, scenario) {
        ("autocomplete-vulnerability-checker", Scenario::Positive) => {
            html(response, r#"<input type="password">"#);
        }
        ("autocomplete-vulnerability-checker", Scenario::Negative) => {
            html(response, r#"<input type="password" autocomplete="off">"#);
        }
        ("autocomplete-vulnerability-checker", Scenario::Edge) => {
            html(
                response,
                r#"<input type="password" autocomplete="current-password">"#,
            );
        }
        ("content-discovery", Scenario::Positive | Scenario::Edge) if call == 0 => html(
            response,
            &format!(
                r#"<a href="/discovered?token={}">candidate</a>"#,
                support::SECRET_MARKER
            ),
        ),
        ("content-discovery", Scenario::Negative) => response.status = 404,
        ("content-discovery", Scenario::Edge) => response.status = 399,
        ("cookie-scope-diff", Scenario::Positive)
            if call == 0 || request.url.host_str() == Some("shop8.example.com") =>
        {
            response.cookies.push(cookie(
                "stable-cookie-fingerprint",
                if request.url.host_str() == Some("shop8.example.com") {
                    "/admin"
                } else {
                    "/"
                },
            ));
        }
        ("cookie-scope-diff", Scenario::Negative) => {
            response
                .cookies
                .push(cookie("stable-cookie-fingerprint", "/"));
        }
        ("cookie-scope-diff", Scenario::Edge) => {
            response.cookies.push(cookie(
                if request.url.host_str() == Some("shop8.example.com") {
                    "cookie-fingerprint-b"
                } else {
                    "cookie-fingerprint-a"
                },
                "/",
            ));
        }
        _ => {}
    }
}

fn apply_content_fixture(response: &mut HttpResponse, id: &str, scenario: Scenario) {
    match (id, scenario) {
        ("dependency-js-cdn-scanner", Scenario::Positive) => html(
            response,
            &format!(
                r#"<script src="https://cdn.example.net/app.js?token={}"></script>"#,
                support::SECRET_MARKER
            ),
        ),
        ("dependency-js-cdn-scanner", Scenario::Negative) => {
            html(response, r#"<script src="/app.js"></script>"#);
        }
        ("dependency-js-cdn-scanner", Scenario::Edge) => html(
            response,
            r#"<script src="https://cdn.example.net/a.js"></script><script src="https://cdn.example.net/b.js" integrity="sha384-fixture"></script>"#,
        ),
        ("dom-sink-scanner", Scenario::Positive) => html(
            response,
            r"<script>document.querySelector('#x').innerHTML = '<b>x</b>';</script>",
        ),
        ("dom-sink-scanner", Scenario::Negative) => {
            html(response, "<p>ordinary content</p>");
        }
        ("dom-sink-scanner", Scenario::Edge) => {
            html(response, "<p>Documentation mentions .innerHTML safely.</p>");
        }
        ("embedded-object-hunter", Scenario::Positive) => html(
            response,
            &format!(
                r#"<object data="/viewer?token={}"></object>"#,
                support::SECRET_MARKER
            ),
        ),
        ("embedded-object-hunter", Scenario::Negative) => {
            html(response, "<main>No embedded content</main>");
        }
        ("embedded-object-hunter", Scenario::Edge) => {
            html(response, r#"<iframe sandbox src="/frame"></iframe>"#);
        }
        ("dependency-js-cdn-scanner", Scenario::PartialFailure) => html(
            response,
            &format!(
                r#"<script src="https://cdn.example.net/app.js"></script><a href="/child0?token={}">child</a>"#,
                support::SECRET_MARKER
            ),
        ),
        ("dom-sink-scanner", Scenario::PartialFailure) => html(
            response,
            &format!(
                "<script>target.innerHTML = value;</script><a href=\"/child0?token={}\">child</a>",
                support::SECRET_MARKER
            ),
        ),
        ("embedded-object-hunter", Scenario::PartialFailure) => html(
            response,
            &format!(
                r#"<object data="/viewer"></object><a href="/child0?token={}">child</a>"#,
                support::SECRET_MARKER
            ),
        ),
        _ => {}
    }
}

async fn assert_dns_stage_failures() -> Result<(), Box<dyn std::error::Error>> {
    for (port_kind, scan_kind) in [
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
        let mut services = support::Harness::successful().services();
        services.http = Arc::new(FixtureHttp {
            id: "cdn-detection".into(),
            scenario: Scenario::Negative,
            calls: AtomicUsize::new(0),
        });
        services.dns = Arc::new(ErrorDns(port_kind));
        let builtins = build_builtins(&services)?;
        let scanner_id = sugra_domain::ScannerId::new("cdn-detection")?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("failure scanner is missing")?;
        let request = support::request_for(scanner.descriptor())?;
        let result = scanner.scan(&request, &support::context(false)).await?;

        assert_eq!(result.status, ExecutionStatus::Partial, "{port_kind:?}");
        assert_eq!(result.evidence.len(), 1, "{port_kind:?}");
        assert!(result.findings.is_empty(), "{port_kind:?}");
        assert_eq!(result.diagnostics.len(), 1, "{port_kind:?}");
        assert!(
            result.diagnostics[0]
                .message
                .contains(&format!("{scan_kind:?}")),
            "{port_kind:?}"
        );
        assert!(!serde_json::to_string(&result)?.contains(support::SECRET_MARKER));
    }
    Ok(())
}

fn html(response: &mut HttpResponse, body: &str) {
    response.body = body.as_bytes().to_vec();
}

fn cookie(name_sha256: &str, path: &str) -> HttpCookie {
    HttpCookie {
        name_sha256: name_sha256.into(),
        domain: None,
        path: Some(path.into()),
        secure: true,
        http_only: true,
        same_site: Some("Lax".into()),
        max_age_seconds: None,
    }
}

async fn scan(id: &str, scenario: Scenario) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FixtureHttp {
        id: id.into(),
        scenario,
        calls: AtomicUsize::new(0),
    });
    services.dns = Arc::new(FixtureDns(scenario));
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("fixture scanner is missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    if id == "cookie-scope-diff" {
        request
            .options
            .insert("include_subdomains".into(), serde_json::json!(true));
        request.scope.rules = vec![ScopeRule::Domain("example.com".into())];
    }
    Ok(scanner.scan(&request, &support::context(false)).await?)
}

async fn assert_typed_failures(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    for (port_kind, scan_kind) in [
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
        let mut services = support::Harness::failing().services();
        services.http = Arc::new(ErrorHttp(port_kind));
        let builtins = build_builtins(&services)?;
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("failure scanner is missing")?;
        let request = support::request_for(scanner.descriptor())?;
        let Err(error) = scanner.scan(&request, &support::context(false)).await else {
            return Err(format!("{id} converted {port_kind:?} into success").into());
        };
        assert_eq!(error.kind, scan_kind, "{id}: {port_kind:?}");
        assert!(!error.message.contains(support::SECRET_MARKER));
    }
    Ok(())
}

fn expected_contract(id: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match id {
        "cdn-detection" => Some((
            "cdn-signal-observed",
            "technology-detection-analysis",
            "Detect delivery networks from scoped HTTP and DNS indicators.",
        )),
        "server-info" => Some((
            "server-banner-observed",
            "web-metadata-analysis",
            "Summarize status, headers, protocol, and document metadata.",
        )),
        "autocomplete-vulnerability-checker" => Some((
            "sensitive-autocomplete-enabled",
            "browser-surface-analysis",
            "Inspect sensitive forms for unsafe autocomplete policy.",
        )),
        "content-discovery" => Some((
            "content-resource-observed",
            "bounded-crawl-analysis",
            "Discover in-scope linked content.",
        )),
        "cookie-scope-diff" => Some((
            "cookie-scope-varies",
            "privacy-analysis",
            "Compare cookie scope attributes across observed hosts.",
        )),
        "dependency-js-cdn-scanner" => Some((
            "external-javascript-dependency",
            "web-inventory-analysis",
            "Inventory JavaScript dependencies and delivery origins.",
        )),
        "dom-sink-scanner" => Some((
            "dom-sink-marker-observed",
            "content-risk-analysis",
            "Find risky browser-side DOM sinks in public scripts.",
        )),
        "embedded-object-hunter" => Some((
            "embedded-object-observed",
            "web-inventory-analysis",
            "Inventory embedded object surfaces.",
        )),
        _ => None,
    }
}

fn assert_completed(
    id: &str,
    result: &ScanResult,
    expected_evidence: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((_, analysis, purpose)) = expected_contract(id) else {
        return Err(format!("missing contract for {id}").into());
    };
    assert_eq!(result.status, ExecutionStatus::Completed);
    assert!(result.diagnostics.is_empty());
    assert_eq!(result.evidence.len(), expected_evidence, "{id}");
    for evidence in &result.evidence {
        assert_eq!(evidence.observation["scanner_id"], id);
        assert_eq!(evidence.observation["purpose"], purpose);
        if id == "cdn-detection" && evidence.kind == "cdn-detection-dns-records" {
            assert_eq!(evidence.observation["analysis"], "dns-topology-analysis");
        } else {
            assert_eq!(evidence.kind, format!("{id}-http-observation"));
            assert_eq!(evidence.observation["analysis"], analysis);
        }
    }
    assert!(!serde_json::to_string(result)?.contains(support::SECRET_MARKER));
    Ok(())
}

fn finding_keys(result: &ScanResult) -> BTreeSet<&str> {
    result
        .findings
        .iter()
        .map(|finding| finding.key.as_str())
        .collect()
}

async fn assert_standard_contract(
    id: &str,
    positive_evidence: usize,
    negative_evidence: usize,
    edge_has_signal: bool,
    edge_evidence: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((key, _, _)) = expected_contract(id) else {
        return Err(format!("missing expected finding for {id}").into());
    };
    let positive = scan(id, Scenario::Positive).await?;
    assert_eq!(finding_keys(&positive), BTreeSet::from([key]), "{id}");
    assert!(positive.findings.iter().all(|finding| {
        !finding.evidence.is_empty()
            && finding
                .evidence
                .iter()
                .all(|index| *index < positive.evidence.len())
    }));
    assert_completed(id, &positive, positive_evidence)?;

    let negative = scan(id, Scenario::Negative).await?;
    assert!(negative.findings.is_empty(), "{id}: negative");
    assert_completed(id, &negative, negative_evidence)?;

    let edge = scan(id, Scenario::Edge).await?;
    if edge_has_signal {
        assert_eq!(finding_keys(&edge), BTreeSet::from([key]), "{id}: edge");
    } else {
        assert!(edge.findings.is_empty(), "{id}: edge");
    }
    assert_completed(id, &edge, edge_evidence)?;
    assert_typed_failures(id).await
}

#[tokio::test]
async fn header_and_metadata_scanners_prove_public_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let http_signal = scan("cdn-detection", Scenario::Positive).await?;
    assert_eq!(
        finding_keys(&http_signal),
        BTreeSet::from(["cdn-signal-observed"])
    );
    assert_completed("cdn-detection", &http_signal, 2)?;

    let negative = scan("cdn-detection", Scenario::Negative).await?;
    assert!(negative.findings.is_empty());
    assert_completed("cdn-detection", &negative, 2)?;

    let dns_signal = scan("cdn-detection", Scenario::Edge).await?;
    assert_eq!(
        finding_keys(&dns_signal),
        BTreeSet::from(["cdn-dns-signal-observed"])
    );
    assert_eq!(dns_signal.findings[0].evidence, [1]);
    assert_completed("cdn-detection", &dns_signal, 2)?;
    assert_typed_failures("cdn-detection").await?;
    assert_dns_stage_failures().await?;

    assert_standard_contract("server-info", 1, 1, false, 1).await
}

#[tokio::test]
async fn browser_and_crawler_scanners_prove_public_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    assert_standard_contract("autocomplete-vulnerability-checker", 1, 1, true, 1).await?;
    assert_standard_contract("content-discovery", 2, 1, true, 2).await
}

#[tokio::test]
async fn privacy_and_inventory_scanners_prove_public_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    assert_standard_contract("cookie-scope-diff", 4, 4, false, 4).await?;
    assert_standard_contract("dependency-js-cdn-scanner", 1, 1, true, 1).await?;
    assert_standard_contract("embedded-object-hunter", 1, 1, true, 1).await
}

#[tokio::test]
async fn dom_sink_scanner_ignores_prose_and_proves_public_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("dom-sink-scanner", Scenario::Positive).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["dom-sink-marker-observed"])
    );
    assert_eq!(positive.findings[0].severity, Severity::Medium);
    assert_eq!(positive.findings[0].confidence, Confidence::Inferred);
    assert_eq!(positive.findings[0].evidence, [0]);
    assert_completed("dom-sink-scanner", &positive, 1)?;

    let negative = scan("dom-sink-scanner", Scenario::Negative).await?;
    assert!(negative.findings.is_empty());
    assert_completed("dom-sink-scanner", &negative, 1)?;

    let edge = scan("dom-sink-scanner", Scenario::Edge).await?;
    assert!(edge.findings.is_empty());
    assert_completed("dom-sink-scanner", &edge, 1)?;
    assert_typed_failures("dom-sink-scanner").await
}

#[tokio::test]
async fn partial_crawl_diagnostics_never_retain_discovered_urls()
-> Result<(), Box<dyn std::error::Error>> {
    for id in [
        "dependency-js-cdn-scanner",
        "dom-sink-scanner",
        "embedded-object-hunter",
    ] {
        let result = scan(id, Scenario::PartialFailure).await?;
        assert_eq!(result.status, ExecutionStatus::Partial, "{id}");
        assert_eq!(result.evidence.len(), 1, "{id}");
        assert_eq!(result.diagnostics.len(), 1, "{id}");
        assert!(
            result.diagnostics[0]
                .message
                .starts_with("HTTP probe failed:"),
            "{id}"
        );
        assert!(!serde_json::to_string(&result)?.contains(support::SECRET_MARKER));
    }
    Ok(())
}
