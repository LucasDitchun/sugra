//! Public offline contracts for Wave 5 HTTP analysis scanners.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};
use sugra_core::{
    HttpCookie, HttpMethod, HttpPort, HttpRedirect, HttpRedirectDecision, HttpRequest,
    HttpResponse, PortError, PortErrorKind, ScanErrorKind,
};
use sugra_domain::{
    Budget, Confidence, ExecutionStatus, Finding, ScanRequest, ScanResult, Severity, TargetKind,
};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

const SECRET: &str = "wave5-analysis-secret-7f31";

const SCANNERS: [&str; 18] = [
    "carbon-footprint",
    "email-harvester",
    "file-upload-surface-finder",
    "firewall-detection",
    "hidden-parameter-discovery",
    "html5-feature-abuse-detector",
    "javascript-file-analyzer",
    "lazy-load-resource-finder",
    "passive-cve-mapper",
    "pixel-tracker-finder",
    "privacy-gdpr",
    "quality-metrics",
    "rate-limit-waf-bypass-test",
    "redirect-chain",
    "seo-abuse-detector",
    "session-hijacking-passive",
    "static-asset-fingerprinter",
    "third-party-script-risk-profiler",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    Positive,
    Negative,
    Edge,
    Bounded,
}

#[derive(Clone)]
struct FixtureHttp {
    scanner_id: &'static str,
    case: Case,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

#[async_trait]
impl HttpPort for FixtureHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let call = {
            let mut requests = self
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let call = requests.len();
            requests.push(request.clone());
            call
        };
        Ok(fixture_response(self.scanner_id, self.case, call, &request))
    }
}

struct FailingHttp(PortErrorKind);

#[async_trait]
impl HttpPort for FailingHttp {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        Err(PortError::new(
            self.0,
            format!("wave5 analysis HTTP {:?} failure", self.0),
        ))
    }
}

fn fixture_response(
    scanner_id: &str,
    case: Case,
    call: usize,
    request: &HttpRequest,
) -> HttpResponse {
    let mut response = HttpResponse {
        final_url: request.url.clone(),
        status: 200,
        headers: BTreeMap::from([
            ("content-type".into(), "text/html; charset=utf-8".into()),
            ("x-private-fixture".into(), SECRET.into()),
        ]),
        cookies: Vec::new(),
        redirects: Vec::new(),
        body: b"<main>ordinary public page</main>".to_vec(),
        duration_ms: 4,
    };
    response
        .final_url
        .query_pairs_mut()
        .append_pair("private", SECRET);

    if case == Case::Bounded {
        response.body = format!(
            "<main>{}</main>",
            format!(r#"<a href="/next?token={SECRET}">next</a>"#).repeat(512)
        )
        .into_bytes();
        for index in 0..300 {
            response
                .headers
                .insert(format!("x-bound-{index:03}"), SECRET.into());
        }
        return response;
    }

    match scanner_id {
        "carbon-footprint" => configure_carbon(&mut response, case),
        "email-harvester" => configure_email(&mut response, case),
        "file-upload-surface-finder" => configure_upload(&mut response, case, call),
        "firewall-detection" => configure_firewall(&mut response, case),
        "hidden-parameter-discovery" => configure_hidden_parameter(&mut response, case, call),
        "html5-feature-abuse-detector" => configure_html5(&mut response, case),
        "javascript-file-analyzer" => configure_javascript(&mut response, case, call),
        "lazy-load-resource-finder" => configure_lazy(&mut response, case),
        "passive-cve-mapper" => configure_cve(&mut response, case),
        "pixel-tracker-finder" => configure_pixel(&mut response, case),
        "privacy-gdpr" => configure_privacy(&mut response, case),
        "quality-metrics" => configure_quality(&mut response, case),
        "rate-limit-waf-bypass-test" => configure_rate_limit(&mut response, case, call),
        "redirect-chain" => configure_redirect(&mut response, case, request),
        "seo-abuse-detector" => configure_seo(&mut response, case, call),
        "session-hijacking-passive" => configure_session(&mut response, case, call),
        "static-asset-fingerprinter" => configure_static_assets(&mut response, case, call),
        "third-party-script-risk-profiler" => configure_third_party(&mut response, case),
        _ => unreachable!("missing fixture for {scanner_id}"),
    }
    response
}

fn configure_carbon(response: &mut HttpResponse, case: Case) {
    let bytes = match case {
        Case::Positive => 1_048_577,
        Case::Negative => 1_048_575,
        Case::Edge => 1_048_576,
        Case::Bounded => unreachable!(),
    };
    response.body = vec![b'x'; bytes];
    response
        .headers
        .insert("content-type".into(), "application/octet-stream".into());
}

fn configure_email(response: &mut HttpResponse, case: Case) {
    response.body = match case {
        Case::Positive => format!("Contact security-team@example.net about {SECRET}").into_bytes(),
        Case::Negative => b"Contact the security team through the published form.".to_vec(),
        Case::Edge => b"The malformed token user@example has no public domain suffix.".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

fn configure_upload(response: &mut HttpResponse, case: Case, call: usize) {
    if call > 0 {
        response.status = 404;
        return;
    }
    response.body = match case {
        Case::Positive => b"<form method=post><input type=file name=document></form>".to_vec(),
        Case::Negative => b"<form method=post><input type=text name=document></form>".to_vec(),
        Case::Edge => b"<file-input>custom documentation element</file-input>".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

fn configure_firewall(response: &mut HttpResponse, case: Case) {
    match case {
        Case::Positive => {
            response
                .headers
                .insert("cf-ray".into(), "fixture-edge".into());
        }
        Case::Negative => {}
        Case::Edge => {
            response
                .headers
                .insert("x-cf-ray-documentation".into(), "not a WAF header".into());
        }
        Case::Bounded => unreachable!(),
    }
}

fn configure_hidden_parameter(response: &mut HttpResponse, case: Case, call: usize) {
    let baseline = b"stable response body".to_vec();
    response.body = match case {
        Case::Positive if call > 0 => format!("parameter-specific response {call}").into_bytes(),
        Case::Edge if call == 1 => b"stable response bodY".to_vec(),
        Case::Positive | Case::Negative | Case::Edge => baseline,
        Case::Bounded => unreachable!(),
    };
}

fn configure_html5(response: &mut HttpResponse, case: Case) {
    response.body = match case {
        Case::Positive => {
            b"<script>navigator.geolocation.getCurrentPosition(render)</script>".to_vec()
        }
        Case::Negative => b"<script>document.querySelector('main')</script>".to_vec(),
        Case::Edge => {
            b"<p>The documentation mentions geolocation without executable code.</p>".to_vec()
        }
        Case::Bounded => unreachable!(),
    };
}

fn configure_javascript(response: &mut HttpResponse, case: Case, call: usize) {
    match (case, call) {
        (Case::Positive, 0) => {
            response.body = b"<script src=/assets/app.js></script>".to_vec();
        }
        (Case::Positive, 1) => {
            response
                .headers
                .insert("content-type".into(), "application/javascript".into());
            response.body = b"fetch('/api/v1/profile');".to_vec();
        }
        (Case::Negative, _) => {
            response.body = b"<script>const answer = 42;</script>".to_vec();
        }
        (Case::Edge, _) => {
            response.body =
                b"<script type=application/json>{\"example\":\"/api/v1\"}</script>".to_vec();
        }
        _ => {}
    }
}

fn configure_lazy(response: &mut HttpResponse, case: Case) {
    response.body = match case {
        Case::Positive => b"<img src=/hero.png loading=lazy>".to_vec(),
        Case::Negative => b"<img src=/hero.png>".to_vec(),
        Case::Edge => b"<p>Use loading=lazy in sample markup.</p>".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

fn configure_cve(response: &mut HttpResponse, case: Case) {
    match case {
        Case::Positive => {
            response
                .headers
                .insert("server".into(), "Apache/2.4.49".into());
        }
        Case::Negative => {
            response.headers.insert("server".into(), "Apache".into());
        }
        Case::Edge => {
            response
                .headers
                .insert("server".into(), "Product/release-notes2".into());
        }
        Case::Bounded => unreachable!(),
    }
}

fn configure_pixel(response: &mut HttpResponse, case: Case) {
    response.body = match case {
        Case::Positive => b"<img src=/beacon.gif width=1 height=1>".to_vec(),
        Case::Negative => b"<img src=/logo.png width=120 height=40>".to_vec(),
        Case::Edge => b"<img src=/logo.png style='width:1px;height:1px'>".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

fn configure_privacy(response: &mut HttpResponse, case: Case) {
    response.body = match case {
        Case::Positive => b"<form><input name=email></form>".to_vec(),
        Case::Negative => {
            b"<a href=/privacy>Privacy policy</a><form><input name=email></form>".to_vec()
        }
        Case::Edge => b"<p>No data collection form is present.</p>".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

fn configure_quality(response: &mut HttpResponse, case: Case) {
    match case {
        Case::Positive => response.status = 500,
        Case::Negative => {}
        Case::Edge => {
            response.status = 204;
            response.body.clear();
        }
        Case::Bounded => unreachable!(),
    }
}

fn configure_rate_limit(response: &mut HttpResponse, case: Case, call: usize) {
    match case {
        Case::Negative if call == 2 => response.status = 429,
        Case::Positive | Case::Negative => {}
        Case::Edge => {
            response.headers.insert(
                "x-not-ratelimit-policy".into(),
                "unrelated application metadata".into(),
            );
        }
        Case::Bounded => unreachable!(),
    }
}

fn configure_redirect(response: &mut HttpResponse, case: Case, request: &HttpRequest) {
    match case {
        Case::Positive => {
            let mut to = request.url.clone();
            to.set_path(&format!("/landing/{SECRET}"));
            to.query_pairs_mut().append_pair("token", SECRET);
            response.redirects.push(HttpRedirect {
                status: 302,
                from: request.url.clone(),
                to,
                decision: HttpRedirectDecision::Followed,
            });
        }
        Case::Negative => {}
        Case::Edge => {
            response.status = 302;
            response
                .headers
                .insert("location".into(), "/landing".into());
        }
        Case::Bounded => unreachable!(),
    }
}

fn configure_seo(response: &mut HttpResponse, case: Case, call: usize) {
    response.body = match case {
        Case::Positive if call == 0 => {
            b"<div hidden>cheap pills and free money</div><main>public</main>".to_vec()
        }
        Case::Positive => b"<main>ordinary public page with equal padding text</main>".to_vec(),
        Case::Negative => b"<main>ordinary public page</main>".to_vec(),
        Case::Edge => b"<div hidden>navigation template</div><main>public</main>".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

fn configure_session(response: &mut HttpResponse, case: Case, call: usize) {
    if call > 0 {
        return;
    }
    response.cookies.push(HttpCookie {
        name_sha256: "session-name-fingerprint".into(),
        domain: Some(format!("{SECRET}.invalid")),
        path: Some("/private".into()),
        secure: case != Case::Positive,
        http_only: true,
        same_site: Some("Lax".into()),
        max_age_seconds: Some(600),
    });
}

fn configure_static_assets(response: &mut HttpResponse, case: Case, call: usize) {
    match (case, call) {
        (Case::Positive, 0) => {
            response.body = b"<script src=/app.js></script><img src=/logo.png>".to_vec();
        }
        (Case::Negative, _) => response.body = b"<main>text only</main>".to_vec(),
        (Case::Edge, _) => {
            response.body =
                b"<script type=application/json>{\"asset\":\"logo.png\"}</script>".to_vec();
        }
        _ => response.body = b"const ready = true;".to_vec(),
    }
}

fn configure_third_party(response: &mut HttpResponse, case: Case) {
    response.body = match case {
        Case::Positive => b"<script src=https://cdn.example.net/app.js></script>".to_vec(),
        Case::Negative => {
            b"<script src=https://cdn.example.net/app.js integrity='sha384-fixture'></script>"
                .to_vec()
        }
        Case::Edge => {
            b"<script type=application/json>{\"src\":\"https://cdn.example.net/app.js\"}</script>"
                .to_vec()
        }
        Case::Bounded => unreachable!(),
    };
}

struct Run {
    result: ScanResult,
    requests: Vec<HttpRequest>,
}

async fn scan_case(
    scanner_id: &'static str,
    case: Case,
) -> Result<Run, Box<dyn std::error::Error>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FixtureHttp {
        scanner_id,
        case,
        requests: Arc::clone(&requests),
    });
    let builtins = build_builtins(&services)?;
    let id = sugra_domain::ScannerId::new(scanner_id)?;
    let scanner = builtins.registry.get(&id).ok_or("scanner is missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    configure_request(&mut request, scanner_id, case)?;
    let result = scanner.scan(&request, &support::context(false)).await?;
    let requests = requests
        .lock()
        .map_err(|_| "request log is unavailable")?
        .clone();
    Ok(Run { result, requests })
}

fn configure_request(
    request: &mut ScanRequest,
    scanner_id: &str,
    case: Case,
) -> Result<(), Box<dyn std::error::Error>> {
    match scanner_id {
        "carbon-footprint" => {
            request.budget = Budget {
                max_response_bytes: 2 * 1_048_576,
                ..request.budget
            }
            .validate()?;
        }
        "hidden-parameter-discovery" => {
            request.options.insert("max_params".into(), json!(2));
            request
                .options
                .insert("test_values".into(), json!(["alpha", "beta"]));
            request.options.insert("threshold".into(), json!(50));
        }
        "rate-limit-waf-bypass-test" => {
            request.options.insert("batch_size".into(), json!(3));
        }
        _ => {}
    }
    if case == Case::Bounded {
        request.budget = Budget {
            max_requests: 2,
            max_response_bytes: 4_096,
            ..request.budget
        }
        .validate()?;
    }
    Ok(())
}

fn expected_contract(id: &str) -> (&'static str, &'static str) {
    match id {
        "carbon-footprint" => (
            "web-performance-analysis",
            "Estimate transfer impact from bounded response sizes.",
        ),
        "email-harvester" => (
            "web-inventory-analysis",
            "Extract public email addresses from in-scope documents.",
        ),
        "file-upload-surface-finder" => (
            "api-surface-analysis",
            "Locate public file-upload form surfaces.",
        ),
        "firewall-detection" => (
            "technology-detection-analysis",
            "Detect public web-application firewall indicators.",
        ),
        "hidden-parameter-discovery" => (
            "web-inventory-analysis",
            "Inventory hidden form and query parameters.",
        ),
        "html5-feature-abuse-detector" => (
            "browser-surface-analysis",
            "Detect potentially risky browser feature usage.",
        ),
        "javascript-file-analyzer" => (
            "content-risk-analysis",
            "Inventory and inspect public JavaScript resources.",
        ),
        "lazy-load-resource-finder" => {
            ("web-inventory-analysis", "Inventory lazy-loaded resources.")
        }
        "passive-cve-mapper" => (
            "technology-detection-analysis",
            "Map detected public products to vulnerability identifiers.",
        ),
        "pixel-tracker-finder" => (
            "privacy-analysis",
            "Detect tracking pixels and beacon-like resources.",
        ),
        "privacy-gdpr" => (
            "privacy-analysis",
            "Inspect public privacy and consent indicators.",
        ),
        "quality-metrics" => (
            "web-performance-analysis",
            "Compute deterministic document quality metrics.",
        ),
        "rate-limit-waf-bypass-test" => (
            "authorized-web-probe-analysis",
            "Perform a bounded authorized rate-limit consistency probe.",
        ),
        "redirect-chain" => ("web-metadata-analysis", "Observe scoped redirect behavior."),
        "seo-abuse-detector" => (
            "content-risk-analysis",
            "Detect suspicious public SEO manipulation indicators.",
        ),
        "session-hijacking-passive" => (
            "privacy-analysis",
            "Inspect redacted session transport protections.",
        ),
        "static-asset-fingerprinter" => (
            "web-inventory-analysis",
            "Fingerprint public static assets.",
        ),
        "third-party-script-risk-profiler" => (
            "content-risk-analysis",
            "Profile third-party script origins and integrity controls.",
        ),
        _ => unreachable!("missing contract for {id}"),
    }
}

#[allow(clippy::too_many_lines)]
fn expected_finding(id: &str, evidence: Vec<usize>) -> Finding {
    let (key, title, severity, confidence) = match id {
        "carbon-footprint" => (
            "large-transfer-sample",
            "The bounded page sample transferred more than one mebibyte",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "email-harvester" => (
            "public-email-reference",
            "Public email references were observed and fingerprinted",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "file-upload-surface-finder" => (
            "file-upload-surface",
            "A file upload input is present",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "firewall-detection" => (
            "web-protection-signal-observed",
            "A web protection intermediary signal is present",
            Severity::Info,
            Confidence::Inferred,
        ),
        "hidden-parameter-discovery" => (
            "hidden-parameter-response-differs",
            "A bounded parameter probe consistently changed the public response",
            Severity::Info,
            Confidence::Inferred,
        ),
        "html5-feature-abuse-detector" => (
            "browser-capability-marker-observed",
            "Client code references sensitive browser capabilities",
            Severity::Info,
            Confidence::Inferred,
        ),
        "javascript-file-analyzer" => (
            "javascript-api-reference-observed",
            "Client code contains API endpoint references",
            Severity::Info,
            Confidence::Inferred,
        ),
        "lazy-load-resource-finder" => (
            "lazy-resource-observed",
            "Lazy-loaded resources are present",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "passive-cve-mapper" => (
            "known-vulnerable-component",
            "A public banner matches a locally curated vulnerable component version",
            Severity::High,
            Confidence::Confirmed,
        ),
        "pixel-tracker-finder" => (
            "tracking-pixel-observed",
            "One-pixel image resources are present",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "privacy-gdpr" => (
            "privacy-notice-not-observed",
            "No privacy or consent marker was observed near public forms",
            Severity::Info,
            Confidence::Unknown,
        ),
        "quality-metrics" => (
            "quality-signal-observed",
            "The bounded sample contains an HTTP quality degradation signal",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "rate-limit-waf-bypass-test" => (
            "rate-limit-not-observed",
            "No rate-limit response or header appeared in the small authorized sample",
            Severity::Info,
            Confidence::Unknown,
        ),
        "redirect-chain" => (
            "redirect-chain-observed",
            "One or more redirect hops were recorded",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "seo-abuse-detector" => (
            "seo-hidden-content-signal",
            "The document combines hidden presentation with common SEO-spam language",
            Severity::Medium,
            Confidence::Inferred,
        ),
        "session-hijacking-passive" => (
            "cookie-secure-missing",
            "A response cookie does not declare Secure",
            Severity::Medium,
            Confidence::Confirmed,
        ),
        "static-asset-fingerprinter" => (
            "static-assets-observed",
            "Static assets are available for local fingerprinting",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "third-party-script-risk-profiler" => (
            "external-script-without-integrity",
            "An external script does not declare subresource integrity",
            Severity::Low,
            Confidence::Confirmed,
        ),
        _ => unreachable!("missing finding for {id}"),
    };
    Finding {
        key: key.into(),
        title: title.into(),
        severity,
        confidence,
        evidence,
    }
}

fn positive_evidence(id: &str, request_count: usize) -> Vec<usize> {
    match id {
        "hidden-parameter-discovery" | "rate-limit-waf-bypass-test" => (0..request_count).collect(),
        "javascript-file-analyzer" => vec![1],
        _ => vec![0],
    }
}

fn firewall_supplement_findings() -> Vec<Finding> {
    [22_u16, 53, 80, 443]
        .into_iter()
        .enumerate()
        .map(|(index, port)| Finding {
            key: "tcp-port-open".into(),
            title: format!("TCP port {port} accepted a connection"),
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            evidence: vec![index + 1],
        })
        .collect()
}

fn assert_envelope(run: &Run, id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (analysis, purpose) = expected_contract(id);
    assert_eq!(run.result.status, ExecutionStatus::Completed, "{id}");
    assert!(run.result.diagnostics.is_empty(), "{id}");
    if id == "firewall-detection" {
        assert_eq!(run.requests.len(), 1);
        assert_eq!(run.result.evidence.len(), 5);
        let observed_analyses = run
            .result
            .evidence
            .iter()
            .map(|evidence| {
                evidence.observation["analysis"]
                    .as_str()
                    .unwrap_or_default()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_analyses,
            BTreeSet::from(["tcp-port-analysis", "technology-detection-analysis"])
        );
        for evidence in &run.result.evidence {
            assert!(evidence.kind.starts_with("firewall-detection-"));
            assert_eq!(evidence.observation["scanner_id"], id);
            assert_eq!(evidence.observation["purpose"], purpose);
            assert_eq!(
                object_keys(&evidence.observation),
                BTreeSet::from(["analysis", "observation", "purpose", "scanner_id"])
            );
        }
        let serialized = serde_json::to_string(&run.result)?;
        assert!(!serialized.contains(SECRET));
        return Ok(());
    }
    assert_eq!(run.result.evidence.len(), run.requests.len(), "{id}");
    for evidence in &run.result.evidence {
        assert_eq!(evidence.kind, format!("{id}-http-observation"), "{id}");
        assert!(!evidence.source.contains('?'), "{id}");
        assert_eq!(evidence.observation["scanner_id"], id, "{id}");
        assert_eq!(evidence.observation["analysis"], analysis, "{id}");
        assert_eq!(evidence.observation["purpose"], purpose, "{id}");
        assert_eq!(
            object_keys(&evidence.observation),
            BTreeSet::from(["analysis", "observation", "purpose", "scanner_id"]),
            "{id}"
        );
        assert_eq!(
            object_keys(&evidence.observation["observation"]),
            BTreeSet::from([
                "bytes",
                "cookies",
                "document",
                "duration_ms",
                "headers",
                "method",
                "probe",
                "redirects",
                "sha256",
                "status"
            ]),
            "{id}"
        );
    }
    let serialized = serde_json::to_string(&run.result)?;
    assert!(!serialized.contains(SECRET), "{id}");
    assert!(run.result.findings.iter().all(|finding| {
        finding
            .evidence
            .iter()
            .all(|index| *index < run.result.evidence.len())
    }));
    Ok(())
}

fn object_keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys().map(String::as_str))
        .collect()
}

#[tokio::test]
async fn every_analysis_scanner_proves_real_positive_negative_and_edge_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    for id in SCANNERS {
        let positive = scan_case(id, Case::Positive).await?;
        assert_envelope(&positive, id)?;
        let mut expected_positive = vec![expected_finding(
            id,
            positive_evidence(id, positive.requests.len()),
        )];
        if id == "firewall-detection" {
            expected_positive.extend(firewall_supplement_findings());
        }
        assert_eq!(
            positive.result.findings, expected_positive,
            "{id}: positive"
        );
        assert_plan(id, &positive.requests);

        let negative = scan_case(id, Case::Negative).await?;
        assert_envelope(&negative, id)?;
        let expected_supplements = if id == "firewall-detection" {
            firewall_supplement_findings()
        } else {
            Vec::new()
        };
        assert_eq!(
            negative.result.findings, expected_supplements,
            "{id}: negative"
        );

        let edge = scan_case(id, Case::Edge).await?;
        assert_envelope(&edge, id)?;
        let expected_edge = if id == "rate-limit-waf-bypass-test" {
            vec![expected_finding(id, (0..edge.requests.len()).collect())]
        } else if id == "firewall-detection" {
            firewall_supplement_findings()
        } else {
            Vec::new()
        };
        assert_eq!(edge.result.findings, expected_edge, "{id}: edge");
    }
    Ok(())
}

fn assert_plan(id: &str, requests: &[HttpRequest]) {
    let paths = requests
        .iter()
        .map(|request| request.url.path())
        .collect::<Vec<_>>();
    match id {
        "file-upload-surface-finder" => assert_eq!(paths, ["/", "/upload", "/uploads"]),
        "hidden-parameter-discovery" => {
            assert_eq!(requests.len(), 5);
            let queries = requests
                .iter()
                .map(|request| request.url.query().unwrap_or_default())
                .collect::<Vec<_>>();
            assert_eq!(
                queries,
                [
                    "",
                    "debug=alpha",
                    "debug=beta",
                    "preview=alpha",
                    "preview=beta"
                ]
            );
        }
        "javascript-file-analyzer" | "static-asset-fingerprinter" => {
            assert_eq!(paths.first(), Some(&"/"));
            assert!(requests.len() >= 2);
        }
        "rate-limit-waf-bypass-test" => assert_eq!(requests.len(), 3),
        "redirect-chain" => {
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].max_redirects, 10);
        }
        "seo-abuse-detector" => {
            assert_eq!(requests.len(), 2);
            assert!(requests[0].headers["user-agent"].contains("Chrome/124.0.0.0"));
            assert!(!requests[0].headers["user-agent"].contains("compatible"));
            assert!(requests[1].headers["user-agent"].contains("Googlebot"));
        }
        "session-hijacking-passive" => assert_eq!(paths, ["/", "/login", "/account"]),
        _ => assert_eq!(requests.len(), 1, "{id}"),
    }
    assert!(
        requests
            .iter()
            .all(|request| request.method == HttpMethod::Get)
    );
    assert!(requests.iter().all(|request| request.body.is_empty()));
}

#[test]
fn descriptors_publish_exact_target_kinds_and_typed_option_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let builtins = build_builtins(&support::Harness::successful().services())?;
    for id in SCANNERS {
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("scanner is missing")?;
        let descriptor = scanner.descriptor();
        let (target_kinds, options): (&[TargetKind], &[&str]) = match id {
            "carbon-footprint"
            | "email-harvester"
            | "pixel-tracker-finder"
            | "quality-metrics"
            | "seo-abuse-detector"
            | "static-asset-fingerprinter"
            | "third-party-script-risk-profiler"
            | "passive-cve-mapper"
            | "privacy-gdpr" => (&[TargetKind::Domain, TargetKind::Url], &[]),
            "file-upload-surface-finder" => (
                &[TargetKind::Domain, TargetKind::Url],
                &["include_subs", "max_pages", "timeout"],
            ),
            "firewall-detection" => (&[TargetKind::Domain, TargetKind::Ip], &["timeout"]),
            "hidden-parameter-discovery" => (
                &[TargetKind::Domain, TargetKind::Url],
                &[
                    "max_params",
                    "params_file",
                    "test_values",
                    "threshold",
                    "timeout",
                ],
            ),
            "html5-feature-abuse-detector"
            | "javascript-file-analyzer"
            | "lazy-load-resource-finder" => (&[TargetKind::Domain, TargetKind::Url], &["timeout"]),
            "redirect-chain" => (&[TargetKind::Url], &[]),
            "rate-limit-waf-bypass-test" => (
                &[TargetKind::Domain, TargetKind::Url],
                &["batch_size", "timeout"],
            ),
            "session-hijacking-passive" => (
                &[TargetKind::Domain, TargetKind::Url],
                &["paths", "session_hints", "timeout"],
            ),
            _ => unreachable!(),
        };
        assert_eq!(descriptor.target_kinds, target_kinds, "{id}");
        assert_eq!(
            descriptor
                .options
                .iter()
                .map(|option| option.key.as_str())
                .collect::<Vec<_>>(),
            options,
            "{id}"
        );
        assert!(
            descriptor
                .options
                .iter()
                .all(|option| option.validate().is_ok())
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_analysis_scanner_preserves_all_http_error_kinds()
-> Result<(), Box<dyn std::error::Error>> {
    let matrix = [
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
    ];
    for id in SCANNERS {
        for (port_kind, scan_kind) in matrix {
            let mut services = support::Harness::successful().services();
            services.http = Arc::new(FailingHttp(port_kind));
            let builtins = build_builtins(&services)?;
            let scanner_id = sugra_domain::ScannerId::new(id)?;
            let scanner = builtins
                .registry
                .get(&scanner_id)
                .ok_or("scanner is missing")?;
            let mut request = support::request_for(scanner.descriptor())?;
            configure_request(&mut request, id, Case::Positive)?;
            let outcome = scanner.scan(&request, &support::context(false)).await;
            if id == "firewall-detection" {
                let result = outcome?;
                assert_eq!(
                    result.status,
                    ExecutionStatus::Partial,
                    "{id}: {port_kind:?}"
                );
                assert!(result.diagnostics.iter().any(|diagnostic| {
                    diagnostic.kind == "analysis-stage-unavailable"
                        && diagnostic.message
                            == format!(
                                "technology-detection-analysis stage unavailable ({scan_kind:?})"
                            )
                }));
            } else {
                let Err(error) = outcome else {
                    return Err(format!("{id}: {port_kind:?} became success").into());
                };
                assert_eq!(error.kind, scan_kind, "{id}: {port_kind:?}");
                assert_eq!(
                    error.message,
                    format!("wave5 analysis HTTP {port_kind:?} failure")
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn every_analysis_scanner_is_cancel_safe_bounded_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    for id in SCANNERS {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut services = support::Harness::successful().services();
        services.http = Arc::new(FixtureHttp {
            scanner_id: id,
            case: Case::Bounded,
            requests: Arc::clone(&requests),
        });
        let builtins = build_builtins(&services)?;
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("scanner is missing")?;
        let mut request = support::request_for(scanner.descriptor())?;
        configure_request(&mut request, id, Case::Bounded)?;
        let budget = request.budget;

        let Err(cancelled) = scanner.scan(&request, &support::context(true)).await else {
            return Err(format!("{id}: cancelled scan became success").into());
        };
        assert_eq!(cancelled.kind, ScanErrorKind::Cancelled, "{id}");
        assert!(
            requests
                .lock()
                .map_err(|_| "request log unavailable")?
                .is_empty()
        );

        let result = scanner.scan(&request, &support::context(false)).await?;
        let requests = requests.lock().map_err(|_| "request log unavailable")?;
        assert!(!requests.is_empty(), "{id}");
        assert!(requests.len() <= 2, "{id}");
        if id == "firewall-detection" {
            assert_eq!(result.status, ExecutionStatus::Completed);
            assert_eq!(result.evidence.len(), 2);
            assert_eq!(requests.len(), 1);
            let stage_budget = Budget {
                max_requests: 1,
                ..budget
            };
            assert!(
                requests
                    .iter()
                    .all(|request| request.budget == stage_budget)
            );
        } else {
            assert_eq!(result.evidence.len(), requests.len(), "{id}");
            assert!(requests.iter().all(|request| request.budget == budget));
        }
        let serialized = serde_json::to_string(&result)?;
        assert!(!serialized.contains(SECRET), "{id}");
        assert!(serialized.len() < 100_000, "{id}");
        let http_evidence = result
            .evidence
            .iter()
            .filter_map(|evidence| evidence.observation["observation"]["headers"].as_array());
        assert!(http_evidence.clone().all(|headers| headers.len() <= 256));
        assert!(http_evidence.count() >= requests.len(), "{id}");
    }
    Ok(())
}

#[test]
fn analysis_fixture_covers_exactly_the_assigned_ids() {
    assert_eq!(
        SCANNERS.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "carbon-footprint",
            "email-harvester",
            "file-upload-surface-finder",
            "firewall-detection",
            "hidden-parameter-discovery",
            "html5-feature-abuse-detector",
            "javascript-file-analyzer",
            "lazy-load-resource-finder",
            "passive-cve-mapper",
            "pixel-tracker-finder",
            "privacy-gdpr",
            "quality-metrics",
            "rate-limit-waf-bypass-test",
            "redirect-chain",
            "seo-abuse-detector",
            "session-hijacking-passive",
            "static-asset-fingerprinter",
            "third-party-script-risk-profiler",
        ])
    );
}
