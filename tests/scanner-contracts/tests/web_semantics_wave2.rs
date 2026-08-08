//! Public runtime contracts for the second HTTP semantic wave.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use sugra_core::{HttpPort, HttpRequest, HttpResponse, PortError, ScanErrorKind};
use sugra_domain::{Confidence, ExecutionStatus, ScanResult, Severity};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

#[derive(Debug, Clone, Copy)]
enum Fixture {
    ApiOpenApi,
    ApiUnrelatedJson,
    ApiSwaggerTwo,
    BrokenMissingTarget,
    BrokenReachableTarget,
    BrokenRedirectTarget,
    CacheVaries,
    CacheStable,
    CacheRevalidated,
    CaptchaScript,
    CaptchaProseOnly,
    CaptchaTurnstileClass,
    CmsWordPressAsset,
    CmsUnknownGenerator,
    CmsJoomlaGenerator,
    RobotsDisallow,
    RobotsMissing,
    RobotsCrLfAllow,
    CrawlerLinkedPage,
    CrawlerNoLinks,
    CrawlerNotModified,
    CrawlerJsonLink,
    CspUnsafe,
    CspRestrictive,
    CspReportOnly,
}

struct FixtureHttp {
    fixture: Fixture,
    calls: AtomicUsize,
}

impl FixtureHttp {
    fn new(fixture: Fixture) -> Self {
        Self {
            fixture,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl HttpPort for FixtureHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(fixture_response(self.fixture, &request, call))
    }
}

fn fixture_response(fixture: Fixture, request: &HttpRequest, call: usize) -> HttpResponse {
    let mut response = HttpResponse {
        final_url: request.url.clone(),
        status: 200,
        headers: BTreeMap::new(),
        cookies: Vec::new(),
        redirects: Vec::new(),
        body: Vec::new(),
        duration_ms: 1,
    };
    match fixture {
        Fixture::ApiOpenApi | Fixture::ApiUnrelatedJson | Fixture::ApiSwaggerTwo => {
            api_response(fixture, &mut response);
        }
        Fixture::BrokenMissingTarget
        | Fixture::BrokenReachableTarget
        | Fixture::BrokenRedirectTarget => broken_link_response(fixture, &mut response),
        Fixture::CacheVaries | Fixture::CacheStable | Fixture::CacheRevalidated => {
            cache_response(fixture, call, &mut response);
        }
        Fixture::CaptchaScript
        | Fixture::CaptchaProseOnly
        | Fixture::CaptchaTurnstileClass
        | Fixture::CmsWordPressAsset
        | Fixture::CmsUnknownGenerator
        | Fixture::CmsJoomlaGenerator
        | Fixture::CrawlerLinkedPage
        | Fixture::CrawlerNoLinks
        | Fixture::CrawlerNotModified
        | Fixture::CrawlerJsonLink => document_response(fixture, &mut response),
        Fixture::RobotsDisallow | Fixture::RobotsMissing | Fixture::RobotsCrLfAllow => {
            robots_response(fixture, &mut response);
        }
        Fixture::CspUnsafe | Fixture::CspRestrictive | Fixture::CspReportOnly => {
            csp_response(fixture, &mut response);
        }
    }
    response
}

fn api_response(fixture: Fixture, response: &mut HttpResponse) {
    response
        .headers
        .insert("content-type".into(), "application/json".into());
    response.body = match fixture {
        Fixture::ApiOpenApi => format!(
            r#"{{"openapi":"3.1.0","info":{{"title":"{}"}},"paths":{{}}}}"#,
            support::SECRET_MARKER
        )
        .into_bytes(),
        Fixture::ApiUnrelatedJson => br#"{"note":"swagger migration documentation"}"#.to_vec(),
        Fixture::ApiSwaggerTwo => br#"{"swagger":"2.0","paths":{}}"#.to_vec(),
        _ => Vec::new(),
    };
}

fn cache_response(fixture: Fixture, call: usize, response: &mut HttpResponse) {
    response
        .headers
        .insert("cache-control".into(), "public, max-age=60".into());
    match fixture {
        Fixture::CacheVaries => {
            response.body = format!("{}-{call}", support::SECRET_MARKER).into_bytes();
        }
        Fixture::CacheStable => {
            response.body = format!("{}-stable", support::SECRET_MARKER).into_bytes();
        }
        Fixture::CacheRevalidated if call > 0 => response.status = 304,
        Fixture::CacheRevalidated => {
            response.body = format!("{}-fresh", support::SECRET_MARKER).into_bytes();
        }
        _ => {}
    }
}

fn document_response(fixture: Fixture, response: &mut HttpResponse) {
    if matches!(fixture, Fixture::CrawlerJsonLink) {
        response
            .headers
            .insert("content-type".into(), "application/json".into());
        response.body = format!(
            r#"{{"link":"<a href=/child?token={}>child</a>"}}"#,
            support::SECRET_MARKER
        )
        .into_bytes();
        return;
    }
    let body = match fixture {
        Fixture::CaptchaScript => format!(
            r#"<script src="https://www.google.com/recaptcha/api.js?token={}"></script>"#,
            support::SECRET_MARKER
        ),
        Fixture::CaptchaProseOnly => "<p>This site does not use recaptcha.</p>".into(),
        Fixture::CaptchaTurnstileClass => format!(
            r#"<div class="cf-turnstile" data-sitekey="{}"></div>"#,
            support::SECRET_MARKER
        ),
        Fixture::CmsWordPressAsset => format!(
            r#"<link rel="stylesheet" href="/wp-content/themes/{}.css">"#,
            support::SECRET_MARKER
        ),
        Fixture::CmsUnknownGenerator => {
            r#"<meta name="generator" content="Private Site Builder">"#.into()
        }
        Fixture::CmsJoomlaGenerator => r#"<meta name="generator" content="Joomla! 5">"#.into(),
        Fixture::CrawlerLinkedPage => format!(
            r#"<a href="/child?token={}">Child</a>"#,
            support::SECRET_MARKER
        ),
        Fixture::CrawlerNoLinks => "<p>No links</p>".into(),
        Fixture::CrawlerNotModified => {
            response.status = 304;
            r#"<a href="/cached">Cached</a>"#.into()
        }
        _ => String::new(),
    };
    html(response, &body);
}

fn robots_response(fixture: Fixture, response: &mut HttpResponse) {
    response
        .headers
        .insert("content-type".into(), "text/plain".into());
    match fixture {
        Fixture::RobotsDisallow => {
            response.body =
                format!("User-agent: *\nDisallow: /{}\n", support::SECRET_MARKER).into_bytes();
        }
        Fixture::RobotsMissing => {
            response.status = 404;
            response.body = b"not found".to_vec();
        }
        Fixture::RobotsCrLfAllow => {
            response.body = b"# fixture\r\nUser-agent: ExampleBot\r\nAllow: /\r\n".to_vec();
        }
        _ => {}
    }
}

fn csp_response(fixture: Fixture, response: &mut HttpResponse) {
    html(response, "<p>CSP fixture</p>");
    let (name, value) = match fixture {
        Fixture::CspUnsafe => (
            "content-security-policy",
            format!(
                "default-src * 'unsafe-inline'; script-src 'unsafe-eval' https://{}.invalid",
                support::SECRET_MARKER
            ),
        ),
        Fixture::CspRestrictive => (
            "content-security-policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'".into(),
        ),
        Fixture::CspReportOnly => (
            "content-security-policy-report-only",
            "default-src 'none'".into(),
        ),
        _ => return,
    };
    response.headers.insert(name.into(), value);
}

fn broken_link_response(fixture: Fixture, response: &mut HttpResponse) {
    if response.final_url.path() == "/" {
        let path = match fixture {
            Fixture::BrokenMissingTarget => "/missing",
            Fixture::BrokenReachableTarget => "/reachable",
            Fixture::BrokenRedirectTarget => "/redirect",
            _ => return,
        };
        html(
            response,
            &format!(
                r#"<a href="{path}?token={}">candidate</a>"#,
                support::SECRET_MARKER
            ),
        );
        return;
    }
    response.body = format!("{}-target", support::SECRET_MARKER).into_bytes();
    response.status = match fixture {
        Fixture::BrokenMissingTarget => 404,
        Fixture::BrokenRedirectTarget => 399,
        _ => 200,
    };
}

fn html(response: &mut HttpResponse, body: &str) {
    response
        .headers
        .insert("content-type".into(), "text/html; charset=utf-8".into());
    response.body = body.as_bytes().to_vec();
}

async fn scan(id: &str, fixture: Fixture) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FixtureHttp::new(fixture));
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("fixture scanner is missing from the registry")?;
    let mut request = support::request_for(scanner.descriptor())?;
    if id == "broken-links" {
        request
            .options
            .insert("sample_ratio".into(), serde_json::json!("1"));
    }
    Ok(scanner.scan(&request, &support::context(false)).await?)
}

async fn assert_typed_failure(
    id: &str,
    expected: ScanErrorKind,
) -> Result<(), Box<dyn std::error::Error>> {
    let harness = support::Harness::failing();
    let builtins = build_builtins(&harness.services())?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("failure scanner is missing from the registry")?;
    let request = support::request_for(scanner.descriptor())?;
    let Err(error) = scanner.scan(&request, &support::context(false)).await else {
        return Err(format!("{id} converted a boundary failure into success").into());
    };
    assert_eq!(error.kind, expected, "{id}");
    assert!(!error.message.contains(support::SECRET_MARKER), "{id}");
    Ok(())
}

fn assert_redacted(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
    assert!(!serde_json::to_string(result)?.contains(support::SECRET_MARKER));
    Ok(())
}

fn assert_safe_completed_contract(
    id: &str,
    result: &ScanResult,
    expected_evidence: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(result.status, ExecutionStatus::Completed);
    assert!(result.diagnostics.is_empty());
    assert_eq!(result.evidence.len(), expected_evidence);
    let expected_kind = format!("{id}-http-observation");
    let Some((expected_analysis, expected_purpose)) = expected_annotation(id) else {
        return Err(std::io::Error::other(format!("{id} has no exact fixture annotation")).into());
    };
    for evidence in &result.evidence {
        assert_eq!(evidence.kind, expected_kind);
        assert_eq!(evidence.observation["scanner_id"], id);
        assert_eq!(evidence.observation["analysis"], expected_analysis);
        assert_eq!(evidence.observation["purpose"], expected_purpose);
        assert!(evidence.observation["observation"].is_object());
    }
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
    assert_redacted(result)
}

fn expected_annotation(id: &str) -> Option<(&'static str, &'static str)> {
    match id {
        "api-schema-grabber" => Some((
            "api-surface-analysis",
            "Discover and fingerprint published API schemas.",
        )),
        "broken-links" => Some((
            "bounded-crawl-analysis",
            "Identify linked resources returning error responses.",
        )),
        "cache-behavior-analyzer" => Some((
            "http-policy-analysis",
            "Inspect cache policy and response consistency.",
        )),
        "captcha-presence-checker" => Some((
            "technology-detection-analysis",
            "Detect common CAPTCHA integrations.",
        )),
        "cms-detection" => Some((
            "technology-detection-analysis",
            "Detect content-management platforms from public indicators.",
        )),
        "crawl-rules" => Some((
            "web-metadata-analysis",
            "Retrieve and summarize robots exclusion rules.",
        )),
        "crawler" => Some(("bounded-crawl-analysis", "Traverse bounded in-scope links.")),
        "csp-deep-analyzer" => Some((
            "http-policy-analysis",
            "Inspect Content Security Policy directives.",
        )),
        _ => None,
    }
}

fn assert_api_schema_evidence(result: &ScanResult) {
    let expected = [
        (
            "path-0:a41941b8b4af1fefc5445fd387a888c3269536a4c34522df43edfda817a03d10",
            "https://example.com/openapi.json",
        ),
        (
            "path-1:e8b781bbd4d2f26821863c711cdb840a238cb6f84b851fb1b4d5354279e2bb65",
            "https://example.com/swagger.json",
        ),
        (
            "path-2:185aa5a8967cd2e8ea36516f6e8887afc5770921222ad65a244a0546d35df733",
            "https://example.com/api-docs",
        ),
        (
            "path-3:e6862b57c5407b8605e57256a264e59d7ca08b3df21be7d7bbe5a647348eb0ab",
            "https://example.com/graphql",
        ),
    ];
    assert_eq!(result.evidence.len(), expected.len());
    for (index, (evidence, (probe, source))) in result.evidence.iter().zip(expected).enumerate() {
        assert_eq!(evidence.source, source);
        assert_eq!(
            evidence
                .observation
                .pointer("/observation/probe")
                .and_then(serde_json::Value::as_str),
            Some(probe)
        );
        if let Some(finding) = result.findings.get(index) {
            assert_eq!(finding.key, "api-schema-published");
            assert_eq!(finding.severity, Severity::Info);
            assert_eq!(finding.confidence, Confidence::Confirmed);
            assert_eq!(finding.evidence, [index]);
        }
    }
}

fn response_statuses(result: &ScanResult) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    result
        .evidence
        .iter()
        .map(|evidence| {
            evidence
                .observation
                .pointer("/observation/status")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| format!("missing HTTP status in {}", evidence.source))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn finding_keys(result: &ScanResult) -> BTreeSet<&str> {
    result
        .findings
        .iter()
        .map(|finding| finding.key.as_str())
        .collect()
}

#[tokio::test]
async fn api_schema_grabber_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("api-schema-grabber", Fixture::ApiOpenApi).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["api-schema-published"])
    );
    assert_eq!(positive.findings.len(), 4);
    assert_api_schema_evidence(&positive);
    assert_safe_completed_contract("api-schema-grabber", &positive, 4)?;

    let negative = scan("api-schema-grabber", Fixture::ApiUnrelatedJson).await?;
    assert!(negative.findings.is_empty());
    assert_api_schema_evidence(&negative);
    assert_safe_completed_contract("api-schema-grabber", &negative, 4)?;

    let edge = scan("api-schema-grabber", Fixture::ApiSwaggerTwo).await?;
    assert_eq!(
        finding_keys(&edge),
        BTreeSet::from(["api-schema-published"])
    );
    assert_eq!(edge.findings.len(), 4);
    assert_api_schema_evidence(&edge);
    assert_safe_completed_contract("api-schema-grabber", &edge, 4)?;

    assert_typed_failure("api-schema-grabber", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn broken_links_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("broken-links", Fixture::BrokenMissingTarget).await?;
    assert_eq!(finding_keys(&positive), BTreeSet::from(["broken-link"]));
    assert_eq!(positive.findings.len(), 1);
    assert_eq!(positive.findings[0].severity, Severity::Low);
    assert_eq!(positive.findings[0].confidence, Confidence::Confirmed);
    assert_eq!(positive.findings[0].evidence, [1]);
    assert_eq!(response_statuses(&positive)?, [200, 404]);
    assert_safe_completed_contract("broken-links", &positive, 2)?;

    let negative = scan("broken-links", Fixture::BrokenReachableTarget).await?;
    assert!(negative.findings.is_empty());
    assert_eq!(response_statuses(&negative)?, [200, 200]);
    assert_safe_completed_contract("broken-links", &negative, 2)?;

    let edge = scan("broken-links", Fixture::BrokenRedirectTarget).await?;
    assert!(edge.findings.is_empty());
    assert_eq!(response_statuses(&edge)?, [200, 399]);
    assert_safe_completed_contract("broken-links", &edge, 2)?;

    assert_typed_failure("broken-links", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn cache_behavior_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("cache-behavior-analyzer", Fixture::CacheVaries).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["cache-response-varies"])
    );
    assert_eq!(positive.findings.len(), 1);
    assert_eq!(positive.findings[0].severity, Severity::Info);
    assert_eq!(positive.findings[0].confidence, Confidence::Unknown);
    assert_eq!(positive.findings[0].evidence, [0, 1]);
    assert_eq!(response_statuses(&positive)?, [200, 200]);
    assert_safe_completed_contract("cache-behavior-analyzer", &positive, 2)?;

    let negative = scan("cache-behavior-analyzer", Fixture::CacheStable).await?;
    assert!(negative.findings.is_empty());
    assert_eq!(response_statuses(&negative)?, [200, 200]);
    assert_safe_completed_contract("cache-behavior-analyzer", &negative, 2)?;

    let edge = scan("cache-behavior-analyzer", Fixture::CacheRevalidated).await?;
    assert!(edge.findings.is_empty());
    assert_eq!(response_statuses(&edge)?, [200, 304]);
    assert_safe_completed_contract("cache-behavior-analyzer", &edge, 2)?;

    assert_typed_failure("cache-behavior-analyzer", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn captcha_presence_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("captcha-presence-checker", Fixture::CaptchaScript).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["captcha-control-observed"])
    );
    assert_eq!(positive.findings.len(), 1);
    assert_eq!(positive.findings[0].severity, Severity::Info);
    assert_eq!(positive.findings[0].confidence, Confidence::Confirmed);
    assert_eq!(positive.findings[0].evidence, [0]);
    assert_eq!(
        positive.evidence[0].observation["observation"]["document"]["captcha_markers"],
        1
    );
    assert_safe_completed_contract("captcha-presence-checker", &positive, 1)?;

    let negative = scan("captcha-presence-checker", Fixture::CaptchaProseOnly).await?;
    assert!(negative.findings.is_empty());
    assert_eq!(
        negative.evidence[0].observation["observation"]["document"]["captcha_markers"],
        0
    );
    assert_safe_completed_contract("captcha-presence-checker", &negative, 1)?;

    let edge = scan("captcha-presence-checker", Fixture::CaptchaTurnstileClass).await?;
    assert_eq!(
        finding_keys(&edge),
        BTreeSet::from(["captcha-control-observed"])
    );
    assert_eq!(edge.findings.len(), 1);
    assert_eq!(edge.findings[0].evidence, [0]);
    assert_eq!(
        edge.evidence[0].observation["observation"]["document"]["captcha_markers"],
        1
    );
    assert_safe_completed_contract("captcha-presence-checker", &edge, 1)?;

    assert_typed_failure("captcha-presence-checker", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn cms_detection_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("cms-detection", Fixture::CmsWordPressAsset).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["cms-signal-observed"])
    );
    assert_eq!(positive.findings.len(), 1);
    assert_eq!(positive.findings[0].evidence, [0]);
    assert_safe_completed_contract("cms-detection", &positive, 1)?;

    let negative = scan("cms-detection", Fixture::CmsUnknownGenerator).await?;
    assert!(negative.findings.is_empty());
    assert_safe_completed_contract("cms-detection", &negative, 1)?;

    let edge = scan("cms-detection", Fixture::CmsJoomlaGenerator).await?;
    assert_eq!(finding_keys(&edge), BTreeSet::from(["cms-signal-observed"]));
    assert_eq!(edge.findings.len(), 1);
    assert_eq!(edge.findings[0].evidence, [0]);
    assert_safe_completed_contract("cms-detection", &edge, 1)?;

    assert_typed_failure("cms-detection", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn crawl_rules_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("crawl-rules", Fixture::RobotsDisallow).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["crawl-rules-observed"])
    );
    assert_eq!(positive.findings.len(), 1);
    assert_eq!(positive.findings[0].evidence, [0]);
    assert_safe_completed_contract("crawl-rules", &positive, 1)?;

    let negative = scan("crawl-rules", Fixture::RobotsMissing).await?;
    assert!(negative.findings.is_empty());
    assert_eq!(response_statuses(&negative)?, [404]);
    assert_safe_completed_contract("crawl-rules", &negative, 1)?;

    let edge = scan("crawl-rules", Fixture::RobotsCrLfAllow).await?;
    assert_eq!(
        finding_keys(&edge),
        BTreeSet::from(["crawl-rules-observed"])
    );
    assert_eq!(edge.findings.len(), 1);
    assert_eq!(edge.findings[0].evidence, [0]);
    assert_safe_completed_contract("crawl-rules", &edge, 1)?;

    assert_typed_failure("crawl-rules", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn crawler_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("crawler", Fixture::CrawlerLinkedPage).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from(["crawlable-links-observed"])
    );
    assert_eq!(positive.findings.len(), 2);
    assert_eq!(positive.findings[0].evidence, [0]);
    assert_eq!(positive.findings[1].evidence, [1]);
    assert_safe_completed_contract("crawler", &positive, 2)?;

    let negative = scan("crawler", Fixture::CrawlerNoLinks).await?;
    assert!(negative.findings.is_empty());
    assert_safe_completed_contract("crawler", &negative, 1)?;

    let edge = scan("crawler", Fixture::CrawlerNotModified).await?;
    assert!(edge.findings.is_empty());
    assert_eq!(response_statuses(&edge)?, [304]);
    assert_safe_completed_contract("crawler", &edge, 1)?;

    let non_html = scan("crawler", Fixture::CrawlerJsonLink).await?;
    assert!(non_html.findings.is_empty());
    assert_eq!(response_statuses(&non_html)?, [200]);
    assert_safe_completed_contract("crawler", &non_html, 1)?;

    assert_typed_failure("crawler", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn csp_deep_analyzer_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("csp-deep-analyzer", Fixture::CspUnsafe).await?;
    assert_eq!(
        finding_keys(&positive),
        BTreeSet::from([
            "csp-unsafe-eval",
            "csp-unsafe-inline",
            "csp-wildcard-source",
        ])
    );
    assert_eq!(positive.findings.len(), 3);
    assert!(
        positive
            .findings
            .iter()
            .all(|finding| finding.evidence == [0])
    );
    assert_safe_completed_contract("csp-deep-analyzer", &positive, 1)?;

    let negative = scan("csp-deep-analyzer", Fixture::CspRestrictive).await?;
    assert!(negative.findings.is_empty());
    assert_safe_completed_contract("csp-deep-analyzer", &negative, 1)?;

    let edge = scan("csp-deep-analyzer", Fixture::CspReportOnly).await?;
    assert_eq!(finding_keys(&edge), BTreeSet::from(["csp-not-enforced"]));
    assert_eq!(edge.findings.len(), 1);
    assert_eq!(edge.findings[0].evidence, [0]);
    assert_safe_completed_contract("csp-deep-analyzer", &edge, 1)?;

    assert_typed_failure("csp-deep-analyzer", ScanErrorKind::Transport).await
}
