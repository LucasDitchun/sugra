//! Public end-to-end semantic contracts for HTTP-oriented built-in scanners.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use sugra_core::{
    HttpCookie, HttpPort, HttpRequest, HttpResponse, PortError, ProviderPort, ProviderRequest,
    ProviderResponse, ScanErrorKind,
};
use sugra_domain::ScanResult;
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

const THIRTY_DAYS: i64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy)]
enum WebFixture {
    HttpHeadersMissing,
    HttpHeadersHardened,
    HttpHeadersNonHtml,
    HttpSecurityIneffective,
    HttpSecurityEffective,
    HttpSecurityPlainHttp,
    ClickjackingFrameable,
    ClickjackingRestricted,
    ClickjackingWildcard,
    CorsWildcard,
    CorsTrusted,
    CorsOriginList,
    SecurityTxtPublished,
    SecurityTxtAbsent,
    SecurityTxtMalformed,
    SecurityContactMissing,
    SecurityContactPublished,
    SecurityContactLegacyPath,
    CookiesInsecure,
    CookiesHardened,
    CookiesMalformedSameSite,
    SessionCookieLongLived,
    SessionCookieShortLived,
    SessionCookieThirtyDays,
}

struct FixtureHttp(WebFixture);

#[async_trait]
impl HttpPort for FixtureHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        Ok(response_for(self.0, request))
    }
}

struct FixtureProvider(WebFixture);

#[async_trait]
impl ProviderPort for FixtureProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        let data = match self.0 {
            WebFixture::SecurityContactMissing => json!({"entities": []}),
            WebFixture::SecurityContactPublished => json!({
                "entities": [{"roles": ["registrant"], "contact": {"kind": "organization"}}]
            }),
            WebFixture::SecurityContactLegacyPath => json!({
                "entities": [{"roles": ["technical"], "remarks": [{"title": "legacy contact"}]}]
            }),
            _ => json!({"fixture": "http-only"}),
        };
        Ok(ProviderResponse {
            provider: request.provider,
            data,
            duration_ms: 1,
        })
    }
}

fn response_for(fixture: WebFixture, request: HttpRequest) -> HttpResponse {
    let mut response = HttpResponse {
        final_url: request.url,
        status: 200,
        headers: BTreeMap::from([("content-type".into(), "text/html; charset=utf-8".into())]),
        cookies: Vec::new(),
        redirects: Vec::new(),
        body: format!(
            "<html><body>semantic fixture</body><!-- {} --></html>",
            support::SECRET_MARKER
        )
        .into_bytes(),
        duration_ms: 1,
    };

    match fixture {
        WebFixture::HttpHeadersMissing
        | WebFixture::HttpHeadersHardened
        | WebFixture::HttpHeadersNonHtml
        | WebFixture::HttpSecurityIneffective
        | WebFixture::HttpSecurityEffective
        | WebFixture::HttpSecurityPlainHttp
        | WebFixture::ClickjackingFrameable
        | WebFixture::ClickjackingRestricted
        | WebFixture::ClickjackingWildcard
        | WebFixture::CorsWildcard
        | WebFixture::CorsTrusted
        | WebFixture::CorsOriginList => apply_header_fixture(fixture, &mut response),
        WebFixture::SecurityTxtPublished
        | WebFixture::SecurityTxtAbsent
        | WebFixture::SecurityTxtMalformed
        | WebFixture::SecurityContactMissing
        | WebFixture::SecurityContactPublished
        | WebFixture::SecurityContactLegacyPath => apply_contact_fixture(fixture, &mut response),
        WebFixture::CookiesInsecure
        | WebFixture::CookiesHardened
        | WebFixture::CookiesMalformedSameSite
        | WebFixture::SessionCookieLongLived
        | WebFixture::SessionCookieShortLived
        | WebFixture::SessionCookieThirtyDays => apply_cookie_fixture(fixture, &mut response),
    }
    response
}

fn apply_header_fixture(fixture: WebFixture, response: &mut HttpResponse) {
    match fixture {
        WebFixture::HttpHeadersHardened | WebFixture::HttpSecurityEffective => {
            add_effective_security_headers(&mut response.headers);
        }
        WebFixture::HttpHeadersNonHtml => {
            response
                .headers
                .insert("content-type".into(), "application/json".into());
            response.body = br#"{"ok":true}"#.to_vec();
        }
        WebFixture::HttpSecurityIneffective | WebFixture::HttpSecurityPlainHttp => {
            response.headers.insert(
                "content-security-policy".into(),
                "report-uri https://collector.invalid/report".into(),
            );
            response
                .headers
                .insert("strict-transport-security".into(), "max-age=0".into());
            response
                .headers
                .insert("x-content-type-options".into(), "nosniff-ish".into());
            if matches!(fixture, WebFixture::HttpSecurityPlainHttp) {
                let _ = response.final_url.set_scheme("http");
            }
        }
        WebFixture::ClickjackingRestricted => {
            response
                .headers
                .insert("x-frame-options".into(), "SAMEORIGIN".into());
        }
        WebFixture::ClickjackingWildcard => {
            response.headers.insert(
                "x-frame-options".into(),
                "ALLOW-FROM https://example.test".into(),
            );
            response.headers.insert(
                "content-security-policy".into(),
                "default-src 'self'; frame-ancestors *".into(),
            );
        }
        WebFixture::CorsWildcard => {
            response
                .headers
                .insert("access-control-allow-origin".into(), " * ".into());
        }
        WebFixture::CorsTrusted => {
            response.headers.insert(
                "access-control-allow-origin".into(),
                "https://scope-check.invalid.example".into(),
            );
        }
        WebFixture::CorsOriginList => {
            response.headers.insert(
                "access-control-allow-origin".into(),
                "https://scope-check.invalid, https://example.test".into(),
            );
        }
        _ => {}
    }
}

fn apply_contact_fixture(fixture: WebFixture, response: &mut HttpResponse) {
    match fixture {
        WebFixture::SecurityTxtPublished | WebFixture::SecurityContactPublished => {
            if response.final_url.path() == "/.well-known/security.txt" {
                response
                    .headers
                    .insert("content-type".into(), "text/plain".into());
                response.body = b"Contact: mailto:security@example.test\r\n".to_vec();
            } else {
                response.status = 404;
                response.body = b"not found".to_vec();
            }
        }
        WebFixture::SecurityTxtAbsent | WebFixture::SecurityContactMissing => {
            response.status = 404;
            response.body = b"not found".to_vec();
        }
        WebFixture::SecurityTxtMalformed => {
            response
                .headers
                .insert("content-type".into(), "text/plain".into());
            response.body = format!(
                "# Contact: mailto:{}@example.test\nContact: not an absolute URI\n",
                support::SECRET_MARKER
            )
            .into_bytes();
        }
        WebFixture::SecurityContactLegacyPath => {
            response
                .headers
                .insert("content-type".into(), "text/plain".into());
            if response.final_url.path() == "/security.txt" {
                response.body = b"Contact: https://example.test/security-report\n".to_vec();
            } else {
                response.status = 404;
                response.body = b"not found".to_vec();
            }
        }
        _ => {}
    }
}

fn apply_cookie_fixture(fixture: WebFixture, response: &mut HttpResponse) {
    match fixture {
        WebFixture::CookiesInsecure => {
            response.cookies.push(cookie(false, false, None, None));
        }
        WebFixture::CookiesHardened => {
            response
                .cookies
                .push(cookie(true, true, Some("Strict"), None));
        }
        WebFixture::CookiesMalformedSameSite => {
            response
                .cookies
                .push(cookie(true, true, Some("strict-ish"), None));
        }
        WebFixture::SessionCookieLongLived => {
            response
                .cookies
                .push(cookie(true, true, Some("Lax"), Some(THIRTY_DAYS + 1)));
        }
        WebFixture::SessionCookieShortLived => {
            response
                .cookies
                .push(cookie(true, true, Some("Lax"), Some(86_400)));
        }
        WebFixture::SessionCookieThirtyDays => {
            response.cookies.extend([
                cookie(true, true, Some("Lax"), Some(THIRTY_DAYS)),
                cookie(true, true, Some("Lax"), Some(0)),
                cookie(true, true, Some("Lax"), None),
            ]);
        }
        _ => {}
    }
}

fn add_effective_security_headers(headers: &mut BTreeMap<String, String>) {
    headers.insert(
        "content-security-policy".into(),
        "default-src 'self'; object-src 'none'".into(),
    );
    headers.insert(
        "strict-transport-security".into(),
        "max-age=31536000; includeSubDomains".into(),
    );
    headers.insert("x-content-type-options".into(), "nosniff".into());
}

fn cookie(
    secure: bool,
    http_only: bool,
    same_site: Option<&str>,
    max_age_seconds: Option<i64>,
) -> HttpCookie {
    HttpCookie {
        name_sha256: "00".repeat(32),
        domain: None,
        path: Some("/".into()),
        secure,
        http_only,
        same_site: same_site.map(str::to_owned),
        max_age_seconds,
    }
}

async fn scan(id: &str, fixture: WebFixture) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FixtureHttp(fixture));
    services.provider = Arc::new(FixtureProvider(fixture));
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

fn has_finding(result: &ScanResult, key: &str) -> bool {
    result.findings.iter().any(|finding| finding.key == key)
}

fn assert_redacted(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
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

#[tokio::test]
async fn http_headers_public_contract_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let missing = scan("http-headers", WebFixture::HttpHeadersMissing).await?;
    assert_eq!(
        finding_keys(&missing),
        BTreeSet::from([
            "missing-content-security-policy",
            "missing-strict-transport-security",
            "missing-x-content-type-options",
        ])
    );

    let hardened = scan("http-headers", WebFixture::HttpHeadersHardened).await?;
    assert!(hardened.findings.is_empty());

    let non_html = scan("http-headers", WebFixture::HttpHeadersNonHtml).await?;
    assert!(non_html.findings.is_empty());

    assert_typed_failure("http-headers", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn http_security_public_contract_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let ineffective = scan("http-security", WebFixture::HttpSecurityIneffective).await?;
    assert_eq!(
        finding_keys(&ineffective),
        BTreeSet::from([
            "missing-content-security-policy",
            "missing-strict-transport-security",
            "missing-x-content-type-options",
        ])
    );

    let effective = scan("http-security", WebFixture::HttpSecurityEffective).await?;
    assert!(effective.findings.is_empty());

    let plain_http = scan("http-security", WebFixture::HttpSecurityPlainHttp).await?;
    assert_eq!(
        finding_keys(&plain_http),
        BTreeSet::from([
            "missing-content-security-policy",
            "missing-x-content-type-options",
        ])
    );

    assert_typed_failure("http-security", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn clickjacking_public_contract_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let frameable = scan("clickjacking-test", WebFixture::ClickjackingFrameable).await?;
    assert_eq!(
        finding_keys(&frameable),
        BTreeSet::from(["framing-not-restricted"])
    );

    let restricted = scan("clickjacking-test", WebFixture::ClickjackingRestricted).await?;
    assert!(restricted.findings.is_empty());

    let wildcard = scan("clickjacking-test", WebFixture::ClickjackingWildcard).await?;
    assert_eq!(
        finding_keys(&wildcard),
        BTreeSet::from(["framing-not-restricted"])
    );

    assert_typed_failure("clickjacking-test", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn cors_public_contract_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let wildcard = scan("cors-misconfiguration-scanner", WebFixture::CorsWildcard).await?;
    assert_eq!(finding_keys(&wildcard), BTreeSet::from(["permissive-cors"]));

    let trusted = scan("cors-misconfiguration-scanner", WebFixture::CorsTrusted).await?;
    assert!(trusted.findings.is_empty());

    let list = scan("cors-misconfiguration-scanner", WebFixture::CorsOriginList).await?;
    assert!(list.findings.is_empty());

    assert_typed_failure("cors-misconfiguration-scanner", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn security_txt_public_contract_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let published = scan("security-txt", WebFixture::SecurityTxtPublished).await?;
    assert_eq!(
        finding_keys(&published),
        BTreeSet::from(["security-contact-observed"])
    );

    let absent = scan("security-txt", WebFixture::SecurityTxtAbsent).await?;
    assert_eq!(
        finding_keys(&absent),
        BTreeSet::from(["security-contact-not-observed"])
    );

    let malformed = scan("security-txt", WebFixture::SecurityTxtMalformed).await?;
    assert_eq!(
        finding_keys(&malformed),
        BTreeSet::from(["security-contact-not-observed"])
    );
    assert_redacted(&malformed)?;

    assert_typed_failure("security-txt", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn security_contact_gap_public_contract_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let missing = scan(
        "security-contact-gap-finder",
        WebFixture::SecurityContactMissing,
    )
    .await?;
    assert_eq!(
        finding_keys(&missing),
        BTreeSet::from(["security-contact-not-observed"])
    );

    let published = scan(
        "security-contact-gap-finder",
        WebFixture::SecurityContactPublished,
    )
    .await?;
    assert!(has_finding(&published, "security-contact-observed"));
    assert!(!has_finding(&published, "security-contact-not-observed"));

    let legacy_path = scan(
        "security-contact-gap-finder",
        WebFixture::SecurityContactLegacyPath,
    )
    .await?;
    assert_eq!(
        finding_keys(&legacy_path),
        BTreeSet::from(["security-contact-not-observed", "security-contact-observed",])
    );

    assert_typed_failure("security-contact-gap-finder", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn cookies_public_contract_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let insecure = scan("cookies", WebFixture::CookiesInsecure).await?;
    assert_eq!(
        finding_keys(&insecure),
        BTreeSet::from([
            "cookie-httponly-missing",
            "cookie-samesite-missing",
            "cookie-secure-missing",
        ])
    );

    let hardened = scan("cookies", WebFixture::CookiesHardened).await?;
    assert!(hardened.findings.is_empty());

    let malformed = scan("cookies", WebFixture::CookiesMalformedSameSite).await?;
    assert_eq!(
        finding_keys(&malformed),
        BTreeSet::from(["cookie-samesite-missing"])
    );

    assert_typed_failure("cookies", ScanErrorKind::Transport).await
}

#[tokio::test]
async fn session_cookie_lifetime_public_contract_proves_positive_negative_edge_and_typed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let long_lived = scan(
        "session-cookie-lifetime-checker",
        WebFixture::SessionCookieLongLived,
    )
    .await?;
    assert_eq!(
        finding_keys(&long_lived),
        BTreeSet::from(["long-lived-cookie"])
    );

    let short_lived = scan(
        "session-cookie-lifetime-checker",
        WebFixture::SessionCookieShortLived,
    )
    .await?;
    assert!(short_lived.findings.is_empty());

    let boundary = scan(
        "session-cookie-lifetime-checker",
        WebFixture::SessionCookieThirtyDays,
    )
    .await?;
    assert!(boundary.findings.is_empty());

    assert_typed_failure("session-cookie-lifetime-checker", ScanErrorKind::Transport).await
}
