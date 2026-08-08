//! Rustls HTTP boundary with manual scoped redirects and byte limits.

use std::collections::BTreeMap;
use std::time::Instant;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION, SET_COOKIE};
use reqwest::{Client, Method, redirect};
use sha2::{Digest, Sha256};
use sugra_core::{
    HttpCookie, HttpMethod, HttpPort, HttpRedirect, HttpRedirectDecision, HttpRequest,
    HttpResponse, PortError, PortErrorKind,
};
use sugra_domain::{Budget, ScopeGrant, Target, TargetKind};

/// Reqwest client configured to disable automatic redirects and require Rustls.
#[derive(Clone)]
pub struct ReqwestHttp {
    client: Client,
}

impl ReqwestHttp {
    /// Builds a secure client with a stable user agent and no automatic redirects.
    ///
    /// # Errors
    ///
    /// Returns a typed unavailable error when the secure client cannot be
    /// initialized.
    pub fn new() -> Result<Self, PortError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .user_agent(concat!("sugra/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| {
                PortError::new(
                    PortErrorKind::Unavailable,
                    "HTTP client initialization failed",
                )
            })?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpPort for ReqwestHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let mut url = request.url;
        let mut method = request.method;
        validate_request_headers(&request.headers, &request.scope)?;
        let headers = request_headers(&request.headers)?;
        let started = Instant::now();
        let mut redirects = Vec::new();
        for redirect_count in 0..=request.max_redirects {
            ensure_url_in_scope(&request.scope, &url)?;
            let mut builder = self
                .client
                .request(reqwest_method(method), url.clone())
                .headers(headers.clone())
                .timeout(request.budget.timeout());
            if !request.body.is_empty() {
                builder = builder.body(request.body.clone());
            }
            let response = builder
                .send()
                .await
                .map_err(|_| PortError::new(PortErrorKind::Transport, "HTTP request failed"))?;
            if is_redirect(response.status().as_u16()) {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        PortError::new(
                            PortErrorKind::InvalidResponse,
                            "HTTP redirect omitted Location",
                        )
                    })?;
                let next = response.url().join(location).map_err(|_| {
                    PortError::new(
                        PortErrorKind::InvalidResponse,
                        "HTTP redirect has an invalid URL",
                    )
                })?;
                let decision = if redirect_count == request.max_redirects {
                    HttpRedirectDecision::LimitReached
                } else if ensure_url_in_scope(&request.scope, &next).is_ok() {
                    HttpRedirectDecision::Followed
                } else {
                    HttpRedirectDecision::OutOfScope
                };
                redirects.push(HttpRedirect {
                    status: response.status().as_u16(),
                    from: response.url().clone(),
                    to: next.clone(),
                    decision,
                });
                if decision == HttpRedirectDecision::Followed {
                    url = next;
                    if response.status().as_u16() == 303
                        || (matches!(response.status().as_u16(), 301 | 302)
                            && method == HttpMethod::Post)
                    {
                        method = HttpMethod::Get;
                    }
                    continue;
                }
            }
            return finish_response(response, redirects, started, request.budget).await;
        }
        Err(PortError::new(
            PortErrorKind::Internal,
            "unreachable redirect state",
        ))
    }
}

async fn finish_response(
    mut response: reqwest::Response,
    redirects: Vec<HttpRedirect>,
    started: Instant,
    budget: Budget,
) -> Result<HttpResponse, PortError> {
    if response
        .content_length()
        .is_some_and(|length| length > budget.max_response_bytes as u64)
    {
        return Err(PortError::new(
            PortErrorKind::TooLarge,
            "HTTP response exceeds byte budget",
        ));
    }
    let status = response.status().as_u16();
    let final_url = response.url().clone();
    let headers = response_headers(response.headers());
    let cookies = response_cookies(response.headers());
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| PortError::new(PortErrorKind::Transport, "HTTP response body failed"))?
    {
        if body.len().saturating_add(chunk.len()) > budget.max_response_bytes {
            return Err(PortError::new(
                PortErrorKind::TooLarge,
                "HTTP response exceeds byte budget",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponse {
        final_url,
        status,
        headers,
        cookies,
        redirects,
        body,
        duration_ms: millis(started.elapsed().as_millis()),
    })
}

fn validate_request_headers(
    values: &BTreeMap<String, String>,
    scope: &ScopeGrant,
) -> Result<(), PortError> {
    for (name, value) in values {
        match name.to_ascii_lowercase().as_str() {
            "authorization"
            | "cookie"
            | "proxy-authorization"
            | "content-length"
            | "transfer-encoding"
            | "connection" => {
                return Err(PortError::new(
                    PortErrorKind::InvalidResponse,
                    "request contains a boundary-controlled header",
                ));
            }
            "host" => ensure_host_header_in_scope(scope, value)?,
            _ => {}
        }
    }
    Ok(())
}

fn ensure_host_header_in_scope(scope: &ScopeGrant, value: &str) -> Result<(), PortError> {
    let url = url::Url::parse(&format!("http://{value}/")).map_err(|_| {
        PortError::new(
            PortErrorKind::InvalidResponse,
            "Host header is not a valid authority",
        )
    })?;
    let host = url.host_str().ok_or_else(|| {
        PortError::new(PortErrorKind::InvalidResponse, "Host header omitted a host")
    })?;
    let target = host
        .parse()
        .map(Target::Ip)
        .or_else(|_| Target::parse(TargetKind::Domain, host))
        .map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidResponse,
                "Host header contains an invalid host",
            )
        })?;
    if scope.allows(&target) {
        Ok(())
    } else {
        Err(PortError::new(
            PortErrorKind::OutOfScope,
            "Host header is outside the declared scope",
        ))
    }
}

fn request_headers(values: &BTreeMap<String, String>) -> Result<HeaderMap, PortError> {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::try_from(name.as_str()).map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidResponse,
                "request contains an invalid header name",
            )
        })?;
        let value = HeaderValue::try_from(value).map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidResponse,
                "request contains an invalid header value",
            )
        })?;
        headers.insert(name, value);
    }
    Ok(headers)
}

fn response_headers(values: &HeaderMap) -> BTreeMap<String, String> {
    let mut headers: BTreeMap<_, _> = values
        .iter()
        .filter(|(name, _)| *name != SET_COOKIE)
        .map(|(name, value)| {
            let text = value.to_str().unwrap_or("<non-text>");
            let safe = text.chars().take(4096).collect();
            (name.as_str().to_ascii_lowercase(), safe)
        })
        .collect();
    let cookie_count = values.get_all(SET_COOKIE).iter().count();
    if cookie_count > 0 {
        headers.insert(
            "set-cookie".into(),
            format!("<redacted>; count={cookie_count}"),
        );
    }
    headers
}

fn response_cookies(values: &HeaderMap) -> Vec<HttpCookie> {
    values
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(parse_cookie_metadata)
        .take(256)
        .collect()
}

fn parse_cookie_metadata(value: &str) -> Option<HttpCookie> {
    let mut segments = value.split(';');
    let (name, _) = segments.next()?.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut cookie = HttpCookie {
        name_sha256: hex::encode(Sha256::digest(name.as_bytes())),
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        same_site: None,
        max_age_seconds: None,
    };
    for segment in segments {
        let (name, value) = segment
            .split_once('=')
            .map_or((segment.trim(), None), |(name, value)| {
                (name.trim(), Some(value.trim()))
            });
        match name.to_ascii_lowercase().as_str() {
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "domain" => cookie.domain = value.map(bounded_cookie_attribute),
            "path" => cookie.path = value.map(bounded_cookie_attribute),
            "samesite" => {
                cookie.same_site =
                    value.and_then(|value| match value.to_ascii_lowercase().as_str() {
                        "strict" => Some("strict".into()),
                        "lax" => Some("lax".into()),
                        "none" => Some("none".into()),
                        _ => None,
                    });
            }
            "max-age" => cookie.max_age_seconds = value.and_then(|value| value.parse().ok()),
            _ => {}
        }
    }
    Some(cookie)
}

fn bounded_cookie_attribute(value: &str) -> String {
    value.chars().take(256).collect()
}

fn ensure_url_in_scope(scope: &sugra_domain::ScopeGrant, url: &url::Url) -> Result<(), PortError> {
    let target = Target::parse(TargetKind::Url, url.as_str())
        .map_err(|_| PortError::new(PortErrorKind::InvalidResponse, "HTTP URL is invalid"))?;
    if scope.allows(&target) {
        Ok(())
    } else {
        Err(PortError::new(
            PortErrorKind::OutOfScope,
            "HTTP URL is outside the declared scope",
        ))
    }
}

const fn reqwest_method(method: HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Head => Method::HEAD,
        HttpMethod::Options => Method::OPTIONS,
        HttpMethod::Post => Method::POST,
    }
}

const fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn millis(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE};
    use sugra_domain::{Budget, ScopeGrant};
    use time::OffsetDateTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    async fn local_server(
        responses: Vec<&'static [u8]>,
    ) -> Result<
        (
            url::Url,
            tokio::task::JoinHandle<Result<Vec<Vec<u8>>, std::io::Error>>,
        ),
        Box<dyn std::error::Error>,
    > {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await?;
                let mut request = vec![0_u8; 4096];
                let length = stream.read(&mut request).await?;
                request.truncate(length);
                requests.push(request);
                stream.write_all(response).await?;
            }
            Ok(requests)
        });
        Ok((url::Url::parse(&format!("http://{address}/"))?, server))
    }

    fn scoped_request(
        url: url::Url,
        method: HttpMethod,
        max_redirects: usize,
        max_response_bytes: usize,
    ) -> Result<HttpRequest, Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Url, url.as_str())?;
        Ok(HttpRequest {
            url,
            method,
            headers: BTreeMap::new(),
            body: Vec::new(),
            max_redirects,
            budget: Budget {
                timeout_ms: 1_000,
                max_response_bytes,
                ..Budget::default()
            },
            scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
        })
    }

    #[test]
    fn cookie_values_are_discarded_but_security_attributes_remain()
    -> Result<(), Box<dyn std::error::Error>> {
        let cookie = parse_cookie_metadata(
            "session=secret; Domain=example.com; Path=/account; Secure; HttpOnly; SameSite=Lax; Max-Age=600",
        )
        .ok_or("cookie metadata was not parsed")?;
        assert_eq!(cookie.name_sha256.len(), 64);
        assert_eq!(cookie.domain.as_deref(), Some("example.com"));
        assert_eq!(cookie.path.as_deref(), Some("/account"));
        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site.as_deref(), Some("lax"));
        assert_eq!(cookie.max_age_seconds, Some(600));
        assert!(!serde_json::to_string(&cookie)?.contains("secret"));

        assert!(parse_cookie_metadata("missing-assignment").is_none());
        assert!(parse_cookie_metadata("=value").is_none());
        let bounded = parse_cookie_metadata(&format!(
            "id=value; Domain={}; SameSite=None; Max-Age=invalid; Unknown=ignored",
            "a".repeat(300)
        ))
        .ok_or("bounded cookie metadata was not parsed")?;
        assert_eq!(bounded.domain.as_deref().map(str::len), Some(256));
        assert_eq!(bounded.same_site.as_deref(), Some("none"));
        assert_eq!(bounded.max_age_seconds, None);
        Ok(())
    }

    #[test]
    fn response_headers_never_expose_cookie_values() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("session=secret; Secure; HttpOnly"),
        );
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("preference=value; SameSite=Lax"),
        );
        let safe = response_headers(&headers);
        assert_eq!(
            safe.get("set-cookie").map(String::as_str),
            Some("<redacted>; count=2")
        );
        let cookies = response_cookies(&headers);
        assert_eq!(cookies.len(), 2);
        let serialized = serde_json::to_string(&cookies)?;
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("value"));
        Ok(())
    }

    #[test]
    fn invalid_outbound_header_values_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let result = request_headers(&BTreeMap::from([(
            "authorization".into(),
            "Bearer fixture\nInjected: true".into(),
        )]));
        let Err(error) = result else {
            return Err("newline crossed the HTTP header boundary".into());
        };
        assert_eq!(error.kind, PortErrorKind::InvalidResponse);
        Ok(())
    }

    #[test]
    fn boundary_controlled_and_out_of_scope_host_headers_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let scope = ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH);
        let sensitive = BTreeMap::from([("authorization".into(), "Bearer value".into())]);
        assert!(validate_request_headers(&sensitive, &scope).is_err());

        let host_override = BTreeMap::from([("host".into(), "outside.example".into())]);
        let Err(error) = validate_request_headers(&host_override, &scope) else {
            return Err("out-of-scope Host header was accepted".into());
        };
        assert_eq!(error.kind, PortErrorKind::OutOfScope);
        Ok(())
    }

    #[tokio::test]
    async fn out_of_scope_redirect_is_recorded_without_being_followed()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await?;
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            Ok::<_, std::io::Error>(())
        });
        let url = url::Url::parse(&format!("http://{address}/"))?;
        let target = Target::parse(TargetKind::Url, url.as_str())?;
        let response = ReqwestHttp::new()?
            .execute(HttpRequest {
                url,
                method: HttpMethod::Get,
                headers: BTreeMap::new(),
                body: Vec::new(),
                max_redirects: 3,
                budget: Budget {
                    timeout_ms: 1_000,
                    max_response_bytes: 1_024,
                    ..Budget::default()
                },
                scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
            })
            .await?;
        assert_eq!(response.status, 302);
        assert_eq!(response.redirects.len(), 1);
        assert_eq!(
            response.redirects[0].decision,
            HttpRedirectDecision::OutOfScope
        );
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn successful_post_returns_body_headers_and_redacted_cookie_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let (url, server) = local_server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Result: ready\r\nSet-Cookie: session=secret; Secure; HttpOnly\r\nConnection: close\r\n\r\nhello",
        ])
        .await?;
        let mut request = scoped_request(url, HttpMethod::Post, 0, 1_024)?;
        request.headers.insert("x-request".into(), "fixture".into());
        request.body = b"payload".to_vec();

        let response = ReqwestHttp::new()?.execute(request).await?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(
            response.headers.get("x-result").map(String::as_str),
            Some("ready")
        );
        assert_eq!(response.cookies.len(), 1);
        assert_eq!(
            response.headers.get("set-cookie").map(String::as_str),
            Some("<redacted>; count=1")
        );

        let requests = server.await??;
        let wire = String::from_utf8_lossy(&requests[0]);
        assert!(wire.starts_with("POST / HTTP/1.1"));
        assert!(wire.contains("x-request: fixture"));
        assert!(wire.ends_with("payload"));
        Ok(())
    }

    #[tokio::test]
    async fn same_scope_303_redirect_is_followed_as_get() -> Result<(), Box<dyn std::error::Error>>
    {
        let (url, server) = local_server(vec![
            b"HTTP/1.1 303 See Other\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        ])
        .await?;
        let mut request = scoped_request(url, HttpMethod::Post, 2, 1_024)?;
        request.body = b"payload".to_vec();

        let response = ReqwestHttp::new()?.execute(request).await?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.redirects.len(), 1);
        assert_eq!(
            response.redirects[0].decision,
            HttpRedirectDecision::Followed
        );

        let requests = server.await??;
        assert!(String::from_utf8_lossy(&requests[0]).starts_with("POST / HTTP/1.1"));
        assert!(String::from_utf8_lossy(&requests[1]).starts_with("GET /final HTTP/1.1"));
        Ok(())
    }

    #[tokio::test]
    async fn redirect_limit_returns_the_terminal_redirect() -> Result<(), Box<dyn std::error::Error>>
    {
        let (url, server) = local_server(vec![
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: /later\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ])
        .await?;

        let response = ReqwestHttp::new()?
            .execute(scoped_request(url, HttpMethod::Get, 0, 1_024)?)
            .await?;
        assert_eq!(response.status, 301);
        assert_eq!(response.redirects.len(), 1);
        assert_eq!(
            response.redirects[0].decision,
            HttpRedirectDecision::LimitReached
        );
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn declared_and_streamed_oversized_bodies_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let (declared_url, declared_server) = local_server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nexcess",
        ])
        .await?;
        let Err(declared) = ReqwestHttp::new()?
            .execute(scoped_request(declared_url, HttpMethod::Get, 0, 5)?)
            .await
        else {
            return Err("declared oversized response was accepted".into());
        };
        assert_eq!(declared.kind, PortErrorKind::TooLarge);
        declared_server.await??;

        let (streamed_url, streamed_server) = local_server(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nexcess\r\n0\r\n\r\n",
        ])
        .await?;
        let Err(streamed) = ReqwestHttp::new()?
            .execute(scoped_request(streamed_url, HttpMethod::Get, 0, 5)?)
            .await
        else {
            return Err("streamed oversized response was accepted".into());
        };
        assert_eq!(streamed.kind, PortErrorKind::TooLarge);
        streamed_server.await??;
        Ok(())
    }

    #[test]
    fn redirect_classification_is_explicit() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_redirect(status));
        }
        for status in [200, 304, 400] {
            assert!(!is_redirect(status));
        }
        assert_eq!(reqwest_method(HttpMethod::Get), Method::GET);
        assert_eq!(reqwest_method(HttpMethod::Head), Method::HEAD);
        assert_eq!(reqwest_method(HttpMethod::Options), Method::OPTIONS);
        assert_eq!(reqwest_method(HttpMethod::Post), Method::POST);
        assert_eq!(millis(42), 42);
        assert_eq!(millis(u128::MAX), u64::MAX);
    }
}
