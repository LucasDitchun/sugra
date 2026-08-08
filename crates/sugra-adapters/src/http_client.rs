//! Rustls HTTP boundary with manual scoped redirects and byte limits.

use std::collections::BTreeMap;
use std::time::Instant;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION, SET_COOKIE};
use reqwest::{Client, Method, redirect};
use sha2::{Digest, Sha256};
use sugra_core::{
    HttpCookie, HttpMethod, HttpPort, HttpRedirect, HttpRequest, HttpResponse, PortError,
    PortErrorKind,
};
use sugra_domain::{Target, TargetKind};

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
            let mut response = builder
                .send()
                .await
                .map_err(|_| PortError::new(PortErrorKind::Transport, "HTTP request failed"))?;
            if is_redirect(response.status().as_u16()) {
                if redirect_count == request.max_redirects {
                    return Err(PortError::new(
                        PortErrorKind::InvalidResponse,
                        "HTTP redirect limit exceeded",
                    ));
                }
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
                redirects.push(HttpRedirect {
                    status: response.status().as_u16(),
                    from: response.url().clone(),
                    to: next.clone(),
                });
                url = next;
                if response.status().as_u16() == 303
                    || (matches!(response.status().as_u16(), 301 | 302)
                        && method == HttpMethod::Post)
                {
                    method = HttpMethod::Get;
                }
                continue;
            }

            if response
                .content_length()
                .is_some_and(|length| length > request.budget.max_response_bytes as u64)
            {
                return Err(PortError::new(
                    PortErrorKind::TooLarge,
                    "HTTP response exceeds byte budget",
                ));
            }
            let status = response.status().as_u16();
            let final_url = response.url().clone();
            let response_headers = response_headers(response.headers());
            let cookies = response_cookies(response.headers());
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| {
                PortError::new(PortErrorKind::Transport, "HTTP response body failed")
            })? {
                if body.len().saturating_add(chunk.len()) > request.budget.max_response_bytes {
                    return Err(PortError::new(
                        PortErrorKind::TooLarge,
                        "HTTP response exceeds byte budget",
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            return Ok(HttpResponse {
                final_url,
                status,
                headers: response_headers,
                cookies,
                redirects,
                body,
                duration_ms: millis(started.elapsed().as_millis()),
            });
        }
        Err(PortError::new(
            PortErrorKind::Internal,
            "unreachable redirect state",
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
                cookie.same_site = value.and_then(|value| match value.to_ascii_lowercase().as_str() {
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

    use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE};

    use super::*;

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
    fn redirect_classification_is_explicit() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_redirect(status));
        }
        for status in [200, 304, 400] {
            assert!(!is_redirect(status));
        }
    }
}
