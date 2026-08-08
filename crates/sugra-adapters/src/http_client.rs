//! Rustls HTTP boundary with manual scoped redirects and byte limits.

use std::collections::BTreeMap;
use std::time::Instant;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Client, Method, redirect};
use sugra_core::{HttpMethod, HttpPort, HttpRequest, HttpResponse, PortError, PortErrorKind};
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
                url = response.url().join(location).map_err(|_| {
                    PortError::new(
                        PortErrorKind::InvalidResponse,
                        "HTTP redirect has an invalid URL",
                    )
                })?;
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
    values
        .iter()
        .map(|(name, value)| {
            let text = value.to_str().unwrap_or("<non-text>");
            let safe = if name.as_str().eq_ignore_ascii_case("set-cookie") {
                redact_cookie(text)
            } else {
                text.chars().take(4096).collect()
            };
            (name.as_str().to_ascii_lowercase(), safe)
        })
        .collect()
}

fn redact_cookie(value: &str) -> String {
    value.split_once(';').map_or_else(
        || "<redacted>".into(),
        |(_, attributes)| format!("<redacted>;{attributes}"),
    )
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
