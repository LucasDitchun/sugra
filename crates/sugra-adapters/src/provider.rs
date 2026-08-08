//! Allowlisted HTTP JSON providers with credential injection at the boundary.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use serde_json::Value;
use sugra_core::{
    Clock, HttpMethod, HttpPort, HttpRequest, PortError, PortErrorKind, ProviderPort,
    ProviderRequest, ProviderResponse,
};
use sugra_domain::{ScopeGrant, Target, TargetKind};
use url::Url;

/// HTTP-backed provider boundary restricted to known public endpoints.
#[derive(Clone)]
pub struct ReqwestProvider {
    http: Arc<dyn HttpPort>,
    clock: Arc<dyn Clock>,
}

impl ReqwestProvider {
    /// Constructs a provider boundary over an existing secure HTTP client.
    #[must_use]
    pub fn new(http: Arc<dyn HttpPort>, clock: Arc<dyn Clock>) -> Self {
        Self { http, clock }
    }
}

#[async_trait]
impl ProviderPort for ReqwestProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        let mut endpoint = endpoint_for(&request)?;
        let mut headers = BTreeMap::new();
        if let Some(secret_env) = &request.secret_env {
            let secret = std::env::var(secret_env).map_err(|_| {
                PortError::new(
                    PortErrorKind::Unavailable,
                    "provider credential is not configured",
                )
            })?;
            inject_secret(&request.provider, &mut endpoint, &mut headers, &secret)?;
        }
        let scope_target = Target::parse(TargetKind::Url, endpoint.as_str())
            .map_err(|_| PortError::new(PortErrorKind::Internal, "provider endpoint is invalid"))?;
        let scope = ScopeGrant::exact(&scope_target, false, self.clock.now());
        let started = Instant::now();
        let response = self
            .http
            .execute(HttpRequest {
                url: endpoint,
                method: HttpMethod::Get,
                headers,
                body: Vec::new(),
                max_redirects: 2,
                budget: request.budget,
                scope,
            })
            .await?;
        if response.status == 429 {
            return Err(PortError::new(
                PortErrorKind::RateLimited,
                "provider rate limit reached",
            ));
        }
        if !(200..300).contains(&response.status) {
            return Err(PortError::new(
                PortErrorKind::InvalidResponse,
                format!("provider returned HTTP {}", response.status),
            ));
        }
        let data = serde_json::from_slice::<Value>(&response.body).map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidResponse,
                "provider returned invalid JSON",
            )
        })?;
        Ok(ProviderResponse {
            provider: request.provider,
            data,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

fn endpoint_for(request: &ProviderRequest) -> Result<Url, PortError> {
    let (base, fixed): (&str, &[(&str, &str)]) =
        match (request.provider.as_str(), request.operation.as_str()) {
            ("crtsh", "query") => ("https://crt.sh/", &[("output", "json")]),
            ("wayback", "cdx") => (
                "https://web.archive.org/cdx/search/cdx",
                &[
                    ("output", "json"),
                    ("fl", "timestamp,original,statuscode,digest"),
                ],
            ),
            ("rdap", "domain") => ("https://rdap.org/domain/", &[]),
            ("rdap", "ip") => ("https://rdap.org/ip/", &[]),
            ("shodan", "host") => ("https://api.shodan.io/shodan/host/", &[]),
            ("virustotal", "domain") => ("https://www.virustotal.com/api/v3/domains/", &[]),
            ("virustotal", "ip") => ("https://www.virustotal.com/api/v3/ip_addresses/", &[]),
            ("hibp", "account") => ("https://haveibeenpwned.com/api/v3/breachedaccount/", &[]),
            ("abuseipdb", "check") => ("https://api.abuseipdb.com/api/v2/check", &[]),
            ("ipinfo", "lookup") => ("https://ipinfo.io/", &[]),
            ("otx", "domain") => ("https://otx.alienvault.com/api/v1/indicators/domain/", &[]),
            ("urlhaus", "host") => ("https://urlhaus-api.abuse.ch/v1/host/", &[]),
            ("ssllabs", "analyze") => ("https://api.ssllabs.com/api/v3/analyze", &[]),
            _ => {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "provider operation is not configured",
                ));
            }
        };
    let mut url = Url::parse(base)
        .map_err(|_| PortError::new(PortErrorKind::Internal, "provider endpoint is invalid"))?;
    if matches!(
        (request.provider.as_str(), request.operation.as_str()),
        ("rdap" | "virustotal", "domain" | "ip")
            | ("shodan", "host")
            | ("hibp", "account")
            | ("ipinfo", "lookup")
            | ("otx", "domain")
    ) {
        let target = query_string(&request.query, "target")?;
        url.path_segments_mut()
            .map_err(|()| {
                PortError::new(PortErrorKind::Internal, "provider URL cannot accept a path")
            })?
            .push(target);
        if request.provider == "otx" {
            url.path_segments_mut()
                .map_err(|()| {
                    PortError::new(PortErrorKind::Internal, "provider URL cannot accept a path")
                })?
                .push("general");
        }
    }
    let target_in_path = matches!(
        (request.provider.as_str(), request.operation.as_str()),
        ("rdap" | "virustotal", "domain" | "ip")
            | ("shodan", "host")
            | ("hibp", "account")
            | ("ipinfo", "lookup")
            | ("otx", "domain")
    );
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in fixed {
            pairs.append_pair(key, value);
        }
        for (key, value) in &request.query {
            if key == "target" && target_in_path {
                continue;
            }
            if let Some(value) = value.as_str() {
                pairs.append_pair(key, value);
            } else {
                pairs.append_pair(key, &value.to_string());
            }
        }
    }
    Ok(url)
}

fn query_string<'a>(query: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str, PortError> {
    query.get(key).and_then(Value::as_str).ok_or_else(|| {
        PortError::new(
            PortErrorKind::InvalidResponse,
            "provider request omitted a string target",
        )
    })
}

fn inject_secret(
    provider: &str,
    url: &mut Url,
    headers: &mut BTreeMap<String, String>,
    secret: &str,
) -> Result<(), PortError> {
    match provider {
        "shodan" => {
            url.query_pairs_mut().append_pair("key", secret);
        }
        "virustotal" => {
            headers.insert("x-apikey".into(), secret.into());
        }
        "hibp" => {
            headers.insert("hibp-api-key".into(), secret.into());
        }
        "abuseipdb" => {
            headers.insert("key".into(), secret.into());
            headers.insert("accept".into(), "application/json".into());
        }
        "ipinfo" => {
            url.query_pairs_mut().append_pair("token", secret);
        }
        "otx" => {
            headers.insert("x-otx-api-key".into(), secret.into());
        }
        "crtsh" | "wayback" | "rdap" | "urlhaus" | "ssllabs" => {
            return Err(PortError::new(
                PortErrorKind::InvalidResponse,
                "provider does not accept a credential for this operation",
            ));
        }
        _ => {
            return Err(PortError::new(
                PortErrorKind::Unavailable,
                "provider is not configured",
            ));
        }
    }
    Ok(())
}
