//! Capability-oriented implementations shared by the 147 compiled descriptors.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sugra_core::{
    Catalog, CommandKind, CommandRequest, CommandResponse, DnsQuery, DnsRecord, DnsRecordType,
    HttpMethod, HttpRequest, HttpResponse, LocalInputPort, LocalInputRequest, PortError,
    PortErrorKind, ProviderRequest, ProviderResponse, ScanContext, ScanError, ScanErrorKind,
    Scanner, ScannerRegistry, ServiceBundle, TcpRequest, TlsObservation, TlsRequest, UdpRequest,
};
use sugra_domain::{
    Confidence, Diagnostic, Evidence, ExecutionStatus, Finding, ScanRequest, ScanResult,
    ScannerDescriptor, Severity, Target, TargetKind,
};
use url::Url;

use crate::catalog_data::definitions;
use crate::definition::{BuiltinError, Builtins, Operation, ScannerDefinition};
use crate::dns_analysis::{
    dkim_selector_owners, dns_sla_availability_finding, dnssec_findings, dual_stack_finding,
    email_config_findings, scanner_findings as dns_scanner_findings, summarize_dns_evidence,
    ttl_finding, typosquat_resolution_finding,
};
use crate::network_analysis::{
    NetworkAnalysisError, UdpProbe, analyze_dns_transfer_response,
    analyze_udp_response as analyze_protocol_udp_response, ipv6_reachability_finding,
    udp_payload as protocol_udp_payload,
};
use crate::provider_analysis::{
    NameserverEnrichment, ProviderAnalysis, ProviderBaseline, ProviderSummary,
    analyze_nameserver_diversity, analyze_provider_response, authoritative_nameserver_addresses,
    dns_chain_addresses,
};
use crate::provider_plan::{
    self, ProviderName, ProviderPlanError, ProviderPlanOptions, ProviderWindow,
};
use crate::semantics::{Analyzer, BoundaryFamily, SemanticProfile, profile_for};
use crate::tls_analysis::{
    TlsAnalysisError, TlsSemanticError, analyze_http2_http3_checker,
    analyze_network_certificate_inventory, analyze_pinning, analyze_ssl_chain, analyze_ssl_expiry,
    analyze_tls_cipher_suites, analyze_tls_handshake as analyze_tls_handshake_semantics,
    analyze_tls_security_config, analyze_tls_session_resumption_map, summarize_tls_evidence,
};
use crate::web::{WebProbe, discovered, plan_for, should_sample};
use crate::web_analysis::{
    WebSample, aggregate_findings as aggregate_web_findings, is_crawlable_response,
    observation as web_observation, response_findings as web_response_findings,
    sample as web_sample, signals as web_signals,
};

const fn operation_family(operation: Operation) -> BoundaryFamily {
    match operation {
        Operation::Dns => BoundaryFamily::Dns,
        Operation::Http => BoundaryFamily::Http,
        Operation::Tls => BoundaryFamily::Tls,
        Operation::Registry | Operation::Intelligence => BoundaryFamily::Provider,
        Operation::Tcp => BoundaryFamily::Tcp,
        Operation::Udp => BoundaryFamily::Udp,
        Operation::Command => BoundaryFamily::Command,
        Operation::Local => BoundaryFamily::Local,
    }
}

/// Constructs the complete validated built-in catalog and implementation registry.
///
/// # Errors
///
/// Returns a built-in construction error when compiled metadata violates a
/// domain, catalog, registry, count, or identity-set invariant.
pub fn build_builtins(services: &ServiceBundle) -> Result<Builtins, BuiltinError> {
    let definitions = definitions()?;
    let descriptors: Vec<ScannerDescriptor> = definitions
        .iter()
        .map(|definition| definition.descriptor.clone())
        .collect();
    let catalog = Catalog::new(descriptors)?.require_count(147)?;
    let scanners: Vec<Arc<dyn Scanner>> = definitions
        .into_iter()
        .map(|definition| -> Result<Arc<dyn Scanner>, BuiltinError> {
            Ok(Arc::new(BuiltinScanner::new(definition, services.clone())?) as Arc<dyn Scanner>)
        })
        .collect::<Result<_, _>>()?;
    let registry = ScannerRegistry::new(scanners)?;
    if registry.len() != catalog.len() {
        let missing = catalog
            .iter()
            .find(|descriptor| registry.get(&descriptor.id).is_none())
            .map_or_else(
                || sugra_domain::ScannerId::new("catalog-registry-mismatch"),
                |descriptor| Ok(descriptor.id.clone()),
            )?;
        return Err(BuiltinError::SetMismatch(missing));
    }
    Ok(Builtins { catalog, registry })
}

struct BuiltinScanner {
    descriptor: ScannerDescriptor,
    profile: SemanticProfile,
    services: ServiceBundle,
}

impl BuiltinScanner {
    fn new(definition: ScannerDefinition, services: ServiceBundle) -> Result<Self, BuiltinError> {
        let profile = profile_for(definition.descriptor.id.as_str())
            .ok_or_else(|| BuiltinError::MissingSemantics(definition.descriptor.id.clone()))?;
        if operation_family(definition.operation) != profile.analyzer.family() {
            return Err(BuiltinError::SemanticBoundaryMismatch(
                definition.descriptor.id,
            ));
        }
        Ok(Self {
            descriptor: definition.descriptor,
            profile,
            services,
        })
    }
}

#[async_trait]
impl Scanner for BuiltinScanner {
    fn descriptor(&self) -> &ScannerDescriptor {
        &self.descriptor
    }

    async fn scan(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        if request.scanner_id != self.descriptor.id {
            return Err(ScanError::new(
                ScanErrorKind::InvalidInput,
                "request scanner ID does not match implementation",
            ));
        }
        if !self
            .descriptor
            .target_kinds
            .contains(&request.target.kind())
        {
            return Err(ScanError::new(
                ScanErrorKind::InvalidInput,
                "target kind is not supported by this scanner",
            ));
        }
        request.budget.validate().map_err(|_| {
            ScanError::new(
                ScanErrorKind::InvalidInput,
                "execution budget violates scanner safety bounds",
            )
        })?;
        if context.cancellation.is_cancelled() {
            return Err(ScanError::new(ScanErrorKind::Cancelled, "scan cancelled"));
        }
        validate_scanner_controls(self.descriptor.id.as_str(), &request.options)?;
        self.scan_stages(request, context).await
    }
}

fn validate_scanner_controls(
    scanner_id: &str,
    options: &BTreeMap<String, Value>,
) -> Result<(), ScanError> {
    if matches!(scanner_id, "ip-range-scanner" | "open-ports")
        && let Some(ports) = options.get("ports")
        && ports.as_array().is_none_or(|ports| {
            ports.is_empty()
                || ports.iter().any(|port| {
                    port.as_str()
                        .and_then(|port| port.parse::<u16>().ok())
                        .is_none_or(|port| port == 0)
                })
        })
    {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "TCP ports must be non-zero decimal values",
        ));
    }
    if matches!(
        scanner_id,
        "ip-range-scanner" | "icmp-reachability-matrix" | "ssh-banner-key-fingerprinter"
    ) && options
        .get("max_hosts")
        .is_some_and(|value| value.as_u64().is_none_or(|value| value == 0))
    {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "max_hosts must be a positive integer",
        ));
    }
    if scanner_id == "dns-over-https"
        && options
            .get("qtype")
            .and_then(Value::as_str)
            .is_some_and(|qtype| {
                !matches!(
                    qtype.to_ascii_uppercase().as_str(),
                    "A" | "AAAA" | "CAA" | "CNAME" | "DNSKEY" | "DS" | "MX" | "NS" | "TXT"
                )
            })
    {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "DNS-over-HTTPS record type is not supported",
        ));
    }
    if scanner_id != "performance-monitoring" {
        return Ok(());
    }
    if options.get("verify_ssl").and_then(Value::as_bool) == Some(false) {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "TLS certificate verification cannot be disabled",
        ));
    }
    if let Some(strategies) = options.get("strategies").and_then(Value::as_array)
        && (strategies.is_empty()
            || strategies
                .iter()
                .any(|strategy| !matches!(strategy.as_str(), Some("mobile" | "desktop"))))
    {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "PageSpeed strategies must be mobile or desktop",
        ));
    }
    Ok(())
}

impl BuiltinScanner {
    async fn scan_stages(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let stages: Vec<_> = std::iter::once(self.profile.analyzer)
            .chain(self.profile.supplements.iter().copied())
            .collect();
        let mut combined = ScanResult::completed(Vec::new(), Vec::new());
        let mut first_error = None;
        let base_limit = request.budget.max_requests / stages.len();
        let remainder = request.budget.max_requests % stages.len();

        for (index, analyzer) in stages.into_iter().enumerate() {
            if context.cancellation.is_cancelled() {
                if combined.evidence.is_empty() {
                    return Err(ScanError::new(ScanErrorKind::Cancelled, "scan cancelled"));
                }
                combined.status = ExecutionStatus::Cancelled;
                combined.diagnostics.push(Diagnostic {
                    kind: "cancelled".into(),
                    message: "remaining analysis stages were cancelled".into(),
                });
                return Ok(combined);
            }
            let stage_limit = base_limit + usize::from(index < remainder);
            if stage_limit == 0 {
                combined.status = ExecutionStatus::Partial;
                combined.diagnostics.push(Diagnostic {
                    kind: "budget-exhausted".into(),
                    message: format!("{} stage omitted by the request budget", analyzer.as_str()),
                });
                continue;
            }
            let mut stage_request = request.clone();
            stage_request.budget.max_requests = stage_limit;
            match self.execute_stage(analyzer, &stage_request, context).await {
                Ok(result) => {
                    merge_scan_result(&mut combined, self.annotate_result(analyzer, result));
                }
                Err(error) => {
                    combined.status = ExecutionStatus::Partial;
                    combined.diagnostics.push(Diagnostic {
                        kind: "analysis-stage-unavailable".into(),
                        message: format!(
                            "{} stage unavailable ({:?})",
                            analyzer.as_str(),
                            error.kind
                        ),
                    });
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if combined.evidence.is_empty() {
            return Err(first_error.unwrap_or_else(|| {
                ScanError::new(ScanErrorKind::Internal, "scanner produced no evidence")
            }));
        }
        Ok(combined)
    }

    async fn execute_stage(
        &self,
        analyzer: Analyzer,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        match analyzer.family() {
            BoundaryFamily::Dns => self.scan_dns(request, context).await,
            BoundaryFamily::Http => self.scan_http(request, context).await,
            BoundaryFamily::Tls => self.scan_tls(analyzer, request, context).await,
            BoundaryFamily::Provider => self.scan_providers(request, context).await,
            BoundaryFamily::Tcp => self.scan_tcp(analyzer, request, context).await,
            BoundaryFamily::Udp => self.scan_udp(analyzer, request, context).await,
            BoundaryFamily::Command => self.scan_command(analyzer, request, context).await,
            BoundaryFamily::Local => self.scan_local(analyzer, request, context),
        }
    }

    fn annotate_result(&self, analyzer: Analyzer, mut result: ScanResult) -> ScanResult {
        for evidence in &mut result.evidence {
            evidence.kind = format!("{}-{}", self.profile.id, evidence.kind);
            let prior = std::mem::take(&mut evidence.observation);
            evidence.observation = json!({
                "scanner_id": self.profile.id,
                "analysis": analyzer.as_str(),
                "purpose": self.profile.purpose,
                "observation": prior,
            });
        }
        result
    }

    async fn scan_dns(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let id = self.descriptor.id.as_str();
        let plan = dns_query_plan(id, &request.target, request)?;
        let attempted_samples = plan.len().min(request.budget.max_requests);
        let mut evidence = Vec::new();
        let mut diagnostics = Vec::new();
        let mut findings = Vec::new();
        let mut first_error = None;
        let original_name = dns_name(&request.target).ok();
        let mut aggregate_records = Vec::new();
        for query in plan.into_iter().take(request.budget.max_requests) {
            let started = Instant::now();
            let result = self
                .services
                .dns
                .query(DnsQuery {
                    name: query.name.clone(),
                    record_types: query.record_types.clone(),
                    budget: request.budget,
                })
                .await;
            match result {
                Ok(records) => {
                    let index = evidence.len();
                    analyze_dns(
                        id,
                        original_name.as_deref(),
                        &query,
                        &records,
                        index,
                        &mut findings,
                    );
                    aggregate_records.extend(records.iter().cloned());
                    let summary =
                        summarize_dns_evidence(&query.name, &query.record_types, &records);
                    evidence.push(Evidence {
                        kind: "dns-records".into(),
                        source: query.name,
                        observation: json!({
                            "summary": summary,
                            "duration_ms": millis(started.elapsed().as_millis()),
                        }),
                        observed_at: context.clock.now(),
                    });
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(scan_error_from_port(error.clone()));
                    }
                    diagnostics.push(Diagnostic {
                        kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                        message: format!("{}: {}", query.name, error.message),
                    });
                }
            }
        }
        if matches!(id, "email-config" | "spf-dkim-dmarc-validator")
            && let Some(domain) = original_name.as_deref()
        {
            findings.extend(email_config_findings(domain, &aggregate_records, 0));
        }
        if evidence.is_empty() {
            return Err(first_error.unwrap_or_else(|| {
                ScanError::new(ScanErrorKind::Transport, "all DNS observations failed")
            }));
        }
        if id == "dns-sla-latency-monitor" {
            findings.push(dns_sla_availability_finding(
                evidence.len(),
                attempted_samples,
            ));
        }
        Ok(ScanResult {
            status: completion_status(&diagnostics),
            findings,
            evidence,
            diagnostics,
        })
    }

    async fn scan_http(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let base = base_url(&request.target)?;
        let id = self.descriptor.id.as_str();
        let options = hydrate_web_options(
            id,
            &request.options,
            request.budget,
            self.services.local_input.as_ref(),
        )
        .await?;
        let plan = plan_for(id, &base, &options, request.budget, &request.scope)
            .ok_or_else(|| ScanError::new(ScanErrorKind::Internal, "web probe plan is missing"))?;
        let limit = plan.max_pages.min(request.budget.max_requests);
        let (crawl, max_depth, sample_per_million) =
            (plan.crawl, plan.max_depth, plan.sample_per_million);
        let (delay_ms, include_subdomains) = (plan.delay_ms, plan.include_subdomains);
        let mut queue: VecDeque<(WebProbe, usize)> =
            plan.probes.into_iter().map(|probe| (probe, 0)).collect();
        let mut seen = BTreeSet::new();
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        let mut first_error = None;
        let (mut samples, mut attempts) = (Vec::<WebSample>::new(), 0_usize);
        while let Some((probe, depth)) = queue.pop_front() {
            if attempts >= limit || !seen.insert(probe.identity()) {
                continue;
            }
            if attempts > 0 && delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            attempts += 1;
            let method = probe.method;
            let label = probe.label;
            let response = self
                .services
                .http
                .execute(HttpRequest {
                    url: probe.url,
                    method,
                    headers: probe.headers,
                    body: probe.body,
                    max_redirects: probe.max_redirects,
                    budget: request.budget,
                    scope: request.scope.clone(),
                })
                .await;
            match response {
                Ok(response) => {
                    let index = evidence.len();
                    let signals = web_signals(&response);
                    if id != "content-discovery" || depth > 0 {
                        findings.extend(web_response_findings(id, &response, &signals, index));
                    }
                    if should_discover_links(crawl, method, depth, max_depth, &response) {
                        for url in discover_links(
                            &response.final_url,
                            &base,
                            &response.body,
                            &request.scope,
                            include_subdomains,
                        )
                        .into_iter()
                        .filter(|url| should_sample(url, sample_per_million))
                        {
                            queue.push_back((discovered(url), depth + 1));
                        }
                    }
                    samples.push(web_sample(label.clone(), &response));
                    evidence.push(Evidence {
                        kind: "http-observation".into(),
                        source: safe_url_label(&response.final_url),
                        observation: web_observation(&label, method, &response, &signals),
                        observed_at: context.clock.now(),
                    });
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(scan_error_from_port(error.clone()));
                    }
                    diagnostics.push(Diagnostic {
                        kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                        message: format!("HTTP probe failed: {}", error.message),
                    });
                }
            }
        }
        findings.extend(aggregate_web_findings(id, &samples, &options));
        if evidence.is_empty() {
            return Err(first_error.unwrap_or_else(|| {
                ScanError::new(ScanErrorKind::Transport, "HTTP observation failed")
            }));
        }
        Ok(ScanResult {
            status: completion_status(&diagnostics),
            findings,
            evidence,
            diagnostics,
        })
    }

    async fn scan_tls(
        &self,
        analyzer: Analyzer,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let (host, port) = tls_endpoint(&request.target)?;
        let observation = self
            .services
            .tls
            .handshake(TlsRequest {
                host: host.clone(),
                server_name: None,
                port,
                budget: request.budget,
                scope: request.scope.clone(),
            })
            .await
            .map_err(scan_error_from_port)?;
        let findings = if analyzer == Analyzer::TlsPinning {
            analyze_pinning(
                &observation,
                request
                    .options
                    .get("baseline_sha256")
                    .and_then(Value::as_str),
                0,
            )
            .map_err(scan_error_from_tls_analysis)?
        } else {
            analyze_tls_observation(
                self.descriptor.id.as_str(),
                analyzer,
                &observation,
                context.clock.now().unix_timestamp(),
            )
            .map_err(scan_error_from_tls_semantic)?
        };
        let summary = summarize_tls_evidence(&observation).map_err(scan_error_from_tls_semantic)?;
        Ok(ScanResult::completed(
            vec![Evidence {
                kind: "tls-handshake".into(),
                source: format!("{host}:{port}"),
                observation: serde_json::to_value(summary).map_err(|_| {
                    ScanError::new(ScanErrorKind::Internal, "TLS evidence serialization failed")
                })?,
                observed_at: context.clock.now(),
            }],
            findings,
        ))
    }

    async fn scan_providers(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let scanner_id = self.descriptor.id.as_str();
        let calls = provider_calls(
            scanner_id,
            &request.target,
            &request.options,
            request.budget,
        )?;
        if scanner_id == "ip-info" && matches!(request.target, Target::Domain(_)) {
            let Some(primary) = calls.into_iter().next() else {
                return Err(ScanError::new(
                    ScanErrorKind::DependencyUnavailable,
                    "domain address discovery provider is unavailable",
                ));
            };
            return self.scan_domain_ip_info(request, context, primary).await;
        }
        if scanner_id == "ns-geo-asn-diversity-analyzer" {
            let Some(primary) = calls.into_iter().next() else {
                return Err(ScanError::new(
                    ScanErrorKind::DependencyUnavailable,
                    "nameserver discovery provider is unavailable",
                ));
            };
            return self
                .scan_nameserver_diversity(request, context, primary)
                .await;
        }
        self.scan_provider_calls(request, context, calls).await
    }

    async fn scan_provider_calls(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
        calls: Vec<ProviderCall>,
    ) -> Result<ScanResult, ScanError> {
        let scanner_id = self.descriptor.id.as_str();
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        if let Some(diagnostic) = provider_temporal_gap(scanner_id, &calls, &request.options) {
            diagnostics.push(diagnostic);
        }
        if scanner_id == "ip-info"
            && !(calls.iter().any(|call| call.provider == "ripestat")
                && calls.iter().any(|call| call.provider == "ipinfo"))
        {
            diagnostics.push(Diagnostic {
                kind: "provider-coverage-gap".into(),
                message: "IP information requires both network and location provider coverage"
                    .into(),
            });
        }
        let expected_issuers: Vec<_> = request
            .options
            .get("expected_issuers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for call in calls.into_iter().take(request.budget.max_requests) {
            let response = self.query_provider_call(request, call).await;
            match response {
                Ok(response) => {
                    let (observation, derived_findings) = provider_observation(
                        scanner_id,
                        &response.provider,
                        response.data,
                        &expected_issuers,
                        evidence.len(),
                    )?;
                    findings.extend(derived_findings);
                    evidence.push(Evidence {
                        kind: "provider-observation".into(),
                        source: provider_source(&response.provider).into(),
                        observation,
                        observed_at: context.clock.now(),
                    });
                }
                Err(error) => diagnostics.push(Diagnostic {
                    kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                    message: error.message,
                }),
            }
        }
        if evidence.is_empty() {
            let message = diagnostics
                .first()
                .map_or("all providers are unavailable", |diagnostic| {
                    diagnostic.message.as_str()
                });
            return Err(ScanError::new(
                ScanErrorKind::DependencyUnavailable,
                message,
            ));
        }
        Ok(ScanResult {
            status: if diagnostics.is_empty() {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Partial
            },
            findings,
            evidence,
            diagnostics,
        })
    }

    async fn query_provider_call(
        &self,
        request: &ScanRequest,
        call: ProviderCall,
    ) -> Result<ProviderResponse, PortError> {
        self.services
            .provider
            .query(ProviderRequest {
                provider: call.provider.into(),
                operation: call.operation.into(),
                query: provider_query(
                    self.descriptor.id.as_str(),
                    &call,
                    &request.target,
                    &request.options,
                ),
                secret_env: call.secret_env,
                budget: request.budget,
            })
            .await
    }

    async fn scan_nameserver_diversity(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
        primary: ProviderCall,
    ) -> Result<ScanResult, ScanError> {
        let response = self
            .query_provider_call(request, primary)
            .await
            .map_err(|error| ScanError::new(ScanErrorKind::DependencyUnavailable, error.message))?;
        let addresses = authoritative_nameserver_addresses(&response.data);
        let max_nameservers = request.budget.max_requests.saturating_sub(1) / 2;
        let (enrichments, mut diagnostics) = self
            .enrich_nameservers(request, addresses.clone(), max_nameservers)
            .await;
        if addresses.len() > max_nameservers {
            diagnostics.push(Diagnostic {
                kind: "nameserver-enrichment-gap".into(),
                message: "nameserver enrichment was limited by the request budget".into(),
            });
        }
        let authoritative_values_present = has_authoritative_nameservers(&response.data);
        if authoritative_values_present && addresses.is_empty() {
            diagnostics.push(Diagnostic {
                kind: "nameserver-enrichment-gap".into(),
                message: "authoritative nameserver addresses could not be safely enriched".into(),
            });
        }
        let analysis = analyze_nameserver_diversity(&response.data, &enrichments);
        if authoritative_values_present && nameserver_metadata_is_empty(&analysis.summary) {
            diagnostics.push(Diagnostic {
                kind: "nameserver-enrichment-gap".into(),
                message: "configured providers returned no nameserver geography or ASN metadata"
                    .into(),
            });
        }
        let (observation, findings) = provider_analysis_observation(analysis, 0)?;
        Ok(ScanResult {
            status: completion_status(&diagnostics),
            findings,
            evidence: vec![Evidence {
                kind: "provider-observation".into(),
                source: "RIPEstat + IPinfo".into(),
                observation,
                observed_at: context.clock.now(),
            }],
            diagnostics,
        })
    }

    async fn enrich_nameservers(
        &self,
        request: &ScanRequest,
        addresses: Vec<String>,
        max_nameservers: usize,
    ) -> (Vec<NameserverEnrichment>, Vec<Diagnostic>) {
        let mut enrichments = Vec::new();
        let mut diagnostics = Vec::new();
        for address in addresses.into_iter().take(max_nameservers) {
            let network_info = self
                .services
                .provider
                .query(ProviderRequest {
                    provider: "ripestat".into(),
                    operation: "network-info".into(),
                    query: BTreeMap::from([("resource".into(), Value::String(address.clone()))]),
                    secret_env: None,
                    budget: request.budget,
                })
                .await;
            let location = self
                .services
                .provider
                .query(ProviderRequest {
                    provider: "ipinfo".into(),
                    operation: "lookup".into(),
                    query: BTreeMap::from([("target".into(), Value::String(address))]),
                    secret_env: Some("IPINFO_API_KEY".into()),
                    budget: request.budget,
                })
                .await;
            let network_info = provider_enrichment_result(
                network_info,
                "RIPEstat nameserver enrichment failed",
                &mut diagnostics,
            );
            let location = provider_enrichment_result(
                location,
                "IPinfo nameserver enrichment failed",
                &mut diagnostics,
            );
            enrichments.push(NameserverEnrichment {
                network_info,
                location,
            });
        }
        (enrichments, diagnostics)
    }

    async fn scan_domain_ip_info(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
        primary: ProviderCall,
    ) -> Result<ScanResult, ScanError> {
        let response = self
            .query_provider_call(request, primary)
            .await
            .map_err(|error| ScanError::new(ScanErrorKind::DependencyUnavailable, error.message))?;
        let addresses = dns_chain_addresses(&response.data);
        if addresses.is_empty() {
            return Err(ScanError::new(
                ScanErrorKind::InvalidResponse,
                "domain address discovery returned no enrichable addresses",
            ));
        }
        let max_addresses = request.budget.max_requests.saturating_sub(1) / 2;
        if max_addresses == 0 {
            return Err(ScanError::new(
                ScanErrorKind::InvalidInput,
                "request budget cannot cover domain network and location enrichment",
            ));
        }
        let mut diagnostics = Vec::new();
        if addresses.len() > max_addresses {
            diagnostics.push(Diagnostic {
                kind: "provider-coverage-gap".into(),
                message: "domain address enrichment was limited by the request budget".into(),
            });
        }
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        for address in addresses.into_iter().take(max_addresses) {
            self.append_domain_ip_info_evidence(
                request,
                context,
                address,
                &mut evidence,
                &mut findings,
                &mut diagnostics,
            )
            .await?;
        }
        if evidence.is_empty() {
            return Err(ScanError::new(
                ScanErrorKind::DependencyUnavailable,
                "all domain address enrichment providers are unavailable",
            ));
        }
        Ok(ScanResult {
            status: completion_status(&diagnostics),
            findings,
            evidence,
            diagnostics,
        })
    }

    async fn append_domain_ip_info_evidence(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
        address: String,
        evidence: &mut Vec<Evidence>,
        findings: &mut Vec<Finding>,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<(), ScanError> {
        let responses = [
            self.services
                .provider
                .query(ProviderRequest {
                    provider: "ripestat".into(),
                    operation: "network-info".into(),
                    query: BTreeMap::from([("resource".into(), Value::String(address.clone()))]),
                    secret_env: None,
                    budget: request.budget,
                })
                .await,
            self.services
                .provider
                .query(ProviderRequest {
                    provider: "ipinfo".into(),
                    operation: "lookup".into(),
                    query: BTreeMap::from([("target".into(), Value::String(address))]),
                    secret_env: Some("IPINFO_API_KEY".into()),
                    budget: request.budget,
                })
                .await,
        ];
        for response in responses {
            match response {
                Ok(response) => {
                    let (observation, derived) = provider_observation(
                        "ip-info",
                        &response.provider,
                        response.data,
                        &[],
                        evidence.len(),
                    )?;
                    findings.extend(derived);
                    evidence.push(Evidence {
                        kind: "provider-observation".into(),
                        source: provider_source(&response.provider).into(),
                        observation,
                        observed_at: context.clock.now(),
                    });
                }
                Err(error) => diagnostics.push(Diagnostic {
                    kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                    message: "domain address provider enrichment failed".into(),
                }),
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn scan_tcp(
        &self,
        analyzer: Analyzer,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        if analyzer == Analyzer::TcpRange && self.descriptor.id.as_str() == "ipv6-reachability-test"
        {
            return self.scan_ipv6_reachability(request, context).await;
        }
        if matches!(analyzer, Analyzer::TcpCertificate | Analyzer::TcpTlsState) {
            return self.scan_network_tls(analyzer, request, context).await;
        }
        let targets = network_hosts(&request.target, host_limit(request))?;
        let ports = tcp_ports(self.descriptor.id.as_str(), request);
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        let mut first_error = None;
        let mut attempts = 0_usize;
        for host in targets {
            for port in &ports {
                if attempts >= request.budget.max_requests {
                    break;
                }
                if context.cancellation.is_cancelled() {
                    if evidence.is_empty() {
                        return Err(ScanError::new(ScanErrorKind::Cancelled, "scan cancelled"));
                    }
                    return Ok(cancelled_network_result(evidence, findings, diagnostics));
                }
                attempts += 1;
                let response = self
                    .services
                    .tcp
                    .execute(TcpRequest {
                        host: host.clone(),
                        port: *port,
                        payload: tcp_payload(analyzer, &host, *port)?,
                        read_response: tcp_reads_response(analyzer, *port),
                        budget: request.budget,
                        scope: request.scope.clone(),
                    })
                    .await;
                match response {
                    Ok(response) => {
                        if response.bytes.len() > request.budget.max_response_bytes {
                            let error = scan_error_from_network_analysis(
                                NetworkAnalysisError::ResponseTooLarge,
                            );
                            diagnostics.push(Diagnostic {
                                kind: "invalidresponse".into(),
                                message: format!("{host}:{port}: {}", error.message),
                            });
                            if first_error.is_none() {
                                first_error = Some(error);
                            }
                            continue;
                        }
                        let index = evidence.len();
                        let transfer = (analyzer == Analyzer::TcpDnsTransfer)
                            .then(|| {
                                analyze_dns_transfer_response(
                                    &response.bytes,
                                    request.budget.max_response_bytes,
                                )
                                .map_err(scan_error_from_network_analysis)
                            })
                            .transpose()?;
                        let transfer_accepted = transfer.is_some_and(|value| value.accepted);
                        if transfer_accepted {
                            findings.push(finding(
                                "dns-zone-transfer-accepted",
                                "The authoritative server returned zone-transfer records",
                                Severity::High,
                                Confidence::Confirmed,
                                index,
                            ));
                        } else if matches!(analyzer, Analyzer::TcpPorts | Analyzer::TcpRange) {
                            findings.push(finding(
                                "tcp-port-open",
                                &format!("TCP port {port} accepted a connection"),
                                Severity::Info,
                                Confidence::Confirmed,
                                index,
                            ));
                        }
                        evidence.push(Evidence {
                            kind: "tcp-observation".into(),
                            source: format!("{host}:{port}"),
                            observation: json!({
                                "state": "open",
                                "bytes": response.bytes.len(),
                                "sha256": hex::encode(Sha256::digest(&response.bytes)),
                                "transfer_accepted": transfer_accepted,
                                "response_code": transfer.map(|value| value.response_code),
                                "messages": transfer.map(|value| value.messages),
                                "answer_records": transfer.map(|value| value.answer_records),
                                "soa_records": transfer.map(|value| value.soa_records),
                                "duration_ms": response.duration_ms,
                            }),
                            observed_at: context.clock.now(),
                        });
                    }
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(scan_error_from_port(error.clone()));
                        }
                        push_network_diagnostic(&mut diagnostics, &host, *port, &error);
                    }
                }
            }
        }
        network_result_with_error(evidence, findings, diagnostics, first_error)
    }

    async fn resolve_ipv6_candidates(
        &self,
        request: &ScanRequest,
    ) -> Result<Vec<IpAddr>, ScanError> {
        let resolved = match &request.target {
            Target::Domain(domain) => self
                .services
                .dns
                .query(DnsQuery {
                    name: domain.clone(),
                    record_types: vec![DnsRecordType::Aaaa],
                    budget: request.budget,
                })
                .await
                .map_err(scan_error_from_port)?
                .into_iter()
                .filter(|record| record.record_type == DnsRecordType::Aaaa)
                .filter_map(|record| record.value.parse::<Ipv6Addr>().ok())
                .map(IpAddr::V6)
                .collect::<Vec<_>>(),
            Target::Ip(address) => vec![*address],
            _ => {
                return Err(scan_error_from_network_analysis(
                    NetworkAnalysisError::UnsupportedTarget,
                ));
            }
        };
        if matches!(request.target, Target::Ip(IpAddr::V4(_))) {
            return Err(scan_error_from_network_analysis(
                NetworkAnalysisError::Ipv4Target,
            ));
        }
        Ok(resolved)
    }

    async fn scan_ipv6_reachability(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let resolved = self.resolve_ipv6_candidates(request).await?;
        let candidates = resolved
            .iter()
            .filter_map(|address| match address {
                IpAddr::V6(address) => Some(*address),
                IpAddr::V4(_) => None,
            })
            .take(host_limit(request).min(request.budget.max_requests))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Ok(ScanResult::completed(
                vec![Evidence {
                    kind: "ipv6-resolution".into(),
                    source: request.target.canonical(),
                    observation: json!({"ipv6_addresses": 0}),
                    observed_at: context.clock.now(),
                }],
                Vec::new(),
            ));
        }

        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        for address in candidates {
            let port = 443;
            let response = self
                .services
                .tcp
                .execute(TcpRequest {
                    host: address.to_string(),
                    port,
                    payload: Vec::new(),
                    read_response: false,
                    budget: request.budget,
                    scope: sugra_domain::ScopeGrant::exact(
                        &Target::Ip(IpAddr::V6(address)),
                        request.scope.active_authorized,
                        context.clock.now(),
                    ),
                })
                .await;
            let index = evidence.len();
            match response {
                Ok(response) => {
                    if let Some(finding) = ipv6_reachability_finding(
                        &request.target,
                        &resolved,
                        Some(SocketAddr::new(IpAddr::V6(address), port)),
                        index,
                    )
                    .map_err(scan_error_from_network_analysis)?
                    {
                        findings.push(finding);
                    }
                    evidence.push(Evidence {
                        kind: "ipv6-reachability".into(),
                        source: response.endpoint,
                        observation: json!({
                            "state": "reachable",
                            "duration_ms": response.duration_ms,
                        }),
                        observed_at: context.clock.now(),
                    });
                }
                Err(error)
                    if matches!(
                        error.kind,
                        PortErrorKind::Transport | PortErrorKind::Timeout
                    ) =>
                {
                    evidence.push(Evidence {
                        kind: "ipv6-reachability".into(),
                        source: format!("[{address}]:{port}"),
                        observation: json!({"state": "unreachable"}),
                        observed_at: context.clock.now(),
                    });
                }
                Err(error) => {
                    push_network_diagnostic(&mut diagnostics, &address.to_string(), port, &error);
                }
            }
        }
        network_result(evidence, findings, diagnostics)
    }

    async fn scan_network_tls(
        &self,
        analyzer: Analyzer,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let targets = network_hosts(&request.target, host_limit(request))?;
        let ports = tcp_ports(self.descriptor.id.as_str(), request);
        let samples = if analyzer == Analyzer::TcpTlsState {
            usize_option(&request.options, "samples", 2).clamp(2, 8)
        } else {
            1
        };
        let server_name = request
            .options
            .get("server_name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        let mut attempts = 0_usize;
        let mut tls_samples = Vec::new();
        let mut tls_evidence = Vec::new();
        for host in targets {
            for port in &ports {
                for _ in 0..samples {
                    if attempts >= request.budget.max_requests {
                        break;
                    }
                    attempts += 1;
                    match self
                        .services
                        .tls
                        .handshake(TlsRequest {
                            host: host.clone(),
                            server_name: server_name.clone(),
                            port: *port,
                            budget: request.budget,
                            scope: request.scope.clone(),
                        })
                        .await
                    {
                        Ok(observation) => {
                            let index = evidence.len();
                            let summary = summarize_tls_evidence(&observation)
                                .map_err(scan_error_from_tls_semantic)?;
                            if analyzer == Analyzer::TcpCertificate {
                                let now = context.clock.now().unix_timestamp();
                                findings.extend(
                                    analyze_ssl_chain(&observation, index)
                                        .map_err(scan_error_from_tls_semantic)?,
                                );
                                findings.extend(
                                    analyze_ssl_expiry(&observation, now, index)
                                        .map_err(scan_error_from_tls_semantic)?,
                                );
                            }
                            evidence.push(Evidence {
                                kind: "network-tls-observation".into(),
                                source: format!("{host}:{port}"),
                                observation: serde_json::to_value(summary).map_err(|_| {
                                    ScanError::new(
                                        ScanErrorKind::Internal,
                                        "TLS evidence serialization failed",
                                    )
                                })?,
                                observed_at: context.clock.now(),
                            });
                            tls_samples.push(observation);
                            tls_evidence.push(index);
                        }
                        Err(error) => {
                            push_network_diagnostic(&mut diagnostics, &host, *port, &error);
                        }
                    }
                }
            }
        }
        if !tls_samples.is_empty() && analyzer == Analyzer::TcpTlsState {
            findings.extend(
                analyze_tls_session_resumption_map(&tls_samples, &tls_evidence)
                    .map_err(scan_error_from_tls_semantic)?,
            );
        } else if !tls_samples.is_empty() && analyzer == Analyzer::TcpCertificate {
            let inventory = analyze_network_certificate_inventory(&tls_samples, &tls_evidence)
                .map_err(scan_error_from_tls_semantic)?;
            findings.extend(inventory.findings);
            evidence.push(Evidence {
                kind: "certificate-inventory-summary".into(),
                source: self.descriptor.id.to_string(),
                observation: serde_json::to_value(inventory.summary).map_err(|_| {
                    ScanError::new(
                        ScanErrorKind::Internal,
                        "TLS inventory serialization failed",
                    )
                })?,
                observed_at: context.clock.now(),
            });
        }
        network_result(evidence, findings, diagnostics)
    }

    async fn scan_udp(
        &self,
        analyzer: Analyzer,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let targets = network_hosts(&request.target, host_limit(request))?;
        let ports = udp_ports(self.descriptor.id.as_str(), request);
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        let mut attempts = 0_usize;
        for host in targets {
            for port in &ports {
                if attempts >= request.budget.max_requests {
                    break;
                }
                attempts += 1;
                let probe = udp_probe(analyzer, self.descriptor.id.as_str(), *port)?;
                let response = self
                    .services
                    .udp
                    .execute(UdpRequest {
                        host: host.clone(),
                        port: *port,
                        payload: protocol_udp_payload(probe, *port)
                            .map_err(scan_error_from_network_analysis)?,
                        budget: request.budget,
                        scope: request.scope.clone(),
                    })
                    .await;
                match response {
                    Ok(response) => {
                        let index = evidence.len();
                        let analysis = analyze_protocol_udp_response(
                            probe,
                            &response.bytes,
                            request.budget.max_response_bytes.min(65_507),
                            index,
                        )
                        .map_err(scan_error_from_network_analysis)?;
                        findings.extend(analysis.findings);
                        evidence.push(Evidence {
                            kind: "udp-observation".into(),
                            source: response.endpoint,
                            observation: json!({
                                "responded": true,
                                "bytes": response.bytes.len(),
                                "protocol": analysis.classification,
                                "duration_ms": response.duration_ms,
                            }),
                            observed_at: context.clock.now(),
                        });
                    }
                    Err(error) => push_network_diagnostic(&mut diagnostics, &host, *port, &error),
                }
            }
        }
        network_result(evidence, findings, diagnostics)
    }

    async fn scan_command(
        &self,
        analyzer: Analyzer,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let kind = command_kind(analyzer)?;
        let targets = command_targets(&request.target, host_limit(request));
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        let mut first_error = None;
        for target in targets.into_iter().take(request.budget.max_requests) {
            if context.cancellation.is_cancelled() {
                if evidence.is_empty() {
                    return Err(ScanError::new(ScanErrorKind::Cancelled, "scan cancelled"));
                }
                return Ok(cancelled_network_result(evidence, findings, diagnostics));
            }
            let source = target.canonical();
            match self
                .services
                .command
                .execute(CommandRequest {
                    kind,
                    target,
                    budget: request.budget,
                    scope: request.scope.clone(),
                })
                .await
            {
                Ok(response) => {
                    let index = evidence.len();
                    let (observation, derived_findings) = match analyze_command_response(
                        kind,
                        &response,
                        request.budget.max_response_bytes,
                        index,
                    ) {
                        Ok(analysis) => analysis,
                        Err(error) => {
                            if first_error.is_none() {
                                first_error = Some(error.clone());
                            }
                            diagnostics.push(Diagnostic {
                                kind: "invalidresponse".into(),
                                message: format!("{source}: {}", error.message),
                            });
                            continue;
                        }
                    };
                    findings.extend(derived_findings);
                    evidence.push(Evidence {
                        kind: "platform-command".into(),
                        source: format!("{kind:?}:{source}"),
                        observation,
                        observed_at: context.clock.now(),
                    });
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(scan_error_from_port(error.clone()));
                    }
                    diagnostics.push(Diagnostic {
                        kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                        message: format!("{source}: {}", error.message),
                    });
                }
            }
        }
        network_result_with_error(evidence, findings, diagnostics, first_error)
    }

    fn scan_local(
        &self,
        analyzer: Analyzer,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let id = self.descriptor.id.as_str();
        match analyzer {
            Analyzer::LocalJwt => return scan_jwt(request, context),
            Analyzer::LocalWordlist => {}
            _ => {
                return Err(ScanError::new(
                    ScanErrorKind::Internal,
                    "local analyzer does not define a local analysis contract",
                ));
            }
        }
        let canonical = request.target.canonical();
        let host = request.target.host().unwrap_or(&canonical);
        let tokens = wordlist(host);
        Ok(ScanResult::completed(
            vec![Evidence {
                kind: "generated-wordlist".into(),
                source: id.into(),
                observation: json!({"tokens": tokens}),
                observed_at: context.clock.now(),
            }],
            Vec::new(),
        ))
    }
}

fn completion_status(diagnostics: &[Diagnostic]) -> ExecutionStatus {
    if diagnostics.is_empty() {
        ExecutionStatus::Completed
    } else {
        ExecutionStatus::Partial
    }
}

fn has_authoritative_nameservers(response: &Value) -> bool {
    response
        .get("data")
        .unwrap_or(response)
        .get("authoritative_nameservers")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
}

fn nameserver_metadata_is_empty(summary: &ProviderSummary) -> bool {
    matches!(
        summary,
        ProviderSummary::NameserverDiversity {
            unique_countries: 0,
            unique_autonomous_systems: 0,
            ..
        }
    )
}

fn provider_observation(
    scanner_id: &str,
    provider: &str,
    data: Value,
    expected_issuers: &[&str],
    evidence: usize,
) -> Result<(Value, Vec<Finding>), ScanError> {
    let baseline = if expected_issuers.is_empty() {
        ProviderBaseline::None
    } else {
        ProviderBaseline::CertificateIssuers(expected_issuers)
    };
    if let Some(analysis) = analyze_provider_response(scanner_id, provider, &data, baseline) {
        return provider_analysis_observation(analysis, evidence);
    }

    let observation = redact_provider_data(provider, data);
    let findings = analyze_provider(scanner_id, provider, &observation, evidence);
    Ok((observation, findings))
}

fn provider_analysis_observation(
    analysis: ProviderAnalysis,
    evidence: usize,
) -> Result<(Value, Vec<Finding>), ScanError> {
    let findings = analysis
        .findings
        .into_iter()
        .map(|finding| Finding {
            key: finding.key.into(),
            title: finding.title.into(),
            severity: finding.severity,
            confidence: finding.confidence,
            evidence: vec![evidence],
        })
        .collect();
    let observation = serde_json::to_value(analysis.summary).map_err(|_| {
        ScanError::new(
            ScanErrorKind::Internal,
            "provider summary serialization failed",
        )
    })?;
    Ok((observation, findings))
}

fn provider_enrichment_result(
    result: Result<ProviderResponse, PortError>,
    message: &'static str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Value> {
    match result {
        Ok(response) => Some(response.data),
        Err(error) => {
            diagnostics.push(Diagnostic {
                kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                message: message.into(),
            });
            None
        }
    }
}

fn merge_scan_result(target: &mut ScanResult, mut source: ScanResult) {
    let offset = target.evidence.len();
    for finding in &mut source.findings {
        for evidence in &mut finding.evidence {
            *evidence += offset;
        }
    }
    if target.status == ExecutionStatus::Completed && source.status != ExecutionStatus::Completed {
        target.status = source.status;
    }
    target.findings.append(&mut source.findings);
    target.evidence.append(&mut source.evidence);
    target.diagnostics.append(&mut source.diagnostics);
}

fn analyze_tls_observation(
    scanner_id: &str,
    analyzer: Analyzer,
    observation: &TlsObservation,
    now: i64,
) -> Result<Vec<Finding>, TlsSemanticError> {
    match analyzer {
        Analyzer::TlsHandshake => analyze_tls_handshake_semantics(observation, 0),
        Analyzer::TlsChain => analyze_ssl_chain(observation, 0),
        Analyzer::TlsExpiry => analyze_ssl_expiry(observation, now, 0),
        Analyzer::TlsCipher if scanner_id == "tls-security-config" => {
            analyze_tls_security_config(observation, 0)
        }
        Analyzer::TlsCipher => analyze_tls_cipher_suites(observation, 0),
        Analyzer::TlsProtocol => analyze_http2_http3_checker(observation, 0),
        _ => Ok(Vec::new()),
    }
}

fn dns_name(target: &Target) -> Result<String, ScanError> {
    match target {
        Target::Domain(value) => Ok(value.clone()),
        Target::Url(value) => value
            .host_str()
            .map(str::to_owned)
            .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "URL has no host")),
        Target::Email(value) => value
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_owned())
            .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "email has no domain")),
        Target::Ip(address) => Ok(reverse_name(*address)),
        Target::HostPort { host, .. } => Ok(host.clone()),
        Target::Cidr(_) | Target::Asn(_) | Target::Opaque(_) => Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "scanner requires a DNS-capable target",
        )),
    }
}

fn reverse_name(address: std::net::IpAddr) -> String {
    match address {
        std::net::IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa.")
        }
        std::net::IpAddr::V6(address) => {
            let hex = hex::encode(address.octets());
            format!(
                "{}.ip6.arpa.",
                hex.chars()
                    .rev()
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            )
        }
    }
}

#[derive(Debug, Clone)]
struct DnsPlannedQuery {
    name: String,
    record_types: Vec<DnsRecordType>,
}

fn dns_query_plan(
    id: &str,
    target: &Target,
    request: &ScanRequest,
) -> Result<Vec<DnsPlannedQuery>, ScanError> {
    if id == "dns-sla-latency-monitor"
        && request
            .options
            .get("resolvers")
            .and_then(Value::as_array)
            .is_some_and(|resolvers| !resolvers.is_empty())
    {
        return Err(ScanError::new(
            ScanErrorKind::DependencyUnavailable,
            "the configured DNS boundary cannot select a custom resolver",
        ));
    }
    if id == "reverse-dns-scan" {
        let addresses: Vec<_> = match target {
            Target::Ip(address) => vec![*address],
            Target::Cidr(network) => network.hosts().take(request.budget.max_requests).collect(),
            _ => {
                return Err(ScanError::new(
                    ScanErrorKind::InvalidInput,
                    "reverse DNS scan requires an address or network",
                ));
            }
        };
        return Ok(addresses
            .into_iter()
            .map(|address| DnsPlannedQuery {
                name: reverse_name(address),
                record_types: vec![DnsRecordType::Ptr],
            })
            .collect());
    }

    let name = dns_name(target)?;
    let query =
        |name: String, record_types: Vec<DnsRecordType>| DnsPlannedQuery { name, record_types };
    let plan = match id {
        "typosquat-domain-checker" => typo_candidates(
            &name,
            usize_option(&request.options, "max_variants", 32).clamp(1, 128),
        )
        .into_iter()
        .map(|candidate| {
            query(
                candidate,
                vec![
                    DnsRecordType::A,
                    DnsRecordType::Aaaa,
                    DnsRecordType::Cname,
                    DnsRecordType::Mx,
                ],
            )
        })
        .collect(),
        "dns-sla-latency-monitor" => {
            let samples = request
                .options
                .get("samples")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(3)
                .clamp(1, 10);
            (0..samples)
                .map(|_| query(name.clone(), vec![DnsRecordType::A, DnsRecordType::Aaaa]))
                .collect()
        }
        "spf-dkim-dmarc-validator" => {
            let mut queries = vec![
                query(name.clone(), vec![DnsRecordType::Txt]),
                query(format!("_dmarc.{name}"), vec![DnsRecordType::Txt]),
            ];
            queries.extend(dkim_queries(&name, request)?);
            queries
        }
        "email-config" => {
            let mut queries = vec![
                query(
                    name.clone(),
                    vec![DnsRecordType::Mx, DnsRecordType::Txt, DnsRecordType::Caa],
                ),
                query(format!("_dmarc.{name}"), vec![DnsRecordType::Txt]),
            ];
            queries.extend(dkim_queries(&name, request)?);
            queries
        }
        "rogue-subdomain-resolver" | "subdomain-takeover" => vec![
            query(
                name.clone(),
                vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname],
            ),
            query(
                format!("_sugra-scope-probe.{name}"),
                vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname],
            ),
        ],
        "decoy-dns-beacon" => vec![query(
            format!("_sugra-decoy-beacon.{name}"),
            vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname],
        )],
        _ => vec![query(name, dns_types(id, request))],
    };
    Ok(plan)
}

fn dkim_queries(domain: &str, request: &ScanRequest) -> Result<Vec<DnsPlannedQuery>, ScanError> {
    let mut selectors = string_values(&request.options, "selectors");
    if selectors.is_empty() {
        selectors.push("default".into());
    }
    let selector_refs = selectors.iter().map(String::as_str).collect::<Vec<_>>();
    dkim_selector_owners(domain, &selector_refs)
        .map_err(|error| ScanError::new(ScanErrorKind::InvalidInput, error.to_string()))
        .map(|owners| {
            owners
                .into_iter()
                .map(|name| DnsPlannedQuery {
                    name,
                    record_types: vec![DnsRecordType::Txt],
                })
                .collect()
        })
}

fn typo_candidates(name: &str, limit: usize) -> Vec<String> {
    let canonical = name.trim_end_matches('.').to_ascii_lowercase();
    let (label, suffix) = canonical
        .split_once('.')
        .map_or((canonical.as_str(), ""), |(label, suffix)| (label, suffix));
    let bytes = label.as_bytes();
    let mut variants = BTreeSet::new();
    for index in 0..bytes.len() {
        if bytes.len() > 2 {
            let mut deleted = bytes.to_vec();
            deleted.remove(index);
            variants.insert(String::from_utf8_lossy(&deleted).into_owned());
        }
        if bytes.len() < 63 {
            let mut duplicated = bytes.to_vec();
            duplicated.insert(index, bytes[index]);
            variants.insert(String::from_utf8_lossy(&duplicated).into_owned());
        }
        if index + 1 < bytes.len() && bytes[index] != bytes[index + 1] {
            let mut swapped = bytes.to_vec();
            swapped.swap(index, index + 1);
            variants.insert(String::from_utf8_lossy(&swapped).into_owned());
        }
    }
    variants
        .into_iter()
        .filter(|candidate| candidate != label && !candidate.is_empty())
        .map(|candidate| {
            if suffix.is_empty() {
                candidate
            } else {
                format!("{candidate}.{suffix}")
            }
        })
        .take(limit)
        .collect()
}

fn dns_types(id: &str, request: &ScanRequest) -> Vec<DnsRecordType> {
    if id == "dns-records" {
        if let Some(values) = request.options.get("types").and_then(Value::as_array) {
            let parsed: Vec<DnsRecordType> = values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(parse_dns_type)
                .collect();
            if !parsed.is_empty() {
                return parsed;
            }
        }
        return vec![
            DnsRecordType::A,
            DnsRecordType::Aaaa,
            DnsRecordType::Cname,
            DnsRecordType::Mx,
            DnsRecordType::Ns,
            DnsRecordType::Txt,
            DnsRecordType::Soa,
        ];
    }
    match id {
        "dnssec" => vec![DnsRecordType::Ds, DnsRecordType::Dnskey],
        "dns-caa-checker" => vec![DnsRecordType::Caa],
        "txt-records" | "spf-network-extractor" => vec![DnsRecordType::Txt],
        "domain-info" => vec![
            DnsRecordType::A,
            DnsRecordType::Aaaa,
            DnsRecordType::Cname,
            DnsRecordType::Mx,
            DnsRecordType::Ns,
            DnsRecordType::Soa,
            DnsRecordType::Txt,
            DnsRecordType::Caa,
        ],
        "geo-dns-footprint" => vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Ns],
        "ttl-analysis" => vec![
            DnsRecordType::A,
            DnsRecordType::Aaaa,
            DnsRecordType::Mx,
            DnsRecordType::Ns,
        ],
        "dual-stack-behavior-profiler" | "dual-stack-diff" => {
            vec![DnsRecordType::A, DnsRecordType::Aaaa]
        }
        "recursive-nameserver-leak-test" => {
            vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Ns]
        }
        _ => vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname],
    }
}

fn analyze_dns(
    id: &str,
    original_name: Option<&str>,
    query: &DnsPlannedQuery,
    records: &[DnsRecord],
    evidence: usize,
    findings: &mut Vec<Finding>,
) {
    match id {
        "dnssec" => findings.extend(dnssec_findings(&query.name, records, evidence)),
        "cdn-detection"
        | "dns-caa-checker"
        | "dns-records"
        | "decoy-dns-beacon"
        | "domain-info"
        | "geo-dns-footprint"
        | "reverse-dns-scan"
        | "rogue-subdomain-resolver"
        | "spf-network-extractor"
        | "subdomain-takeover"
        | "txt-records" => {
            findings.extend(dns_scanner_findings(id, &query.name, records, evidence));
        }
        "dual-stack-behavior-profiler" | "dual-stack-diff" => {
            if let Some(finding) = dual_stack_finding(records, evidence) {
                findings.push(finding);
            }
        }
        "typosquat-domain-checker" => {
            if let Some(finding) = original_name.and_then(|original| {
                typosquat_resolution_finding(original, &query.name, records, evidence)
            }) {
                findings.push(finding);
            }
        }
        "ttl-analysis" => {
            if let Some(finding) = ttl_finding(records, evidence) {
                findings.push(finding);
            }
        }
        _ => {}
    }
}

fn doh_provider(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "cloudflare" | "cloudflare-doh" => Some("cloudflare-doh"),
        "google" | "google-doh" => Some("google-doh"),
        _ => None,
    }
}

fn parse_dns_type(value: &str) -> Option<DnsRecordType> {
    match value.to_ascii_uppercase().as_str() {
        "A" => Some(DnsRecordType::A),
        "AAAA" => Some(DnsRecordType::Aaaa),
        "CNAME" => Some(DnsRecordType::Cname),
        "MX" => Some(DnsRecordType::Mx),
        "NS" => Some(DnsRecordType::Ns),
        "SOA" => Some(DnsRecordType::Soa),
        "TXT" => Some(DnsRecordType::Txt),
        "SRV" => Some(DnsRecordType::Srv),
        "CAA" => Some(DnsRecordType::Caa),
        "DNSKEY" => Some(DnsRecordType::Dnskey),
        "DS" => Some(DnsRecordType::Ds),
        "PTR" => Some(DnsRecordType::Ptr),
        _ => None,
    }
}

fn base_url(target: &Target) -> Result<Url, ScanError> {
    let url = match target {
        Target::Url(value) => Ok(value.clone()),
        Target::Domain(value) | Target::HostPort { host: value, .. } => {
            Url::parse(&format!("https://{value}/")).map_err(|_| {
                ScanError::new(ScanErrorKind::InvalidInput, "could not build target URL")
            })
        }
        Target::Ip(value) => Url::parse(&format!("https://{value}/"))
            .map_err(|_| ScanError::new(ScanErrorKind::InvalidInput, "could not build target URL")),
        Target::Email(value) => value
            .rsplit_once('@')
            .and_then(|(_, domain)| Url::parse(&format!("https://{domain}/")).ok())
            .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "email has no web domain")),
        Target::Cidr(_) | Target::Asn(_) | Target::Opaque(_) => Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "scanner requires a web-capable target",
        )),
    }?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "web target must use HTTP(S) without embedded credentials",
        ));
    }
    Ok(url)
}

async fn hydrate_web_options(
    scanner_id: &str,
    options: &BTreeMap<String, Value>,
    budget: sugra_domain::Budget,
    local_input: &dyn LocalInputPort,
) -> Result<BTreeMap<String, Value>, ScanError> {
    let mapping = match scanner_id {
        "directory-finder" => Some(("wordlist", "wordlist")),
        "login-page-brute-identifier" => Some(("paths_file", "paths")),
        "hidden-parameter-discovery" => Some(("params_file", "params")),
        _ => None,
    };
    let Some((source_key, destination_key)) = mapping else {
        return Ok(options.clone());
    };
    let Some(path) = options.get(source_key).and_then(Value::as_str) else {
        return Ok(options.clone());
    };
    let response = local_input
        .read_lines(LocalInputRequest {
            path: path.into(),
            budget,
        })
        .await
        .map_err(scan_error_from_port)?;
    let mut values = options
        .get(destination_key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|value| Value::String(value.into()))
        .collect::<Vec<_>>();
    values.extend(response.lines.into_iter().map(Value::String));
    values.truncate(budget.max_requests);

    let mut hydrated = options.clone();
    hydrated.insert(destination_key.into(), Value::Array(values));
    Ok(hydrated)
}

fn discover_links(
    document_base: &Url,
    root: &Url,
    body: &[u8],
    scope: &sugra_domain::ScopeGrant,
    include_subdomains: bool,
) -> Vec<Url> {
    let document = Html::parse_document(&String::from_utf8_lossy(body));
    let Ok(selector) = Selector::parse("a[href], script[src]") else {
        return Vec::new();
    };
    document
        .select(&selector)
        .filter_map(|element| {
            element
                .value()
                .attr("href")
                .or_else(|| element.value().attr("src"))
                .and_then(|value| document_base.join(value).ok())
        })
        .filter(|candidate| {
            matches!(candidate.scheme(), "http" | "https")
                && candidate.username().is_empty()
                && candidate.password().is_none()
                && candidate.scheme() == root.scheme()
                && candidate.port_or_known_default() == root.port_or_known_default()
                && related_discovery_host(root, candidate, include_subdomains)
                && Target::parse(TargetKind::Url, candidate.as_str())
                    .ok()
                    .is_some_and(|target| scope.allows(&target))
        })
        .take(512)
        .collect()
}

fn related_discovery_host(root: &Url, candidate: &Url, include_subdomains: bool) -> bool {
    let (Some(root_host), Some(candidate_host)) = (root.host_str(), candidate.host_str()) else {
        return false;
    };
    candidate_host.eq_ignore_ascii_case(root_host)
        || include_subdomains
            && candidate_host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", root_host.to_ascii_lowercase()))
}

fn safe_url_label(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

fn should_discover_links(
    crawl: bool,
    method: HttpMethod,
    depth: usize,
    max_depth: usize,
    response: &HttpResponse,
) -> bool {
    crawl && method == HttpMethod::Get && depth < max_depth && is_crawlable_response(response)
}

#[derive(Clone)]
struct ProviderCall {
    provider: &'static str,
    operation: &'static str,
    secret_env: Option<String>,
    strategy: Option<&'static str>,
    controls: ProviderControls,
}

#[derive(Clone, Default)]
struct ProviderControls {
    limit: usize,
    status_filter: Vec<u16>,
    collapse_digest: bool,
    include_wildcard: bool,
    window: Option<ProviderWindow>,
}

fn provider_calls(
    id: &str,
    target: &Target,
    options: &BTreeMap<String, Value>,
    budget: sugra_domain::Budget,
) -> Result<Vec<ProviderCall>, ScanError> {
    if matches!(id, "dark-web-monitoring" | "pastebin-monitoring") {
        validate_secret_reference_option(options, "hibp_key")?;
    }
    let plan_options = provider_plan_options(id, options)?;
    if let Some(plan) = provider_plan::plan_for(id, target.kind(), &plan_options)
        .map_err(|error| provider_plan_error(&error))?
    {
        let controls = ProviderControls {
            limit: plan.limit.min(budget.max_requests),
            status_filter: plan.status_filter,
            collapse_digest: plan.collapse_digest,
            include_wildcard: plan.include_wildcard,
            window: plan.window,
        };
        if id == "performance-monitoring" {
            let Some(probe) = plan.probes.into_iter().next() else {
                return Ok(Vec::new());
            };
            let mut strategies = string_values(options, "strategies")
                .into_iter()
                .filter_map(|strategy| match strategy.as_str() {
                    "mobile" => Some("mobile"),
                    "desktop" => Some("desktop"),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if strategies.is_empty() {
                strategies.extend(["mobile", "desktop"]);
            }
            return Ok(strategies
                .into_iter()
                .take(budget.max_requests)
                .map(|strategy| ProviderCall {
                    provider: probe.provider.as_str(),
                    operation: probe.operation,
                    secret_env: probe.secret_env.clone(),
                    strategy: Some(strategy),
                    controls: controls.clone(),
                })
                .collect());
        }
        return Ok(plan
            .probes
            .into_iter()
            .take(budget.max_requests)
            .map(|probe| ProviderCall {
                provider: probe.provider.as_str(),
                operation: probe.operation,
                secret_env: probe.secret_env,
                strategy: None,
                controls: controls.clone(),
            })
            .collect());
    }
    if let Some(calls) = provider_registry_calls(id, target, options) {
        return Ok(calls);
    }
    provider_intelligence_calls(id, target, options).ok_or_else(|| {
        ScanError::new(
            ScanErrorKind::DependencyUnavailable,
            "provider integration is not configured",
        )
    })
}

fn validate_secret_reference_option(
    options: &BTreeMap<String, Value>,
    key: &str,
) -> Result<(), ScanError> {
    let Some(value) = options.get(key) else {
        return Ok(());
    };
    let valid = value.as_str().is_some_and(|reference| {
        !reference.is_empty()
            && reference.len() <= 128
            && reference
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    });
    if valid {
        Ok(())
    } else {
        Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "provider credential reference is invalid",
        ))
    }
}

fn provider_call(
    provider: &'static str,
    operation: &'static str,
    secret_env: Option<&'static str>,
) -> ProviderCall {
    ProviderCall {
        provider,
        operation,
        secret_env: secret_env.map(str::to_owned),
        strategy: None,
        controls: ProviderControls::default(),
    }
}

fn provider_plan_options(
    scanner_id: &str,
    options: &BTreeMap<String, Value>,
) -> Result<ProviderPlanOptions, ScanError> {
    let mut projected = ProviderPlanOptions {
        sources: string_values(options, "sources"),
        provider: options
            .get("provider")
            .and_then(Value::as_str)
            .map(str::to_owned),
        limit: optional_usize(options, "limit"),
        status_filter: status_values(options, "status_filter")?,
        collapse_digest: boolean_value(options, "collapse_digest"),
        include_wildcard: boolean_value(options, "include_wildcard"),
        short_window: optional_u16(options, "short_window"),
        long_window: optional_u16(options, "long_window"),
        days: optional_u16(options, "days"),
        ..ProviderPlanOptions::default()
    };
    match scanner_id {
        "associated-hosts" => {
            projected
                .secret_refs
                .insert(ProviderName::Shodan, "SHODAN_API_KEY".into());
        }
        "domain-reputation-check" => {
            let virus_total = options
                .get("vt_key")
                .and_then(Value::as_str)
                .unwrap_or("VIRUSTOTAL_API_KEY");
            projected
                .secret_refs
                .insert(ProviderName::VirusTotal, virus_total.into());
            projected
                .secret_refs
                .insert(ProviderName::UrlHaus, "URLHAUS_AUTH_KEY".into());
        }
        "ip-reputation-trending" => {
            projected
                .secret_refs
                .insert(ProviderName::AbuseIpDb, "ABUSEIPDB_API_KEY".into());
        }
        "performance-monitoring" => {
            if let Some(value) = options.get("key").and_then(Value::as_str) {
                projected
                    .secret_refs
                    .insert(ProviderName::PageSpeed, value.into());
            }
        }
        "ip-info" | "network-timezone-detection" | "server-location" => {
            projected
                .secret_refs
                .insert(ProviderName::IpInfo, "IPINFO_API_KEY".into());
        }
        _ => {}
    }
    Ok(projected)
}

fn string_values(options: &BTreeMap<String, Value>, key: &str) -> Vec<String> {
    options
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn optional_usize(options: &BTreeMap<String, Value>, key: &str) -> Option<usize> {
    options
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

fn optional_u16(options: &BTreeMap<String, Value>, key: &str) -> Option<u16> {
    options
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
}

fn boolean_value(options: &BTreeMap<String, Value>, key: &str) -> bool {
    options.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn status_values(options: &BTreeMap<String, Value>, key: &str) -> Result<Vec<u16>, ScanError> {
    options
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|value| {
            value
                .as_u64()
                .and_then(|status| u16::try_from(status).ok())
                .or_else(|| Value::as_str(value).and_then(|status| status.parse().ok()))
                .ok_or_else(|| {
                    ScanError::new(
                        ScanErrorKind::InvalidInput,
                        "status filter must contain HTTP status codes",
                    )
                })
        })
        .collect()
}

fn provider_plan_error(error: &ProviderPlanError) -> ScanError {
    let message = match error {
        ProviderPlanError::UnsupportedSource(_) => "provider source is not supported",
        ProviderPlanError::UnsupportedProvider(_) => "provider selection is not supported",
        ProviderPlanError::UnsupportedTarget { .. } => {
            "provider selection does not support this target"
        }
        ProviderPlanError::InvalidStatus(_) => "status filter contains an invalid HTTP status",
        ProviderPlanError::InvalidSecretReference(_) => "provider credential reference is invalid",
        ProviderPlanError::SecretNotSupported(_) => {
            "provider operation does not accept a credential"
        }
    };
    ScanError::new(ScanErrorKind::InvalidInput, message)
}

fn provider_temporal_gap(
    scanner_id: &str,
    calls: &[ProviderCall],
    options: &BTreeMap<String, Value>,
) -> Option<Diagnostic> {
    let explicitly_requested = match scanner_id {
        "domain-shadowing-detector" => options.contains_key("days"),
        "ip-reputation-trending" => {
            options.contains_key("short_window") || options.contains_key("long_window")
        }
        _ => false,
    };
    if !explicitly_requested {
        return None;
    }
    let has_window = calls.iter().any(|call| call.controls.window.is_some());
    if !has_window {
        return None;
    }
    let message = match scanner_id {
        "domain-shadowing-detector" => {
            "certificate transparency results do not support the requested lookback filter"
        }
        "ip-reputation-trending" => {
            "configured providers do not expose two comparable historical windows"
        }
        _ => return None,
    };
    Some(Diagnostic {
        kind: "temporal-coverage-gap".into(),
        message: message.into(),
    })
}

fn provider_registry_calls(
    id: &str,
    target: &Target,
    options: &BTreeMap<String, Value>,
) -> Option<Vec<ProviderCall>> {
    match id {
        "dns-over-https" => {
            let mut providers: Vec<_> = options
                .get("providers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter_map(doh_provider)
                .collect();
            if providers.is_empty() {
                providers.extend(["cloudflare-doh", "google-doh"]);
            }
            Some(
                providers
                    .into_iter()
                    .map(|provider| provider_call(provider, "resolve", None))
                    .collect(),
            )
        }
        "rdap-lookup" | "security-contact-gap-finder" => Some(vec![provider_call(
            "rdap",
            if matches!(target, Target::Ip(_)) {
                "ip"
            } else {
                "domain"
            },
            None,
        )]),
        "bgp-route-analysis" => Some(vec![provider_call("ripestat", "bgp-state", None)]),
        "rpki-route-validity-check" if options.contains_key("asn") => {
            Some(vec![provider_call("ripestat", "rpki-validation", None)])
        }
        "rpki-route-validity-check" => Some(vec![provider_call("ripestat", "rpki-history", None)]),
        _ => None,
    }
}

fn provider_intelligence_calls(
    id: &str,
    target: &Target,
    options: &BTreeMap<String, Value>,
) -> Option<Vec<ProviderCall>> {
    match id {
        "attack-surface-delta" => Some(vec![
            provider_call("crtsh", "query", None),
            provider_call("urlscan", "search", None),
        ]),
        "subdomain-enum" | "rogue-certificate-check" => {
            Some(vec![provider_call("crtsh", "query", None)])
        }
        "reverse-ip-lookup" | "passive-dns-history" => {
            Some(vec![provider_call("urlscan", "search", None)])
        }
        "shodan" => Some(vec![provider_call(
            "shodan",
            "host",
            Some("SHODAN_API_KEY"),
        )]),
        "censys" => Some(vec![provider_call(
            "censys",
            if matches!(target, Target::Ip(_)) {
                "host"
            } else {
                "webproperty"
            },
            Some("CENSYS_API_TOKEN"),
        )]),
        "virustotal-scan" => Some(vec![provider_call(
            "virustotal",
            if matches!(target, Target::Ip(_)) {
                "ip"
            } else {
                "domain"
            },
            Some("VIRUSTOTAL_API_KEY"),
        )]),
        "breached-credentials-lookup" | "data-leak" => Some(vec![provider_call(
            "hibp",
            if matches!(target, Target::Email(_)) {
                "account"
            } else {
                "domain"
            },
            Some("HIBP_API_KEY"),
        )]),
        "dark-web-monitoring" => Some(vec![hibp_provider_call("stealer-logs-domain", options)]),
        "pastebin-monitoring" => Some(vec![hibp_provider_call("paste-account", options)]),
        "ssl-labs-report" => Some(vec![provider_call("ssllabs", "analyze", None)]),
        "global-ranking" => Some(vec![provider_call(
            "cloudflare-radar",
            "domain-ranking",
            Some("CLOUDFLARE_API_TOKEN"),
        )]),
        "ip-reputation-check" => Some(vec![
            provider_call("ripestat", "dns-blocklists", None),
            provider_call("abuseipdb", "check", Some("ABUSEIPDB_API_KEY")),
        ]),
        "threat-feed-correlator" => Some(vec![
            provider_call("virustotal", "domain", Some("VIRUSTOTAL_API_KEY")),
            provider_call("otx", "domain", Some("OTX_API_KEY")),
            provider_call("urlhaus", "host", Some("URLHAUS_AUTH_KEY")),
        ]),
        "geo-ip-spoof-detection" => Some(vec![
            provider_call("ipinfo", "lookup", Some("IPINFO_API_KEY")),
            provider_call("ripestat", "rir-geo", None),
        ]),
        value
            if value.contains("location")
                || value.contains("timezone")
                || value.contains("geo-ip") =>
        {
            Some(vec![provider_call(
                "ipinfo",
                "lookup",
                Some("IPINFO_API_KEY"),
            )])
        }
        value if value.contains("malware") || value.contains("phishing") => Some(vec![
            provider_call("virustotal", "domain", Some("VIRUSTOTAL_API_KEY")),
            provider_call("urlscan", "search", None),
            provider_call("urlhaus", "host", Some("URLHAUS_AUTH_KEY")),
        ]),
        _ => None,
    }
}

fn hibp_provider_call(operation: &'static str, options: &BTreeMap<String, Value>) -> ProviderCall {
    ProviderCall {
        provider: "hibp",
        operation,
        secret_env: Some(
            options
                .get("hibp_key")
                .and_then(Value::as_str)
                .unwrap_or("HIBP_API_KEY")
                .to_owned(),
        ),
        strategy: None,
        controls: ProviderControls::default(),
    }
}

fn provider_query(
    scanner_id: &str,
    call: &ProviderCall,
    target: &Target,
    options: &BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    let canonical = target.canonical();
    let host = provider_host(target);
    match call.provider {
        "crtsh" => {
            let query = if call.controls.include_wildcard
                || matches!(
                    scanner_id,
                    "associated-hosts" | "subdomain-enum" | "domain-shadowing-detector"
                ) {
                format!("%.{host}")
            } else {
                host
            };
            BTreeMap::from([("q".into(), Value::String(query))])
        }
        "wayback" => {
            let mut query = BTreeMap::from([
                ("url".into(), Value::String(format!("{host}/*"))),
                ("limit".into(), json!(call.controls.limit)),
            ]);
            if !call.controls.status_filter.is_empty() {
                let statuses = call
                    .controls
                    .status_filter
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join("|");
                query.insert(
                    "filter".into(),
                    Value::String(format!("statuscode:({statuses})")),
                );
            }
            if call.controls.collapse_digest {
                query.insert("collapse".into(), Value::String("digest".into()));
            }
            query
        }
        "urlscan" => {
            let field = match target {
                Target::Ip(_) | Target::Cidr(_) => "ip",
                Target::Asn(_) => "asn",
                _ => "domain",
            };
            let mut search = format!("{field}:{host}");
            if let Some(ProviderWindow::LookbackDays(days)) = call.controls.window {
                let _ = write!(search, " AND date:>now-{days}d");
            }
            let mut query = BTreeMap::from([("q".into(), Value::String(search))]);
            if call.controls.limit > 0 {
                query.insert("size".into(), json!(call.controls.limit));
            }
            query
        }
        "ripestat" if call.operation == "rpki-validation" => BTreeMap::from([
            (
                "resource".into(),
                options
                    .get("asn")
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new())),
            ),
            ("prefix".into(), Value::String(canonical)),
        ]),
        "ripestat" => BTreeMap::from([("resource".into(), Value::String(canonical))]),
        "abuseipdb" => BTreeMap::from([("ipAddress".into(), Value::String(host))]),
        "ssllabs" | "urlhaus" => BTreeMap::from([("host".into(), Value::String(host))]),
        "pagespeed" => BTreeMap::from([
            (
                "url".into(),
                Value::String(match target {
                    Target::Url(_) => canonical,
                    _ => format!("https://{host}/"),
                }),
            ),
            (
                "strategy".into(),
                Value::String(call.strategy.unwrap_or("mobile").into()),
            ),
        ]),
        "cloudflare-doh" | "google-doh" => BTreeMap::from([
            ("name".into(), Value::String(host)),
            (
                "type".into(),
                options
                    .get("qtype")
                    .cloned()
                    .unwrap_or_else(|| Value::String("A".into())),
            ),
        ]),
        "censys" if call.operation == "webproperty" => {
            BTreeMap::from([("target".into(), Value::String(format!("{host}:443")))])
        }
        _ => BTreeMap::from([("target".into(), Value::String(host))]),
    }
}

fn provider_host(target: &Target) -> String {
    match target {
        Target::Url(url) => url.host_str().unwrap_or_default().to_owned(),
        Target::HostPort { host, .. } | Target::Domain(host) => host.clone(),
        Target::Email(value) => value.clone(),
        _ => target.canonical(),
    }
}

fn provider_source(provider: &str) -> &str {
    match provider {
        "hibp" => "Have I Been Pwned (https://haveibeenpwned.com/)",
        "ripestat" => "RIPEstat (https://stat.ripe.net/)",
        "urlhaus" => "URLhaus by abuse.ch (https://urlhaus.abuse.ch/)",
        "urlscan" => "urlscan.io (https://urlscan.io/)",
        "censys" => "Censys (https://censys.com/)",
        "cloudflare-radar" => "Cloudflare Radar (https://radar.cloudflare.com/)",
        "pagespeed" => "PageSpeed Insights (https://pagespeed.web.dev/)",
        "ipinfo" => "IPinfo (https://ipinfo.io/)",
        "cloudflare-doh" => "Cloudflare DNS over HTTPS (https://cloudflare-dns.com/)",
        "google-doh" => "Google Public DNS over HTTPS (https://dns.google/)",
        other => other,
    }
}

fn analyze_provider(
    scanner_id: &str,
    provider: &str,
    observation: &Value,
    evidence: usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if scanner_id == "rpki-route-validity-check"
        && observation
            .pointer("/data/status")
            .and_then(Value::as_str)
            .is_some_and(|status| status.starts_with("invalid"))
    {
        findings.push(finding(
            "rpki-route-invalid",
            "The route origin is invalid under the observed RPKI state",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if provider == "hibp"
        && (observation
            .as_array()
            .is_some_and(|items| !items.is_empty())
            || observation
                .get("matched_accounts")
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0))
    {
        findings.push(finding(
            "breach-observation-present",
            "The configured breach source returned matching observations",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if provider == "virustotal"
        && observation
            .pointer("/data/attributes/last_analysis_stats/malicious")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
    {
        findings.push(finding(
            "malicious-engine-observation",
            "One or more reputation engines reported a malicious indicator",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if provider == "abuseipdb"
        && observation
            .pointer("/data/abuseConfidenceScore")
            .and_then(Value::as_u64)
            .is_some_and(|score| score >= 25)
    {
        findings.push(finding(
            "address-abuse-confidence",
            "The address has a material abuse-confidence score",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if provider == "urlhaus"
        && observation
            .get("urls")
            .and_then(Value::as_array)
            .is_some_and(|urls| !urls.is_empty())
    {
        findings.push(finding(
            "malware-url-observation",
            "The malware URL source returned matching observations",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if provider == "ssllabs" && has_weak_tls_grade(observation) {
        findings.push(finding(
            "external-tls-grade-risk",
            "The external TLS assessment reported a weak endpoint grade",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if provider == "pagespeed"
        && observation
            .get("performance_score")
            .and_then(Value::as_f64)
            .is_some_and(|score| score < 0.5)
    {
        findings.push(finding(
            "low-performance-score",
            "The external performance assessment reported a low score",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    findings
}

fn redact_provider_data(provider: &str, value: Value) -> Value {
    if provider != "hibp" {
        return redact_json(value);
    }
    let accounts = match value {
        Value::Object(accounts) => accounts,
        other => return redact_json(other),
    };
    let mut breaches = BTreeSet::new();
    for values in accounts.values() {
        if let Some(items) = values.as_array() {
            breaches.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    json!({
        "matched_accounts": accounts.len(),
        "breaches": breaches,
    })
}

fn has_weak_tls_grade(observation: &Value) -> bool {
    observation
        .get("endpoints")
        .and_then(Value::as_array)
        .is_some_and(|endpoints| {
            endpoints.iter().any(|endpoint| {
                endpoint
                    .get("grade")
                    .and_then(Value::as_str)
                    .is_some_and(|grade| matches!(grade, "C" | "D" | "E" | "F" | "T" | "M"))
            })
        })
}

fn tls_endpoint(target: &Target) -> Result<(String, u16), ScanError> {
    match target {
        Target::HostPort { host, port } => Ok((host.clone(), *port)),
        Target::Domain(host) => Ok((host.clone(), 443)),
        Target::Url(url) => Ok((
            url.host_str()
                .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "URL has no host"))?
                .into(),
            url.port_or_known_default().unwrap_or(443),
        )),
        Target::Ip(address) => Ok((address.to_string(), 443)),
        _ => Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "scanner requires a TLS-capable target",
        )),
    }
}

fn network_hosts(target: &Target, limit: usize) -> Result<Vec<String>, ScanError> {
    let hosts = match target {
        Target::Domain(value) => vec![value.clone()],
        Target::Ip(value) => vec![value.to_string()],
        Target::HostPort { host, .. } => vec![host.clone()],
        Target::Url(value) => value
            .host_str()
            .map(|host| vec![host.into()])
            .unwrap_or_default(),
        Target::Cidr(network) => network
            .hosts()
            .take(limit)
            .map(|address| address.to_string())
            .collect(),
        Target::Email(value) => value
            .rsplit_once('@')
            .map(|(_, host)| vec![host.into()])
            .unwrap_or_default(),
        Target::Asn(_) | Target::Opaque(_) => Vec::new(),
    };
    if hosts.is_empty() {
        Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "scanner target has no network host",
        ))
    } else {
        Ok(hosts)
    }
}

fn tcp_ports(id: &str, request: &ScanRequest) -> Vec<u16> {
    if let Some(values) = request.options.get("ports").and_then(Value::as_array) {
        let ports: BTreeSet<u16> = values
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .collect();
        if !ports.is_empty() {
            return ports.into_iter().collect();
        }
    }
    if id.contains("ssh") {
        vec![22]
    } else if id.contains("zone") {
        vec![53]
    } else if id.contains("tls") || id.contains("certificate") {
        vec![443]
    } else {
        vec![22, 53, 80, 443, 8080, 8443]
    }
}

fn tcp_payload(analyzer: Analyzer, host: &str, port: u16) -> Result<Vec<u8>, ScanError> {
    if analyzer == Analyzer::TcpDnsTransfer && port == 53 {
        dns_axfr_query(host)
    } else {
        Ok(Vec::new())
    }
}

fn tcp_reads_response(analyzer: Analyzer, port: u16) -> bool {
    analyzer == Analyzer::TcpDnsTransfer && port == 53
}

fn dns_axfr_query(name: &str) -> Result<Vec<u8>, ScanError> {
    let mut dns = vec![0x53, 0x55, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let canonical = name.trim_end_matches('.');
    for label in canonical.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ScanError::new(
                ScanErrorKind::InvalidInput,
                "zone-transfer target contains an invalid DNS label",
            ));
        }
        dns.push(
            u8::try_from(label.len()).map_err(|_| {
                ScanError::new(ScanErrorKind::InvalidInput, "DNS label is too long")
            })?,
        );
        dns.extend_from_slice(label.as_bytes());
    }
    dns.extend_from_slice(&[0, 0, 252, 0, 1]);
    let length = u16::try_from(dns.len()).map_err(|_| {
        ScanError::new(
            ScanErrorKind::InvalidInput,
            "zone-transfer query is too large",
        )
    })?;
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend(dns);
    Ok(framed)
}

fn udp_ports(id: &str, request: &ScanRequest) -> Vec<u16> {
    if let Some(values) = request.options.get("ports").and_then(Value::as_array) {
        let ports: Vec<u16> = values
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .collect();
        if !ports.is_empty() {
            return ports;
        }
    }
    if id.contains("ntp") {
        vec![123]
    } else if id.contains("snmp") {
        vec![161]
    } else if id.contains("netbios") {
        vec![137]
    } else {
        vec![53, 123, 161]
    }
}

fn udp_probe(analyzer: Analyzer, id: &str, port: u16) -> Result<UdpProbe, ScanError> {
    let probe = match analyzer {
        Analyzer::UdpNtp => UdpProbe::NtpClient,
        Analyzer::UdpSnmp if id == "snmp-bulk-walk" => UdpProbe::SnmpPublicBulk,
        Analyzer::UdpSnmp => UdpProbe::SnmpPublicGet,
        Analyzer::UdpNetbios => UdpProbe::NetbiosNodeStatus,
        Analyzer::UdpSampler => match port {
            53 => UdpProbe::DnsRootNameserver,
            123 => UdpProbe::NtpClient,
            137 => UdpProbe::NetbiosNodeStatus,
            161 => UdpProbe::SnmpPublicGet,
            _ => {
                return Err(ScanError::new(
                    ScanErrorKind::InvalidInput,
                    "UDP sampler port does not have an allowlisted protocol probe",
                ));
            }
        },
        _ => {
            return Err(ScanError::new(
                ScanErrorKind::Internal,
                "UDP analyzer does not define a protocol probe",
            ));
        }
    };
    if probe.port() != port {
        return Err(scan_error_from_network_analysis(
            NetworkAnalysisError::PortMismatch {
                expected: probe.port(),
                actual: port,
            },
        ));
    }
    Ok(probe)
}

fn command_kind(analyzer: Analyzer) -> Result<CommandKind, ScanError> {
    match analyzer {
        Analyzer::CommandReachability => Ok(CommandKind::Ping),
        Analyzer::CommandPath => Ok(CommandKind::Traceroute),
        Analyzer::CommandWhois => Ok(CommandKind::Whois),
        Analyzer::CommandSsh => Ok(CommandKind::SshKeyscan),
        _ => Err(ScanError::new(
            ScanErrorKind::Internal,
            "command analyzer does not define an allowlisted command",
        )),
    }
}

fn command_targets(target: &Target, limit: usize) -> Vec<Target> {
    match target {
        Target::Cidr(network) => network.hosts().take(limit).map(Target::Ip).collect(),
        other => vec![other.clone()],
    }
}

fn analyze_command_response(
    kind: CommandKind,
    response: &CommandResponse,
    max_response_bytes: usize,
    evidence: usize,
) -> Result<(Value, Vec<Finding>), ScanError> {
    let total_bytes = response
        .stdout
        .len()
        .checked_add(response.stderr.len())
        .ok_or_else(|| {
            ScanError::new(
                ScanErrorKind::InvalidResponse,
                "command output is too large",
            )
        })?;
    if max_response_bytes == 0 || total_bytes > max_response_bytes {
        return Err(ScanError::new(
            ScanErrorKind::InvalidResponse,
            "command output exceeds the declared byte budget",
        ));
    }
    let exit_code = response.exit_code.ok_or_else(|| {
        ScanError::new(
            ScanErrorKind::InvalidResponse,
            "command response does not contain an exit status",
        )
    })?;
    let (details, findings) = match kind {
        CommandKind::Ping => analyze_ping(response, exit_code, evidence)?,
        CommandKind::Traceroute => analyze_traceroute(response, exit_code, evidence)?,
        CommandKind::Whois => analyze_whois(response, exit_code, evidence)?,
        CommandKind::SshKeyscan => analyze_ssh(response, exit_code, evidence)?,
    };
    Ok((
        json!({
            "exit_code": exit_code,
            "stdout_bytes": response.stdout.len(),
            "stdout_sha256": hex::encode(Sha256::digest(response.stdout.as_bytes())),
            "stderr_bytes": response.stderr.len(),
            "stderr_sha256": hex::encode(Sha256::digest(response.stderr.as_bytes())),
            "details": details,
            "duration_ms": response.duration_ms,
        }),
        findings,
    ))
}

fn analyze_ping(
    response: &CommandResponse,
    exit_code: i32,
    evidence: usize,
) -> Result<(Value, Vec<Finding>), ScanError> {
    let output = response.stdout.to_ascii_lowercase();
    let reply = (output.contains("bytes from ") || output.contains("reply from "))
        && (output.contains("ttl=") || output.contains("ttl "));
    let no_reply = output.contains("0 received")
        || output.contains("100% packet loss")
        || output.contains("request timed out");
    if (exit_code == 0 && !reply) || (exit_code != 0 && !no_reply) {
        return Err(ScanError::new(
            ScanErrorKind::InvalidResponse,
            "ping output does not prove reachability or absence of replies",
        ));
    }
    let reachable = exit_code == 0;
    let key = if reachable {
        "icmp-reachable"
    } else {
        "icmp-unreachable"
    };
    Ok((
        json!({"reachable": reachable, "reply_lines": usize::from(reply)}),
        vec![finding(
            key,
            if reachable {
                "The target answered a bounded ICMP probe"
            } else {
                "The target did not answer the bounded ICMP probe"
            },
            Severity::Info,
            if reachable {
                Confidence::Confirmed
            } else {
                Confidence::Unknown
            },
            evidence,
        )],
    ))
}

fn analyze_traceroute(
    response: &CommandResponse,
    exit_code: i32,
    evidence: usize,
) -> Result<(Value, Vec<Finding>), ScanError> {
    let mut hops = 0_usize;
    let mut unanswered = 0_usize;
    for line in response.stdout.lines() {
        let trimmed = line.trim_start();
        let Some((hop, remainder)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        if !hop.parse::<u16>().is_ok_and(|hop| hop > 0) {
            continue;
        }
        let fields = remainder.split_whitespace().collect::<Vec<_>>();
        if fields.len() == 3 && fields.iter().all(|field| *field == "*") {
            hops = hops.saturating_add(1);
            unanswered = unanswered.saturating_add(1);
        } else if traceroute_answer_has_host_and_rtt(&fields) {
            hops = hops.saturating_add(1);
        }
    }
    if hops == 0 {
        return Err(ScanError::new(
            ScanErrorKind::InvalidResponse,
            "traceroute output does not contain structured hops",
        ));
    }
    Ok((
        json!({
            "hop_count": hops,
            "unanswered_hops": unanswered,
            "exit_success": exit_code == 0,
        }),
        vec![finding(
            "network-path-observed",
            "One or more bounded network-path hops were observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )],
    ))
}

fn traceroute_answer_has_host_and_rtt(fields: &[&str]) -> bool {
    let has_host = fields.iter().any(|field| {
        let candidate = field.trim_matches(['(', ')', '[', ']', ',']);
        candidate.parse::<IpAddr>().is_ok()
            || (candidate.contains('.')
                && candidate.split('.').all(|label| {
                    !label.is_empty()
                        && label.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                        })
                }))
    });
    let has_rtt = fields.windows(2).any(|pair| {
        pair[1].eq_ignore_ascii_case("ms")
            && pair[0]
                .trim_start_matches('<')
                .parse::<f64>()
                .is_ok_and(|value| value.is_finite() && value >= 0.0)
    }) || fields.iter().any(|field| {
        field
            .strip_suffix("ms")
            .and_then(|value| value.trim_start_matches('<').parse::<f64>().ok())
            .is_some_and(|value| value.is_finite() && value >= 0.0)
    });
    has_host && has_rtt
}

fn analyze_whois(
    response: &CommandResponse,
    exit_code: i32,
    evidence: usize,
) -> Result<(Value, Vec<Finding>), ScanError> {
    let fields = safe_whois_fields(&response.stdout);
    let lower = response.stdout.to_ascii_lowercase();
    let absent = ["no match", "not found", "no entries found", "no data found"]
        .iter()
        .any(|marker| lower.contains(marker));
    if fields.is_empty() && !absent {
        return Err(ScanError::new(
            ScanErrorKind::InvalidResponse,
            "WHOIS output contains neither allowlisted fields nor a not-found signal",
        ));
    }
    if !fields.is_empty() && absent {
        return Err(ScanError::new(
            ScanErrorKind::InvalidResponse,
            "WHOIS output contains conflicting registration signals",
        ));
    }
    let registered = !fields.is_empty();
    if registered && exit_code != 0 {
        return Err(ScanError::new(
            ScanErrorKind::InvalidResponse,
            "WHOIS command failed despite returning registration-like fields",
        ));
    }
    let findings = registered
        .then(|| {
            finding(
                "registration-record-observed",
                "Allowlisted public registration fields were observed",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            )
        })
        .into_iter()
        .collect();
    Ok((
        json!({"registered": registered, "fields": fields}),
        findings,
    ))
}

fn safe_whois_fields(output: &str) -> BTreeMap<String, String> {
    const ALLOWED: &[&str] = &[
        "domain name",
        "registrar",
        "creation date",
        "updated date",
        "registry expiry date",
        "domain status",
        "name server",
        "dnssec",
    ];
    output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter_map(|(key, value)| {
            let normalized = key.trim().to_ascii_lowercase();
            ALLOWED
                .contains(&normalized.as_str())
                .then(|| (normalized, value.trim().chars().take(256).collect()))
        })
        .take(64)
        .collect()
}

fn analyze_ssh(
    response: &CommandResponse,
    exit_code: i32,
    evidence: usize,
) -> Result<(Value, Vec<Finding>), ScanError> {
    let mut keys = Vec::new();
    for line in response
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3
            || !matches!(
                fields[1],
                "ssh-rsa"
                    | "ssh-ed25519"
                    | "ecdsa-sha2-nistp256"
                    | "ecdsa-sha2-nistp384"
                    | "ecdsa-sha2-nistp521"
            )
        {
            return Err(ScanError::new(
                ScanErrorKind::InvalidResponse,
                "SSH keyscan output contains an invalid host-key record",
            ));
        }
        let decoded = STANDARD.decode(fields[2]).map_err(|_| {
            ScanError::new(
                ScanErrorKind::InvalidResponse,
                "SSH keyscan output contains invalid base64 key material",
            )
        })?;
        if decoded.is_empty() {
            return Err(ScanError::new(
                ScanErrorKind::InvalidResponse,
                "SSH keyscan output contains empty key material",
            ));
        }
        if ssh_blob_key_type(&decoded) != Some(fields[1]) {
            return Err(ScanError::new(
                ScanErrorKind::InvalidResponse,
                "SSH key material does not match its declared key type",
            ));
        }
        keys.push(json!({
            "type": fields[1],
            "sha256": hex::encode(Sha256::digest(&decoded)),
        }));
        if keys.len() == 64 {
            break;
        }
    }
    let banner_hashes = response
        .stderr
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            line.starts_with('#') && line.contains(" SSH-2.0-")
        })
        .take(64)
        .map(|line| hex::encode(Sha256::digest(line.as_bytes())))
        .collect::<Vec<_>>();
    if keys.is_empty() && exit_code == 0 {
        return Err(ScanError::new(
            ScanErrorKind::InvalidResponse,
            "successful SSH keyscan output contains no valid host key",
        ));
    }
    let mut findings = Vec::new();
    if !keys.is_empty() {
        findings.push(finding(
            "ssh-host-key-observed",
            "One or more SSH host keys were observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if !banner_hashes.is_empty() {
        findings.push(finding(
            "ssh-banner-observed",
            "One or more SSH protocol banners were observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ));
    }
    Ok((
        json!({
            "key_count": keys.len(),
            "host_keys": keys,
            "banner_count": banner_hashes.len(),
            "banner_sha256": banner_hashes,
        }),
        findings,
    ))
}

fn ssh_blob_key_type(blob: &[u8]) -> Option<&str> {
    let length = blob
        .get(..4)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .and_then(|length| usize::try_from(length).ok())?;
    let end = 4_usize.checked_add(length)?;
    let key_type = std::str::from_utf8(blob.get(4..end)?).ok()?;
    (end < blob.len()).then_some(key_type)
}

fn scan_jwt(request: &ScanRequest, context: &ScanContext) -> Result<ScanResult, ScanError> {
    let Target::Opaque(token) = &request.target else {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "JWT analyzer requires an opaque token",
        ));
    };
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "JWT must contain three segments",
        ));
    }
    if token.len() > request.budget.max_response_bytes {
        return Err(ScanError::new(
            ScanErrorKind::InvalidResponse,
            "JWT exceeds the declared byte budget",
        ));
    }
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| (bytes.len() <= request.budget.max_response_bytes).then_some(bytes))
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    };
    let header = decode(parts[0])
        .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "JWT header is invalid"))?;
    let payload = decode(parts[1])
        .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "JWT payload is invalid"))?;
    let (Value::Object(header_fields), Value::Object(payload_fields)) = (&header, &payload) else {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "JWT header and payload must be JSON objects",
        ));
    };
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| {
        ScanError::new(
            ScanErrorKind::InvalidInput,
            "JWT signature encoding is invalid",
        )
    })?;
    let mut findings = Vec::new();
    let algorithm = header.get("alg").and_then(Value::as_str);
    if algorithm.is_some_and(|value| value.eq_ignore_ascii_case("none")) {
        findings.push(finding(
            "unsigned-jwt",
            "JWT declares the none algorithm",
            Severity::High,
            Confidence::Confirmed,
            0,
        ));
    }
    if algorithm.is_none() {
        findings.push(finding(
            "jwt-algorithm-missing",
            "JWT header does not declare a signing algorithm",
            Severity::Medium,
            Confidence::Confirmed,
            0,
        ));
    }
    if signature.is_empty() && algorithm.is_some_and(|value| !value.eq_ignore_ascii_case("none")) {
        findings.push(finding(
            "jwt-signature-missing",
            "JWT declares a signed algorithm but has no signature bytes",
            Severity::High,
            Confidence::Confirmed,
            0,
        ));
    }
    findings.extend(jwt_time_findings(
        &payload,
        context.clock.now().unix_timestamp(),
    ));
    let observation = jwt_structure_observation(
        parts.as_slice(),
        header_fields.len(),
        payload_fields.len(),
        &header,
        &payload,
        algorithm,
        &signature,
    );
    Ok(ScanResult::completed(
        vec![Evidence {
            kind: "jwt-structure".into(),
            source: "local-input".into(),
            observation,
            observed_at: context.clock.now(),
        }],
        findings,
    ))
}

fn jwt_structure_observation(
    parts: &[&str],
    header_fields: usize,
    claim_count: usize,
    header: &Value,
    payload: &Value,
    algorithm: Option<&str>,
    signature: &[u8],
) -> Value {
    json!({
        "algorithm": safe_jwt_algorithm(algorithm),
        "typ_is_jwt": header.get("typ").and_then(Value::as_str) == Some("JWT"),
        "header_fields": header_fields,
        "claim_count": claim_count,
        "registered_claims": {
            "iss": payload.get("iss").is_some(),
            "sub": payload.get("sub").is_some(),
            "aud": payload.get("aud").is_some(),
            "exp": payload.get("exp").is_some(),
            "nbf": payload.get("nbf").is_some(),
            "iat": payload.get("iat").is_some(),
            "jti": payload.get("jti").is_some(),
        },
        "header_sha256": hex::encode(Sha256::digest(parts[0].as_bytes())),
        "payload_sha256": hex::encode(Sha256::digest(parts[1].as_bytes())),
        "signature_bytes": signature.len(),
        "signature_sha256": hex::encode(Sha256::digest(signature)),
        "signature_verified": false,
    })
}

fn safe_jwt_algorithm(algorithm: Option<&str>) -> &'static str {
    match algorithm.map(str::to_ascii_uppercase).as_deref() {
        Some("NONE") => "none",
        Some("HS256") => "HS256",
        Some("HS384") => "HS384",
        Some("HS512") => "HS512",
        Some("RS256") => "RS256",
        Some("RS384") => "RS384",
        Some("RS512") => "RS512",
        Some("ES256") => "ES256",
        Some("ES384") => "ES384",
        Some("ES512") => "ES512",
        Some("PS256") => "PS256",
        Some("PS384") => "PS384",
        Some("PS512") => "PS512",
        Some("EDDSA") => "EdDSA",
        Some(_) => "other",
        None => "missing",
    }
}

fn jwt_time_findings(payload: &Value, now: i64) -> Vec<Finding> {
    let mut findings = Vec::new();
    match payload.get("exp") {
        Some(value) if value.as_i64().is_none() => findings.push(finding(
            "jwt-expiration-invalid",
            "The JWT expiration claim is not an integer timestamp",
            Severity::Medium,
            Confidence::Confirmed,
            0,
        )),
        Some(value) if value.as_i64().is_some_and(|expiry| expiry <= now) => {
            findings.push(finding(
                "jwt-expired",
                "The JWT expiration time is in the past",
                Severity::Medium,
                Confidence::Confirmed,
                0,
            ));
        }
        Some(_) => {}
        None => findings.push(finding(
            "jwt-expiration-missing",
            "The JWT does not declare an expiration time",
            Severity::Low,
            Confidence::Confirmed,
            0,
        )),
    }
    if payload
        .get("nbf")
        .and_then(Value::as_i64)
        .is_some_and(|not_before| not_before > now)
    {
        findings.push(finding(
            "jwt-not-active",
            "The JWT is not active yet",
            Severity::Info,
            Confidence::Confirmed,
            0,
        ));
    }
    if payload
        .get("iat")
        .and_then(Value::as_i64)
        .is_some_and(|issued_at| issued_at > now.saturating_add(300))
    {
        findings.push(finding(
            "jwt-issued-in-future",
            "The JWT issue time is unexpectedly in the future",
            Severity::Medium,
            Confidence::Confirmed,
            0,
        ));
    }
    findings
}

fn wordlist(value: &str) -> Vec<String> {
    let base = value
        .split(['.', '-', '_'])
        .filter(|part| part.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let mut values = BTreeSet::new();
    for token in base {
        values.insert(token.clone());
        for suffix in ["admin", "api", "dev", "prod", "staging", "www"] {
            values.insert(format!("{token}-{suffix}"));
            values.insert(format!("{suffix}-{token}"));
        }
    }
    values.into_iter().take(256).collect()
}

fn millis(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn network_result(
    evidence: Vec<Evidence>,
    findings: Vec<Finding>,
    diagnostics: Vec<Diagnostic>,
) -> Result<ScanResult, ScanError> {
    if evidence.is_empty() {
        let message = diagnostics
            .first()
            .map_or("no network endpoint responded", |diagnostic| {
                diagnostic.message.as_str()
            });
        Err(ScanError::new(ScanErrorKind::Transport, message))
    } else {
        Ok(ScanResult {
            status: if diagnostics.is_empty() {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Partial
            },
            findings,
            evidence,
            diagnostics,
        })
    }
}

fn network_result_with_error(
    evidence: Vec<Evidence>,
    findings: Vec<Finding>,
    diagnostics: Vec<Diagnostic>,
    first_error: Option<ScanError>,
) -> Result<ScanResult, ScanError> {
    if evidence.is_empty() {
        Err(first_error.unwrap_or_else(|| {
            ScanError::new(ScanErrorKind::Transport, "no network endpoint responded")
        }))
    } else {
        Ok(ScanResult {
            status: completion_status(&diagnostics),
            findings,
            evidence,
            diagnostics,
        })
    }
}

fn cancelled_network_result(
    evidence: Vec<Evidence>,
    findings: Vec<Finding>,
    mut diagnostics: Vec<Diagnostic>,
) -> ScanResult {
    diagnostics.push(Diagnostic {
        kind: "cancelled".into(),
        message: "remaining network probes were cancelled".into(),
    });
    ScanResult {
        status: ExecutionStatus::Cancelled,
        findings,
        evidence,
        diagnostics,
    }
}

fn push_network_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    host: &str,
    port: u16,
    error: &PortError,
) {
    diagnostics.push(Diagnostic {
        kind: format!("{:?}", error.kind).to_ascii_lowercase(),
        message: format!("{host}:{port}: {}", error.message),
    });
}

fn usize_option(options: &BTreeMap<String, Value>, key: &str, fallback: usize) -> usize {
    options
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(fallback)
}

fn host_limit(request: &ScanRequest) -> usize {
    usize_option(&request.options, "max_hosts", request.budget.max_requests)
        .min(request.budget.max_requests)
}

fn finding(
    key: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    evidence: usize,
) -> Finding {
    Finding {
        key: key.into(),
        title: title.into(),
        severity,
        confidence,
        evidence: vec![evidence],
    }
}

fn scan_error_from_port(error: PortError) -> ScanError {
    let kind = match error.kind {
        PortErrorKind::Unavailable => ScanErrorKind::DependencyUnavailable,
        PortErrorKind::Timeout | PortErrorKind::RateLimited => ScanErrorKind::Timeout,
        PortErrorKind::OutOfScope => ScanErrorKind::PolicyDenied,
        PortErrorKind::InvalidResponse | PortErrorKind::TooLarge => ScanErrorKind::InvalidResponse,
        PortErrorKind::Transport => ScanErrorKind::Transport,
        PortErrorKind::Internal => ScanErrorKind::Internal,
    };
    ScanError::new(kind, error.message)
}

fn scan_error_from_network_analysis(error: NetworkAnalysisError) -> ScanError {
    let kind = match error {
        NetworkAnalysisError::Ipv4Target
        | NetworkAnalysisError::UnsupportedTarget
        | NetworkAnalysisError::Ipv4Connection
        | NetworkAnalysisError::ConnectedAddressNotResolved
        | NetworkAnalysisError::ConnectedAddressDoesNotMatchTarget
        | NetworkAnalysisError::PortMismatch { .. }
        | NetworkAnalysisError::InvalidResponseBudget => ScanErrorKind::InvalidInput,
        NetworkAnalysisError::ResponseTooLarge
        | NetworkAnalysisError::TruncatedResponse
        | NetworkAnalysisError::InvalidProtocolResponse => ScanErrorKind::InvalidResponse,
    };
    ScanError::new(kind, error.to_string())
}

fn scan_error_from_tls_analysis(error: TlsAnalysisError) -> ScanError {
    let kind = match error {
        TlsAnalysisError::MissingBaseline | TlsAnalysisError::InvalidBaselineSha256 => {
            ScanErrorKind::InvalidInput
        }
        TlsAnalysisError::InvalidObservedSha256 => ScanErrorKind::InvalidResponse,
    };
    ScanError::new(kind, error.to_string())
}

fn scan_error_from_tls_semantic(error: TlsSemanticError) -> ScanError {
    ScanError::new(ScanErrorKind::InvalidResponse, error.to_string())
}

fn redact_json(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let sensitive = [
                        "password",
                        "secret",
                        "token",
                        "email",
                        "authorization",
                        "key",
                    ]
                    .iter()
                    .any(|marker| key.to_ascii_lowercase().contains(marker));
                    (
                        key,
                        if sensitive {
                            Value::String("<redacted>".into())
                        } else {
                            redact_json(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::json;
    use sugra_core::{
        Clock, CommandPort, CommandResponse, DnsPort, DnsQuery, DnsRecord, DnsRecordType, HttpPort,
        HttpRequest, HttpResponse, LocalInputPort, LocalInputRequest, LocalInputResponse,
        PortError, ProviderPort, ProviderRequest, ProviderResponse, TcpPort, TcpRequest,
        TcpResponse, TlsCertificate, TlsHandshakeKind, TlsObservation, TlsPort, TlsRequest,
        UdpPort, UdpRequest, UdpResponse,
    };
    use sugra_domain::{Budget, ScanRequest, ScopeGrant, ScopeRule, Target, TargetKind};
    use time::OffsetDateTime;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    struct FakeDns;
    #[async_trait]
    impl DnsPort for FakeDns {
        async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
            let record_type = query
                .record_types
                .first()
                .copied()
                .unwrap_or(DnsRecordType::A);
            Ok(vec![DnsRecord {
                name: query.name,
                record_type,
                value: if record_type == DnsRecordType::Aaaa {
                    "2001:db8::1".into()
                } else {
                    "192.0.2.1".into()
                },
                ttl: Some(300),
            }])
        }
    }

    struct FakeHttp;
    #[async_trait]
    impl HttpPort for FakeHttp {
        async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
            Ok(HttpResponse {
                final_url: request.url,
                status: 200,
                headers: BTreeMap::from([
                    ("content-type".into(), "text/html".into()),
                    (
                        "content-security-policy".into(),
                        "default-src 'self'".into(),
                    ),
                    (
                        "strict-transport-security".into(),
                        "max-age=31536000".into(),
                    ),
                    ("x-content-type-options".into(), "nosniff".into()),
                ]),
                cookies: Vec::new(),
                redirects: Vec::new(),
                body: b"<html><title>Fixture</title><a href='/next'>Next</a></html>".to_vec(),
                duration_ms: 1,
            })
        }
    }

    #[test]
    fn link_discovery_never_leaves_scope_and_requires_subdomain_opt_in()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Url::parse("https://example.com/")?;
        let scope = ScopeGrant::new(
            vec![ScopeRule::Domain("example.com".into())],
            true,
            "tests",
            OffsetDateTime::UNIX_EPOCH,
        )?;
        let body = br#"
            <a href="/same-origin">same</a>
            <a href="https://api.example.com/scoped">subdomain</a>
            <script src="https://outside.example/script.js"></script>
        "#;

        let exact = discover_links(&root, &root, body, &scope, false);
        assert_eq!(exact, vec![Url::parse("https://example.com/same-origin")?]);

        let subdomains = discover_links(&root, &root, body, &scope, true);
        assert_eq!(
            subdomains,
            vec![
                Url::parse("https://example.com/same-origin")?,
                Url::parse("https://api.example.com/scoped")?,
            ]
        );
        assert!(
            subdomains
                .iter()
                .all(|url| !url.as_str().contains("outside.example"))
        );
        Ok(())
    }

    struct FakeTcp;
    #[async_trait]
    impl TcpPort for FakeTcp {
        async fn execute(&self, request: TcpRequest) -> Result<TcpResponse, PortError> {
            let bytes = if request.port == 53 && request.read_response {
                fake_axfr_response(&request.payload)
            } else {
                b"fixture-banner".to_vec()
            };
            Ok(TcpResponse {
                endpoint: if request.host.contains(':') {
                    format!("[{}]:{}", request.host, request.port)
                } else {
                    format!("{}:{}", request.host, request.port)
                },
                bytes,
                duration_ms: 1,
            })
        }
    }

    fn fake_axfr_response(query: &[u8]) -> Vec<u8> {
        let Some(transaction) = query.get(2..4) else {
            return Vec::new();
        };
        let Some(question) = query.get(14..) else {
            return Vec::new();
        };
        let mut message = vec![
            transaction[0],
            transaction[1],
            0x81,
            0x80,
            0,
            1,
            0,
            2,
            0,
            0,
            0,
            0,
        ];
        message.extend_from_slice(question);
        for _ in 0..2 {
            message.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 1, 44, 0, 22]);
            message.extend_from_slice(&[0_u8; 22]);
        }
        let Ok(length) = u16::try_from(message.len()) else {
            return Vec::new();
        };
        let mut framed = length.to_be_bytes().to_vec();
        framed.extend(message);
        framed
    }

    struct FakeUdp;
    #[async_trait]
    impl UdpPort for FakeUdp {
        async fn execute(&self, request: UdpRequest) -> Result<UdpResponse, PortError> {
            let bytes = match request.port {
                53 => {
                    let mut response = vec![0_u8; 12];
                    response[..2].copy_from_slice(&request.payload[..2]);
                    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
                    response
                }
                123 => {
                    let mut response = vec![0_u8; 48];
                    response[0] = 0x24;
                    response[1] = 2;
                    response[24..32].copy_from_slice(&request.payload[40..48]);
                    response
                }
                137 => {
                    let mut response = vec![0_u8; 12];
                    response[..2].copy_from_slice(&request.payload[..2]);
                    response[2..4].copy_from_slice(&0x8000_u16.to_be_bytes());
                    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
                    response
                }
                161 => {
                    let mut response = request.payload.clone();
                    if let Some(index) = response
                        .iter()
                        .rposition(|byte| matches!(byte, 0xa0 | 0xa5))
                    {
                        response[index] = 0xa2;
                    }
                    response
                }
                _ => Vec::new(),
            };
            Ok(UdpResponse {
                endpoint: format!("{}:{}", request.host, request.port),
                bytes,
                duration_ms: 1,
            })
        }
    }

    struct FakeTls;
    #[async_trait]
    impl TlsPort for FakeTls {
        async fn handshake(&self, _request: TlsRequest) -> Result<TlsObservation, PortError> {
            Ok(TlsObservation {
                handshake_kind: TlsHandshakeKind::Full,
                protocol: "TLSv1_3".into(),
                cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
                alpn: Some("h2".into()),
                certificate_sha256: vec!["00".repeat(32)],
                certificates: Vec::new(),
                duration_ms: 1,
            })
        }
    }

    struct FakeProvider;
    #[async_trait]
    impl ProviderPort for FakeProvider {
        async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
            Ok(ProviderResponse {
                provider: request.provider,
                data: json!({"fixture": true}),
                duration_ms: 1,
            })
        }
    }

    struct FakeCommand;
    #[async_trait]
    impl CommandPort for FakeCommand {
        async fn execute(&self, request: CommandRequest) -> Result<CommandResponse, PortError> {
            let (stdout, stderr) = match request.kind {
                CommandKind::Ping => ("64 bytes from 192.0.2.1: ttl=52 time=1 ms", ""),
                CommandKind::Traceroute => (
                    "traceroute to 192.0.2.1, 30 hops max\n 1 192.0.2.1 1 ms",
                    "",
                ),
                CommandKind::Whois => ("Domain Name: EXAMPLE.COM", ""),
                CommandKind::SshKeyscan => (
                    "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx",
                    "# example.com:22 SSH-2.0-OpenSSH_fixture",
                ),
            };
            Ok(CommandResponse {
                exit_code: Some(0),
                stdout: stdout.into(),
                stderr: stderr.into(),
                duration_ms: 1,
            })
        }
    }

    struct FakeLocalInput;
    #[async_trait]
    impl LocalInputPort for FakeLocalInput {
        async fn read_lines(
            &self,
            _request: LocalInputRequest,
        ) -> Result<LocalInputResponse, PortError> {
            Ok(LocalInputResponse { lines: Vec::new() })
        }
    }

    struct StaticLocalInput(Vec<String>);

    #[async_trait]
    impl LocalInputPort for StaticLocalInput {
        async fn read_lines(
            &self,
            _request: LocalInputRequest,
        ) -> Result<LocalInputResponse, PortError> {
            Ok(LocalInputResponse {
                lines: self.0.clone(),
            })
        }
    }

    struct FailingLocalInput;

    #[async_trait]
    impl LocalInputPort for FailingLocalInput {
        async fn read_lines(
            &self,
            _request: LocalInputRequest,
        ) -> Result<LocalInputResponse, PortError> {
            Err(PortError::new(
                PortErrorKind::Unavailable,
                "local input is unavailable",
            ))
        }
    }

    #[tokio::test]
    async fn local_path_file_lines_merge_with_explicit_paths_without_exceeding_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let options = BTreeMap::from([
            ("paths".into(), json!(["/explicit"])),
            ("paths_file".into(), json!("/operator/paths.txt")),
        ]);
        let budget = Budget {
            max_requests: 3,
            ..Budget::DEFAULT
        };

        let hydrated = hydrate_web_options(
            "login-page-brute-identifier",
            &options,
            budget,
            &StaticLocalInput(vec![
                "/from-file".into(),
                "/third".into(),
                "/ignored".into(),
            ]),
        )
        .await?;

        assert_eq!(
            hydrated.get("paths"),
            Some(&json!(["/explicit", "/from-file", "/third"]))
        );
        Ok(())
    }

    #[tokio::test]
    async fn wordlist_and_parameter_files_map_to_in_memory_planner_options()
    -> Result<(), Box<dyn std::error::Error>> {
        for (scanner_id, source_key, destination_key) in [
            ("directory-finder", "wordlist", "wordlist"),
            ("hidden-parameter-discovery", "params_file", "params"),
        ] {
            let options = BTreeMap::from([(
                source_key.into(),
                json!(format!("/operator/{source_key}.txt")),
            )]);
            let hydrated = hydrate_web_options(
                scanner_id,
                &options,
                Budget::DEFAULT,
                &StaticLocalInput(vec!["from-file".into()]),
            )
            .await?;
            assert_eq!(hydrated.get(destination_key), Some(&json!(["from-file"])));
        }
        Ok(())
    }

    #[tokio::test]
    async fn absent_file_options_skip_the_boundary_and_failures_remain_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        let untouched = BTreeMap::from([("paths".into(), json!(["/login"]))]);
        let hydrated = hydrate_web_options(
            "login-page-brute-identifier",
            &untouched,
            Budget::DEFAULT,
            &FailingLocalInput,
        )
        .await?;
        assert_eq!(hydrated, untouched);

        let sensitive_path = "/operator/private/customer-paths.txt";
        let options = BTreeMap::from([("paths_file".into(), json!(sensitive_path))]);
        let result = hydrate_web_options(
            "login-page-brute-identifier",
            &options,
            Budget::DEFAULT,
            &FailingLocalInput,
        )
        .await;
        let Err(error) = result else {
            return Err("local input failure must propagate".into());
        };
        assert_eq!(error.kind, ScanErrorKind::DependencyUnavailable);
        assert_eq!(error.message, "local input is unavailable");
        assert!(!error.message.contains(sensitive_path));
        Ok(())
    }

    #[tokio::test]
    async fn directory_scanner_consumes_wordlist_lines_through_the_injected_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut scanner_services = services();
        scanner_services.local_input = Arc::new(StaticLocalInput(vec![
            "from-file".into(),
            "https://outside.example/private".into(),
        ]));
        let builtins = build_builtins(&scanner_services)?;
        let descriptor = builtins
            .catalog
            .iter()
            .find(|descriptor| descriptor.id.as_str() == "directory-finder")
            .ok_or("directory scanner is missing")?;
        let scanner = builtins
            .registry
            .get(&descriptor.id)
            .ok_or("directory implementation is missing")?;
        let target = Target::parse(TargetKind::Url, "https://example.com/")?;
        let request = ScanRequest {
            scanner_id: descriptor.id.clone(),
            target: target.clone(),
            options: BTreeMap::from([("wordlist".into(), json!("/operator/wordlist.txt"))]),
            budget: Budget {
                max_requests: 2,
                ..Budget::DEFAULT
            },
            scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
        };
        let context = ScanContext {
            run_id: sugra_domain::RunId::new(),
            cancellation: CancellationToken::new(),
            clock: Arc::new(FixedClock),
        };

        let result = scanner.scan(&request, &context).await?;

        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].source, "https://example.com/from-file");
        assert!(
            result
                .evidence
                .iter()
                .all(|evidence| !evidence.source.contains("outside.example"))
        );
        Ok(())
    }

    fn services() -> ServiceBundle {
        ServiceBundle {
            dns: Arc::new(FakeDns),
            http: Arc::new(FakeHttp),
            tcp: Arc::new(FakeTcp),
            udp: Arc::new(FakeUdp),
            tls: Arc::new(FakeTls),
            command: Arc::new(FakeCommand),
            provider: Arc::new(FakeProvider),
            local_input: Arc::new(FakeLocalInput),
            clock: Arc::new(FixedClock),
        }
    }

    fn target_for(kind: TargetKind, id: &str) -> Result<Target, Box<dyn std::error::Error>> {
        let target = match kind {
            TargetKind::Domain => Target::parse(kind, "example.com")?,
            TargetKind::Ip => Target::parse(kind, "192.0.2.10")?,
            TargetKind::Cidr => Target::parse(kind, "192.0.2.0/30")?,
            TargetKind::Url => Target::parse(kind, "https://example.com/")?,
            TargetKind::HostPort => Target::parse(kind, "example.com:443")?,
            TargetKind::Asn => Target::parse(kind, "AS64496")?,
            TargetKind::Email => Target::parse(kind, "security@example.com")?,
            TargetKind::Opaque if id == "jwt-token-analyzer" => Target::parse(
                kind,
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl",
            )?,
            TargetKind::Opaque => Target::parse(kind, "example-fixture")?,
        };
        Ok(target)
    }

    fn tls_observation(certificate: Option<TlsCertificate>) -> TlsObservation {
        TlsObservation {
            handshake_kind: TlsHandshakeKind::Full,
            protocol: "TLSv1_3".into(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
            alpn: Some("h2".into()),
            certificate_sha256: vec!["00".repeat(32)],
            certificates: certificate.into_iter().collect(),
            duration_ms: 1,
        }
    }

    fn tls_certificate(not_before: i64, not_after: i64) -> TlsCertificate {
        TlsCertificate {
            sha256: "00".repeat(32),
            subject: "CN=example.com".into(),
            issuer: "CN=Fixture CA".into(),
            serial: "01".into(),
            not_before,
            not_after,
            dns_names: vec!["example.com".into()],
            signature_algorithm: "1.2.840.113549.1.1.11".into(),
            public_key_algorithm: "1.2.840.113549.1.1.1".into(),
            is_ca: Some(false),
        }
    }

    #[test]
    fn tls_expiry_analysis_distinguishes_expired_and_expiring_certificates()
    -> Result<(), Box<dyn std::error::Error>> {
        let expired = tls_observation(Some(tls_certificate(-10_000, -1)));
        let expired_findings =
            analyze_tls_observation("ssl-expiry", Analyzer::TlsExpiry, &expired, 0)?;
        assert_eq!(expired_findings[0].key, "tls-certificate-expired");
        assert_eq!(expired_findings[0].severity, Severity::Critical);

        let expiring = tls_observation(Some(tls_certificate(-10_000, 6 * 86_400)));
        let expiring_findings =
            analyze_tls_observation("ssl-expiry", Analyzer::TlsExpiry, &expiring, 0)?;
        assert_eq!(expiring_findings[0].key, "tls-certificate-expiring");
        assert_eq!(expiring_findings[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn tls_chain_analysis_flags_a_ca_leaf() -> Result<(), Box<dyn std::error::Error>> {
        let mut certificate = tls_certificate(-10_000, 365 * 86_400);
        certificate.is_ca = Some(true);
        let findings = analyze_tls_observation(
            "ssl-chain",
            Analyzer::TlsChain,
            &tls_observation(Some(certificate)),
            0,
        )?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.key == "tls-leaf-is-ca")
        );
        Ok(())
    }

    #[test]
    fn tls_cipher_analysis_flags_obsolete_protocols_and_weak_suites()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut observation = tls_observation(None);
        observation.protocol = "TLSv1_0".into();
        observation.cipher_suite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into();
        let findings =
            analyze_tls_observation("tls-security-config", Analyzer::TlsCipher, &observation, 0)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.key == "tls-obsolete-protocol")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.key == "tls-weak-cipher")
        );
        Ok(())
    }

    #[tokio::test]
    async fn tls_pinning_runtime_requires_and_compares_an_explicit_baseline()
    -> Result<(), Box<dyn std::error::Error>> {
        let builtins = build_builtins(&services())?;
        let descriptor = builtins
            .catalog
            .iter()
            .find(|descriptor| descriptor.id.as_str() == "ssl-pinning-check")
            .ok_or("missing TLS pinning descriptor")?;
        assert!(descriptor.options[0].required);
        let scanner = builtins
            .registry
            .get(&descriptor.id)
            .ok_or("missing TLS pinning scanner")?;
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let context = ScanContext {
            run_id: sugra_domain::RunId::new(),
            cancellation: CancellationToken::new(),
            clock: Arc::new(FixedClock),
        };

        let request = |baseline: Option<Value>| ScanRequest {
            scanner_id: descriptor.id.clone(),
            scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
            target: target.clone(),
            options: baseline
                .map(|baseline| BTreeMap::from([("baseline_sha256".into(), baseline)]))
                .unwrap_or_default(),
            budget: Budget::DEFAULT,
        };
        let matching = scanner
            .scan(&request(Some(json!("00".repeat(32)))), &context)
            .await?;
        assert!(matching.findings.is_empty());

        let mismatch = scanner
            .scan(&request(Some(json!("ff".repeat(32)))), &context)
            .await?;
        assert_eq!(mismatch.findings[0].key, "tls-pinning-baseline-mismatch");

        let Err(missing) = scanner.scan(&request(None), &context).await else {
            return Err("missing baseline must fail".into());
        };
        assert_eq!(missing.kind, ScanErrorKind::InvalidInput);
        let Err(malformed) = scanner
            .scan(&request(Some(json!("not-a-fingerprint"))), &context)
            .await
        else {
            return Err("malformed baseline must fail".into());
        };
        assert_eq!(malformed.kind, ScanErrorKind::InvalidInput);
        assert!(!malformed.message.contains("not-a-fingerprint"));
        Ok(())
    }

    #[test]
    fn mail_policy_plans_query_each_validated_dkim_selector()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let request = ScanRequest {
            scanner_id: sugra_domain::ScannerId::new("email-config")?,
            scope: ScopeGrant::exact(&target, false, OffsetDateTime::UNIX_EPOCH),
            target: target.clone(),
            options: BTreeMap::from([("selectors".into(), json!(["google", "default"]))]),
            budget: Budget::DEFAULT,
        };
        let plan = dns_query_plan("email-config", &target, &request)?;
        let names = plan
            .iter()
            .map(|query| query.name.as_str())
            .collect::<BTreeSet<_>>();
        assert!(names.contains("google._domainkey.example.com"));
        assert!(names.contains("default._domainkey.example.com"));

        let mut invalid = request;
        invalid
            .options
            .insert("selectors".into(), json!(["Sensitive.Value"]));
        let Err(error) = dns_query_plan("email-config", &target, &invalid) else {
            return Err("invalid selector must fail".into());
        };
        assert_eq!(error.kind, ScanErrorKind::InvalidInput);
        assert!(!error.message.contains("Sensitive.Value"));
        Ok(())
    }

    #[test]
    fn decoy_dns_runtime_rejects_unrelated_and_malformed_answers() {
        let query = DnsPlannedQuery {
            name: "_sugra-decoy-beacon.example.com".into(),
            record_types: vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname],
        };
        let mut findings = Vec::new();
        analyze_dns(
            "decoy-dns-beacon",
            Some("example.com"),
            &query,
            &[
                DnsRecord {
                    name: "other.example".into(),
                    record_type: DnsRecordType::A,
                    value: "192.0.2.20".into(),
                    ttl: Some(300),
                },
                DnsRecord {
                    name: query.name.clone(),
                    record_type: DnsRecordType::Txt,
                    value: "192.0.2.20".into(),
                    ttl: Some(300),
                },
                DnsRecord {
                    name: query.name.clone(),
                    record_type: DnsRecordType::A,
                    value: "not-an-address".into(),
                    ttl: Some(300),
                },
            ],
            0,
            &mut findings,
        );
        assert!(findings.is_empty());

        analyze_dns(
            "decoy-dns-beacon",
            Some("example.com"),
            &query,
            &[DnsRecord {
                name: query.name.clone(),
                record_type: DnsRecordType::A,
                value: "192.0.2.20".into(),
                ttl: Some(300),
            }],
            1,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].key, "decoy-probe-answer-observed");
        assert_eq!(findings[0].evidence, [1]);
    }

    #[tokio::test]
    async fn ipv6_and_udp_runtime_use_protocol_specific_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let builtins = build_builtins(&services())?;
        let context = ScanContext {
            run_id: sugra_domain::RunId::new(),
            cancellation: CancellationToken::new(),
            clock: Arc::new(FixedClock),
        };
        for id in [
            "ipv6-reachability-test",
            "ntp-info-leak-checker",
            "snmp-public-community-checker",
            "udp-service-sampler",
            "netbios-name-query",
            "snmp-bulk-walk",
        ] {
            let descriptor = builtins
                .catalog
                .iter()
                .find(|descriptor| descriptor.id.as_str() == id)
                .ok_or_else(|| format!("missing descriptor {id}"))?;
            let scanner = builtins
                .registry
                .get(&descriptor.id)
                .ok_or_else(|| format!("missing scanner {id}"))?;
            let target = Target::parse(TargetKind::Domain, "example.com")?;
            let result = scanner
                .scan(
                    &ScanRequest {
                        scanner_id: descriptor.id.clone(),
                        scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
                        target,
                        options: BTreeMap::new(),
                        budget: Budget::DEFAULT,
                    },
                    &context,
                )
                .await?;
            assert!(!result.evidence.is_empty(), "{id} returned no evidence");
            assert!(
                !result.findings.is_empty(),
                "{id} returned no protocol signal"
            );
            assert!(
                result.evidence.iter().all(|evidence| {
                    evidence.kind.contains("ipv6") || evidence.kind.contains("udp")
                }),
                "{id} returned a generic boundary observation"
            );
        }
        Ok(())
    }

    #[test]
    fn every_provider_scanner_has_an_explicit_provider_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let builtins = build_builtins(&services())?;
        let mut provider_scanners = 0;
        for descriptor in builtins.catalog.iter() {
            let profile = profile_for(descriptor.id.as_str())
                .ok_or_else(|| format!("missing semantic profile for {}", descriptor.id))?;
            if profile.analyzer.family() != BoundaryFamily::Provider {
                continue;
            }
            provider_scanners += 1;
            let target = target_for(descriptor.target_kinds[0], descriptor.id.as_str())?;
            let calls = provider_calls(
                descriptor.id.as_str(),
                &target,
                &BTreeMap::new(),
                Budget::DEFAULT,
            )?;
            assert!(!calls.is_empty(), "{} has no provider plan", descriptor.id);
            assert!(
                calls
                    .iter()
                    .all(|call| !call.provider.starts_with("configured-")),
                "{} fell through to a fictitious provider",
                descriptor.id
            );
        }
        assert_eq!(provider_scanners, 37);
        Ok(())
    }

    #[test]
    fn lawful_monitoring_scanners_use_explicit_hibp_operations()
    -> Result<(), Box<dyn std::error::Error>> {
        let domain = Target::parse(TargetKind::Domain, "example.com")?;
        let dark = provider_calls(
            "dark-web-monitoring",
            &domain,
            &BTreeMap::from([("hibp_key".into(), json!("CUSTOM_HIBP_KEY"))]),
            Budget::DEFAULT,
        )?;
        assert_eq!(dark.len(), 1);
        assert_eq!(dark[0].provider, "hibp");
        assert_eq!(dark[0].operation, "stealer-logs-domain");
        assert_eq!(dark[0].secret_env.as_deref(), Some("CUSTOM_HIBP_KEY"));

        let email = Target::parse(TargetKind::Email, "security@example.com")?;
        let pastes = provider_calls(
            "pastebin-monitoring",
            &email,
            &BTreeMap::new(),
            Budget::DEFAULT,
        )?;
        assert_eq!(pastes.len(), 1);
        assert_eq!(pastes[0].provider, "hibp");
        assert_eq!(pastes[0].operation, "paste-account");
        assert_eq!(pastes[0].secret_env.as_deref(), Some("HIBP_API_KEY"));
        Ok(())
    }

    #[test]
    fn rpki_provider_query_keeps_asn_and_prefix_separate() -> Result<(), Box<dyn std::error::Error>>
    {
        let target = Target::parse(TargetKind::Cidr, "192.0.2.0/24")?;
        let call = ProviderCall {
            provider: "ripestat",
            operation: "rpki-validation",
            secret_env: None,
            strategy: None,
            controls: ProviderControls::default(),
        };
        let query = provider_query(
            "rpki-route-validity-check",
            &call,
            &target,
            &BTreeMap::from([("asn".into(), json!("64496"))]),
        );
        assert_eq!(query.get("resource"), Some(&json!("64496")));
        assert_eq!(query.get("prefix"), Some(&json!("192.0.2.0/24")));
        Ok(())
    }

    #[test]
    fn archive_provider_query_applies_limit_status_and_digest_controls()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Url, "https://example.com/path")?;
        let options = BTreeMap::from([
            ("limit".into(), json!(25)),
            ("status_filter".into(), json!([200, 301])),
            ("collapse_digest".into(), json!(true)),
        ]);
        let calls = provider_calls("archive-history", &target, &options, Budget::DEFAULT)?;
        let call = calls.first().ok_or("archive provider call is missing")?;
        let query = provider_query("archive-history", call, &target, &options);

        assert_eq!(query.get("limit"), Some(&json!(25)));
        assert_eq!(query.get("filter"), Some(&json!("statuscode:(200|301)")));
        assert_eq!(query.get("collapse"), Some(&json!("digest")));
        assert_eq!(query.get("url"), Some(&json!("example.com/*")));
        Ok(())
    }

    #[test]
    fn ct_wildcard_and_urlscan_window_are_projected_without_fake_ripe_parameters()
    -> Result<(), Box<dyn std::error::Error>> {
        let domain = Target::parse(TargetKind::Domain, "example.com")?;
        let ct_options = BTreeMap::from([("include_wildcard".into(), json!(true))]);
        let ct_calls = provider_calls("ct-log-query", &domain, &ct_options, Budget::DEFAULT)?;
        let ct_query = provider_query("ct-log-query", &ct_calls[0], &domain, &ct_options);
        assert_eq!(
            ct_query,
            BTreeMap::from([("q".into(), json!("%.example.com"))])
        );

        let shadow_options = BTreeMap::from([("days".into(), json!(14))]);
        let budget = Budget {
            max_requests: 7,
            ..Budget::DEFAULT
        };
        let shadow_calls = provider_calls(
            "domain-shadowing-detector",
            &domain,
            &shadow_options,
            budget,
        )?;
        let default_shadow_calls = provider_calls(
            "domain-shadowing-detector",
            &domain,
            &BTreeMap::new(),
            Budget::DEFAULT,
        )?;
        assert!(
            provider_temporal_gap(
                "domain-shadowing-detector",
                &default_shadow_calls,
                &BTreeMap::new(),
            )
            .is_none()
        );
        let urlscan = shadow_calls
            .iter()
            .find(|call| call.provider == "urlscan")
            .ok_or("urlscan call is missing")?;
        let urlscan_query = provider_query(
            "domain-shadowing-detector",
            urlscan,
            &domain,
            &shadow_options,
        );
        assert_eq!(
            urlscan_query.get("q"),
            Some(&json!("domain:example.com AND date:>now-14d"))
        );
        assert_eq!(urlscan_query.get("size"), Some(&json!(7)));

        let ip = Target::parse(TargetKind::Ip, "192.0.2.10")?;
        let trend_options = BTreeMap::from([
            ("short_window".into(), json!(7)),
            ("long_window".into(), json!(30)),
        ]);
        let trend_calls = provider_calls(
            "ip-reputation-trending",
            &ip,
            &trend_options,
            Budget::DEFAULT,
        )?;
        let default_trend_calls = provider_calls(
            "ip-reputation-trending",
            &ip,
            &BTreeMap::new(),
            Budget::DEFAULT,
        )?;
        assert!(
            provider_temporal_gap(
                "ip-reputation-trending",
                &default_trend_calls,
                &BTreeMap::new(),
            )
            .is_none()
        );
        let ripe = trend_calls
            .iter()
            .find(|call| call.provider == "ripestat")
            .ok_or("RIPEstat call is missing")?;
        assert_eq!(
            provider_query("ip-reputation-trending", ripe, &ip, &trend_options),
            BTreeMap::from([("resource".into(), json!("192.0.2.10"))])
        );
        let gap = provider_temporal_gap("ip-reputation-trending", &trend_calls, &trend_options)
            .ok_or("temporal coverage gap is missing")?;
        assert_eq!(gap.kind, "temporal-coverage-gap");
        assert!(!gap.message.contains("192.0.2.10"));
        Ok(())
    }

    #[test]
    fn provider_selection_operations_secrets_and_budget_are_enforced()
    -> Result<(), Box<dyn std::error::Error>> {
        let ip = Target::parse(TargetKind::Ip, "192.0.2.10")?;
        let associated = provider_calls(
            "associated-hosts",
            &ip,
            &BTreeMap::from([("sources".into(), json!(["shodan", "passive_dns"]))]),
            Budget {
                max_requests: 1,
                ..Budget::DEFAULT
            },
        )?;
        assert_eq!(associated.len(), 1);
        assert_eq!(associated[0].provider, "shodan");
        assert_eq!(associated[0].operation, "host");
        assert_eq!(associated[0].secret_env.as_deref(), Some("SHODAN_API_KEY"));

        let registry = provider_calls(
            "asn-lookup",
            &ip,
            &BTreeMap::from([("provider".into(), json!("both"))]),
            Budget {
                max_requests: 2,
                ..Budget::DEFAULT
            },
        )?;
        assert_eq!(
            registry
                .iter()
                .map(|call| (call.provider, call.operation, call.secret_env.as_deref()))
                .collect::<Vec<_>>(),
            vec![("rdap", "ip", None), ("ripestat", "network-info", None)]
        );

        let archive = Target::parse(TargetKind::Domain, "example.com")?;
        let archive_calls = provider_calls(
            "archive-history",
            &archive,
            &BTreeMap::from([("limit".into(), json!(1_000))]),
            Budget {
                max_requests: 3,
                ..Budget::DEFAULT
            },
        )?;
        let query = provider_query(
            "archive-history",
            &archive_calls[0],
            &archive,
            &BTreeMap::new(),
        );
        assert_eq!(query.get("limit"), Some(&json!(3)));
        Ok(())
    }

    #[test]
    fn invalid_provider_options_fail_without_echoing_raw_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let domain = Target::parse(TargetKind::Domain, "example.com")?;
        let raw_source = "private-provider-token";
        let source_result = provider_calls(
            "associated-hosts",
            &domain,
            &BTreeMap::from([("sources".into(), json!([raw_source]))]),
            Budget::DEFAULT,
        );
        let Err(source_error) = source_result else {
            return Err("unsupported provider source must fail".into());
        };
        assert_eq!(source_error.kind, ScanErrorKind::InvalidInput);
        assert!(!source_error.message.contains(raw_source));

        let raw_secret = "not-a-secret-reference";
        let secret_result = provider_calls(
            "domain-reputation-check",
            &domain,
            &BTreeMap::from([("vt_key".into(), json!(raw_secret))]),
            Budget::DEFAULT,
        );
        let Err(secret_error) = secret_result else {
            return Err("invalid provider secret reference must fail".into());
        };
        assert_eq!(secret_error.kind, ScanErrorKind::InvalidInput);
        assert!(!secret_error.message.contains(raw_secret));

        for raw_hibp in [json!("invalid-secret-reference"), json!(42)] {
            let hibp_result = provider_calls(
                "dark-web-monitoring",
                &domain,
                &BTreeMap::from([("hibp_key".into(), raw_hibp)]),
                Budget::DEFAULT,
            );
            let Err(hibp_error) = hibp_result else {
                return Err("invalid HIBP secret reference must fail".into());
            };
            assert_eq!(hibp_error.kind, ScanErrorKind::InvalidInput);
            assert_eq!(
                hibp_error.message,
                "provider credential reference is invalid"
            );
        }
        Ok(())
    }

    #[test]
    fn encrypted_dns_plan_uses_only_allowlisted_providers_and_qtypes()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let options = BTreeMap::from([
            (
                "providers".into(),
                json!(["google", "unconfigured", "cloudflare"]),
            ),
            ("qtype".into(), json!("AAAA")),
        ]);
        let calls = provider_calls("dns-over-https", &target, &options, Budget::DEFAULT)?;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].provider, "google-doh");
        assert_eq!(calls[1].provider, "cloudflare-doh");
        for call in calls {
            let query = provider_query("dns-over-https", &call, &target, &options);
            assert_eq!(query.get("name"), Some(&json!("example.com")));
            assert_eq!(query.get("type"), Some(&json!("AAAA")));
        }
        assert!(
            validate_scanner_controls(
                "dns-over-https",
                &BTreeMap::from([("qtype".into(), json!("unsupported"))]),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn provider_analysis_reports_confirmed_security_signals() {
        let rpki = analyze_provider(
            "rpki-route-validity-check",
            "ripestat",
            &json!({"data": {"status": "invalid_asn"}}),
            0,
        );
        assert_eq!(rpki[0].key, "rpki-route-invalid");
        assert_eq!(rpki[0].severity, Severity::High);

        let reputation = analyze_provider(
            "virustotal-scan",
            "virustotal",
            &json!({"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}),
            0,
        );
        assert_eq!(reputation[0].key, "malicious-engine-observation");

        let redacted = redact_provider_data(
            "hibp",
            json!({"alice": ["FixtureBreach"], "bob": ["OtherBreach"]}),
        );
        assert_eq!(redacted.get("matched_accounts"), Some(&json!(2)));
        assert!(!redacted.to_string().contains("alice"));
        assert!(!redacted.to_string().contains("bob"));
    }

    #[test]
    fn pagespeed_plan_honors_strategies_and_secret_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Url, "https://example.com/path")?;
        let options = BTreeMap::from([
            ("key".into(), json!("GOOGLE_API_KEY")),
            ("strategies".into(), json!(["desktop"])),
        ]);
        let calls = provider_calls("performance-monitoring", &target, &options, Budget::DEFAULT)?;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].provider, "pagespeed");
        assert_eq!(calls[0].secret_env.as_deref(), Some("GOOGLE_API_KEY"));
        let query = provider_query("performance-monitoring", &calls[0], &target, &options);
        assert_eq!(query.get("url"), Some(&json!("https://example.com/path")));
        assert_eq!(query.get("strategy"), Some(&json!("desktop")));

        let defaults = provider_calls(
            "performance-monitoring",
            &target,
            &BTreeMap::new(),
            Budget::DEFAULT,
        )?;
        assert_eq!(
            defaults
                .iter()
                .filter_map(|call| call.strategy)
                .collect::<Vec<_>>(),
            vec!["mobile", "desktop"]
        );
        assert!(defaults.iter().all(|call| call.secret_env.is_none()));
        Ok(())
    }

    #[test]
    fn pagespeed_controls_reject_tls_bypass_and_unknown_strategies() {
        assert!(
            validate_scanner_controls(
                "performance-monitoring",
                &BTreeMap::from([("verify_ssl".into(), json!(false))]),
            )
            .is_err()
        );
        assert!(
            validate_scanner_controls(
                "performance-monitoring",
                &BTreeMap::from([("strategies".into(), json!(["tablet"]))]),
            )
            .is_err()
        );
        assert!(
            validate_scanner_controls(
                "performance-monitoring",
                &BTreeMap::from([
                    ("verify_ssl".into(), json!(true)),
                    ("strategies".into(), json!(["mobile", "desktop"])),
                ]),
            )
            .is_ok()
        );
    }

    #[test]
    fn pagespeed_analysis_distinguishes_low_and_healthy_scores() {
        let low = analyze_provider(
            "performance-monitoring",
            "pagespeed",
            &json!({"performance_score": 0.32}),
            0,
        );
        assert_eq!(low[0].key, "low-performance-score");
        assert_eq!(low[0].severity, Severity::Medium);
        assert!(
            analyze_provider(
                "performance-monitoring",
                "pagespeed",
                &json!({"performance_score": 0.9}),
                0,
            )
            .is_empty()
        );
        assert!(
            analyze_provider(
                "performance-monitoring",
                "pagespeed",
                &json!({"performance_score": null}),
                0,
            )
            .is_empty()
        );
    }

    #[test]
    fn axfr_query_is_framed() -> Result<(), Box<dyn std::error::Error>> {
        let query = dns_axfr_query("example.com")?;
        assert_eq!(
            usize::from(u16::from_be_bytes([query[0], query[1]])),
            query.len() - 2
        );
        assert_eq!(&query[2..4], &[0x53, 0x55]);
        assert_eq!(&query[query.len() - 4..query.len() - 2], &[0, 252]);

        Ok(())
    }

    #[test]
    fn jwt_time_analysis_reports_expiry_activation_and_clock_skew() {
        let findings = jwt_time_findings(&json!({"exp": 99, "nbf": 200, "iat": 500}), 100);
        let keys: BTreeSet<_> = findings
            .iter()
            .map(|finding| finding.key.as_str())
            .collect();
        assert!(keys.contains("jwt-expired"));
        assert!(keys.contains("jwt-not-active"));
        assert!(keys.contains("jwt-issued-in-future"));
    }

    #[test]
    fn command_metadata_omits_raw_host_keys_and_whois_contacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let ssh = CommandResponse {
            exit_code: Some(0),
            stdout: "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx".into(),
            stderr: String::new(),
            duration_ms: 1,
        };
        let (ssh_value, _) = analyze_command_response(CommandKind::SshKeyscan, &ssh, 1_024, 0)?;
        let ssh_value = ssh_value.to_string();
        assert!(
            !ssh_value
                .contains("AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx")
        );
        assert!(ssh_value.contains("ssh-ed25519"));

        let whois = safe_whois_fields(
            "Domain Name: EXAMPLE.COM\nRegistrar: Fixture\nRegistrant Email: person@example.com",
        );
        assert_eq!(
            whois.get("domain name").map(String::as_str),
            Some("EXAMPLE.COM")
        );
        assert!(!whois.contains_key("registrant email"));
        Ok(())
    }

    #[test]
    fn cidr_command_targets_respect_the_host_limit() -> Result<(), Box<dyn std::error::Error>> {
        let cidr = Target::parse(TargetKind::Cidr, "192.0.2.0/24")?;
        let targets = command_targets(&cidr, 3);
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|target| matches!(target, Target::Ip(_))));
        Ok(())
    }

    #[test]
    fn typo_candidates_are_deterministic_bounded_and_domain_preserving() {
        let candidates = typo_candidates("example.com", 7);
        assert_eq!(candidates.len(), 7);
        assert_eq!(candidates.iter().collect::<BTreeSet<_>>().len(), 7);
        assert!(candidates.iter().all(|candidate| {
            candidate
                .rsplit_once('.')
                .is_some_and(|(_, tld)| tld == "com")
        }));
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate == "example.com")
        );
        assert_eq!(typo_candidates("example.com", 2).len(), 2);
    }

    #[tokio::test]
    async fn every_built_in_has_an_offline_functional_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let builtins = build_builtins(&services())?;
        assert_eq!(builtins.catalog.len(), 147);
        assert_eq!(builtins.registry.len(), 147);
        for descriptor in builtins.catalog.iter() {
            let scanner = builtins
                .registry
                .get(&descriptor.id)
                .ok_or_else(|| format!("missing implementation for {}", descriptor.id))?;
            let target = target_for(descriptor.target_kinds[0], descriptor.id.as_str())?;
            let options = if descriptor.id.as_str() == "ssl-pinning-check" {
                BTreeMap::from([("baseline_sha256".into(), json!("00".repeat(32)))])
            } else {
                BTreeMap::new()
            };
            let request = ScanRequest {
                scanner_id: descriptor.id.clone(),
                scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
                target,
                options,
                budget: Budget {
                    max_requests: 4,
                    ..Budget::default()
                },
            };
            let context = ScanContext {
                run_id: sugra_domain::RunId::new(),
                cancellation: CancellationToken::new(),
                clock: Arc::new(FixedClock),
            };
            let result = scanner
                .scan(&request, &context)
                .await
                .map_err(|error| format!("{} failed its fixture: {error}", descriptor.id))?;
            assert!(
                !result.evidence.is_empty(),
                "{} returned no fixture evidence",
                descriptor.id
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn composite_scanners_merge_typed_evidence_with_one_shared_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let builtins = build_builtins(&services())?;
        let descriptor = builtins
            .catalog
            .iter()
            .find(|descriptor| descriptor.id.as_str() == "attack-surface-delta")
            .ok_or("missing composite descriptor")?;
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let scanner = builtins
            .registry
            .get(&descriptor.id)
            .ok_or("missing composite scanner")?;
        let context = ScanContext {
            run_id: sugra_domain::RunId::new(),
            cancellation: CancellationToken::new(),
            clock: Arc::new(FixedClock),
        };
        let request = ScanRequest {
            scanner_id: descriptor.id.clone(),
            scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
            target: target.clone(),
            options: BTreeMap::new(),
            budget: Budget {
                max_requests: 4,
                ..Budget::default()
            },
        };
        let result = scanner.scan(&request, &context).await?;
        let analyses: BTreeSet<_> = result
            .evidence
            .iter()
            .filter_map(|evidence| evidence.observation.get("analysis"))
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            analyses,
            BTreeSet::from([
                "asset-source-analysis",
                "dns-topology-analysis",
                "tcp-port-analysis",
                "web-change-analysis",
            ])
        );
        assert!(result.evidence.len() <= request.budget.max_requests);

        let limited = ScanRequest {
            budget: Budget {
                max_requests: 1,
                ..request.budget
            },
            ..request
        };
        let result = scanner.scan(&limited, &context).await?;
        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.status, ExecutionStatus::Partial);
        assert_eq!(
            result
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.kind == "budget-exhausted")
                .count(),
            3
        );
        Ok(())
    }

    #[test]
    fn catalog_has_unique_complete_compatibility_mapping() -> Result<(), Box<dyn std::error::Error>>
    {
        let builtins = build_builtins(&services())?;
        let legacy: BTreeSet<_> = builtins
            .catalog
            .iter()
            .filter_map(|descriptor| descriptor.legacy_id)
            .collect();
        assert_eq!(legacy.len(), 147);
        Ok(())
    }
}
