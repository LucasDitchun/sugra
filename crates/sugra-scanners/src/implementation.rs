//! Capability-oriented implementations shared by the 147 compiled descriptors.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use scraper::{Html, Selector};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sugra_core::{
    Catalog, CommandKind, CommandRequest, CommandResponse, DnsQuery, DnsRecord, DnsRecordType,
    HttpMethod, HttpRequest, PortError, PortErrorKind, ProviderRequest, ScanContext, ScanError,
    ScanErrorKind, Scanner, ScannerRegistry, ServiceBundle, TcpRequest, TlsHandshakeKind,
    TlsObservation, TlsRequest, UdpRequest,
};
use sugra_domain::{
    Confidence, Diagnostic, Evidence, ExecutionStatus, Finding, ScanRequest, ScanResult,
    ScannerDescriptor, Severity, Target, TargetKind,
};
use url::Url;

use crate::catalog_data::definitions;
use crate::definition::{BuiltinError, Builtins, Operation, ScannerDefinition};
use crate::semantics::{Analyzer, BoundaryFamily, SemanticProfile, profile_for};

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
        if context.cancellation.is_cancelled() {
            return Err(ScanError::new(ScanErrorKind::Cancelled, "scan cancelled"));
        }
        let result = match self.profile.analyzer.family() {
            BoundaryFamily::Dns => self.scan_dns(request, context).await,
            BoundaryFamily::Http => self.scan_http(request, context).await,
            BoundaryFamily::Tls => self.scan_tls(request, context).await,
            BoundaryFamily::Provider => self.scan_providers(request, context).await,
            BoundaryFamily::Tcp => self.scan_tcp(request, context).await,
            BoundaryFamily::Udp => self.scan_udp(request, context).await,
            BoundaryFamily::Command => self.scan_command(request, context).await,
            BoundaryFamily::Local => self.scan_local(request, context),
        }?;
        Ok(self.annotate_result(result))
    }
}

impl BuiltinScanner {
    fn annotate_result(&self, mut result: ScanResult) -> ScanResult {
        for evidence in &mut result.evidence {
            evidence.kind = format!("{}-{}", self.profile.id, evidence.kind);
            let prior = std::mem::take(&mut evidence.observation);
            evidence.observation = json!({
                "scanner_id": self.profile.id,
                "analysis": self.profile.analyzer.as_str(),
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
        if id == "dns-over-https" {
            return self.scan_doh(request, context).await;
        }
        let plan = dns_query_plan(id, &request.target, request)?;
        let mut evidence = Vec::new();
        let mut diagnostics = Vec::new();
        let mut findings = Vec::new();
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
                    analyze_dns(id, &query, &records, index, &mut findings);
                    evidence.push(Evidence {
                        kind: "dns-records".into(),
                        source: query.name,
                        observation: json!({
                            "requested_types": query.record_types,
                            "records": records,
                            "duration_ms": millis(started.elapsed().as_millis()),
                        }),
                        observed_at: context.clock.now(),
                    });
                }
                Err(error) => diagnostics.push(Diagnostic {
                    kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                    message: format!("{}: {}", query.name, error.message),
                }),
            }
        }
        if evidence.is_empty() {
            let message = diagnostics
                .first()
                .map_or("all DNS observations failed", |value| {
                    value.message.as_str()
                });
            return Err(ScanError::new(ScanErrorKind::Transport, message));
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

    async fn scan_doh(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let name = dns_name(&request.target)?;
        let qtype = request
            .options
            .get("qtype")
            .and_then(Value::as_str)
            .unwrap_or("A");
        let providers = request
            .options
            .get("providers")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(doh_provider)
                    .collect::<Vec<_>>()
            })
            .filter(|items| !items.is_empty())
            .unwrap_or_else(|| vec!["cloudflare-doh", "google-doh"]);
        let mut evidence = Vec::new();
        let mut diagnostics = Vec::new();
        for provider in providers.into_iter().take(request.budget.max_requests) {
            let response = self
                .services
                .provider
                .query(ProviderRequest {
                    provider: provider.into(),
                    operation: "resolve".into(),
                    query: BTreeMap::from([
                        ("name".into(), Value::String(name.clone())),
                        ("type".into(), Value::String(qtype.into())),
                    ]),
                    secret_env: None,
                    budget: request.budget,
                })
                .await;
            match response {
                Ok(response) => evidence.push(Evidence {
                    kind: "dns-over-https".into(),
                    source: response.provider,
                    observation: redact_json(response.data),
                    observed_at: context.clock.now(),
                }),
                Err(error) => diagnostics.push(Diagnostic {
                    kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                    message: error.message,
                }),
            }
        }
        if evidence.is_empty() {
            let message = diagnostics
                .first()
                .map_or("all DNS-over-HTTPS providers failed", |value| {
                    value.message.as_str()
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
            findings: Vec::new(),
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
        let mut queue: VecDeque<Url> = http_paths(id)
            .into_iter()
            .filter_map(|path| base.join(path).ok())
            .collect();
        let methods = http_methods(id);
        let mut seen = BTreeSet::new();
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        let crawl = is_crawler(id);

        while let Some(url) = queue.pop_front() {
            if evidence.len() >= request.budget.max_requests
                || !seen.insert(url.as_str().to_owned())
            {
                continue;
            }
            for method in &methods {
                if evidence.len() >= request.budget.max_requests {
                    break;
                }
                let mut headers = BTreeMap::new();
                if id == "cors-misconfiguration-scanner" {
                    headers.insert("origin".into(), "https://scope-check.invalid".into());
                }
                let response = self
                    .services
                    .http
                    .execute(HttpRequest {
                        url: url.clone(),
                        method: *method,
                        headers,
                        body: Vec::new(),
                        max_redirects: if id == "redirect-chain" { 10 } else { 3 },
                        budget: request.budget,
                        scope: request.scope.clone(),
                    })
                    .await;
                match response {
                    Ok(response) => {
                        let index = evidence.len();
                        let metrics = document_metrics(&response.body);
                        analyze_http(id, &response, &metrics, index, &mut findings);
                        if crawl && *method == HttpMethod::Get {
                            enqueue_links(
                                &response.final_url,
                                &response.body,
                                &request.scope,
                                &mut queue,
                            );
                        }
                        evidence.push(Evidence {
                            kind: "http-observation".into(),
                            source: response.final_url.as_str().into(),
                            observation: json!({
                                "method": format!("{method:?}").to_ascii_uppercase(),
                                "status": response.status,
                                "headers": response.headers,
                                "bytes": response.body.len(),
                                "sha256": hex::encode(Sha256::digest(&response.body)),
                                "document": metrics,
                                "duration_ms": response.duration_ms,
                            }),
                            observed_at: context.clock.now(),
                        });
                    }
                    Err(error) => diagnostics.push(Diagnostic {
                        kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                        message: error.message,
                    }),
                }
            }
        }
        if evidence.is_empty() {
            let first = diagnostics
                .first()
                .map_or("HTTP observation failed", |diagnostic| {
                    diagnostic.message.as_str()
                });
            return Err(ScanError::new(ScanErrorKind::Transport, first));
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

    async fn scan_tls(
        &self,
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
        let findings = analyze_tls(
            self.profile.analyzer,
            &observation,
            context.clock.now().unix_timestamp(),
        );
        Ok(ScanResult::completed(
            vec![Evidence {
                kind: "tls-handshake".into(),
                source: format!("{host}:{port}"),
                observation: serde_json::to_value(observation).map_err(|_| {
                    ScanError::new(
                        ScanErrorKind::Internal,
                        "TLS observation serialization failed",
                    )
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
        let calls = provider_calls(
            self.descriptor.id.as_str(),
            &request.target,
            &request.options,
        );
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        for call in calls {
            let response = self
                .services
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
                    secret_env: call.secret_env.map(str::to_owned),
                    budget: request.budget,
                })
                .await;
            match response {
                Ok(response) => {
                    let observation = redact_provider_data(&response.provider, response.data);
                    findings.extend(analyze_provider(
                        self.descriptor.id.as_str(),
                        &response.provider,
                        &observation,
                        evidence.len(),
                    ));
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

    async fn scan_tcp(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        if matches!(
            self.profile.analyzer,
            Analyzer::TcpCertificate | Analyzer::TcpTlsState
        ) {
            return self.scan_network_tls(request, context).await;
        }
        let targets = network_hosts(&request.target, host_limit(request))?;
        let ports = tcp_ports(self.descriptor.id.as_str(), request);
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
                let response = self
                    .services
                    .tcp
                    .execute(TcpRequest {
                        host: host.clone(),
                        port: *port,
                        payload: tcp_payload(self.profile.analyzer, &host, *port)?,
                        read_response: tcp_reads_response(self.profile.analyzer, *port),
                        budget: request.budget,
                        scope: request.scope.clone(),
                    })
                    .await;
                match response {
                    Ok(response) => {
                        let index = evidence.len();
                        let transfer_accepted = self.profile.analyzer == Analyzer::TcpDnsTransfer
                            && dns_transfer_accepted(&response.bytes);
                        if transfer_accepted {
                            findings.push(finding(
                                "dns-zone-transfer-accepted",
                                "The authoritative server returned zone-transfer records",
                                Severity::High,
                                Confidence::Confirmed,
                                index,
                            ));
                        } else if matches!(
                            self.profile.analyzer,
                            Analyzer::TcpPorts | Analyzer::TcpRange
                        ) {
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
                            source: response.endpoint,
                            observation: json!({
                                "state": "open",
                                "bytes": response.bytes.len(),
                                "sha256": hex::encode(Sha256::digest(&response.bytes)),
                                "transfer_accepted": transfer_accepted,
                                "duration_ms": response.duration_ms,
                            }),
                            observed_at: context.clock.now(),
                        });
                    }
                    Err(error)
                        if matches!(
                            self.profile.analyzer,
                            Analyzer::TcpPorts | Analyzer::TcpRange
                        ) && matches!(
                            error.kind,
                            PortErrorKind::Transport | PortErrorKind::Timeout
                        ) =>
                    {
                        evidence.push(Evidence {
                            kind: "tcp-observation".into(),
                            source: format!("{host}:{port}"),
                            observation: json!({
                                "state": if error.kind == PortErrorKind::Timeout {
                                    "filtered-or-unreachable"
                                } else {
                                    "closed-or-unreachable"
                                },
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

    async fn scan_network_tls(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let targets = network_hosts(&request.target, host_limit(request))?;
        let ports = tcp_ports(self.descriptor.id.as_str(), request);
        let samples = if self.profile.analyzer == Analyzer::TcpTlsState {
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
        let mut resumed = false;
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
                            resumed |= observation.handshake_kind == TlsHandshakeKind::Resumed;
                            if self.profile.analyzer == Analyzer::TcpCertificate {
                                let now = context.clock.now().unix_timestamp();
                                let mut observed = analyze_tls_chain(&observation);
                                observed.extend(analyze_tls_expiry(&observation, now));
                                reindex_findings(&mut observed, index);
                                findings.extend(observed);
                            }
                            evidence.push(Evidence {
                                kind: "network-tls-observation".into(),
                                source: format!("{host}:{port}"),
                                observation: serde_json::to_value(observation).map_err(|_| {
                                    ScanError::new(
                                        ScanErrorKind::Internal,
                                        "TLS observation serialization failed",
                                    )
                                })?,
                                observed_at: context.clock.now(),
                            });
                        }
                        Err(error) => {
                            push_network_diagnostic(&mut diagnostics, &host, *port, &error);
                        }
                    }
                }
            }
        }
        if self.profile.analyzer == Analyzer::TcpTlsState && !evidence.is_empty() && !resumed {
            findings.push(Finding {
                key: "tls-session-not-resumed".into(),
                title: "No TLS session resumption was observed in the bounded sample".into(),
                severity: Severity::Info,
                confidence: Confidence::Unknown,
                evidence: (0..evidence.len()).collect(),
            });
        }
        network_result(evidence, findings, diagnostics)
    }

    async fn scan_udp(
        &self,
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
                let response = self
                    .services
                    .udp
                    .execute(UdpRequest {
                        host: host.clone(),
                        port: *port,
                        payload: udp_payload(
                            self.profile.analyzer,
                            self.descriptor.id.as_str(),
                            *port,
                        )?,
                        budget: request.budget,
                        scope: request.scope.clone(),
                    })
                    .await;
                match response {
                    Ok(response) => {
                        let index = evidence.len();
                        findings.extend(analyze_udp_response(
                            self.profile.analyzer,
                            &response.bytes,
                            index,
                        ));
                        evidence.push(Evidence {
                            kind: "udp-observation".into(),
                            source: response.endpoint,
                            observation: json!({
                                "responded": true,
                                "bytes": response.bytes.len(),
                                "sha256": hex::encode(Sha256::digest(&response.bytes)),
                                "protocol": udp_observation(self.profile.analyzer, &response.bytes),
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
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let kind = command_kind(self.descriptor.id.as_str());
        let targets = command_targets(&request.target, host_limit(request));
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        for target in targets.into_iter().take(request.budget.max_requests) {
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
                    findings.extend(analyze_command(kind, &response, index));
                    evidence.push(Evidence {
                        kind: "platform-command".into(),
                        source: format!("{kind:?}:{source}"),
                        observation: command_observation(kind, &response),
                        observed_at: context.clock.now(),
                    });
                }
                Err(error) => diagnostics.push(Diagnostic {
                    kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                    message: format!("{source}: {}", error.message),
                }),
            }
        }
        network_result(evidence, findings, diagnostics)
    }

    fn scan_local(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let id = self.descriptor.id.as_str();
        if id == "jwt-token-analyzer" {
            return scan_jwt(request, context);
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

fn analyze_tls(analyzer: Analyzer, observation: &TlsObservation, now: i64) -> Vec<Finding> {
    match analyzer {
        Analyzer::TlsHandshake => analyze_tls_handshake(observation),
        Analyzer::TlsChain => analyze_tls_chain(observation),
        Analyzer::TlsExpiry => analyze_tls_expiry(observation, now),
        Analyzer::TlsCipher => analyze_tls_cipher(observation),
        Analyzer::TlsProtocol => analyze_tls_protocol(observation),
        Analyzer::TlsPinning => analyze_tls_pinning(observation),
        _ => Vec::new(),
    }
}

fn analyze_tls_handshake(observation: &TlsObservation) -> Vec<Finding> {
    if observation.protocol == "unknown" || observation.cipher_suite == "unknown" {
        vec![finding(
            "tls-negotiation-incomplete",
            "TLS negotiation metadata is incomplete",
            Severity::Medium,
            Confidence::Confirmed,
            0,
        )]
    } else {
        Vec::new()
    }
}

fn analyze_tls_chain(observation: &TlsObservation) -> Vec<Finding> {
    match observation.certificates.first() {
        None => vec![finding(
            "tls-chain-metadata-unavailable",
            "The peer certificate chain could not be inspected",
            Severity::Medium,
            Confidence::Confirmed,
            0,
        )],
        Some(leaf) => {
            let mut findings = Vec::new();
            if leaf.is_ca == Some(true) {
                findings.push(finding(
                    "tls-leaf-is-ca",
                    "The TLS leaf certificate is marked as a certificate authority",
                    Severity::High,
                    Confidence::Confirmed,
                    0,
                ));
            }
            if leaf.subject == leaf.issuer {
                findings.push(finding(
                    "tls-self-issued-leaf",
                    "The TLS leaf certificate is self-issued",
                    Severity::Medium,
                    Confidence::Confirmed,
                    0,
                ));
            }
            findings
        }
    }
}

fn analyze_tls_expiry(observation: &TlsObservation, now: i64) -> Vec<Finding> {
    match observation.certificates.first() {
        None => vec![finding(
            "tls-validity-metadata-unavailable",
            "Certificate validity metadata is unavailable",
            Severity::Medium,
            Confidence::Confirmed,
            0,
        )],
        Some(leaf) if now < leaf.not_before => vec![finding(
            "tls-certificate-not-yet-valid",
            "The TLS certificate is not yet valid",
            Severity::High,
            Confidence::Confirmed,
            0,
        )],
        Some(leaf) if now >= leaf.not_after => vec![finding(
            "tls-certificate-expired",
            "The TLS certificate has expired",
            Severity::Critical,
            Confidence::Confirmed,
            0,
        )],
        Some(leaf) => {
            let days = (leaf.not_after - now) / 86_400;
            let risk = if days <= 7 {
                Some((Severity::High, "The TLS certificate expires within 7 days"))
            } else if days <= 30 {
                Some((
                    Severity::Medium,
                    "The TLS certificate expires within 30 days",
                ))
            } else if days <= 90 {
                Some((Severity::Low, "The TLS certificate expires within 90 days"))
            } else {
                None
            };
            risk.map_or_else(Vec::new, |(severity, title)| {
                vec![finding(
                    "tls-certificate-expiring",
                    title,
                    severity,
                    Confidence::Confirmed,
                    0,
                )]
            })
        }
    }
}

fn analyze_tls_cipher(observation: &TlsObservation) -> Vec<Finding> {
    let protocol = observation.protocol.to_ascii_lowercase();
    let cipher = observation.cipher_suite.to_ascii_lowercase();
    let mut findings = Vec::new();
    if protocol.contains("tlsv1_0") || protocol.contains("tlsv1_1") {
        findings.push(finding(
            "tls-obsolete-protocol",
            "An obsolete TLS protocol version was negotiated",
            Severity::High,
            Confidence::Confirmed,
            0,
        ));
    } else if protocol.contains("tlsv1_2") {
        findings.push(finding(
            "tls-modernization",
            "TLS 1.2 was negotiated; verify TLS 1.3 availability",
            Severity::Info,
            Confidence::Confirmed,
            0,
        ));
    }
    if ["rc4", "3des", "des_cbc", "null", "export"]
        .iter()
        .any(|marker| cipher.contains(marker))
    {
        findings.push(finding(
            "tls-weak-cipher",
            "A weak TLS cipher suite was negotiated",
            Severity::High,
            Confidence::Confirmed,
            0,
        ));
    }
    findings
}

fn analyze_tls_protocol(observation: &TlsObservation) -> Vec<Finding> {
    if observation.alpn.as_deref() == Some("h2") {
        Vec::new()
    } else {
        vec![finding(
            "http2-not-negotiated",
            "HTTP/2 was not negotiated over TLS",
            Severity::Info,
            Confidence::Confirmed,
            0,
        )]
    }
}

fn analyze_tls_pinning(observation: &TlsObservation) -> Vec<Finding> {
    if observation.certificate_sha256.is_empty() {
        vec![finding(
            "tls-pinning-material-unavailable",
            "No certificate fingerprint is available for pinning review",
            Severity::Medium,
            Confidence::Confirmed,
            0,
        )]
    } else {
        Vec::new()
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
        "spf-dkim-dmarc-validator" => vec![
            query(name.clone(), vec![DnsRecordType::Txt]),
            query(format!("_dmarc.{name}"), vec![DnsRecordType::Txt]),
            query(
                format!("default._domainkey.{name}"),
                vec![DnsRecordType::Txt],
            ),
        ],
        "email-config" => vec![
            query(
                name.clone(),
                vec![DnsRecordType::Mx, DnsRecordType::Txt, DnsRecordType::Caa],
            ),
            query(format!("_dmarc.{name}"), vec![DnsRecordType::Txt]),
        ],
        "rogue-subdomain-resolver" | "subdomain-takeover" | "decoy-dns-beacon" => vec![
            query(
                name.clone(),
                vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname],
            ),
            query(
                format!("_sugra-scope-probe.{name}"),
                vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname],
            ),
        ],
        _ => vec![query(name, dns_types(id, request))],
    };
    Ok(plan)
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
    query: &DnsPlannedQuery,
    records: &[DnsRecord],
    evidence: usize,
    findings: &mut Vec<Finding>,
) {
    let missing = records.is_empty();
    match id {
        "dnssec" if missing => findings.push(finding(
            "dnssec-not-observed",
            "DNSSEC material was not observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        )),
        "dns-caa-checker" if missing => findings.push(finding(
            "caa-not-observed",
            "No CAA policy was observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        )),
        "reverse-dns-scan" if missing => findings.push(finding(
            "ptr-not-observed",
            "No reverse DNS record was observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )),
        "spf-network-extractor"
            if !records
                .iter()
                .any(|record| record.value.to_ascii_lowercase().contains("v=spf1")) =>
        {
            findings.push(finding(
                "spf-not-observed",
                "No SPF policy was observed",
                Severity::Low,
                Confidence::Confirmed,
                evidence,
            ));
        }
        "spf-dkim-dmarc-validator" if missing => findings.push(finding(
            "mail-policy-not-observed",
            "A sender-authentication policy record was not observed",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        )),
        "email-config"
            if query.record_types.contains(&DnsRecordType::Mx)
                && !records
                    .iter()
                    .any(|record| record.record_type == DnsRecordType::Mx) =>
        {
            findings.push(finding(
                "mail-exchanger-not-observed",
                "No mail exchanger was observed",
                Severity::Low,
                Confidence::Confirmed,
                evidence,
            ));
        }
        "dual-stack-behavior-profiler" | "dual-stack-diff" => {
            if let Some(finding) = analyze_dns_dual_stack(records, evidence) {
                findings.push(finding);
            }
        }
        "rogue-subdomain-resolver" | "decoy-dns-beacon"
            if query.name.starts_with("_sugra-scope-probe.") && !missing =>
        {
            findings.push(finding(
                "unexpected-probe-answer",
                "A deterministic nonexistent-label probe returned DNS data",
                Severity::Low,
                Confidence::Inferred,
                evidence,
            ));
        }
        "subdomain-takeover" => {
            if let Some(finding) = analyze_dns_takeover(records, evidence) {
                findings.push(finding);
            }
        }
        "ttl-analysis" => {
            if let Some(finding) = analyze_dns_ttl(records, evidence) {
                findings.push(finding);
            }
        }
        _ => {}
    }
}

fn analyze_dns_dual_stack(records: &[DnsRecord], evidence: usize) -> Option<Finding> {
    let ipv4 = records
        .iter()
        .any(|record| record.record_type == DnsRecordType::A);
    let ipv6 = records
        .iter()
        .any(|record| record.record_type == DnsRecordType::Aaaa);
    (ipv4 != ipv6).then(|| {
        finding(
            "address-family-asymmetry",
            "IPv4 and IPv6 publication differs",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )
    })
}

fn analyze_dns_takeover(records: &[DnsRecord], evidence: usize) -> Option<Finding> {
    let external_alias = records.iter().any(|record| {
        let value = record.value.to_ascii_lowercase();
        [
            "github.io",
            "herokuapp.com",
            "azurewebsites.net",
            "cloudfront.net",
            "s3.amazonaws.com",
        ]
        .iter()
        .any(|suffix| value.contains(suffix))
    });
    external_alias.then(|| {
        finding(
            "external-service-alias",
            "A DNS alias points to an external service and requires ownership review",
            Severity::Medium,
            Confidence::Inferred,
            evidence,
        )
    })
}

fn analyze_dns_ttl(records: &[DnsRecord], evidence: usize) -> Option<Finding> {
    records
        .iter()
        .filter_map(|record| record.ttl)
        .any(|ttl| ttl < 60)
        .then(|| {
            finding(
                "short-dns-ttl",
                "A DNS record uses a time-to-live below 60 seconds",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            )
        })
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
    match target {
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
    }
}

fn is_crawler(id: &str) -> bool {
    matches!(
        id,
        "broken-links"
            | "crawler"
            | "content-discovery"
            | "email-harvester"
            | "javascript-file-analyzer"
            | "dom-sink-scanner"
            | "dependency-js-cdn-scanner"
            | "third-party-script-risk-profiler"
            | "static-asset-fingerprinter"
    )
}

fn http_paths(id: &str) -> Vec<&'static str> {
    match id {
        "crawl-rules" => vec!["/robots.txt"],
        "sitemap-parsing" => vec!["/sitemap.xml", "/sitemap_index.xml"],
        "security-txt" | "security-contact-gap-finder" => {
            vec!["/.well-known/security.txt", "/security.txt", "/"]
        }
        "exposed-env-files" => vec!["/.env", "/.env.production", "/.env.local"],
        "git-repo-exposure-check" => vec!["/.git/HEAD", "/.git/config"],
        "api-schema-grabber" => vec!["/openapi.json", "/swagger.json", "/api-docs", "/graphql"],
        "exposed-api-endpoints" => vec!["/api", "/api/v1", "/swagger", "/openapi.json"],
        "directory-finder" => vec!["/admin/", "/backup/", "/config/", "/uploads/"],
        "graphql-introspection-probe" => vec!["/graphql"],
        "file-upload-surface-finder" => vec!["/", "/upload", "/uploads"],
        "cloud-bucket-exposure" | "cloud-service-enumeration" => {
            vec!["/", "/.well-known/assetlinks.json"]
        }
        _ => vec!["/"],
    }
}

fn http_methods(id: &str) -> Vec<HttpMethod> {
    if id == "http-method-enumerator" {
        vec![HttpMethod::Get, HttpMethod::Head, HttpMethod::Options]
    } else {
        vec![HttpMethod::Get]
    }
}

#[derive(Debug, serde::Serialize)]
struct DocumentMetrics {
    title: Option<String>,
    links: usize,
    scripts: usize,
    forms: usize,
    inputs: usize,
    comments: usize,
}

fn document_metrics(body: &[u8]) -> DocumentMetrics {
    let text = String::from_utf8_lossy(body);
    let document = Html::parse_document(&text);
    let count = |selector: &str| {
        Selector::parse(selector)
            .ok()
            .map_or(0, |selector| document.select(&selector).count())
    };
    let title = Selector::parse("title").ok().and_then(|selector| {
        document.select(&selector).next().map(|element| {
            element
                .text()
                .collect::<String>()
                .trim()
                .chars()
                .take(256)
                .collect()
        })
    });
    DocumentMetrics {
        title,
        links: count("a[href]"),
        scripts: count("script"),
        forms: count("form"),
        inputs: count("input, textarea, select"),
        comments: text.matches("<!--").count(),
    }
}

fn enqueue_links(
    base: &Url,
    body: &[u8],
    scope: &sugra_domain::ScopeGrant,
    queue: &mut VecDeque<Url>,
) {
    let document = Html::parse_document(&String::from_utf8_lossy(body));
    let Ok(selector) = Selector::parse("a[href], script[src]") else {
        return;
    };
    for element in document.select(&selector) {
        let candidate = element
            .value()
            .attr("href")
            .or_else(|| element.value().attr("src"))
            .and_then(|value| base.join(value).ok());
        if let Some(candidate) = candidate
            && Target::parse(TargetKind::Url, candidate.as_str())
                .ok()
                .is_some_and(|target| scope.allows(&target))
        {
            queue.push_back(candidate);
        }
    }
}

fn analyze_http(
    id: &str,
    response: &sugra_core::HttpResponse,
    metrics: &DocumentMetrics,
    evidence: usize,
    findings: &mut Vec<Finding>,
) {
    if id == "broken-links" && response.status >= 400 {
        findings.push(finding(
            "broken-link",
            "A linked resource returned an error status",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if id == "exposed-env-files"
        && response.status == 200
        && contains_any(
            &response.body,
            &[b"=".as_slice(), b"SECRET", b"PASSWORD", b"TOKEN"],
        )
    {
        findings.push(finding(
            "environment-file-exposed",
            "An environment-style file is publicly readable",
            Severity::Critical,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if id == "git-repo-exposure-check"
        && response.status == 200
        && contains_any(&response.body, &[b"ref: refs/", b"[core]"])
    {
        findings.push(finding(
            "git-metadata-exposed",
            "Repository metadata is publicly readable",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if matches!(
        id,
        "http-headers" | "http-security-features" | "csp-deep-analyzer"
    ) {
        for header in [
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
        ] {
            if !response.headers.contains_key(header) {
                findings.push(finding(
                    &format!("missing-{header}"),
                    &format!("Security header {header} was not observed"),
                    Severity::Low,
                    Confidence::Confirmed,
                    evidence,
                ));
            }
        }
    }
    if id == "clickjacking-test"
        && !response.headers.contains_key("x-frame-options")
        && !response
            .headers
            .get("content-security-policy")
            .is_some_and(|value| value.to_ascii_lowercase().contains("frame-ancestors"))
    {
        findings.push(finding(
            "framing-not-restricted",
            "No framing restriction was observed",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if id == "cors-misconfiguration-scanner"
        && response
            .headers
            .get("access-control-allow-origin")
            .is_some_and(|value| value == "*" || value == "https://scope-check.invalid")
    {
        findings.push(finding(
            "permissive-cors",
            "A permissive cross-origin policy was observed",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if id == "file-upload-surface-finder" && metrics.inputs > 0 {
        let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        if text.contains("type=\"file\"") || text.contains("type='file'") {
            findings.push(finding(
                "upload-surface",
                "A file upload input was observed",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            ));
        }
    }
}

fn contains_any(body: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| {
        body.windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
    })
}

#[derive(Clone, Copy)]
struct ProviderCall {
    provider: &'static str,
    operation: &'static str,
    secret_env: Option<&'static str>,
}

fn provider_calls(
    id: &str,
    target: &Target,
    options: &BTreeMap<String, Value>,
) -> Vec<ProviderCall> {
    if let Some(calls) = provider_registry_calls(id, target, options) {
        return calls;
    }
    provider_intelligence_calls(id, target)
        .unwrap_or_else(|| vec![provider_call("configured-provider", "query", None)])
}

const fn provider_call(
    provider: &'static str,
    operation: &'static str,
    secret_env: Option<&'static str>,
) -> ProviderCall {
    ProviderCall {
        provider,
        operation,
        secret_env,
    }
}

fn provider_registry_calls(
    id: &str,
    target: &Target,
    options: &BTreeMap<String, Value>,
) -> Option<Vec<ProviderCall>> {
    match id {
        "asn-lookup" if matches!(target, Target::Ip(_)) => {
            Some(vec![provider_call("ripestat", "network-info", None)])
        }
        "asn-lookup" | "rdap-lookup" => Some(vec![provider_call(
            "rdap",
            if matches!(target, Target::Ip(_)) {
                "ip"
            } else {
                "domain"
            },
            None,
        )]),
        "autonomous-neighbor-peering-map" => {
            Some(vec![provider_call("ripestat", "asn-neighbours", None)])
        }
        "bgp-route-analysis" => Some(vec![provider_call("ripestat", "bgp-state", None)]),
        "ip-allocation-history-tracker" => {
            Some(vec![provider_call("ripestat", "historical-whois", None)])
        }
        "ip-info" => Some(vec![provider_call("ripestat", "network-info", None)]),
        "ns-geo-asn-diversity-analyzer" => Some(vec![provider_call("ripestat", "dns-chain", None)]),
        "rpki-route-validity-check" if options.contains_key("asn") => {
            Some(vec![provider_call("ripestat", "rpki-validation", None)])
        }
        "rpki-route-validity-check" => Some(vec![provider_call("ripestat", "rpki-history", None)]),
        "irr-routing-registry-analyzer" => Some(vec![provider_call("ripestat", "whois", None)]),
        "archive-history" => Some(vec![provider_call("wayback", "cdx", None)]),
        _ => None,
    }
}

fn provider_intelligence_calls(id: &str, target: &Target) -> Option<Vec<ProviderCall>> {
    match id {
        "associated-hosts" | "domain-shadowing-detector" => Some(vec![
            provider_call("crtsh", "query", None),
            provider_call("urlscan", "search", None),
        ]),
        "ct-log-query"
        | "subdomain-enum"
        | "certificate-authority-recon"
        | "rogue-certificate-check" => Some(vec![provider_call("crtsh", "query", None)]),
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
        "ssl-labs-report" => Some(vec![provider_call("ssllabs", "analyze", None)]),
        "global-ranking" => Some(vec![provider_call(
            "cloudflare-radar",
            "domain-ranking",
            Some("CLOUDFLARE_API_TOKEN"),
        )]),
        "ip-reputation-check" | "ip-reputation-trending" => Some(vec![
            provider_call("ripestat", "dns-blocklists", None),
            provider_call("abuseipdb", "check", Some("ABUSEIPDB_API_KEY")),
        ]),
        "domain-reputation-check" => Some(vec![
            provider_call("virustotal", "domain", Some("VIRUSTOTAL_API_KEY")),
            provider_call("urlscan", "search", None),
            provider_call("urlhaus", "host", Some("URLHAUS_AUTH_KEY")),
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
        "pastebin-monitoring" | "dark-web-monitoring" => {
            Some(vec![provider_call("configured-monitoring", "search", None)])
        }
        _ => None,
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
            let query = if matches!(
                scanner_id,
                "associated-hosts" | "subdomain-enum" | "domain-shadowing-detector"
            ) {
                format!("%.{host}")
            } else {
                host
            };
            BTreeMap::from([("q".into(), Value::String(query))])
        }
        "wayback" => BTreeMap::from([("url".into(), Value::String(format!("{host}/*")))]),
        "urlscan" => {
            let field = match target {
                Target::Ip(_) | Target::Cidr(_) => "ip",
                Target::Asn(_) => "asn",
                _ => "domain",
            };
            BTreeMap::from([("q".into(), Value::String(format!("{field}:{host}")))])
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

fn dns_transfer_accepted(response: &[u8]) -> bool {
    if response.len() < 14 {
        return false;
    }
    let header = &response[2..14];
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let answers = u16::from_be_bytes([header[6], header[7]]);
    header[..2] == [0x53, 0x55] && flags & 0x8000 != 0 && flags.trailing_zeros() >= 4 && answers > 0
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

fn udp_payload(analyzer: Analyzer, id: &str, port: u16) -> Result<Vec<u8>, ScanError> {
    match port {
        123 => {
            let mut packet = vec![0_u8; 48];
            packet[0] = 0x1b;
            Ok(packet)
        }
        161 => snmp_request(
            "public",
            analyzer == Analyzer::UdpSnmp && id == "snmp-bulk-walk",
        ),
        137 => Ok(vec![
            0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, b'C',
            b'K', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
            b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
            b'A', b'A', b'A', 0x00, 0x00, 0x21, 0x00, 0x01,
        ]),
        _ => Ok(vec![0_u8; 12]),
    }
}

fn snmp_request(community: &str, bulk: bool) -> Result<Vec<u8>, ScanError> {
    if community.is_empty()
        || community.len() > 64
        || !community.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "SNMP community must contain 1 to 64 printable ASCII characters",
        ));
    }
    let oid = ber_tlv(0x06, &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    let mut variable = oid;
    variable.extend(ber_tlv(0x05, &[]));
    let binding = ber_tlv(0x30, &variable);
    let bindings = ber_tlv(0x30, &binding);
    let mut pdu = ber_tlv(0x02, &[0x53, 0x55, 0x47, 0x52]);
    pdu.extend(ber_tlv(0x02, &[0]));
    pdu.extend(ber_tlv(0x02, &[if bulk { 10 } else { 0 }]));
    pdu.extend(bindings);
    let pdu = ber_tlv(if bulk { 0xa5 } else { 0xa0 }, &pdu);
    let mut message = ber_tlv(0x02, &[1]);
    message.extend(ber_tlv(0x04, community.as_bytes()));
    message.extend(pdu);
    Ok(ber_tlv(0x30, &message))
}

fn ber_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    if body.len() < 128 {
        encoded.push(u8::try_from(body.len()).unwrap_or(127));
    } else {
        encoded.extend_from_slice(&[
            0x82,
            u8::try_from((body.len() >> 8) & 0xff).unwrap_or(0xff),
            u8::try_from(body.len() & 0xff).unwrap_or(0xff),
        ]);
    }
    encoded.extend_from_slice(body);
    encoded
}

fn udp_observation(analyzer: Analyzer, response: &[u8]) -> Value {
    match analyzer {
        Analyzer::UdpNtp if response.len() >= 48 => json!({
            "mode": response[0] & 0x07,
            "version": (response[0] >> 3) & 0x07,
            "stratum": response[1],
            "leap_indicator": response[0] >> 6,
        }),
        Analyzer::UdpSnmp => json!({
            "response_valid": snmp_response_status(response).is_some(),
            "error_status": snmp_response_status(response),
        }),
        Analyzer::UdpNetbios => json!({
            "transaction_matches": response.starts_with(&[0x13, 0x37]),
            "answer_count": response
                .get(6..8)
                .map_or(0, |value| u16::from_be_bytes([value[0], value[1]])),
        }),
        _ => json!({"classified": "bounded-datagram"}),
    }
}

fn analyze_udp_response(analyzer: Analyzer, response: &[u8], evidence: usize) -> Vec<Finding> {
    match analyzer {
        Analyzer::UdpSnmp if snmp_response_status(response) == Some(0) => {
            vec![finding(
                "snmp-public-community-accepted",
                "The SNMP service responded to the public community",
                Severity::Medium,
                Confidence::Confirmed,
                evidence,
            )]
        }
        Analyzer::UdpNtp if response.len() >= 48 => vec![finding(
            "ntp-service-observed",
            "An NTP service returned protocol metadata",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )],
        _ => Vec::new(),
    }
}

fn snmp_response_status(response: &[u8]) -> Option<u8> {
    let mut outer_offset = 0;
    let (outer_tag, message) = ber_element(response, &mut outer_offset)?;
    if outer_tag != 0x30 || outer_offset != response.len() {
        return None;
    }
    let mut message_offset = 0;
    let (version_tag, _) = ber_element(message, &mut message_offset)?;
    let (community_tag, community) = ber_element(message, &mut message_offset)?;
    let (pdu_tag, pdu) = ber_element(message, &mut message_offset)?;
    if version_tag != 0x02 || community_tag != 0x04 || community != b"public" || pdu_tag != 0xa2 {
        return None;
    }
    let mut pdu_offset = 0;
    let (request_tag, request_id) = ber_element(pdu, &mut pdu_offset)?;
    let (status_tag, status) = ber_element(pdu, &mut pdu_offset)?;
    if request_tag != 0x02
        || request_id != [0x53, 0x55, 0x47, 0x52]
        || status_tag != 0x02
        || status.len() != 1
    {
        return None;
    }
    status.first().copied()
}

fn ber_element<'a>(input: &'a [u8], offset: &mut usize) -> Option<(u8, &'a [u8])> {
    let tag = *input.get(*offset)?;
    *offset += 1;
    let first_length = *input.get(*offset)?;
    *offset += 1;
    let length = if first_length & 0x80 == 0 {
        usize::from(first_length)
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > 2 {
            return None;
        }
        let mut length = 0_usize;
        for byte in input.get(*offset..(*offset).checked_add(length_bytes)?)? {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        *offset += length_bytes;
        length
    };
    let end = (*offset).checked_add(length)?;
    let body = input.get(*offset..end)?;
    *offset = end;
    Some((tag, body))
}

fn command_kind(id: &str) -> CommandKind {
    if id.contains("traceroute") {
        CommandKind::Traceroute
    } else if id.contains("whois") {
        CommandKind::Whois
    } else if id.contains("ssh") {
        CommandKind::SshKeyscan
    } else {
        CommandKind::Ping
    }
}

fn command_targets(target: &Target, limit: usize) -> Vec<Target> {
    match target {
        Target::Cidr(network) => network.hosts().take(limit).map(Target::Ip).collect(),
        other => vec![other.clone()],
    }
}

fn command_observation(kind: CommandKind, response: &CommandResponse) -> Value {
    let details = match kind {
        CommandKind::Ping => json!({"reachable": response.exit_code == Some(0)}),
        CommandKind::Traceroute => json!({
            "hop_lines": response
                .stdout
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count()
                .saturating_sub(1),
        }),
        CommandKind::Whois => json!({"fields": safe_whois_fields(&response.stdout)}),
        CommandKind::SshKeyscan => json!({"host_keys": ssh_key_metadata(&response.stdout)}),
    };
    json!({
        "exit_code": response.exit_code,
        "stdout_bytes": response.stdout.len(),
        "stdout_sha256": hex::encode(Sha256::digest(response.stdout.as_bytes())),
        "stderr": safe_text(response.stderr.as_bytes(), 512),
        "details": details,
        "duration_ms": response.duration_ms,
    })
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

fn ssh_key_metadata(output: &str) -> Vec<Value> {
    output
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _host = fields.next()?;
            let key_type = fields.next()?;
            let encoded = fields.next()?;
            Some(json!({
                "type": key_type,
                "sha256": hex::encode(Sha256::digest(encoded.as_bytes())),
            }))
        })
        .take(64)
        .collect()
}

fn analyze_command(kind: CommandKind, response: &CommandResponse, evidence: usize) -> Vec<Finding> {
    match kind {
        CommandKind::SshKeyscan if !ssh_key_metadata(&response.stdout).is_empty() => vec![finding(
            "ssh-host-key-observed",
            "One or more SSH host keys were observed",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        )],
        CommandKind::Ping if response.exit_code != Some(0) => vec![finding(
            "icmp-unreachable",
            "The target did not answer the bounded ICMP probe",
            Severity::Info,
            Confidence::Unknown,
            evidence,
        )],
        _ => Vec::new(),
    }
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
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    };
    let header = decode(parts[0])
        .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "JWT header is invalid"))?;
    let payload = decode(parts[1])
        .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "JWT payload is invalid"))?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| {
        ScanError::new(
            ScanErrorKind::InvalidInput,
            "JWT signature encoding is invalid",
        )
    })?;
    let mut findings = Vec::new();
    if header
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|algorithm| algorithm.eq_ignore_ascii_case("none"))
    {
        findings.push(finding(
            "unsigned-jwt",
            "JWT declares the none algorithm",
            Severity::High,
            Confidence::Confirmed,
            0,
        ));
    }
    findings.extend(jwt_time_findings(
        &payload,
        context.clock.now().unix_timestamp(),
    ));
    Ok(ScanResult::completed(
        vec![Evidence {
            kind: "jwt-structure".into(),
            source: "local-input".into(),
            observation: json!({
                "header": redact_json(header),
                "payload": redact_json(payload),
                "signature_bytes": signature.len(),
                "signature_sha256": hex::encode(Sha256::digest(&signature)),
                "signature_verified": false,
            }),
            observed_at: context.clock.now(),
        }],
        findings,
    ))
}

fn jwt_time_findings(payload: &Value, now: i64) -> Vec<Finding> {
    let mut findings = Vec::new();
    match payload.get("exp").and_then(Value::as_i64) {
        Some(expiry) if expiry <= now => findings.push(finding(
            "jwt-expired",
            "The JWT expiration time is in the past",
            Severity::Medium,
            Confidence::Confirmed,
            0,
        )),
        None => findings.push(finding(
            "jwt-expiration-missing",
            "The JWT does not declare an expiration time",
            Severity::Low,
            Confidence::Confirmed,
            0,
        )),
        Some(_) => {}
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

fn reindex_findings(findings: &mut [Finding], evidence: usize) {
    for finding in findings {
        finding.evidence = vec![evidence];
    }
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

fn safe_text(bytes: &[u8], limit: usize) -> String {
    redact_text(&String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]))
}

fn redact_text(value: &str) -> String {
    value
        .lines()
        .take(128)
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if ["password", "secret", "token", "authorization", "api_key"]
                .iter()
                .any(|marker| lower.contains(marker))
            {
                "<redacted>".into()
            } else {
                line.chars().take(512).collect::<String>()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
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
        HttpRequest, HttpResponse, PortError, ProviderPort, ProviderRequest, ProviderResponse,
        TcpPort, TcpRequest, TcpResponse, TlsCertificate, TlsObservation, TlsPort, TlsRequest,
        UdpPort, UdpRequest, UdpResponse,
    };
    use sugra_domain::{Budget, ScanRequest, ScopeGrant, Target, TargetKind};
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
            Ok(vec![DnsRecord {
                name: query.name,
                record_type: query
                    .record_types
                    .first()
                    .copied()
                    .unwrap_or(DnsRecordType::A),
                value: "192.0.2.1".into(),
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
                body: b"<html><title>Fixture</title><a href='/next'>Next</a></html>".to_vec(),
                duration_ms: 1,
            })
        }
    }

    struct FakeTcp;
    #[async_trait]
    impl TcpPort for FakeTcp {
        async fn execute(&self, request: TcpRequest) -> Result<TcpResponse, PortError> {
            Ok(TcpResponse {
                endpoint: format!("{}:{}", request.host, request.port),
                bytes: b"fixture-banner".to_vec(),
                duration_ms: 1,
            })
        }
    }

    struct FakeUdp;
    #[async_trait]
    impl UdpPort for FakeUdp {
        async fn execute(&self, request: UdpRequest) -> Result<UdpResponse, PortError> {
            Ok(UdpResponse {
                endpoint: format!("{}:{}", request.host, request.port),
                bytes: vec![1, 2, 3],
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
        async fn execute(&self, _request: CommandRequest) -> Result<CommandResponse, PortError> {
            Ok(CommandResponse {
                exit_code: Some(0),
                stdout: "fixture".into(),
                stderr: String::new(),
                duration_ms: 1,
            })
        }
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
    fn tls_expiry_analysis_distinguishes_expired_and_expiring_certificates() {
        let expired = tls_observation(Some(tls_certificate(-10_000, -1)));
        let expired_findings = analyze_tls(Analyzer::TlsExpiry, &expired, 0);
        assert_eq!(expired_findings[0].key, "tls-certificate-expired");
        assert_eq!(expired_findings[0].severity, Severity::Critical);

        let expiring = tls_observation(Some(tls_certificate(-10_000, 6 * 86_400)));
        let expiring_findings = analyze_tls(Analyzer::TlsExpiry, &expiring, 0);
        assert_eq!(expiring_findings[0].key, "tls-certificate-expiring");
        assert_eq!(expiring_findings[0].severity, Severity::High);
    }

    #[test]
    fn tls_chain_analysis_flags_a_ca_leaf() {
        let mut certificate = tls_certificate(-10_000, 365 * 86_400);
        certificate.is_ca = Some(true);
        let findings = analyze_tls(Analyzer::TlsChain, &tls_observation(Some(certificate)), 0);
        assert!(
            findings
                .iter()
                .any(|finding| finding.key == "tls-leaf-is-ca")
        );
    }

    #[test]
    fn tls_cipher_analysis_flags_obsolete_protocols_and_weak_suites() {
        let mut observation = tls_observation(None);
        observation.protocol = "TLSv1_0".into();
        observation.cipher_suite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into();
        let findings = analyze_tls(Analyzer::TlsCipher, &observation, 0);
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
            let calls = provider_calls(descriptor.id.as_str(), &target, &BTreeMap::new());
            assert!(!calls.is_empty(), "{} has no provider plan", descriptor.id);
            assert!(
                calls
                    .iter()
                    .all(|call| call.provider != "configured-provider"),
                "{} fell through to the generic provider",
                descriptor.id
            );
        }
        assert_eq!(provider_scanners, 36);
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
    fn axfr_query_is_framed_and_only_accepts_answer_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let query = dns_axfr_query("example.com")?;
        assert_eq!(
            usize::from(u16::from_be_bytes([query[0], query[1]])),
            query.len() - 2
        );
        assert_eq!(&query[2..4], &[0x53, 0x55]);
        assert_eq!(&query[query.len() - 4..query.len() - 2], &[0, 252]);

        let accepted = [0, 12, 0x53, 0x55, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        let refused = [0, 12, 0x53, 0x55, 0x81, 0x85, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(dns_transfer_accepted(&accepted));
        assert!(!dns_transfer_accepted(&refused));
        Ok(())
    }

    #[test]
    fn snmp_requests_are_bounded_and_distinguish_get_from_bulk()
    -> Result<(), Box<dyn std::error::Error>> {
        let get = snmp_request("public", false)?;
        let bulk = snmp_request("public", true)?;
        assert_eq!(get.first(), Some(&0x30));
        assert!(get.contains(&0xa0));
        assert!(!get.contains(&0xa5));
        assert!(bulk.contains(&0xa5));
        assert!(snmp_request("", false).is_err());
        assert!(snmp_request(&"x".repeat(65), false).is_err());

        let mut pdu = ber_tlv(0x02, &[0x53, 0x55, 0x47, 0x52]);
        pdu.extend(ber_tlv(0x02, &[0]));
        pdu.extend(ber_tlv(0x02, &[0]));
        pdu.extend(ber_tlv(0x30, &[]));
        let mut message = ber_tlv(0x02, &[1]);
        message.extend(ber_tlv(0x04, b"public"));
        message.extend(ber_tlv(0xa2, &pdu));
        let response = ber_tlv(0x30, &message);
        assert_eq!(snmp_response_status(&response), Some(0));
        let mut invalid = response;
        let Some(request_id) = invalid
            .windows(4)
            .position(|window| window == [0x53, 0x55, 0x47, 0x52])
        else {
            return Err("fixture SNMP request ID is missing".into());
        };
        invalid[request_id] = 0;
        assert_eq!(snmp_response_status(&invalid), None);
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
    fn command_metadata_omits_raw_host_keys_and_whois_contacts() {
        let ssh = CommandResponse {
            exit_code: Some(0),
            stdout: "example.com ssh-ed25519 AAAA-sensitive-key-material".into(),
            stderr: String::new(),
            duration_ms: 1,
        };
        let ssh_value = command_observation(CommandKind::SshKeyscan, &ssh).to_string();
        assert!(!ssh_value.contains("AAAA-sensitive-key-material"));
        assert!(ssh_value.contains("ssh-ed25519"));

        let whois = safe_whois_fields(
            "Domain Name: EXAMPLE.COM\nRegistrar: Fixture\nRegistrant Email: person@example.com",
        );
        assert_eq!(
            whois.get("domain name").map(String::as_str),
            Some("EXAMPLE.COM")
        );
        assert!(!whois.contains_key("registrant email"));
    }

    #[test]
    fn cidr_command_targets_respect_the_host_limit() -> Result<(), Box<dyn std::error::Error>> {
        let cidr = Target::parse(TargetKind::Cidr, "192.0.2.0/24")?;
        let targets = command_targets(&cidr, 3);
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|target| matches!(target, Target::Ip(_))));
        Ok(())
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
            let request = ScanRequest {
                scanner_id: descriptor.id.clone(),
                scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
                target,
                options: BTreeMap::new(),
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
