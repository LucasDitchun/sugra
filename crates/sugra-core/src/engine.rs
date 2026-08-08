//! Concurrent execution with deterministic report ordering.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sugra_domain::{
    Diagnostic, ExecutionStatus, RunId, RunReport, ScanExecution, ScanRequest, ScanResult,
    ScannerId,
};
use thiserror::Error;
use tokio::sync::{Semaphore, broadcast};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{Clock, ScanContext, ScanError, ScanErrorKind, Scanner, evaluate_policy};

/// Engine setup or plan failure.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Registry is missing a requested scanner.
    #[error("scanner is not registered: {0}")]
    ScannerNotRegistered(ScannerId),
    /// Request scanner ID disagrees with the selected implementation.
    #[error("request scanner ID does not match implementation: {0}")]
    ScannerMismatch(ScannerId),
    /// Policy rejected a request before execution.
    #[error("policy rejected {scanner_id}: {message}")]
    PolicyRejected {
        /// Rejected scanner.
        scanner_id: ScannerId,
        /// Safe reason.
        message: String,
    },
    /// Engine concurrency must be non-zero.
    #[error("engine concurrency must be greater than zero")]
    InvalidConcurrency,
}

/// Immutable registry of concrete scanner implementations.
#[derive(Clone, Default)]
pub struct ScannerRegistry {
    scanners: BTreeMap<ScannerId, Arc<dyn Scanner>>,
}

impl ScannerRegistry {
    /// Constructs a registry and rejects duplicate implementations.
    ///
    /// # Errors
    ///
    /// Returns `EngineError::ScannerMismatch` when two implementations publish
    /// the same scanner identity.
    pub fn new(scanners: Vec<Arc<dyn Scanner>>) -> Result<Self, EngineError> {
        let mut registry = Self::default();
        for scanner in scanners {
            let id = scanner.descriptor().id.clone();
            if registry.scanners.insert(id.clone(), scanner).is_some() {
                return Err(EngineError::ScannerMismatch(id));
            }
        }
        Ok(registry)
    }

    /// Looks up a scanner implementation.
    #[must_use]
    pub fn get(&self, id: &ScannerId) -> Option<Arc<dyn Scanner>> {
        self.scanners.get(id).cloned()
    }

    /// Returns the number of implementations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scanners.len()
    }

    /// Returns whether no implementations are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scanners.is_empty()
    }
}

/// Observable run lifecycle event used by CLI and TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RunEvent {
    /// A run has a validated plan.
    Planned {
        /// Run identity.
        run_id: RunId,
        /// Number of scanner requests.
        scanners: usize,
    },
    /// A scanner acquired capacity and started.
    ScanStarted {
        /// Run identity.
        run_id: RunId,
        /// Scanner identity.
        scanner_id: ScannerId,
    },
    /// A scanner reached a terminal state.
    ScanFinished {
        /// Run identity.
        run_id: RunId,
        /// Scanner identity.
        scanner_id: ScannerId,
        /// Terminal state.
        status: ExecutionStatus,
        /// Duration in milliseconds.
        duration_ms: u64,
    },
    /// Every scanner reached a terminal state.
    Completed {
        /// Run identity.
        run_id: RunId,
        /// Aggregate terminal state.
        status: ExecutionStatus,
    },
}

/// Supervised bounded scanner engine.
pub struct Engine {
    registry: ScannerRegistry,
    clock: Arc<dyn Clock>,
    concurrency: usize,
}

impl Engine {
    /// Constructs an engine with a global concurrency limit.
    ///
    /// # Errors
    ///
    /// Returns `EngineError::InvalidConcurrency` when concurrency is zero.
    pub fn new(
        registry: ScannerRegistry,
        clock: Arc<dyn Clock>,
        concurrency: usize,
    ) -> Result<Self, EngineError> {
        if concurrency == 0 {
            return Err(EngineError::InvalidConcurrency);
        }
        Ok(Self {
            registry,
            clock,
            concurrency,
        })
    }

    /// Validates requests without opening any boundary.
    ///
    /// # Errors
    ///
    /// Returns an engine error when a scanner is absent, identities disagree,
    /// policy rejects a request, or a budget violates its bounds.
    pub fn validate(&self, requests: &[ScanRequest]) -> Result<(), EngineError> {
        for request in requests {
            let scanner = self
                .registry
                .get(&request.scanner_id)
                .ok_or_else(|| EngineError::ScannerNotRegistered(request.scanner_id.clone()))?;
            if scanner.descriptor().id != request.scanner_id {
                return Err(EngineError::ScannerMismatch(request.scanner_id.clone()));
            }
            evaluate_policy(scanner.descriptor(), request).map_err(|error| {
                EngineError::PolicyRejected {
                    scanner_id: request.scanner_id.clone(),
                    message: error.to_string(),
                }
            })?;
            request
                .budget
                .validate()
                .map_err(|error| EngineError::PolicyRejected {
                    scanner_id: request.scanner_id.clone(),
                    message: error.to_string(),
                })?;
        }
        Ok(())
    }

    /// Executes validated requests concurrently and returns results in plan order.
    ///
    /// # Errors
    ///
    /// Returns an engine error when plan validation fails before execution.
    pub async fn execute(
        &self,
        requests: Vec<ScanRequest>,
        cancellation: CancellationToken,
        events: Option<broadcast::Sender<RunEvent>>,
    ) -> Result<RunReport, EngineError> {
        self.validate(&requests)?;
        let run_id = RunId::new();
        let started_at = self.clock.now();
        emit(
            events.as_ref(),
            RunEvent::Planned {
                run_id,
                scanners: requests.len(),
            },
        );
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut handles: Vec<(ScannerId, JoinHandle<ScanExecution>)> =
            Vec::with_capacity(requests.len());

        for request in requests {
            let scanner = self
                .registry
                .get(&request.scanner_id)
                .ok_or_else(|| EngineError::ScannerNotRegistered(request.scanner_id.clone()))?;
            let id = request.scanner_id.clone();
            let handle = spawn_execution(
                request,
                scanner,
                Arc::clone(&semaphore),
                cancellation.child_token(),
                Arc::clone(&self.clock),
                events.clone(),
                run_id,
            );
            handles.push((id, handle));
        }

        let executions = collect_executions(handles).await;
        let report = RunReport {
            schema_version: 1,
            run_id,
            app_version: env!("CARGO_PKG_VERSION").into(),
            started_at,
            finished_at: self.clock.now(),
            executions,
        };
        emit(
            events.as_ref(),
            RunEvent::Completed {
                run_id,
                status: report.status(),
            },
        );
        Ok(report)
    }
}

fn spawn_execution(
    request: ScanRequest,
    scanner: Arc<dyn Scanner>,
    permit_pool: Arc<Semaphore>,
    token: CancellationToken,
    clock: Arc<dyn Clock>,
    events: Option<broadcast::Sender<RunEvent>>,
    run_id: RunId,
) -> JoinHandle<ScanExecution> {
    tokio::spawn(async move {
        let acquired = tokio::select! {
            permit = permit_pool.acquire_owned() => permit.ok(),
            () = token.cancelled() => None,
        };
        let scanner_id = request.scanner_id.clone();
        if acquired.is_none() {
            return cancelled_execution(scanner_id, 0);
        }
        emit(
            events.as_ref(),
            RunEvent::ScanStarted {
                run_id,
                scanner_id: scanner_id.clone(),
            },
        );
        let started = Instant::now();
        let context = ScanContext {
            run_id,
            cancellation: token.clone(),
            clock,
        };
        let outcome = tokio::select! {
            () = token.cancelled() => Err(ScanError::new(ScanErrorKind::Cancelled, "scan cancelled")),
            value = tokio::time::timeout(request.budget.timeout(), scanner.scan(&request, &context)) => {
                value.unwrap_or_else(|_| Err(ScanError::new(ScanErrorKind::Timeout, "scan timed out")))
            }
        };
        let duration_ms = millis(started.elapsed().as_millis());
        let result = outcome.unwrap_or_else(failed_result);
        emit(
            events.as_ref(),
            RunEvent::ScanFinished {
                run_id,
                scanner_id: scanner_id.clone(),
                status: result.status,
                duration_ms,
            },
        );
        ScanExecution {
            scanner_id,
            result,
            duration_ms,
        }
    })
}

async fn collect_executions(
    handles: Vec<(ScannerId, JoinHandle<ScanExecution>)>,
) -> Vec<ScanExecution> {
    let mut executions = Vec::with_capacity(handles.len());
    for (scanner_id, handle) in handles {
        match handle.await {
            Ok(execution) => executions.push(execution),
            Err(error) => executions.push(ScanExecution {
                scanner_id,
                result: failed_result(ScanError::new(
                    ScanErrorKind::Internal,
                    format!("scanner task ended unexpectedly: {error}"),
                )),
                duration_ms: 0,
            }),
        }
    }
    executions
}

fn emit(sender: Option<&broadcast::Sender<RunEvent>>, event: RunEvent) {
    if let Some(sender) = sender {
        let _receiver_count = sender.send(event);
    }
}

fn failed_result(error: ScanError) -> ScanResult {
    let status = match error.kind {
        ScanErrorKind::Cancelled => ExecutionStatus::Cancelled,
        ScanErrorKind::DependencyUnavailable | ScanErrorKind::PolicyDenied => {
            ExecutionStatus::Skipped
        }
        ScanErrorKind::InvalidInput
        | ScanErrorKind::Timeout
        | ScanErrorKind::Transport
        | ScanErrorKind::InvalidResponse
        | ScanErrorKind::Internal => ExecutionStatus::Failed,
    };
    ScanResult {
        status,
        findings: Vec::new(),
        evidence: Vec::new(),
        diagnostics: vec![Diagnostic {
            kind: format!("{:?}", error.kind).to_ascii_lowercase(),
            message: error.message,
        }],
    }
}

fn cancelled_execution(scanner_id: ScannerId, duration_ms: u64) -> ScanExecution {
    ScanExecution {
        scanner_id,
        result: ScanResult {
            status: ExecutionStatus::Cancelled,
            findings: Vec::new(),
            evidence: Vec::new(),
            diagnostics: vec![Diagnostic {
                kind: "cancelled".into(),
                message: "scan cancelled before it started".into(),
            }],
        },
        duration_ms,
    }
}

fn millis(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
