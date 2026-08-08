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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use async_trait::async_trait;
    use sugra_domain::{Budget, Capability, ScannerDescriptor, ScopeGrant, Target, TargetKind};
    use time::OffsetDateTime;

    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum Behavior {
        Complete,
        Fail(ScanErrorKind),
        Delay(Duration),
    }

    struct TestScanner {
        descriptor: ScannerDescriptor,
        behavior: Behavior,
    }

    #[async_trait]
    impl Scanner for TestScanner {
        fn descriptor(&self) -> &ScannerDescriptor {
            &self.descriptor
        }

        async fn scan(
            &self,
            _request: &ScanRequest,
            _context: &ScanContext,
        ) -> Result<ScanResult, ScanError> {
            match self.behavior {
                Behavior::Complete => Ok(ScanResult::completed(Vec::new(), Vec::new())),
                Behavior::Fail(kind) => Err(ScanError::new(kind, "safe failure")),
                Behavior::Delay(duration) => {
                    tokio::time::sleep(duration).await;
                    Ok(ScanResult::completed(Vec::new(), Vec::new()))
                }
            }
        }
    }

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    fn descriptor(id: &str, capabilities: Vec<Capability>) -> ScannerDescriptor {
        ScannerDescriptor {
            id: ScannerId::new(id).unwrap_or_else(|error| unreachable!("valid test ID: {error}")),
            legacy_id: None,
            name: id.into(),
            description: "test scanner".into(),
            track: "test".into(),
            target_kinds: vec![TargetKind::Domain],
            capabilities,
            options: Vec::new(),
            version: "1".into(),
        }
    }

    fn scanner(id: &str, behavior: Behavior, capabilities: Vec<Capability>) -> Arc<dyn Scanner> {
        Arc::new(TestScanner {
            descriptor: descriptor(id, capabilities),
            behavior,
        })
    }

    fn request(id: &str, active_authorized: bool) -> ScanRequest {
        let target = Target::parse(TargetKind::Domain, "example.com")
            .unwrap_or_else(|error| unreachable!("valid test target: {error}"));
        ScanRequest {
            scanner_id: ScannerId::new(id)
                .unwrap_or_else(|error| unreachable!("valid test ID: {error}")),
            scope: ScopeGrant::exact(&target, active_authorized, OffsetDateTime::UNIX_EPOCH),
            target,
            options: BTreeMap::new(),
            budget: Budget::default(),
        }
    }

    #[test]
    fn registry_rejects_duplicates_and_supports_lookup() -> Result<(), EngineError> {
        let empty = ScannerRegistry::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let registered = scanner(
            "registered",
            Behavior::Complete,
            vec![Capability::PassiveNetwork],
        );
        let registry = ScannerRegistry::new(vec![Arc::clone(&registered)])?;
        assert_eq!(registry.len(), 1);
        assert!(registry.get(&registered.descriptor().id).is_some());

        let duplicate = ScannerRegistry::new(vec![Arc::clone(&registered), registered]);
        assert!(matches!(duplicate, Err(EngineError::ScannerMismatch(_))));
        Ok(())
    }

    #[test]
    fn validation_rejects_invalid_setup_requests_and_budgets() -> Result<(), EngineError> {
        assert!(matches!(
            Engine::new(ScannerRegistry::default(), Arc::new(FixedClock), 0),
            Err(EngineError::InvalidConcurrency)
        ));

        let engine = Engine::new(ScannerRegistry::default(), Arc::new(FixedClock), 1)?;
        assert!(matches!(
            engine.validate(&[request("missing", false)]),
            Err(EngineError::ScannerNotRegistered(_))
        ));

        let active = scanner(
            "active",
            Behavior::Complete,
            vec![Capability::ActiveProtocol],
        );
        let engine = Engine::new(ScannerRegistry::new(vec![active])?, Arc::new(FixedClock), 1)?;
        assert!(matches!(
            engine.validate(&[request("active", false)]),
            Err(EngineError::PolicyRejected { .. })
        ));

        let mut invalid_budget = request("active", true);
        invalid_budget.budget.timeout_ms = 0;
        assert!(matches!(
            engine.validate(&[invalid_budget]),
            Err(EngineError::PolicyRejected { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn execute_preserves_plan_order_and_emits_terminal_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let scanners = vec![
            scanner(
                "slow-success",
                Behavior::Delay(Duration::from_millis(15)),
                vec![Capability::PassiveNetwork],
            ),
            scanner(
                "unavailable",
                Behavior::Fail(ScanErrorKind::DependencyUnavailable),
                vec![Capability::PassiveNetwork],
            ),
            scanner(
                "invalid-response",
                Behavior::Fail(ScanErrorKind::InvalidResponse),
                vec![Capability::PassiveNetwork],
            ),
            scanner(
                "timeout",
                Behavior::Delay(Duration::from_millis(50)),
                vec![Capability::PassiveNetwork],
            ),
        ];
        let engine = Engine::new(ScannerRegistry::new(scanners)?, Arc::new(FixedClock), 4)?;
        let mut requests = vec![
            request("slow-success", false),
            request("unavailable", false),
            request("invalid-response", false),
            request("timeout", false),
        ];
        requests[3].budget.timeout_ms = 1;
        let (sender, mut receiver) = broadcast::channel(32);

        let report = engine
            .execute(requests, CancellationToken::new(), Some(sender))
            .await?;

        assert_eq!(report.started_at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(report.finished_at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(
            report
                .executions
                .iter()
                .map(|execution| execution.scanner_id.as_str())
                .collect::<Vec<_>>(),
            vec!["slow-success", "unavailable", "invalid-response", "timeout"]
        );
        assert_eq!(
            report
                .executions
                .iter()
                .map(|execution| execution.result.status)
                .collect::<Vec<_>>(),
            vec![
                ExecutionStatus::Completed,
                ExecutionStatus::Skipped,
                ExecutionStatus::Failed,
                ExecutionStatus::Failed,
            ]
        );
        assert_eq!(report.status(), ExecutionStatus::Failed);

        let events: Vec<_> = std::iter::from_fn(|| receiver.try_recv().ok()).collect();
        assert!(matches!(
            events.first(),
            Some(RunEvent::Planned { scanners: 4, .. })
        ));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, RunEvent::ScanStarted { .. }))
                .count(),
            4
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, RunEvent::ScanFinished { .. }))
                .count(),
            4
        );
        assert!(matches!(
            events.last(),
            Some(RunEvent::Completed {
                status: ExecutionStatus::Failed,
                ..
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_stops_running_and_waiting_scanners()
    -> Result<(), Box<dyn std::error::Error>> {
        let scanners = vec![
            scanner(
                "first",
                Behavior::Delay(Duration::from_secs(1)),
                vec![Capability::PassiveNetwork],
            ),
            scanner(
                "second",
                Behavior::Delay(Duration::from_secs(1)),
                vec![Capability::PassiveNetwork],
            ),
        ];
        let engine = Engine::new(ScannerRegistry::new(scanners)?, Arc::new(FixedClock), 1)?;
        let cancellation = CancellationToken::new();
        let (sender, mut receiver) = broadcast::channel(16);
        let execution = tokio::spawn({
            let cancellation = cancellation.clone();
            async move {
                engine
                    .execute(
                        vec![request("first", false), request("second", false)],
                        cancellation,
                        Some(sender),
                    )
                    .await
            }
        });

        loop {
            if matches!(receiver.recv().await?, RunEvent::ScanStarted { .. }) {
                break;
            }
        }
        cancellation.cancel();
        let report = execution.await??;

        assert!(
            report
                .executions
                .iter()
                .all(|execution| execution.result.status == ExecutionStatus::Cancelled)
        );
        assert!(report.executions.iter().any(|execution| {
            execution
                .result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message == "scan cancelled before it started")
        }));
        Ok(())
    }

    #[test]
    fn scanner_failures_map_to_safe_terminal_results() {
        let cases = [
            (ScanErrorKind::Cancelled, ExecutionStatus::Cancelled),
            (
                ScanErrorKind::DependencyUnavailable,
                ExecutionStatus::Skipped,
            ),
            (ScanErrorKind::PolicyDenied, ExecutionStatus::Skipped),
            (ScanErrorKind::InvalidInput, ExecutionStatus::Failed),
            (ScanErrorKind::Timeout, ExecutionStatus::Failed),
            (ScanErrorKind::Transport, ExecutionStatus::Failed),
            (ScanErrorKind::InvalidResponse, ExecutionStatus::Failed),
            (ScanErrorKind::Internal, ExecutionStatus::Failed),
        ];
        for (kind, expected) in cases {
            let result = failed_result(ScanError::new(kind, "safe message"));
            assert_eq!(result.status, expected);
            assert!(result.findings.is_empty());
            assert!(result.evidence.is_empty());
            assert_eq!(result.diagnostics[0].message, "safe message");
        }
        assert_eq!(millis(u128::MAX), u64::MAX);
    }
}
