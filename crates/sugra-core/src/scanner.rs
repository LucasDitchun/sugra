//! Scanner contract and typed failures.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sugra_domain::{RunId, ScanRequest, ScanResult, ScannerDescriptor};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::Clock;

/// Categories of scanner failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanErrorKind {
    /// Request violates scanner-specific validation.
    InvalidInput,
    /// Scope or authorization policy rejected the operation.
    PolicyDenied,
    /// Optional provider, tool, or credential is unavailable.
    DependencyUnavailable,
    /// Time budget expired.
    Timeout,
    /// Parent run was cancelled.
    Cancelled,
    /// Transport boundary failed.
    Transport,
    /// Response violated its expected protocol or schema.
    InvalidResponse,
    /// Unexpected internal invariant failure.
    Internal,
}

/// Safe scanner failure without secrets or raw response bodies.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("{message}")]
pub struct ScanError {
    /// Stable failure category.
    pub kind: ScanErrorKind,
    /// Safe user-facing message.
    pub message: String,
}

impl ScanError {
    /// Constructs a typed scanner failure.
    #[must_use]
    pub fn new(kind: ScanErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// Runtime context shared with a scanner invocation.
#[derive(Clone)]
pub struct ScanContext {
    /// Parent run identity.
    pub run_id: RunId,
    /// Cooperative cancellation token.
    pub cancellation: CancellationToken,
    /// Injectable clock.
    pub clock: Arc<dyn Clock>,
}

/// Stateless typed scanner implementation.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Returns immutable scanner metadata.
    fn descriptor(&self) -> &ScannerDescriptor;

    /// Executes one validated request.
    async fn scan(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError>;
}
