//! Internal definition model and validated built-in bundle.

use sugra_core::{Catalog, CatalogError, EngineError, ScannerRegistry};
use sugra_domain::{ScannerDescriptor, ScannerId};
use thiserror::Error;

/// Reusable implementation family selected for a scanner descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Public DNS record analysis.
    Dns,
    /// Bounded HTTP observation and document analysis.
    Http,
    /// Certificate-validating TLS handshake analysis.
    Tls,
    /// Public registration and routing provider analysis.
    Registry,
    /// Optional security-intelligence provider analysis.
    Intelligence,
    /// Bounded TCP protocol probe.
    Tcp,
    /// Bounded UDP protocol probe.
    Udp,
    /// Allowlisted operating-system command.
    Command,
    /// Pure local parsing or generation.
    Local,
}

/// One compiled built-in definition before construction of the public catalog.
#[derive(Debug, Clone)]
pub(crate) struct ScannerDefinition {
    pub(crate) descriptor: ScannerDescriptor,
    pub(crate) operation: Operation,
}

/// Validated catalog and implementation registry.
pub struct Builtins {
    /// Public metadata catalog.
    pub catalog: Catalog,
    /// Concrete scanner registry consumed by the engine.
    pub registry: ScannerRegistry,
}

/// Failure while constructing the compiled scanner set.
#[derive(Debug, Error)]
pub enum BuiltinError {
    /// Generated scanner identity violated canonical syntax.
    #[error("invalid built-in scanner ID: {0}")]
    InvalidId(#[from] sugra_domain::DomainError),
    /// Descriptor catalog violated an invariant.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// Implementation registry violated an invariant.
    #[error(transparent)]
    Registry(#[from] EngineError),
    /// Descriptor and implementation sets differ.
    #[error("descriptor and implementation sets differ at scanner {0}")]
    SetMismatch(ScannerId),
    /// A scanner has no explicit semantic ownership contract.
    #[error("scanner has no explicit semantic contract: {0}")]
    MissingSemantics(ScannerId),
    /// Compiled operation and semantic boundary disagree.
    #[error("scanner operation disagrees with its semantic boundary: {0}")]
    SemanticBoundaryMismatch(ScannerId),
}
