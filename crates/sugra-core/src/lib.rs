//! Application services, execution, policy, storage, and reporting.

mod catalog;
mod engine;
mod options;
mod policy;
mod ports;
mod report;
mod scanner;
mod store;

pub use catalog::{Catalog, CatalogError};
pub use engine::{Engine, EngineError, RunEvent, ScannerRegistry};
pub use options::{OptionError, resolve_options};
pub use policy::{PolicyDecision, PolicyError, evaluate_policy};
pub use ports::{
    Clock, CommandKind, CommandPort, CommandRequest, CommandResponse, DnsFlagState, DnsPort,
    DnsQuery, DnsRecord, DnsRecordType, DnsRecursionObservation, DnsRecursionRequest, HttpCookie,
    HttpMethod, HttpPort, HttpRedirect, HttpRedirectDecision, HttpRequest, HttpResponse,
    LocalInputPort, LocalInputRequest, LocalInputResponse, PortError, PortErrorKind, ProviderPort,
    ProviderRequest, ProviderResponse, QuicObservation, QuicRequest, ServiceBundle, TcpPort,
    TcpRequest, TcpResponse, TlsCertificate, TlsHandshakeKind, TlsObservation, TlsPort, TlsRequest,
    UdpPort, UdpRequest, UdpResponse,
};
pub use report::{render_csv, render_html, render_terminal};
pub use scanner::{ScanContext, ScanError, ScanErrorKind, Scanner};
pub use store::{Artifact, RunStore, StoreError};
