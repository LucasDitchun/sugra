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
    Clock, CommandKind, CommandPort, CommandRequest, CommandResponse, DnsPort, DnsQuery, DnsRecord,
    DnsRecordType, HttpMethod, HttpPort, HttpRequest, HttpResponse, PortError, PortErrorKind,
    ProviderPort, ProviderRequest, ProviderResponse, ServiceBundle, TcpPort, TcpRequest,
    TcpResponse, TlsObservation, TlsPort, TlsRequest, UdpPort, UdpRequest, UdpResponse,
};
pub use report::{render_csv, render_html, render_terminal};
pub use scanner::{ScanContext, ScanError, ScanErrorKind, Scanner};
pub use store::{Artifact, RunStore, StoreError};
