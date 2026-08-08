//! Concrete network and provider boundaries.

mod command;
mod dns;
mod http_client;
mod provider;
mod system;
mod tcp;
mod tls;
mod udp;

pub use command::SystemCommand;
pub use dns::{DnsAdapterError, HickoryDns};
pub use http_client::ReqwestHttp;
pub use provider::ReqwestProvider;
pub use system::SystemClock;
pub use tcp::TokioTcp;
pub use tls::{RustlsTls, TlsAdapterError};
pub use udp::TokioUdp;
