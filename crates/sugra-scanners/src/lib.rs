//! Built-in scanner implementations and catalog.

mod catalog_data;
mod definition;
mod dns_analysis;
mod implementation;
mod network_analysis;
mod provider_analysis;
mod provider_plan;
mod semantics;
mod tls_analysis;
mod web;
mod web_analysis;

pub use definition::{BuiltinError, Builtins, Operation};
pub use implementation::build_builtins;
