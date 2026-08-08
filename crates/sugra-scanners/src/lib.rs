//! Built-in scanner implementations and catalog.

mod catalog_data;
mod definition;
mod dns_analysis;
mod implementation;
mod provider_analysis;
mod semantics;
mod web;
mod web_analysis;

pub use definition::{BuiltinError, Builtins, Operation};
pub use implementation::build_builtins;
