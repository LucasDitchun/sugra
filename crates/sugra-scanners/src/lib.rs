//! Built-in scanner implementations and catalog.

mod catalog_data;
mod definition;
mod implementation;
mod semantics;
mod web;

pub use definition::{BuiltinError, Builtins, Operation};
pub use implementation::build_builtins;
