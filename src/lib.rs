//! wasmscout — audit a WebAssembly binary before you run it.
//!
//! Parses the core wasm binary format with plain `std`, maps every import to
//! a capability (the WASI preview 1 catalog, preview 2 interface prefixes,
//! custom host modules), decodes well-known custom sections, and turns the
//! result into findings a CI gate can act on.

#![forbid(unsafe_code)]

pub mod audit;
pub mod builder;
pub mod caps;
pub mod cli;
pub mod custom;
pub mod json;
pub mod reader;
pub mod report;
pub mod types;
pub mod wasi;
pub mod wasm;

/// Crate version, single source of truth for `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
