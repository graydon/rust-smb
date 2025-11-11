//! SMB Protocol Implementation in Rust
//!
//! A safe, modular, sans-io SMB protocol implementation supporting both client and server roles.

#![allow(missing_docs)]
#![forbid(unsafe_code)]

pub mod dcerpc;
pub mod error;
pub mod filesystem;
pub mod netbios;
pub mod protocol;
pub mod transport;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub mod auth;

#[cfg(test)]
pub mod e2e_tests;

pub use error::{Error, Result};
