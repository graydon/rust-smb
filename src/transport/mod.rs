//! Transport layer for SMB protocol
//!
//! This module provides the tokio-based async transport layer that handles
//! network I/O while keeping the protocol logic separate (sans-io design)

use crate::error::Result;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;

pub mod tcp;

/// Trait for SMB transport implementations
#[async_trait]
pub trait SmbTransport: Send + Sync {
    /// Connect to a remote SMB server
    async fn connect(&mut self, addr: SocketAddr) -> Result<()>;

    /// Send data to the remote endpoint
    async fn send(&mut self, data: Bytes) -> Result<()>;

    /// Receive data from the remote endpoint
    async fn receive(&mut self) -> Result<BytesMut>;

    /// Check if the transport is connected
    fn is_connected(&self) -> bool;

    /// Close the connection
    async fn close(&mut self) -> Result<()>;

    /// Get the local address
    fn local_addr(&self) -> Result<SocketAddr>;

    /// Get the remote address
    fn remote_addr(&self) -> Result<SocketAddr>;
}
