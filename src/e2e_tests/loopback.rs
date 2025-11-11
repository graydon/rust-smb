//! Loopback testing framework for SMB client-server communication
//!
//! This module provides in-process testing of SMB client and server
//! without requiring actual network connections.

use crate::error::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A loopback transport that connects client and server in-process
pub struct LoopbackTransport {
    _client_stream: Option<TcpStream>,
    _server_stream: Option<TcpStream>,
}

impl LoopbackTransport {
    /// Create a new loopback transport pair using TCP on localhost
    pub async fn new() -> Result<(TcpStream, TcpStream)> {
        // Bind to a random port on localhost
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Connect client to server
        let client_future = TcpStream::connect(addr);
        let server_future = async { listener.accept().await.map(|(stream, _)| stream) };

        let (client_stream, server_stream) = tokio::try_join!(client_future, server_future)?;

        Ok((client_stream, server_stream))
    }

    /// Create a loopback transport using Unix domain sockets (Linux/macOS only)
    #[cfg(unix)]
    pub async fn new_unix() -> Result<(tokio::net::UnixStream, tokio::net::UnixStream)> {
        use tempfile::tempdir;
        use tokio::net::{UnixListener, UnixStream};

        // Create a temporary directory for the socket
        let dir = tempdir()?;
        let socket_path = dir.path().join("test.sock");

        // Create listener
        let listener = UnixListener::bind(&socket_path)?;

        // Connect client to server
        let client_future = UnixStream::connect(&socket_path);
        let server_future = async { listener.accept().await.map(|(stream, _)| stream) };

        let (client_stream, server_stream) = tokio::try_join!(client_future, server_future)?;

        Ok((client_stream, server_stream))
    }
}

/// Test harness for running SMB client-server tests
pub struct TestHarness {
    server_handle: Option<tokio::task::JoinHandle<Result<()>>>,
    client_stream: Option<TcpStream>,
}

impl TestHarness {
    /// Create a new test harness with loopback connection
    pub async fn new() -> Result<Self> {
        let (client_stream, server_stream) = LoopbackTransport::new().await?;

        // Start server task
        let server_handle = tokio::spawn(async move {
            use crate::server::connection::ConnectionHandler;
            use crate::server::real_filesystem::RealFileSystem;
            use tempfile::tempdir;

            // Create temporary directory for test filesystem
            let test_dir = tempdir()?;
            let filesystem = Arc::new(RealFileSystem::new(test_dir.path()));

            // Create default shares for testing
            let shares = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
            {
                let mut shares_guard = shares.write().await;
                shares_guard.insert(
                    "PUBLIC".to_string(),
                    crate::server::ShareInfo {
                        name: "public".to_string(),
                        description: "Test share".to_string(),
                        path: test_dir.path().to_str().unwrap_or("/tmp").to_string(),
                        share_type: 0x01, // Disk share
                    },
                );
            }

            // Handle connection
            let mut handler = ConnectionHandler::new(server_stream, filesystem, shares);
            handler.handle().await
        });

        Ok(Self {
            server_handle: Some(server_handle),
            client_stream: Some(client_stream),
        })
    }

    /// Get the client stream for testing
    pub fn client_stream(&mut self) -> Option<TcpStream> {
        self.client_stream.take()
    }

    /// Shutdown the test harness
    pub async fn shutdown(self) -> Result<()> {
        // Close client connection
        if let Some(mut stream) = self.client_stream {
            stream.shutdown().await.ok();
        }

        // Wait for server to finish
        if let Some(handle) = self.server_handle {
            handle.await.ok();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_loopback_transport() {
        let (mut client, mut server) = LoopbackTransport::new().await.unwrap();

        // Test bidirectional communication
        let test_data = b"Hello, SMB!";

        // Client sends data
        client.write_all(test_data).await.unwrap();

        // Server receives data
        let mut buf = vec![0u8; test_data.len()];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);

        // Server sends response
        let response = b"ACK";
        server.write_all(response).await.unwrap();

        // Client receives response
        let mut buf = vec![0u8; response.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, response);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_unix_loopback() {
        let (mut client, mut server) = LoopbackTransport::new_unix().await.unwrap();

        // Test bidirectional communication
        let test_data = b"Unix socket test";

        // Client sends data
        client.write_all(test_data).await.unwrap();

        // Server receives data
        let mut buf = vec![0u8; test_data.len()];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);
    }
}
