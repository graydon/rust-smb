//! Test context for end-to-end testing
//!
//! Provides a unified test context that manages client transport, server task, and test directory
//! for all end-to-end tests.

use super::loopback::LoopbackTransport;
use crate::error::Result;
use crate::server::connection::ConnectionHandler;
use crate::server::real_filesystem::RealFileSystem;
use crate::transport::tcp::TcpTransport;
use crate::transport::SmbTransport;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::task::JoinHandle;

/// Test context that manages client transport, server task, and test directory
pub struct TestContext {
    pub client_transport: TcpTransport,
    pub server_task: JoinHandle<Result<()>>,
    pub test_dir: TempDir,
}

impl TestContext {
    /// Create a new test context with connected client and server
    pub async fn new() -> Result<Self> {
        // Create temporary directory for test filesystem
        let test_dir = tempfile::tempdir()?;
        let test_path = test_dir.path().to_path_buf();

        // Create loopback connection
        let (client_stream, server_stream) = LoopbackTransport::new().await?;

        // Start server in background task
        let filesystem = Arc::new(RealFileSystem::new(&test_path));

        // Create default shares for testing
        let shares = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
        {
            let mut shares_guard = shares.write().await;
            shares_guard.insert(
                "PUBLIC".to_string(),
                crate::server::ShareInfo {
                    name: "public".to_string(),
                    description: "Test share".to_string(),
                    path: test_path.to_str().unwrap_or("/tmp").to_string(),
                    share_type: 0x01, // Disk share
                },
            );
        }

        let server_task = tokio::spawn(async move {
            let mut handler = ConnectionHandler::new(server_stream, filesystem, shares);
            handler.handle().await
        });

        // Create client transport
        let client_transport = TcpTransport::from_stream(client_stream);

        Ok(Self {
            client_transport,
            server_task,
            test_dir,
        })
    }

    /// Shutdown the test context cleanly
    pub async fn shutdown(mut self) -> Result<()> {
        // Close the transport
        self.client_transport.close().await?;

        // Wait for server to finish (ignore errors from server abort)
        let _ = self.server_task.await;

        Ok(())
    }
}
