//! SMB server implementation

pub mod connection;
pub mod enumeration;
pub mod filesystem;
pub mod pipes;
pub mod real_filesystem;

use crate::error::{Error, Result};
use crate::transport::tcp::TcpTransport;
use connection::ConnectionHandler;
use filesystem::{FileSystem, MemoryFileSystem};
use real_filesystem::RealFileSystem;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// SMB server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server name
    pub server_name: String,
    /// Server description
    pub server_description: String,
    /// Workgroup/domain name
    pub workgroup: String,
    /// Enable guest access
    pub allow_guest: bool,
    /// Require signing
    pub require_signing: bool,
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_name: "RUST-SMB-SERVER".to_string(),
            server_description: "Rust SMB Server".to_string(),
            workgroup: "WORKGROUP".to_string(),
            allow_guest: true,
            require_signing: false,
            max_connections: 100,
        }
    }
}

/// Share information
#[derive(Debug, Clone)]
pub struct ShareInfo {
    /// Share name
    pub name: String,
    /// Share description
    pub description: String,
    /// Filesystem path
    pub path: String,
    /// Share type (disk, print, etc.)
    pub share_type: u8,
}

/// SMB server
pub struct SmbServer {
    config: ServerConfig,
    filesystem: Arc<dyn FileSystem>,
    shares: Arc<RwLock<HashMap<String, ShareInfo>>>,
}

impl SmbServer {
    /// Create a new SMB server with default config
    pub fn new() -> Self {
        Self::with_config(ServerConfig::default())
    }

    /// Create a new SMB server with custom config
    pub fn with_config(config: ServerConfig) -> Self {
        Self {
            config,
            filesystem: Arc::new(MemoryFileSystem::new()),
            shares: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set a custom filesystem
    pub fn with_filesystem(mut self, filesystem: Arc<dyn FileSystem>) -> Self {
        self.filesystem = filesystem;
        self
    }

    /// Use a real filesystem backend with the specified root directory
    pub fn with_real_filesystem<P: AsRef<std::path::Path>>(mut self, root_path: P) -> Self {
        self.filesystem = Arc::new(RealFileSystem::new(root_path));
        self
    }

    /// Add a share to the server
    pub async fn add_share(&self, name: &str, description: &str, path: &str) {
        let share = ShareInfo {
            name: name.to_string(),
            description: description.to_string(),
            path: path.to_string(),
            share_type: 0, // DISK_SHARE
        };

        let mut shares = self.shares.write().await;
        shares.insert(name.to_uppercase(), share);
    }

    /// Run the SMB server on the specified address
    pub async fn run(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("SMB server listening on {}", addr);
        info!("Server name: {}", self.config.server_name);
        info!("Workgroup: {}", self.config.workgroup);

        // Check if we're on NetBIOS port (139) or Direct TCP port (445 or other)
        let use_netbios = addr.port() == 139;

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            info!("New connection from {}", remote_addr);

            let filesystem = Arc::clone(&self.filesystem);
            let shares = Arc::clone(&self.shares);

            // Spawn a task to handle the connection
            tokio::spawn(async move {
                let mut transport = TcpTransport::from_stream(stream);

                // Only do NetBIOS session establishment on port 139
                if use_netbios {
                    // Wait for NetBIOS session request
                    match transport.receive_netbios_message().await {
                        Ok(_data) => {
                            // We expect a NetBIOS session request
                            // For now, always send positive response
                            match crate::netbios::NetBiosMessage::positive_response() {
                                Ok(response) => {
                                    if let Err(e) =
                                        transport.send_netbios_message(&response.to_bytes()).await
                                    {
                                        error!("Failed to send NetBIOS response: {}", e);
                                        return;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to create NetBIOS positive response: {}", e);
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to receive NetBIOS request: {}", e);
                            return;
                        }
                    }
                }

                // Now handle SMB protocol
                let mut handler =
                    ConnectionHandler::from_transport(transport, filesystem, shares.clone());

                if let Err(e) = handler.handle().await {
                    error!("Connection error from {}: {}", remote_addr, e);
                }

                debug!("Connection from {} closed", remote_addr);
            });
        }
    }

    /// Run server on standard SMB port (445)
    pub async fn run_standard(&self) -> Result<()> {
        let addr = "0.0.0.0:445"
            .parse()
            .map_err(|e| Error::InvalidParameter(format!("Invalid address: {}", e)))?;
        self.run(addr).await
    }

    /// Run server on NetBIOS port (139)
    pub async fn run_netbios(&self) -> Result<()> {
        let addr = "0.0.0.0:139"
            .parse()
            .map_err(|e| Error::InvalidParameter(format!("Invalid address: {}", e)))?;
        self.run(addr).await
    }
}

impl Default for SmbServer {
    fn default() -> Self {
        Self::new()
    }
}
