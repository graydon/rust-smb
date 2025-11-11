//! SMB client implementation

use crate::auth::ntlm::NtlmAuth;
use crate::error::{Error, Result};
use crate::netbios::frame::NetBiosFrame;
use crate::protocol::messages::{
    common::{FileId, Smb2Header, SmbMessage},
    file_ops::{
        Smb2CloseRequest, Smb2CreateRequest, Smb2CreateResponse, Smb2ReadRequest, Smb2ReadResponse,
        Smb2WriteRequest, Smb2WriteResponse,
    },
    negotiate::{Smb2NegotiateRequest, Smb2NegotiateResponse},
    session::{Smb2SessionSetupRequest, Smb2SessionSetupResponse},
    tree::{Smb2TreeConnectRequest, Smb2TreeConnectResponse},
};
use crate::protocol::smb2_constants::{
    CreateDisposition, CreateOptions, DesiredAccess, FileAttributes, ShareAccess,
};
use crate::protocol::smb2_constants::{
    SecurityMode,
    Smb2Capabilities,
    // SMB2_HDR_FLAG_RESPONSE,
    Smb2Command,
    Smb2Dialect,
};
use bytes::{BufMut, BytesMut};
use std::collections::HashMap;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

/// SMB client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Client GUID
    pub client_guid: Uuid,
    /// Supported dialects
    pub dialects: Vec<Smb2Dialect>,
    /// Security mode
    pub security_mode: SecurityMode,
    /// Capabilities
    pub capabilities: Smb2Capabilities,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: String,
    /// Domain for authentication
    pub domain: String,
    /// Workstation name
    pub workstation: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client_guid: Uuid::new_v4(),
            dialects: vec![
                Smb2Dialect::Smb210,
                Smb2Dialect::Smb300,
                Smb2Dialect::Smb302,
            ],
            security_mode: SecurityMode::SIGNING_ENABLED,
            capabilities: Smb2Capabilities::DFS | Smb2Capabilities::LARGE_MTU,
            username: String::new(),
            password: String::new(),
            domain: String::new(),
            workstation: String::from("RUST-SMB-CLIENT"),
        }
    }
}

/// SMB client connection state
#[derive(Debug)]
enum ConnectionState {
    Disconnected,
    Connected,
    Negotiated,
    SessionEstablished,
}

/// SMB tree connection
#[derive(Debug, Clone)]
pub struct TreeConnection {
    pub tree_id: u32,
    pub share_name: String,
}

/// Open file handle
#[derive(Debug, Clone)]
pub struct FileHandle {
    pub file_id: FileId,
    pub tree_id: u32,
    pub path: String,
}

/// SMB client
pub struct SmbClient {
    config: ClientConfig,
    stream: Option<TcpStream>,
    state: ConnectionState,
    session_id: u64,
    message_id: u64,
    server_guid: Option<Uuid>,
    dialect: Option<Smb2Dialect>,
    trees: HashMap<u32, TreeConnection>,
    open_files: HashMap<FileId, FileHandle>,
    ntlm_context: Option<NtlmAuth>,
}

impl SmbClient {
    /// Create a new SMB client with default configuration
    pub fn new() -> Self {
        Self::with_config(ClientConfig::default())
    }

    /// Create a new SMB client with custom configuration
    pub fn with_config(config: ClientConfig) -> Self {
        Self {
            config,
            stream: None,
            state: ConnectionState::Disconnected,
            session_id: 0,
            message_id: 0,
            server_guid: None,
            dialect: None,
            trees: HashMap::new(),
            open_files: HashMap::new(),
            ntlm_context: None,
        }
    }

    /// Set authentication credentials
    pub fn set_credentials(&mut self, username: &str, password: &str, domain: &str) {
        self.config.username = username.to_string();
        self.config.password = password.to_string();
        self.config.domain = domain.to_string();
    }

    /// Connect to an SMB server
    pub async fn connect(&mut self, host: &str, port: u16) -> Result<()> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr).await.map_err(|e| Error::Io(e))?;

        self.stream = Some(stream);
        self.state = ConnectionState::Connected;

        // Establish NetBIOS session if using port 139
        if port == 139 {
            self.establish_netbios_session().await?;
        }

        // Negotiate protocol
        self.negotiate().await?;

        Ok(())
    }

    /// Establish NetBIOS session
    async fn establish_netbios_session(&mut self) -> Result<()> {
        // Send NetBIOS session request
        let session_request = vec![
            0x81, // Session request
            0x00, 0x00, 0x44, // Length
            // Called name (SERVER) - encoded
            0x20, 0x45, 0x48, 0x45, 0x42, 0x45, 0x4F, 0x45, 0x46, 0x46, 0x45, 0x46, 0x45, 0x43,
            0x45, 0x4A, 0x45, 0x46, 0x46, 0x43, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41,
            0x43, 0x41, 0x43, 0x41, 0x00, // Calling name (CLIENT) - encoded
            0x20, 0x45, 0x44, 0x45, 0x42, 0x45, 0x44, 0x45, 0x4E, 0x45, 0x46, 0x45, 0x45, 0x45,
            0x50, 0x46, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
            0x41, 0x43, 0x41, 0x43, 0x41, 0x00,
        ];

        if let Some(ref mut stream) = self.stream {
            stream
                .write_all(&session_request)
                .await
                .map_err(|e| Error::Io(e))?;

            // Read response
            let mut response = vec![0u8; 4];
            stream
                .read_exact(&mut response)
                .await
                .map_err(|e| Error::Io(e))?;

            // Check for positive response
            if response[0] != 0x82 {
                return Err(Error::Protocol(
                    "NetBIOS session establishment failed".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Negotiate SMB protocol
    async fn negotiate(&mut self) -> Result<()> {
        let negotiate_req = Smb2NegotiateRequest {
            structure_size: 36,
            dialect_count: self.config.dialects.len() as u16,
            security_mode: self.config.security_mode,
            reserved: 0,
            capabilities: self.config.capabilities,
            client_guid: self.config.client_guid,
            client_start_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|e| Error::InvalidState(format!("System time error: {}", e)))?
                .as_secs(),
            dialects: self.config.dialects.clone(),
            negotiate_contexts: None,
        };

        let header = self.create_header(Smb2Command::Negotiate);
        let response = self
            .send_request(header, &negotiate_req.serialize()?)
            .await?;

        // Parse response
        let negotiate_resp = Smb2NegotiateResponse::parse(&response)?;

        self.server_guid = Some(negotiate_resp.server_guid);
        self.dialect = Some(negotiate_resp.dialect_revision);
        self.state = ConnectionState::Negotiated;

        Ok(())
    }

    /// Establish session with authentication
    pub async fn session_setup(&mut self) -> Result<()> {
        // Initialize NTLM context
        self.ntlm_context = Some(NtlmAuth::new_client(
            self.config.username.clone(),
            self.config.domain.clone(),
            self.config.workstation.clone(),
        ));

        // Send Type 1 (Negotiate) message
        let ntlm_negotiate = self
            .ntlm_context
            .as_mut()
            .ok_or_else(|| Error::InvalidState("NTLM context not initialized".to_string()))?
            .create_negotiate_message()?;

        let session_setup_req = Smb2SessionSetupRequest {
            structure_size: 25,
            flags: 0,
            security_mode: self.config.security_mode,
            capabilities: self.config.capabilities,
            channel: 0,
            security_buffer_offset: 0, // Will be calculated during serialization
            security_buffer_length: ntlm_negotiate.len() as u16,
            previous_session_id: 0,
            security_blob: ntlm_negotiate,
        };

        let header = self.create_header(Smb2Command::SessionSetup);
        let response = self
            .send_request(header, &session_setup_req.serialize()?)
            .await?;

        // Parse Type 2 (Challenge) response
        let session_resp = Smb2SessionSetupResponse::parse(&response)?;

        // Send Type 3 (Authenticate) message
        let ntlm_auth = self
            .ntlm_context
            .as_mut()
            .ok_or_else(|| Error::InvalidState("NTLM context not initialized".to_string()))?
            .create_authenticate_message(&session_resp.security_blob, &self.config.password)?;

        let session_setup_req2 = Smb2SessionSetupRequest {
            structure_size: 25,
            flags: 0,
            security_mode: self.config.security_mode,
            capabilities: self.config.capabilities,
            channel: 0,
            security_buffer_offset: 0, // Will be calculated during serialization
            security_buffer_length: ntlm_auth.len() as u16,
            previous_session_id: 0,
            security_blob: ntlm_auth,
        };

        let header2 = self.create_header(Smb2Command::SessionSetup);
        let response2 = self
            .send_request(header2, &session_setup_req2.serialize()?)
            .await?;

        // Parse final response
        let final_resp = Smb2SessionSetupResponse::parse(&response2)?;

        self.session_id = final_resp.session_flags as u64; // This should be from header
        self.state = ConnectionState::SessionEstablished;

        Ok(())
    }

    /// Connect to a share
    pub async fn tree_connect(&mut self, share: &str) -> Result<u32> {
        let tree_connect_req = Smb2TreeConnectRequest {
            structure_size: 9,
            flags: 0,
            path_offset: 0,
            path_length: 0,
            path: format!("\\\\{}\\{}", self.get_server_name(), share),
        };

        let header = self.create_header(Smb2Command::TreeConnect);
        let response = self
            .send_request(header, &tree_connect_req.serialize()?)
            .await?;

        let _tree_resp = Smb2TreeConnectResponse::parse(&response)?;
        let tree_id = 1; // Should be from response header

        self.trees.insert(
            tree_id,
            TreeConnection {
                tree_id,
                share_name: share.to_string(),
            },
        );

        Ok(tree_id)
    }

    /// Open a file
    pub async fn open_file(
        &mut self,
        tree_id: u32,
        path: &str,
        access: DesiredAccess,
        disposition: CreateDisposition,
    ) -> Result<FileHandle> {
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: access,
            file_attributes: FileAttributes::NORMAL,
            share_access: ShareAccess::FILE_SHARE_READ | ShareAccess::FILE_SHARE_WRITE,
            create_disposition: disposition,
            create_options: CreateOptions::empty(),
            name_offset: 0,
            name_length: (path.len() * 2) as u16, // UTF-16 length
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: path.to_string(),
            create_contexts: Vec::new(),
        };

        let header = self.create_header(Smb2Command::Create);
        // Set tree_id in header

        let response = self.send_request(header, &create_req.serialize()?).await?;
        let create_resp = Smb2CreateResponse::parse(&response)?;

        let handle = FileHandle {
            file_id: create_resp.file_id,
            tree_id,
            path: path.to_string(),
        };

        self.open_files.insert(create_resp.file_id, handle.clone());

        Ok(handle)
    }

    /// Read from a file
    pub async fn read_file(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>> {
        let read_req = Smb2ReadRequest {
            structure_size: 49,
            padding: 0,
            flags: 0,
            length,
            offset,
            file_id: handle.file_id,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            read_channel_info: Vec::new(),
        };

        let header = self.create_header(Smb2Command::Read);
        let response = self.send_request(header, &read_req.serialize()?).await?;

        let read_resp = Smb2ReadResponse::parse(&response)?;
        Ok(read_resp.data)
    }

    /// Write to a file
    pub async fn write_file(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        data: &[u8],
    ) -> Result<u32> {
        let write_req = Smb2WriteRequest {
            structure_size: 49,
            data_offset: 112, // Header + request size
            length: data.len() as u32,
            offset,
            file_id: handle.file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: data.to_vec(),
        };

        let header = self.create_header(Smb2Command::Write);
        let response = self.send_request(header, &write_req.serialize()?).await?;

        let write_resp = Smb2WriteResponse::parse(&response)?;
        Ok(write_resp.count)
    }

    /// Close a file
    pub async fn close_file(&mut self, handle: &FileHandle) -> Result<()> {
        let close_req = Smb2CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id: handle.file_id,
        };

        let header = self.create_header(Smb2Command::Close);
        let _response = self.send_request(header, &close_req.serialize()?).await?;

        self.open_files.remove(&handle.file_id);
        Ok(())
    }

    /// Disconnect from the server
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await.map_err(|e| Error::Io(e))?;
        }

        self.state = ConnectionState::Disconnected;
        self.session_id = 0;
        self.trees.clear();
        self.open_files.clear();

        Ok(())
    }

    /// Create SMB2 header for requests
    fn create_header(&mut self, command: Smb2Command) -> Smb2Header {
        let mut header = Smb2Header::new_with_command(command);
        header.message_id = self.get_next_message_id();
        header.session_id = self.session_id;
        header.tree_id = 0;
        header
    }

    /// Send request and receive response
    async fn send_request(&mut self, header: Smb2Header, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(ref mut stream) = self.stream {
            // Build complete message
            let mut message = BytesMut::new();
            message.put_slice(&header.serialize()?);
            message.put_slice(data);

            // Wrap in NetBIOS frame if needed
            let frame = NetBiosFrame::new_session_message(message.to_vec())?;
            stream
                .write_all(&frame.to_bytes())
                .await
                .map_err(|e| Error::Io(e))?;

            // Read response
            let mut netbios_header = [0u8; 4];
            stream
                .read_exact(&mut netbios_header)
                .await
                .map_err(|e| Error::Io(e))?;

            let length = ((netbios_header[1] as usize) << 16)
                | ((netbios_header[2] as usize) << 8)
                | (netbios_header[3] as usize);

            let mut response = vec![0u8; length];
            stream
                .read_exact(&mut response)
                .await
                .map_err(|e| Error::Io(e))?;

            // Skip SMB2 header in response and return body
            if response.len() >= 64 {
                Ok(response[64..].to_vec())
            } else {
                Err(Error::Protocol("Invalid response size".to_string()))
            }
        } else {
            Err(Error::ConnectionError("Not connected".to_string()))
        }
    }

    /// Get next message ID
    fn get_next_message_id(&mut self) -> u64 {
        self.message_id += 1;
        self.message_id
    }

    /// Get server name from stream
    fn get_server_name(&self) -> String {
        // In real implementation, this would be from the connection
        "server".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = SmbClient::new();
        assert!(matches!(client.state, ConnectionState::Disconnected));
    }

    #[test]
    fn test_client_config() {
        let config = ClientConfig {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            domain: "TESTDOMAIN".to_string(),
            ..Default::default()
        };

        let client = SmbClient::with_config(config.clone());
        assert_eq!(client.config.username, "testuser");
        assert_eq!(client.config.domain, "TESTDOMAIN");
    }

    #[test]
    fn test_set_credentials() {
        let mut client = SmbClient::new();
        client.set_credentials("user", "pass", "domain");

        assert_eq!(client.config.username, "user");
        assert_eq!(client.config.password, "pass");
        assert_eq!(client.config.domain, "domain");
    }
}
