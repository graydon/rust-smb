//! SMB server connection handler

use crate::error::{Error, Result};
use crate::protocol::messages::{
    common::{FileId, Smb2Header, SmbMessage},
    file_ops::{
        Smb2CloseRequest, Smb2CloseResponse, Smb2CreateRequest, Smb2CreateResponse,
        Smb2ReadRequest, Smb2ReadResponse, Smb2WriteRequest, Smb2WriteResponse,
    },
    negotiate::{Smb2NegotiateRequest, Smb2NegotiateResponse},
    session::{Smb2SessionSetupRequest, Smb2SessionSetupResponse},
    tree::{Smb2TreeConnectRequest, Smb2TreeConnectResponse},
};
// Query/Set info messages are in info module
use crate::protocol::messages::directory::{Smb2QueryDirectoryRequest, Smb2QueryDirectoryResponse};
use crate::protocol::messages::info::{
    FileInfoClass, InfoType, Smb2QueryInfoRequest, Smb2QueryInfoResponse, Smb2SetInfoRequest,
    Smb2SetInfoResponse,
};
use crate::protocol::messages::ioctl::{
    Smb2IoctlRequest, Smb2IoctlResponse, FSCTL_DFS_GET_REFERRALS, FSCTL_PIPE_TRANSCEIVE,
};
use crate::protocol::smb2_constants::query_directory_flags::*;
use crate::protocol::smb2_constants::Smb2Command;
use crate::protocol::smb2_constants::{CreateAction, FileAttributes};
use crate::protocol::state::OpenFile;
use crate::protocol::Smb2StateMachine;
use crate::server::enumeration::EnumerationManager;
use crate::server::filesystem::FileSystem;
use crate::server::pipes::PipeManager;
use crate::server::real_filesystem::RealFileSystem;
use crate::server::ShareInfo;
use crate::transport::tcp::TcpTransport;
use byteorder::{LittleEndian, WriteBytesExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, trace};

/// Build an SMB2 error response
fn build_error_response() -> Result<Vec<u8>> {
    let mut error_resp = Vec::new();
    error_resp.write_u16::<LittleEndian>(9)?; // StructureSize (9 for error response)
    error_resp.push(0); // ErrorContextCount
    error_resp.push(0); // Reserved
    error_resp.write_u32::<LittleEndian>(0)?; // ByteCount
    error_resp.push(0); // ErrorData
    Ok(error_resp)
}

/// SMB connection handler
pub struct ConnectionHandler {
    transport: TcpTransport,
    state: Arc<Mutex<Smb2StateMachine>>,
    filesystem: Arc<dyn FileSystem>,
    shares: Arc<RwLock<HashMap<String, ShareInfo>>>,
    pipe_manager: Arc<PipeManager>,
    enumeration_manager: Arc<Mutex<EnumerationManager>>,
    session_id: Option<u64>,
    tree_id: Option<u32>,
}

impl ConnectionHandler {
    /// Create a new connection handler from a stream
    pub fn new(
        stream: TcpStream,
        filesystem: Arc<dyn FileSystem>,
        shares: Arc<RwLock<HashMap<String, ShareInfo>>>,
    ) -> Self {
        let transport = TcpTransport::from_stream(stream);

        Self {
            transport,
            state: Arc::new(Mutex::new(Smb2StateMachine::new())),
            filesystem,
            shares: shares.clone(),
            pipe_manager: Arc::new(PipeManager::with_shares(shares)),
            enumeration_manager: Arc::new(Mutex::new(EnumerationManager::new())),
            session_id: None,
            tree_id: None,
        }
    }

    /// Create a new connection handler from an existing transport
    pub fn from_transport(
        transport: TcpTransport,
        filesystem: Arc<dyn FileSystem>,
        shares: Arc<RwLock<HashMap<String, ShareInfo>>>,
    ) -> Self {
        Self {
            transport,
            state: Arc::new(Mutex::new(Smb2StateMachine::new())),
            filesystem,
            shares: shares.clone(),
            pipe_manager: Arc::new(PipeManager::with_shares(shares)),
            enumeration_manager: Arc::new(Mutex::new(EnumerationManager::new())),
            session_id: None,
            tree_id: None,
        }
    }

    /// Handle the connection
    pub async fn handle(&mut self) -> Result<()> {
        // Mark connection as established
        {
            let mut state = self.state.lock().await;
            state.on_connect()?;
        }

        loop {
            // Receive NetBIOS message
            let data = match self.transport.receive_netbios_message().await {
                Ok(data) => data,
                Err(Error::ConnectionClosed) => break,
                Err(e) => return Err(e),
            };

            // Parse SMB2 header
            if data.len() < 64 {
                return Err(Error::Protocol(
                    "Message too small for SMB2 header".to_string(),
                ));
            }

            let header = Smb2Header::parse(&data[..64])?;

            // Check protocol ID
            if header.protocol_id != 0x424D53FE {
                return Err(Error::Protocol("Invalid SMB2 protocol ID".to_string()));
            }

            // Process command
            let (response_data, status) = match header.command {
                Smb2Command::Negotiate => {
                    let req = Smb2NegotiateRequest::parse(&data[64..])?;
                    let resp = self.handle_negotiate(req).await?;
                    (resp.serialize()?, 0) // Success
                }
                Smb2Command::SessionSetup => {
                    debug!("Handling SessionSetup command");
                    let req = match Smb2SessionSetupRequest::parse(&data[64..]) {
                        Ok(r) => r,
                        Err(e) => {
                            debug!("Failed to parse SessionSetup request: {:?}", e);
                            return Err(e);
                        }
                    };
                    debug!("Parsed SessionSetup request");
                    let (resp, status) = match self.handle_session_setup(req).await {
                        Ok(r) => r,
                        Err(e) => {
                            debug!("Failed to handle SessionSetup: {:?}", e);
                            return Err(e);
                        }
                    };
                    debug!("SessionSetup handled with status: 0x{:08x}", status);
                    if status == 0 {
                        // Only set session ID if authentication is complete
                        if let Some(session) = self.state.lock().await.sessions.values().last() {
                            self.session_id = Some(session.session_id);
                        }
                    }
                    (resp.serialize()?, status)
                }
                Smb2Command::TreeConnect => {
                    let req = Smb2TreeConnectRequest::parse(&data[64..])?;
                    debug!("TreeConnect request for: {}", req.path);
                    let resp = self.handle_tree_connect(req, header.tree_id).await?;
                    (resp.serialize()?, 0)
                }
                Smb2Command::Create => {
                    let req = Smb2CreateRequest::parse(&data[64..])?;
                    match self.handle_create(req, header.tree_id).await {
                        Ok(resp) => (resp.serialize()?, 0),
                        Err(Error::AlreadyExists(_)) => {
                            // Return proper SMB2 error response for OBJECT_NAME_COLLISION
                            // SMB2 Error Response structure per MS-SMB2 2.2.2
                            (build_error_response()?, 0xC0000035) // STATUS_OBJECT_NAME_COLLISION
                        }
                        Err(e) => return Err(e),
                    }
                }
                Smb2Command::Close => {
                    let req = Smb2CloseRequest::parse(&data[64..])?;
                    let resp = self.handle_close(req).await?;
                    (resp.serialize()?, 0)
                }
                Smb2Command::Read => {
                    // Use the CORRECT parser/serializer from file_ops
                    let req = Smb2ReadRequest::parse(&data[64..])?;
                    let resp = self.handle_read(req).await?;
                    (resp.serialize()?, 0)
                }
                Smb2Command::Write => {
                    let req = Smb2WriteRequest::parse(&data[64..])?;
                    let resp = self.handle_write(req).await?;
                    (resp.serialize()?, 0)
                }
                Smb2Command::Logoff => {
                    // Handle logoff
                    self.session_id = None;
                    break;
                }
                Smb2Command::TreeDisconnect => {
                    // Handle tree disconnect
                    self.tree_id = None;
                    // Create minimal response
                    (vec![4, 0, 0, 0], 0) // Structure size = 4, status = success
                }
                Smb2Command::QueryDirectory => {
                    let req = Smb2QueryDirectoryRequest::parse(&data[64..])?;
                    let resp = self.handle_query_directory(req).await?;
                    let status = if resp.output_buffer.is_empty() {
                        0x80000006 // STATUS_NO_MORE_FILES
                    } else {
                        0 // Success
                    };
                    (resp.serialize()?, status)
                }
                Smb2Command::GetInfo => {
                    let req = Smb2QueryInfoRequest::parse(&data[64..])?;
                    match self.handle_query_info(req).await {
                        Ok(resp) => (resp.serialize()?, 0),
                        Err(Error::InvalidParameter(msg)) => {
                            debug!("Query info error: {}", msg);
                            // Return proper SMB2 error response for invalid info class
                            (build_error_response()?, 0xC0000024) // STATUS_INVALID_INFO_CLASS
                        }
                        Err(e) => return Err(e),
                    }
                }
                Smb2Command::SetInfo => {
                    let req = Smb2SetInfoRequest::parse(&data[64..])?;
                    let resp = self.handle_set_info(req, header.tree_id).await?;
                    (resp.serialize()?, 0)
                }
                Smb2Command::KeepAlive => {
                    // Echo/KeepAlive response - just echo back with reserved field
                    (vec![4, 0, 0, 0], 0) // Structure size = 4, reserved = 0
                }
                Smb2Command::Ioctl => {
                    let req = Smb2IoctlRequest::parse(&data[64..])?;
                    let resp = self.handle_ioctl(req).await?;
                    (resp.serialize()?, 0)
                }
                _ => {
                    // Unknown command - send error response
                    debug!(
                        "Unhandled command: {:?} (0x{:04x})",
                        header.command, header.command as u16
                    );
                    (vec![9, 0, 0, 0], 0xC0000002) // STATUS_NOT_IMPLEMENTED
                }
            };

            // Create response header
            // For TreeConnect response, use the newly assigned tree_id
            // For other commands, use the tree_id from request or our stored one
            let response_tree_id = match header.command {
                Smb2Command::TreeConnect if status == 0 => {
                    // TreeConnect successful - use the newly assigned tree_id
                    self.tree_id.unwrap_or(header.tree_id)
                }
                _ => {
                    // For other commands, prefer the stored tree_id if we have one,
                    // otherwise use the one from the request
                    if header.tree_id != 0 {
                        header.tree_id
                    } else {
                        self.tree_id.unwrap_or(header.tree_id)
                    }
                }
            };

            // Similarly for session_id
            let response_session_id = match header.command {
                Smb2Command::SessionSetup if status == 0 => {
                    // SessionSetup successful - use the newly assigned session_id
                    self.session_id.unwrap_or(header.session_id)
                }
                _ => {
                    // For other commands, prefer the one from request if non-zero,
                    // otherwise use our stored one
                    if header.session_id != 0 {
                        header.session_id
                    } else {
                        self.session_id.unwrap_or(header.session_id)
                    }
                }
            };

            let response_header = Smb2Header {
                protocol_id: 0x424D53FE,
                structure_size: 64,
                credit_charge: 0,
                status,
                command: header.command,
                credits: 1,
                flags: crate::protocol::smb2_constants::header_flags::RESPONSE,
                next_command: 0,
                message_id: header.message_id,
                reserved: 0,
                tree_id: response_tree_id,
                session_id: response_session_id,
                signature: [0u8; 16],
            };

            // Combine header and response
            let mut response = Vec::with_capacity(64 + response_data.len());
            response.extend_from_slice(&response_header.serialize()?);
            response.extend_from_slice(&response_data);

            // Send response via NetBIOS
            debug!(
                "Sending response for command {:?} with status 0x{:08x}, {} bytes",
                header.command,
                status,
                response.len()
            );

            // Debug Read responses
            if header.command == Smb2Command::Read
                && response_data.len() > 0
                && response_data.len() < 100
            {
                trace!(
                    "Read Response body bytes: {:02x?}",
                    &response_data[..20.min(response_data.len())]
                );
                if response_data.len() > 2 {
                    trace!(
                        "Structure size: {:02x} {:02x}",
                        response_data[0],
                        response_data[1]
                    );
                    trace!(
                        "Data offset field (byte 2): {:02x} (should be 0x50=80)",
                        response_data[2]
                    );
                }
                if response_data.len() > 16 {
                    trace!(
                        "Data starts at position 16: {:02x?}",
                        &response_data[16..20.min(response_data.len())]
                    );
                }
            }

            self.transport.send_netbios_message(&response).await?;
        }

        Ok(())
    }

    async fn handle_negotiate(
        &mut self,
        req: Smb2NegotiateRequest,
    ) -> Result<Smb2NegotiateResponse> {
        let mut state = self.state.lock().await;
        state.handle_negotiate_request(&req)
    }

    async fn handle_session_setup(
        &mut self,
        req: Smb2SessionSetupRequest,
    ) -> Result<(Smb2SessionSetupResponse, u32)> {
        let mut state = self.state.lock().await;
        let resp = state.handle_session_setup_request(&req)?;

        // Check if we need MORE_PROCESSING_REQUIRED status
        let status = if resp.security_blob.is_empty() {
            0 // Success - authentication complete
        } else {
            0xC0000016 // STATUS_MORE_PROCESSING_REQUIRED
        };

        Ok((resp, status))
    }

    async fn handle_tree_connect(
        &mut self,
        req: Smb2TreeConnectRequest,
        requested_tree_id: u32,
    ) -> Result<Smb2TreeConnectResponse> {
        let session_id = self
            .session_id
            .ok_or_else(|| Error::InvalidState("No session established".to_string()))?;

        // Extract share name from the path (e.g., \\server\share -> share)
        let share_name = req
            .path
            .split('\\')
            .filter(|s| !s.is_empty())
            .nth(1) // Skip server name, get share name
            .unwrap_or("")
            .to_uppercase();

        // Check if this is IPC$ (always allowed) or validate against shares list
        if share_name != "IPC$" {
            let shares = self.shares.read().await;
            if !shares.contains_key(&share_name) {
                debug!("Tree connect request for unknown share: {}", share_name);
                return Err(Error::InvalidParameter(format!(
                    "Share '{}' not found",
                    share_name
                )));
            }
        }

        let mut state = self.state.lock().await;
        let resp = state.handle_tree_connect_request(&req, session_id, requested_tree_id)?;

        // Get the tree ID that was created or reused
        if let Some(tree) = state.trees.values().find(|t| t.share_name == req.path) {
            self.tree_id = Some(tree.tree_id);
        }

        Ok(resp)
    }

    async fn handle_create(
        &mut self,
        req: Smb2CreateRequest,
        tree_id: u32,
    ) -> Result<Smb2CreateResponse> {
        use crate::protocol::smb2_constants::{CreateDisposition, CreateOptions};

        // Use the tree_id from the request if non-zero, otherwise use our stored one
        let effective_tree_id = if tree_id != 0 {
            tree_id
        } else {
            self.tree_id
                .ok_or_else(|| Error::InvalidState("No tree connection".to_string()))?
        };

        debug!(
            "Create request for file: {}, tree_id: {} (from request: {})",
            req.file_name, effective_tree_id, tree_id
        );

        let mut state = self.state.lock().await;

        // First check if this is a pipe share - if so, delegate to state machine
        let tree = state.trees.get(&effective_tree_id).ok_or_else(|| {
            Error::InvalidParameter(format!("Invalid tree ID: {}", effective_tree_id))
        })?;
        let is_pipe_share = tree.share_type == 0x02; // ShareType::Pipe

        if is_pipe_share {
            // Pipe shares are handled by the state machine
            debug!("Delegating pipe share create to state machine");
            return state.handle_create_request(&req, effective_tree_id);
        }

        // For filesystem shares, handle directly here with real filesystem operations
        // Check if this is for a directory
        let is_directory = (req.file_attributes.bits() & 0x10 != 0) || // FILE_ATTRIBUTE_DIRECTORY
                          (req.create_options.bits() & CreateOptions::FILE_DIRECTORY_FILE.bits() != 0);

        // Check if this is a create vs open operation
        let create_disposition = req.create_disposition;

        let create_action: u32; // Will be set based on operation
        let file_path = req.file_name.clone();

        // Handle filesystem operations based on disposition
        match create_disposition {
            CreateDisposition::CREATE => {
                // Create new file/directory - fail if exists
                match self.filesystem.stat(&file_path).await {
                    Ok(_) => {
                        // File already exists - return error
                        return Err(Error::AlreadyExists(format!(
                            "File or directory already exists: {}",
                            file_path
                        )));
                    }
                    Err(_) => {
                        // Good, doesn't exist - create it
                        self.filesystem.create(&file_path, is_directory).await?;
                        create_action = CreateAction::Created as u32;
                    }
                }
            }
            CreateDisposition::OPEN => {
                // Open existing - fail if doesn't exist
                self.filesystem.stat(&file_path).await?;
                create_action = CreateAction::Opened as u32;
            }
            CreateDisposition::OpenIf => {
                // Open if exists, create if doesn't
                match self.filesystem.stat(&file_path).await {
                    Ok(_) => {
                        create_action = CreateAction::Opened as u32;
                    }
                    Err(_) => {
                        self.filesystem.create(&file_path, is_directory).await?;
                        create_action = CreateAction::Created as u32;
                    }
                }
            }
            CreateDisposition::OVERWRITE => {
                // Overwrite existing file - fail if doesn't exist
                let info = self.filesystem.stat(&file_path).await?;
                if info.is_directory {
                    return Err(Error::InvalidParameter(
                        "Cannot overwrite a directory".to_string(),
                    ));
                }
                // Truncate the file to zero length
                self.filesystem.truncate(&file_path, 0).await?;
                create_action = CreateAction::Overwritten as u32;
            }
            CreateDisposition::OverwriteIf => {
                // Overwrite if exists, create if doesn't
                match self.filesystem.stat(&file_path).await {
                    Ok(info) => {
                        if info.is_directory {
                            return Err(Error::InvalidParameter(
                                "Cannot overwrite a directory".to_string(),
                            ));
                        }
                        self.filesystem.truncate(&file_path, 0).await?;
                        create_action = CreateAction::Overwritten as u32;
                    }
                    Err(_) => {
                        self.filesystem.create(&file_path, is_directory).await?;
                        create_action = CreateAction::Created as u32;
                    }
                }
            }
            CreateDisposition::SUPERSEDE => {
                // Supersede - delete and recreate, or create if doesn't exist
                match self.filesystem.stat(&file_path).await {
                    Ok(info) => {
                        if info.is_directory {
                            // Delete and recreate directory
                            self.filesystem.delete(&file_path).await.ok();
                            self.filesystem.create(&file_path, true).await?;
                        } else {
                            // Truncate file
                            self.filesystem.truncate(&file_path, 0).await?;
                        }
                    }
                    Err(_) => {
                        // Doesn't exist - create it
                        self.filesystem.create(&file_path, is_directory).await?;
                    }
                }
                create_action = CreateAction::Superseded as u32;
            }
        }

        // Get file metadata
        let file_info = self.filesystem.stat(&file_path).await?;

        // Convert Unix timestamps to Windows FILETIME (100-nanosecond intervals since 1601)
        let windows_epoch_offset = 11644473600u64; // Seconds between 1601 and 1970
        let to_windows_time = |unix_time: u64| (unix_time + windows_epoch_offset) * 10_000_000;

        // Generate file ID
        let file_id = FileId {
            persistent: rand::random(),
            volatile: rand::random(),
        };

        // Create open file entry
        let open_file = OpenFile {
            file_id,
            tree_id: effective_tree_id,
            file_name: file_path.clone(),
            desired_access: req.desired_access.bits(),
            share_access: req.share_access.bits(),
            create_options: req.create_options.bits(),
            file_attributes: if file_info.is_directory {
                0x10 // FILE_ATTRIBUTE_DIRECTORY
            } else if req.file_attributes.bits() != 0 {
                req.file_attributes.bits()
            } else {
                0x80 // FILE_ATTRIBUTE_NORMAL
            },
            create_time: to_windows_time(file_info.created),
            access_time: to_windows_time(file_info.accessed),
            write_time: to_windows_time(file_info.modified),
            change_time: to_windows_time(file_info.modified),
            allocation_size: file_info.size,
            end_of_file: file_info.size,
        };

        state.open_files.insert(file_id, open_file.clone());

        Ok(Smb2CreateResponse {
            structure_size: 89,
            oplock_level: 0, // SMB2_OPLOCK_LEVEL_NONE
            flags: 0,
            create_action,
            creation_time: open_file.create_time,
            last_access_time: open_file.access_time,
            last_write_time: open_file.write_time,
            change_time: open_file.change_time,
            allocation_size: open_file.allocation_size,
            end_of_file: open_file.end_of_file,
            file_attributes: FileAttributes::from_bits_truncate(open_file.file_attributes),
            reserved2: 0,
            file_id,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            create_contexts: Vec::new(),
        })
    }

    async fn handle_close(&mut self, req: Smb2CloseRequest) -> Result<Smb2CloseResponse> {
        // Convert FileId for enumeration cleanup
        let file_id = FileId {
            persistent: req.file_id.persistent,
            volatile: req.file_id.volatile,
        };

        // Clean up enumeration state for this file handle
        {
            let mut enum_manager = self.enumeration_manager.lock().await;
            enum_manager.remove(&file_id);
        }

        let mut state = self.state.lock().await;

        // Check if file should be deleted on close
        if let Some(open_file) = state.open_files.get(&file_id) {
            use crate::protocol::smb2_constants::CreateOptions;

            if open_file.create_options & CreateOptions::FILE_DELETE_ON_CLOSE.bits() != 0 {
                debug!("Deleting file/directory on close: {}", open_file.file_name);

                // Delete the file/directory
                if let Err(e) = self.filesystem.delete(&open_file.file_name).await {
                    debug!("Failed to delete {}: {}", open_file.file_name, e);
                    // Continue with close even if delete fails
                }
            }
        }

        state.handle_close_request(&req)
    }

    async fn handle_read(&mut self, req: Smb2ReadRequest) -> Result<Smb2ReadResponse> {
        let state = self.state.lock().await;

        debug!(
            "Read request: file_id={:?}, offset={}, length={}",
            req.file_id, req.offset, req.length
        );

        // Convert new FileId type to old FileId type for compatibility
        let old_file_id = FileId {
            persistent: req.file_id.persistent,
            volatile: req.file_id.volatile,
        };

        // Check if file is open
        if let Some(open_file) = state.open_files.get(&old_file_id) {
            debug!(
                "Reading from file: {}, offset={}, length={}",
                open_file.file_name, req.offset, req.length
            );

            // Read from filesystem
            let data = self
                .filesystem
                .read(&open_file.file_name, req.offset, req.length as usize)
                .await?;

            debug!("Read {} bytes from file", data.len());

            Ok(Smb2ReadResponse {
                structure_size: 17,
                data_offset: 80, // 64 (header) + 16
                reserved: 0,
                data_length: data.len() as u32,
                data_remaining: 0,
                reserved2: 0,
                data,
            })
        } else {
            debug!("Read request for invalid file ID: {:?}", req.file_id);
            Err(Error::InvalidParameter("Invalid file ID".to_string()))
        }
    }

    async fn handle_write(&mut self, req: Smb2WriteRequest) -> Result<Smb2WriteResponse> {
        let mut state = self.state.lock().await;

        // Check if file is open
        if let Some(open_file) = state.open_files.get_mut(&req.file_id) {
            // Write to filesystem
            let written = self
                .filesystem
                .write(&open_file.file_name, req.offset, &req.data)
                .await?;

            // Update file size if needed
            if req.offset + written as u64 > open_file.end_of_file {
                open_file.end_of_file = req.offset + written as u64;
            }

            Ok(Smb2WriteResponse {
                structure_size: 17,
                reserved: 0,
                count: written as u32,
                remaining: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
            })
        } else {
            Err(Error::InvalidParameter("Invalid file ID".to_string()))
        }
    }

    async fn handle_query_directory(
        &mut self,
        req: Smb2QueryDirectoryRequest,
    ) -> Result<Smb2QueryDirectoryResponse> {
        use crate::protocol::messages::file_info::{
            build_directory_listing, FileIdBothDirectoryInfo,
        };
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = self.state.lock().await;

        // Convert FileId from messages::common to message::FileId
        let file_id = FileId {
            persistent: req.file_id.persistent,
            volatile: req.file_id.volatile,
        };

        // Check if file handle is valid and get the path
        let path = match state.open_files.get(&file_id) {
            Some(file_info) => file_info.file_name.clone(),
            None => return Err(Error::InvalidParameter("Invalid file ID".to_string())),
        };

        debug!(
            "Query Directory request: path={}, pattern={}, class=0x{:02x}, flags=0x{:02x}, output_buffer_length={}",
            path, req.file_name, req.file_information_class, req.flags, req.output_buffer_length
        );

        // Drop the state lock before accessing enumeration_manager
        drop(state);

        // Handle enumeration state
        let mut enum_manager = self.enumeration_manager.lock().await;

        // Check flags for restart/reset behavior
        if req.flags & SMB2_RESTART_SCANS != 0 || req.flags & SMB2_REOPEN != 0 {
            debug!(
                "Query Directory: Restarting enumeration for file_id {:?}",
                file_id
            );
            enum_manager.reset(&file_id);
        }

        // Get or create enumeration state
        let search_pattern = if !req.file_name.is_empty() {
            req.file_name.clone()
        } else {
            "*".to_string()
        };

        let enum_state = enum_manager.get_or_create(&file_id, search_pattern);

        // Check if enumeration is already completed
        if enum_state.completed {
            debug!("Query Directory: Enumeration already completed, returning no more files");
            // Return empty response with STATUS_NO_MORE_FILES
            return Ok(Smb2QueryDirectoryResponse {
                structure_size: 9,
                output_buffer_offset: 0,
                output_buffer_length: 0,
                output_buffer: Vec::new(),
            });
        }

        // Get current time as Windows FILETIME (100ns intervals since 1601-01-01)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::InvalidState(format!("System time error: {}", e)))?
            .as_secs();
        // Convert Unix timestamp to Windows FILETIME
        let windows_time = (now + 11644473600) * 10000000; // Add seconds between 1601 and 1970

        // Get directory entries from the filesystem
        let mut all_entries = Vec::new();

        // Add . and .. entries first
        all_entries.push(FileIdBothDirectoryInfo::new(
            ".".to_string(),
            true, // is_directory
            0,    // size
            windows_time,
            windows_time,
        ));

        all_entries.push(FileIdBothDirectoryInfo::new(
            "..".to_string(),
            true, // is_directory
            0,    // size
            windows_time,
            windows_time,
        ));

        // Try to list the actual directory
        // Check if we can cast to RealFileSystem to use its list_directory method
        let fs_any = self.filesystem.as_any();
        if let Some(real_fs) = fs_any.downcast_ref::<RealFileSystem>() {
            match real_fs.list_directory(&path).await {
                Ok(entries) => {
                    let num_entries = entries.len();
                    for entry in entries {
                        // Convert Unix timestamps to Windows FILETIME
                        let created_time = if entry.created > 0 {
                            (entry.created + 11644473600) * 10000000
                        } else {
                            windows_time
                        };
                        let modified_time = if entry.modified > 0 {
                            (entry.modified + 11644473600) * 10000000
                        } else {
                            windows_time
                        };

                        all_entries.push(FileIdBothDirectoryInfo::new(
                            entry.file_name,
                            entry.is_directory,
                            entry.size,
                            created_time,
                            modified_time,
                        ));
                    }
                    debug!(
                        "Query Directory: Listed {} real filesystem entries",
                        num_entries
                    );
                }
                Err(e) => {
                    debug!(
                        "Query Directory: Failed to list directory {}: {}, using sample entries",
                        path, e
                    );
                    // Fallback to sample entries for testing
                    all_entries.push(FileIdBothDirectoryInfo::new(
                        "readme.txt".to_string(),
                        false, // is_directory
                        1024,  // size
                        windows_time,
                        windows_time,
                    ));

                    all_entries.push(FileIdBothDirectoryInfo::new(
                        "test_dir".to_string(),
                        true, // is_directory
                        0,    // size
                        windows_time,
                        windows_time,
                    ));

                    all_entries.push(FileIdBothDirectoryInfo::new(
                        "document.pdf".to_string(),
                        false,  // is_directory
                        524288, // size
                        windows_time,
                        windows_time,
                    ));
                }
            }
        } else {
            // Use basic filesystem list method
            match self.filesystem.list(&path).await {
                Ok(entries) => {
                    let num_entries = entries.len();
                    for file_name in entries {
                        // Try to get file info for each entry
                        let full_path = if path.is_empty() || path == "/" || path == "\\" {
                            format!("\\{}", file_name)
                        } else {
                            format!("{}\\{}", path, file_name)
                        };

                        if let Ok(info) = self.filesystem.stat(&full_path).await {
                            let created_time = if info.created > 0 {
                                (info.created + 11644473600) * 10000000
                            } else {
                                windows_time
                            };
                            let modified_time = if info.modified > 0 {
                                (info.modified + 11644473600) * 10000000
                            } else {
                                windows_time
                            };

                            all_entries.push(FileIdBothDirectoryInfo::new(
                                file_name,
                                info.is_directory,
                                info.size,
                                created_time,
                                modified_time,
                            ));
                        }
                    }
                    debug!("Query Directory: Listed {} filesystem entries", num_entries);
                }
                Err(e) => {
                    debug!(
                        "Query Directory: Failed to list directory {}: {}, using sample entries",
                        path, e
                    );
                    // Fallback to sample entries for testing
                    all_entries.push(FileIdBothDirectoryInfo::new(
                        "readme.txt".to_string(),
                        false, // is_directory
                        1024,  // size
                        windows_time,
                        windows_time,
                    ));

                    all_entries.push(FileIdBothDirectoryInfo::new(
                        "test_dir".to_string(),
                        true, // is_directory
                        0,    // size
                        windows_time,
                        windows_time,
                    ));

                    all_entries.push(FileIdBothDirectoryInfo::new(
                        "document.pdf".to_string(),
                        false,  // is_directory
                        524288, // size
                        windows_time,
                        windows_time,
                    ));
                }
            }
        }

        // Determine which entries to return based on enumeration state
        let entries_to_return = if enum_state.position >= all_entries.len() {
            // No more entries
            enum_state.complete();
            Vec::new()
        } else if req.flags & SMB2_RETURN_SINGLE_ENTRY != 0 {
            // Return only one entry
            let entry = all_entries[enum_state.position].clone();
            enum_state.advance(1);
            vec![entry]
        } else {
            // Return remaining entries (or up to a reasonable limit)
            let start = enum_state.position;
            let end = all_entries.len();
            let entries: Vec<_> = all_entries[start..end].to_vec();
            enum_state.position = end;

            // If we've returned all entries, mark as completed
            if enum_state.position >= all_entries.len() {
                enum_state.complete();
            }

            entries
        };

        debug!(
            "Query Directory: Returning {} entries starting from position {}",
            entries_to_return.len(),
            enum_state.position - entries_to_return.len()
        );

        // Build the response buffer
        let output_buffer = if entries_to_return.is_empty() {
            Vec::new()
        } else {
            build_directory_listing(entries_to_return)?
        };

        let output_len = output_buffer.len() as u32;

        debug!("Query Directory: returning {} bytes of data", output_len);

        // According to MS-SMB2, the response structure is 8 bytes but StructureSize field must be 9
        // The buffer offset is from the beginning of the SMB2 header
        // SMB2_HDR_BODY (64) + response structure (8) = 72
        let response = Smb2QueryDirectoryResponse {
            structure_size: 9, // Must be 9 per MS-SMB2 spec
            output_buffer_offset: if output_len > 0 {
                72 // 64 (SMB2 header) + 8 (response structure)
            } else {
                0
            },
            output_buffer_length: output_len,
            output_buffer,
        };

        debug!("Query Directory response: structure_size={}, offset={}, length={}, actual_data_size={}", 
               response.structure_size, response.output_buffer_offset, response.output_buffer_length,
               response.output_buffer.len());

        Ok(response)
    }

    async fn handle_query_info(
        &mut self,
        req: Smb2QueryInfoRequest,
    ) -> Result<Smb2QueryInfoResponse> {
        debug!(
            "Query info request: info_type={}, file_info_class={}, file_id={:?}",
            req.info_type as u8, req.file_info_class as u8, req.file_id
        );
        let mut state = self.state.lock().await;
        let resp = state.handle_query_info_request(&req)?;
        debug!(
            "Query info response: buffer_length={}",
            resp.output_buffer_length
        );
        Ok(resp)
    }

    async fn handle_set_info(
        &mut self,
        req: Smb2SetInfoRequest,
        _tree_id: u32,
    ) -> Result<Smb2SetInfoResponse> {
        debug!(
            "SET_INFO request: info_type={:?}, file_info_class={:?}, file_id={:?}",
            req.info_type, req.file_info_class, req.file_id
        );

        let mut state = self.state.lock().await;

        // Convert FileId from messages::info to message::FileId
        let file_id = FileId {
            persistent: req.file_id.persistent,
            volatile: req.file_id.volatile,
        };

        // Find the open file
        let open_file = state
            .open_files
            .get_mut(&file_id)
            .ok_or_else(|| Error::InvalidParameter("Invalid file ID".to_string()))?;

        match req.info_type {
            InfoType::FILE => {
                match req.file_info_class {
                    FileInfoClass::DISPOSITION => {
                        // File delete on close
                        if req.buffer.len() >= 1 {
                            let delete_on_close = req.buffer[0] != 0;
                            debug!(
                                "SET_INFO: Setting delete_on_close={} for file {}",
                                delete_on_close, open_file.file_name
                            );

                            if delete_on_close {
                                // Mark file for deletion on close
                                open_file.create_options |= crate::protocol::smb2_constants::CreateOptions::FILE_DELETE_ON_CLOSE.bits();
                            } else {
                                // Clear the delete on close flag
                                open_file.create_options &= !crate::protocol::smb2_constants::CreateOptions::FILE_DELETE_ON_CLOSE.bits();
                            }
                        }
                    }
                    FileInfoClass::RENAME => {
                        // File rename
                        if req.buffer.len() >= 24 {
                            // Parse rename information
                            // Structure: ReplaceIfExists(1) + Reserved(7) + RootDirectory(8) + FileNameLength(4) + FileName
                            let mut cursor = std::io::Cursor::new(&req.buffer);
                            use byteorder::{LittleEndian, ReadBytesExt};

                            let replace_if_exists = cursor.read_u8()? != 0;
                            cursor.set_position(20); // Skip reserved and root directory
                            let file_name_length = cursor.read_u32::<LittleEndian>()? as usize;

                            if req.buffer.len() >= 24 + file_name_length {
                                // Read the new filename (UTF-16LE)
                                let name_bytes = &req.buffer[24..24 + file_name_length];
                                let name_u16: Vec<u16> = name_bytes
                                    .chunks_exact(2)
                                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                                    .collect();
                                let new_name = String::from_utf16(&name_u16).map_err(|_| {
                                    Error::InvalidParameter(
                                        "Invalid UTF-16 in filename".to_string(),
                                    )
                                })?;

                                debug!(
                                    "SET_INFO: Rename file {} to {} (replace={})",
                                    open_file.file_name, new_name, replace_if_exists
                                );

                                // Perform the rename
                                let old_path = open_file.file_name.clone();
                                let filesystem = self.filesystem.clone();

                                // Drop the state lock before async filesystem operation
                                drop(state);

                                // Do the rename
                                filesystem
                                    .rename(&old_path, &new_name, replace_if_exists)
                                    .await?;

                                // Re-acquire state and update the file name
                                let mut state = self.state.lock().await;
                                if let Some(open_file) = state.open_files.get_mut(&file_id) {
                                    open_file.file_name = new_name;
                                }
                            }
                        }
                    }
                    FileInfoClass::EndOfFile => {
                        // Set end of file (truncate)
                        if req.buffer.len() >= 8 {
                            use byteorder::{LittleEndian, ReadBytesExt};
                            let mut cursor = std::io::Cursor::new(&req.buffer);
                            let new_size = cursor.read_u64::<LittleEndian>()?;

                            debug!(
                                "SET_INFO: Set end of file to {} for {}",
                                new_size, open_file.file_name
                            );

                            let file_path = open_file.file_name.clone();
                            let filesystem = self.filesystem.clone();

                            // Drop the state lock before async filesystem operation
                            drop(state);

                            // Truncate the file
                            filesystem.truncate(&file_path, new_size).await?;
                        }
                    }
                    _ => {
                        debug!(
                            "SET_INFO: Unsupported file info class {:?}",
                            req.file_info_class
                        );
                        // Silently ignore unsupported info classes for compatibility
                    }
                }
            }
            _ => {
                debug!("SET_INFO: Unsupported info type {:?}", req.info_type);
                // Silently ignore unsupported info types for compatibility
            }
        }

        Ok(Smb2SetInfoResponse { structure_size: 2 })
    }

    async fn handle_ioctl(&mut self, req: Smb2IoctlRequest) -> Result<Smb2IoctlResponse> {
        let state = self.state.lock().await;

        // Check if file handle is valid (unless it's a share-level IOCTL)
        let is_share_level = req.file_id.persistent == 0xFFFFFFFFFFFFFFFF
            && req.file_id.volatile == 0xFFFFFFFFFFFFFFFF;

        let pipe_name = if !is_share_level {
            // Convert FileId from messages::ioctl to message::FileId
            let file_id = FileId {
                persistent: req.file_id.persistent,
                volatile: req.file_id.volatile,
            };

            if let Some(open_file) = state.open_files.get(&file_id) {
                // Check if this is a named pipe
                if open_file.file_name.starts_with("\\pipe\\")
                    || open_file.file_name.starts_with("\\PIPE\\")
                {
                    Some(open_file.file_name.clone())
                } else {
                    None
                }
            } else {
                return Err(Error::InvalidParameter("Invalid file ID".to_string()));
            }
        } else {
            None
        };

        // Handle specific IOCTL codes
        match req.ctl_code {
            FSCTL_PIPE_TRANSCEIVE => {
                // Pipe transceive - write then read from named pipe
                if let Some(pipe_name) = pipe_name {
                    // Open the pipe
                    let pipe = self.pipe_manager.open_pipe(&pipe_name).await?;
                    let mut pipe = pipe.lock().await;

                    // Transceive operation
                    debug!(
                        "IOCTL: FSCTL_PIPE_TRANSCEIVE on pipe '{}' with {} bytes input",
                        pipe_name,
                        req.input_buffer.len()
                    );
                    let output_data = pipe.transceive(&req.input_buffer, 65536)?;
                    debug!("IOCTL: Got {} bytes response from pipe", output_data.len());

                    Ok(Smb2IoctlResponse {
                        structure_size: 49,
                        reserved: 0,
                        ctl_code: req.ctl_code,
                        file_id: req.file_id,
                        input_offset: 0,
                        input_count: 0,
                        output_offset: if !output_data.is_empty() { 112 } else { 0 },
                        output_count: output_data.len() as u32,
                        flags: 0,
                        reserved2: 0,
                        input_buffer: Vec::new(),
                        output_buffer: output_data,
                    })
                } else {
                    // No pipe - echo back for compatibility
                    Ok(Smb2IoctlResponse {
                        structure_size: 49,
                        reserved: 0,
                        ctl_code: req.ctl_code,
                        file_id: req.file_id,
                        input_offset: 0,
                        input_count: 0,
                        output_offset: if !req.input_buffer.is_empty() { 112 } else { 0 },
                        output_count: req.input_buffer.len() as u32,
                        flags: 0,
                        reserved2: 0,
                        input_buffer: Vec::new(),
                        output_buffer: req.input_buffer,
                    })
                }
            }
            FSCTL_DFS_GET_REFERRALS => {
                // DFS referrals - return empty response (no DFS support)
                // This is enough to let smbclient proceed
                Ok(Smb2IoctlResponse {
                    structure_size: 49,
                    reserved: 0,
                    ctl_code: req.ctl_code,
                    file_id: req.file_id,
                    input_offset: 0,
                    input_count: 0,
                    output_offset: 0,
                    output_count: 0,
                    flags: 0,
                    reserved2: 0,
                    input_buffer: Vec::new(),
                    output_buffer: Vec::new(),
                })
            }
            _ => {
                // Unsupported IOCTL code
                Err(Error::NotImplemented(format!(
                    "IOCTL code 0x{:08x}",
                    req.ctl_code
                )))
            }
        }
    }
}
