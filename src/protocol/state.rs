//! SMB2 protocol state machine

use crate::auth::ntlm::{NtlmAuth, NtlmMessageType};
use crate::error::{Error, Result};
use crate::protocol::messages::directory::{Smb2QueryDirectoryRequest, Smb2QueryDirectoryResponse};
use crate::protocol::messages::info::{
    FileInfoClass, FsInfoClass, InfoType, Smb2QueryInfoRequest, Smb2QueryInfoResponse,
    Smb2SetInfoRequest, Smb2SetInfoResponse,
};
use crate::protocol::messages::{common::FileId, file_ops::*, negotiate::*, session::*, tree::*};
use crate::protocol::smb2_constants::*;
use crate::protocol::smb2_constants::{protocol_offsets, CreateAction, FileAttributes};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Cursor;

/// SMB2 connection state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state - no connection established
    Disconnected,
    /// Connected but not negotiated
    Connected,
    /// Protocol negotiated
    Negotiated,
    /// Session established
    SessionEstablished,
    /// Error state
    Error(String),
}

/// SMB2 session state
#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_id: u64,
    pub user_name: Option<String>,
    pub is_guest: bool,
    pub is_anonymous: bool,
    pub session_key: Option<Vec<u8>>,
    pub signing_required: bool,
    pub encryption_required: bool,
}

/// SMB2 tree connect state
#[derive(Debug, Clone)]
pub struct TreeConnect {
    pub tree_id: u32,
    pub share_name: String,
    pub share_type: u8,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

/// SMB2 open file state
#[derive(Debug, Clone)]
pub struct OpenFile {
    pub file_id: FileId,
    pub tree_id: u32,
    pub file_name: String,
    pub desired_access: u32,
    pub share_access: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub create_time: u64,
    pub access_time: u64,
    pub write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
}

/// Helper function to unwrap SPNEGO and extract NTLM token
fn unwrap_spnego_to_ntlm(spnego_blob: &[u8]) -> Option<&[u8]> {
    // Basic SPNEGO unwrapping - find NTLM token inside
    // SPNEGO can start with 0x60 (APPLICATION 0) or 0xa1 (CONTEXT SPECIFIC 1)
    if spnego_blob.len() < 16 {
        return None;
    }

    if spnego_blob[0] != 0x60 && spnego_blob[0] != 0xa1 {
        return None;
    }

    // Search for NTLMSSP signature in the blob
    for i in 0..spnego_blob.len().saturating_sub(8) {
        if &spnego_blob[i..i + 8] == b"NTLMSSP\0" {
            // Found NTLM token, return from here to end
            return Some(&spnego_blob[i..]);
        }
    }

    None
}

/// Helper function to create SPNEGO accept-completed response
fn create_spnego_accept_completed() -> Vec<u8> {
    // Build a minimal SPNEGO negTokenTarg with accept-completed
    let mut result = Vec::new();

    // negTokenTarg [1] EXPLICIT SEQUENCE
    result.push(0xa1); // CONTEXT SPECIFIC 1
    result.push(0x07); // length

    // SEQUENCE
    result.push(0x30);
    result.push(0x05);

    // negResult [0] ENUMERATED = accept-completed (0)
    result.push(0xa0); // CONTEXT SPECIFIC 0
    result.push(0x03);
    result.push(0x0a); // ENUMERATED tag
    result.push(0x01);
    result.push(0x00); // accept-completed

    result
}

/// Helper function to wrap NTLM token in SPNEGO negTokenTarg
fn wrap_ntlm_in_spnego_response(ntlm_token: &[u8]) -> Vec<u8> {
    // Build a minimal SPNEGO negTokenTarg response
    // This is simplified ASN.1 encoding
    let mut result = Vec::new();

    // Build content first to calculate proper lengths
    let mut content = Vec::new();

    // negResult [0] ENUMERATED = accept-incomplete (1)
    content.push(0xa0); // CONTEXT SPECIFIC 0
    content.push(0x03);
    content.push(0x0a); // ENUMERATED tag
    content.push(0x01);
    content.push(0x01); // accept-incomplete

    // supportedMech [1] OBJECT IDENTIFIER (NTLMSSP)
    // OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
    content.push(0xa1); // CONTEXT SPECIFIC 1
    content.push(0x0c); // length
    content.push(0x06); // OBJECT IDENTIFIER
    content.push(0x0a); // length
    content.extend_from_slice(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]);

    // responseToken [2] OCTET STRING
    content.push(0xa2); // CONTEXT SPECIFIC 2
    let token_content_len = 2 + ntlm_token.len(); // OCTET STRING tag + length + data
    if token_content_len < 128 {
        content.push(token_content_len as u8);
    } else {
        content.push(0x81);
        content.push(token_content_len as u8);
    }
    content.push(0x04); // OCTET STRING
    if ntlm_token.len() < 128 {
        content.push(ntlm_token.len() as u8);
    } else {
        content.push(0x81);
        content.push(ntlm_token.len() as u8);
    }
    content.extend_from_slice(ntlm_token);

    // Now build the wrapper
    // negTokenTarg [1] EXPLICIT SEQUENCE
    result.push(0xa1); // CONTEXT SPECIFIC 1
    let seq_len = content.len() + 2; // SEQUENCE tag + length
    if seq_len < 128 {
        result.push(seq_len as u8);
    } else {
        result.push(0x81);
        result.push(seq_len as u8);
    }

    // SEQUENCE
    result.push(0x30);
    if content.len() < 128 {
        result.push(content.len() as u8);
    } else {
        result.push(0x81);
        result.push(content.len() as u8);
    }

    result.extend_from_slice(&content);

    result
}

/// SMB2 protocol state machine
pub struct Smb2StateMachine {
    /// Current connection state
    pub state: ConnectionState,

    /// Negotiated protocol details
    pub dialect: Option<u16>,
    pub server_guid: Option<[u8; 16]>,
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub server_start_time: Option<u64>,

    /// Sessions (session_id -> SessionState)
    pub sessions: HashMap<u64, SessionState>,

    /// Tree connections (tree_id -> TreeConnect)
    pub trees: HashMap<u32, TreeConnect>,

    /// Open files (file_id -> OpenFile)
    pub open_files: HashMap<FileId, OpenFile>,

    /// Next available IDs
    pub next_session_id: u64,
    pub next_tree_id: u32,
    pub next_message_id: u64,

    /// Credits for flow control
    pub credits_requested: u16,
    pub credits_granted: u16,

    /// Security mode
    pub security_mode: u16,

    /// NTLM authentication contexts for sessions in progress
    pub ntlm_contexts: HashMap<u64, NtlmAuth>,
}

impl Smb2StateMachine {
    /// Create a new SMB2 state machine
    pub fn new() -> Self {
        // Set server start time
        use std::time::{SystemTime, UNIX_EPOCH};
        let server_start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| (d.as_secs() + 11644473600) * 10_000_000)
            .ok();

        Self {
            state: ConnectionState::Disconnected,
            dialect: None,
            server_guid: None,
            capabilities: 0,
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            server_start_time,
            sessions: HashMap::new(),
            trees: HashMap::new(),
            open_files: HashMap::new(),
            next_session_id: 1,
            next_tree_id: 1,
            next_message_id: 0,
            credits_requested: 1,
            credits_granted: 1,
            security_mode: SecurityMode::SIGNING_ENABLED.bits(),
            ntlm_contexts: HashMap::new(),
        }
    }

    /// Handle connection established
    pub fn on_connect(&mut self) -> Result<()> {
        match self.state {
            ConnectionState::Disconnected => {
                self.state = ConnectionState::Connected;
                Ok(())
            }
            _ => Err(Error::InvalidState("Already connected".to_string())),
        }
    }

    /// Handle negotiate request
    pub fn handle_negotiate_request(
        &mut self,
        req: &Smb2NegotiateRequest,
    ) -> Result<Smb2NegotiateResponse> {
        if self.state != ConnectionState::Connected {
            return Err(Error::InvalidState("Not in connected state".to_string()));
        }

        // Select dialect (prefer SMB 2.1)
        let selected_dialect = if req.dialects.contains(&Smb2Dialect::Smb210) {
            0x0210
        } else if req.dialects.contains(&Smb2Dialect::Smb202) {
            0x0202
        } else {
            return Err(Error::Protocol("No supported dialect".to_string()));
        };

        self.dialect = Some(selected_dialect);
        // Generate a proper random GUID
        let mut guid = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut guid);
        self.server_guid = Some(guid);
        self.capabilities = Smb2Capabilities::DFS.bits() | Smb2Capabilities::LARGE_MTU.bits();
        self.security_mode = req.security_mode.bits() & SecurityMode::SIGNING_REQUIRED.bits();

        self.state = ConnectionState::Negotiated;

        let dialect = Smb2Dialect::try_from(selected_dialect)?;
        let server_guid = self
            .server_guid
            .ok_or_else(|| Error::InvalidState("Server GUID not set".to_string()))?;

        Ok(Smb2NegotiateResponse {
            structure_size: 65,
            security_mode: SecurityMode::from_bits(self.security_mode as u16)
                .unwrap_or(SecurityMode::empty()),
            dialect_revision: dialect,
            reserved: 0,
            server_guid: uuid::Uuid::from_bytes(server_guid),
            capabilities: Smb2Capabilities::from_bits(self.capabilities)
                .unwrap_or(Smb2Capabilities::empty()),
            max_transact_size: self.max_transact_size,
            max_read_size: self.max_read_size,
            max_write_size: self.max_write_size,
            // Get current system time as Windows FILETIME (100ns intervals since 1601)
            system_time: {
                use std::time::{SystemTime, UNIX_EPOCH};
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| Error::InvalidState(format!("System time error: {}", e)))?
                    .as_secs();
                (now + 11644473600) * 10_000_000 // Convert Unix to Windows time
            },
            server_start_time: self.server_start_time.unwrap_or(0),
            security_buffer_offset: 0,
            security_buffer_length: 0,
            reserved2: 0,
            security_blob: Vec::new(),
            negotiate_contexts: None,
        })
    }

    /// Handle session setup request
    pub fn handle_session_setup_request(
        &mut self,
        req: &Smb2SessionSetupRequest,
    ) -> Result<Smb2SessionSetupResponse> {
        if self.state != ConnectionState::Negotiated
            && self.state != ConnectionState::SessionEstablished
        {
            return Err(Error::InvalidState("Protocol not negotiated".to_string()));
        }

        // Handle NTLM authentication
        if req.security_blob.is_empty() {
            // No security blob - guest authentication
            let session_id = self.next_session_id;
            self.next_session_id += 1;

            let session = SessionState {
                session_id,
                user_name: Some("guest".to_string()),
                is_guest: true,
                is_anonymous: false,
                session_key: None,
                signing_required: false,
                encryption_required: false,
            };

            self.sessions.insert(session_id, session);
            self.state = ConnectionState::SessionEstablished;

            return Ok(Smb2SessionSetupResponse {
                structure_size: 9,
                session_flags: SessionFlags::IS_GUEST.bits(),
                security_buffer_offset: 0,
                security_buffer_length: 0,
                security_blob: Vec::new(),
            });
        }

        // Check if this is SPNEGO-wrapped authentication
        let mut auth_data = &req.security_blob[..];
        if req.security_blob.len() > 0
            && (req.security_blob[0] == 0x60 || req.security_blob[0] == 0xa1)
        {
            // This is SPNEGO (ASN.1 APPLICATION 0 or CONTEXT SPECIFIC 1)
            // Try to unwrap and find the NTLM token inside
            auth_data = unwrap_spnego_to_ntlm(&req.security_blob).unwrap_or(&req.security_blob[..]);
        }

        // Check if this is NTLM
        if auth_data.len() >= 12 && &auth_data[0..8] == b"NTLMSSP\0" {
            let mut cursor = Cursor::new(&auth_data[8..12]);
            let msg_type_value = cursor.read_u32::<LittleEndian>()?;
            let msg_type = NtlmMessageType::try_from(msg_type_value)?;

            match msg_type {
                NtlmMessageType::Negotiate => {
                    // Type 1: Negotiate message - client is starting NTLM

                    // Create server NTLM context and generate challenge
                    let mut ntlm = NtlmAuth::new_server();
                    let challenge_bytes = ntlm.create_challenge_message(auth_data)?;

                    // Use a temporary session ID for the NTLM context
                    let temp_session_id = self.next_session_id;
                    self.ntlm_contexts.insert(temp_session_id, ntlm);

                    // Wrap NTLM challenge in SPNEGO if request was SPNEGO
                    let response_blob =
                        if req.security_blob.len() > 0 && req.security_blob[0] == 0x60 {
                            // Wrap in SPNEGO negTokenTarg
                            wrap_ntlm_in_spnego_response(&challenge_bytes)
                        } else {
                            challenge_bytes
                        };

                    // Return MORE_PROCESSING_REQUIRED status (indicated by returning challenge)
                    Ok(Smb2SessionSetupResponse {
                        structure_size: 9,
                        session_flags: 0,
                        security_buffer_offset: protocol_offsets::SESSION_SETUP_SECURITY_OFFSET,
                        security_buffer_length: response_blob.len() as u16,
                        security_blob: response_blob,
                    })
                }
                NtlmMessageType::Authenticate => {
                    // Type 3: Authenticate message
                    // Accept authentication (in production would verify against password database)
                    let session_id = self.next_session_id;
                    self.next_session_id += 1;

                    // Parse the Type 3 message to get the username
                    let username = if auth_data.len() >= 64 {
                        // Try to extract username from Type 3 message
                        // This is a simplified extraction - proper parsing would be more complex
                        "authenticated_user".to_string()
                    } else {
                        "anonymous".to_string()
                    };

                    let session = SessionState {
                        session_id,
                        user_name: Some(username),
                        is_guest: false, // Mark as authenticated (not guest)
                        is_anonymous: false,
                        session_key: None,
                        signing_required: false,
                        encryption_required: false,
                    };

                    self.sessions.insert(session_id, session);
                    self.state = ConnectionState::SessionEstablished;

                    // Clean up NTLM context
                    self.ntlm_contexts.remove(&session_id);

                    // If this was SPNEGO, send an empty SPNEGO accept-completed response
                    let response_blob =
                        if req.security_blob.len() > 0 && req.security_blob[0] == 0xa1 {
                            // This is a SPNEGO negTokenTarg - send accept-completed
                            create_spnego_accept_completed()
                        } else {
                            Vec::new()
                        };

                    Ok(Smb2SessionSetupResponse {
                        structure_size: 9,
                        session_flags: SessionFlags::IS_GUEST.bits(),
                        security_buffer_offset: if response_blob.is_empty() {
                            0
                        } else {
                            protocol_offsets::SESSION_SETUP_SECURITY_OFFSET
                        },
                        security_buffer_length: response_blob.len() as u16,
                        security_blob: response_blob,
                    })
                }
                NtlmMessageType::Challenge => {
                    // We should not receive a Challenge message from the client
                    Err(Error::ParseError(
                        "Unexpected NTLM Challenge message from client".to_string(),
                    ))
                }
            }
        } else {
            Err(Error::ParseError("Invalid security blob".into()))
        }
    }

    /// Handle tree connect request
    pub fn handle_tree_connect_request(
        &mut self,
        req: &Smb2TreeConnectRequest,
        session_id: u64,
        requested_tree_id: u32,
    ) -> Result<Smb2TreeConnectResponse> {
        if !self.sessions.contains_key(&session_id) {
            return Err(Error::InvalidParameter("Invalid session ID".to_string()));
        }

        // Use the requested tree_id if valid (non-zero), otherwise assign a new one
        let tree_id = if requested_tree_id != 0 {
            // Client wants to use a specific tree_id
            // First remove any existing tree with this ID (in case of reconnect)
            self.trees.remove(&requested_tree_id);
            requested_tree_id
        } else {
            // Client wants us to assign a tree_id
            let new_id = self.next_tree_id;
            self.next_tree_id += 1;
            new_id
        };

        // Check if this is the IPC$ share
        let (share_type, share_flags) = if req.path.to_uppercase().ends_with("\\IPC$") {
            // IPC$ is a pipe share for RPC
            (ShareType::Pipe, 0u32)
        } else {
            // Regular disk share
            (
                ShareType::Disk,
                crate::protocol::smb2_constants::ShareFlags::NO_CACHING.bits(),
            )
        };

        let tree = TreeConnect {
            tree_id,
            share_name: req.path.clone(),
            share_type: share_type as u8,
            share_flags,
            capabilities: 0,
            maximal_access: 0x001f01ff, // Generic all access
        };

        self.trees.insert(tree_id, tree.clone());

        Ok(Smb2TreeConnectResponse {
            structure_size: 16,
            share_type,
            reserved: 0,
            share_flags: tree.share_flags,
            capabilities: tree.capabilities,
            maximal_access: tree.maximal_access,
        })
    }

    /// Handle create (open) request
    pub fn handle_create_request(
        &mut self,
        req: &Smb2CreateRequest,
        tree_id: u32,
    ) -> Result<Smb2CreateResponse> {
        let tree = self
            .trees
            .get(&tree_id)
            .ok_or_else(|| Error::InvalidParameter("Invalid tree ID".to_string()))?;

        // Check if this is a pipe share (IPC$)
        let is_pipe_share = tree.share_type == ShareType::Pipe as u8;

        // For pipe shares, ensure the filename is a valid pipe name
        let file_name = if is_pipe_share && !req.file_name.is_empty() {
            // Normalize pipe name
            if !req.file_name.starts_with("\\pipe\\") && !req.file_name.starts_with("\\PIPE\\") {
                format!("\\pipe\\{}", req.file_name)
            } else {
                req.file_name.clone()
            }
        } else {
            req.file_name.clone()
        };

        // Generate a file ID
        let file_id = FileId {
            persistent: rand::random(),
            volatile: rand::random(),
        };

        let open_file = OpenFile {
            file_id,
            tree_id,
            file_name,
            desired_access: req.desired_access.bits(),
            share_access: req.share_access.bits(),
            create_options: req.create_options.bits(),
            file_attributes: if is_pipe_share {
                0x80
            } else {
                req.file_attributes.bits()
            }, // FILE_ATTRIBUTE_NORMAL for pipes
            create_time: 0,
            access_time: 0,
            write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
        };

        self.open_files.insert(file_id, open_file.clone());

        Ok(Smb2CreateResponse {
            structure_size: 89,
            oplock_level: 0, // SMB2_OPLOCK_LEVEL_NONE
            flags: 0,
            create_action: CreateAction::Opened as u32,
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

    /// Handle close request
    pub fn handle_close_request(&mut self, req: &Smb2CloseRequest) -> Result<Smb2CloseResponse> {
        if let Some(open_file) = self.open_files.remove(&req.file_id) {
            Ok(Smb2CloseResponse {
                structure_size: 60,
                flags: req.flags,
                reserved: 0,
                creation_time: open_file.create_time,
                last_access_time: open_file.access_time,
                last_write_time: open_file.write_time,
                change_time: open_file.change_time,
                allocation_size: open_file.allocation_size,
                end_of_file: open_file.end_of_file,
                file_attributes: FileAttributes::from_bits_truncate(open_file.file_attributes),
            })
        } else {
            Err(Error::InvalidParameter("Invalid file ID".to_string()))
        }
    }

    /// Handle read request
    pub fn handle_read_request(&mut self, req: &Smb2ReadRequest) -> Result<Smb2ReadResponse> {
        if !self.open_files.contains_key(&req.file_id) {
            return Err(Error::InvalidParameter("Invalid file ID".to_string()));
        }

        // For now, return empty data
        Ok(Smb2ReadResponse {
            structure_size: 17,
            data_offset: 80, // Standard offset for read response
            reserved: 0,
            data_length: 0,
            data_remaining: 0,
            reserved2: 0,
            data: Vec::new(),
        })
    }

    /// Handle write request
    pub fn handle_write_request(&mut self, req: &Smb2WriteRequest) -> Result<Smb2WriteResponse> {
        if let Some(open_file) = self.open_files.get_mut(&req.file_id) {
            // Update file size if writing past EOF
            if req.offset + req.length as u64 > open_file.end_of_file {
                open_file.end_of_file = req.offset + req.length as u64;
            }

            Ok(Smb2WriteResponse {
                structure_size: 17,
                reserved: 0,
                count: req.length,
                remaining: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
            })
        } else {
            Err(Error::InvalidParameter("Invalid file ID".to_string()))
        }
    }

    /// Get next message ID
    pub fn next_message_id(&mut self) -> u64 {
        let id = self.next_message_id;
        self.next_message_id += 1;
        id
    }

    /// Check if signing is required
    pub fn is_signing_required(&self) -> bool {
        self.security_mode & SecurityMode::SIGNING_REQUIRED.bits() != 0
    }

    /// Handle query info request
    pub fn handle_query_info_request(
        &mut self,
        req: &Smb2QueryInfoRequest,
    ) -> Result<Smb2QueryInfoResponse> {
        // Check file exists
        let open_file = self
            .open_files
            .get(&req.file_id)
            .ok_or_else(|| Error::InvalidParameter("Invalid file ID".to_string()))?;

        // Build response based on info type and class
        let output_buffer = match req.info_type {
            InfoType::FILE => {
                match req.file_info_class {
                    FileInfoClass::DirectoryInfo
                    | FileInfoClass::FullDirectoryInfo
                    | FileInfoClass::BothDirectoryInfo => {
                        // These are directory query classes, not file info classes
                        // Return error or empty buffer for now
                        // TODO: These should be handled by QUERY_DIRECTORY, not QUERY_INFO
                        return Err(Error::InvalidParameter(format!(
                            "Directory info class {:?} not supported in QUERY_INFO",
                            req.file_info_class
                        )));
                    }
                    FileInfoClass::BASIC => {
                        // Return basic file information
                        let mut buf = Vec::new();
                        buf.write_u64::<LittleEndian>(open_file.create_time)?;
                        buf.write_u64::<LittleEndian>(open_file.access_time)?;
                        buf.write_u64::<LittleEndian>(open_file.write_time)?;
                        buf.write_u64::<LittleEndian>(open_file.change_time)?;
                        buf.write_u32::<LittleEndian>(open_file.file_attributes)?;
                        buf.write_u32::<LittleEndian>(0)?; // Reserved
                        buf
                    }
                    FileInfoClass::STANDARD => {
                        // Return standard file information
                        let mut buf = Vec::new();
                        buf.write_u64::<LittleEndian>(open_file.allocation_size)?;
                        buf.write_u64::<LittleEndian>(open_file.end_of_file)?;
                        buf.write_u32::<LittleEndian>(1)?; // Number of links
                        buf.write_u8(0)?; // Delete pending
                        buf.write_u8(if open_file.file_attributes & 0x10 != 0 {
                            1
                        } else {
                            0
                        })?; // Directory
                        buf.write_u16::<LittleEndian>(0)?; // Reserved
                        buf
                    }
                    FileInfoClass::ALL => {
                        // FileAllInformation - combination of all basic info
                        let mut buf = Vec::new();

                        // BasicInfo (0x04)
                        buf.write_u64::<LittleEndian>(open_file.create_time)?;
                        buf.write_u64::<LittleEndian>(open_file.access_time)?;
                        buf.write_u64::<LittleEndian>(open_file.write_time)?;
                        buf.write_u64::<LittleEndian>(open_file.change_time)?;
                        buf.write_u32::<LittleEndian>(open_file.file_attributes)?;
                        buf.write_u32::<LittleEndian>(0)?; // Reserved

                        // StandardInfo (0x05)
                        buf.write_u64::<LittleEndian>(open_file.allocation_size)?;
                        buf.write_u64::<LittleEndian>(open_file.end_of_file)?;
                        buf.write_u32::<LittleEndian>(1)?; // Number of links
                        buf.write_u8(0)?; // Delete pending
                        buf.write_u8(if open_file.file_attributes & 0x10 != 0 {
                            1
                        } else {
                            0
                        })?; // Directory
                        buf.write_u16::<LittleEndian>(0)?; // Reserved

                        // InternalInfo (0x06) - 8 bytes
                        buf.write_u64::<LittleEndian>(0)?; // IndexNumber

                        // EaInfo (0x07) - 4 bytes
                        buf.write_u32::<LittleEndian>(0)?; // EaSize

                        // AccessInfo (0x08) - 4 bytes
                        buf.write_u32::<LittleEndian>(open_file.desired_access)?;

                        // PositionInfo (0x0E) - 8 bytes
                        buf.write_u64::<LittleEndian>(0)?; // CurrentByteOffset

                        // ModeInfo (0x10) - 4 bytes
                        buf.write_u32::<LittleEndian>(0)?; // Mode

                        // AlignmentInfo (0x11) - 4 bytes
                        buf.write_u32::<LittleEndian>(0)?; // AlignmentRequirement

                        // NameInfo (0x09) - variable length
                        let name_utf16: Vec<u16> = open_file.file_name.encode_utf16().collect();
                        buf.write_u32::<LittleEndian>((name_utf16.len() * 2) as u32)?; // FileNameLength
                        for c in name_utf16 {
                            buf.write_u16::<LittleEndian>(c)?;
                        }

                        buf
                    }
                    _ => Vec::new(), // Not implemented
                }
            }
            InfoType::FILESYSTEM => {
                // Handle filesystem info queries
                let fs_info_class =
                    FsInfoClass::try_from(req.file_info_class as u8).unwrap_or(FsInfoClass::Size);

                match fs_info_class {
                    FsInfoClass::Size | FsInfoClass::FullSize => {
                        // FileFsSizeInformation or FileFsFullSizeInformation
                        let mut buf = Vec::new();
                        // TotalAllocationUnits (total space)
                        buf.write_u64::<LittleEndian>(1000000)?;
                        // AvailableAllocationUnits (free space)
                        buf.write_u64::<LittleEndian>(500000)?;
                        // SectorsPerAllocationUnit
                        buf.write_u32::<LittleEndian>(8)?;
                        // BytesPerSector
                        buf.write_u32::<LittleEndian>(512)?;
                        buf
                    }
                    FsInfoClass::Volume => {
                        // FileFsVolumeInformation
                        let mut buf = Vec::new();
                        // VolumeCreationTime
                        buf.write_u64::<LittleEndian>(0)?;
                        // VolumeSerialNumber
                        buf.write_u32::<LittleEndian>(0x12345678)?;
                        // VolumeLabelLength (in bytes)
                        let label = "SMB_SHARE";
                        let label_bytes = label.encode_utf16().collect::<Vec<u16>>();
                        buf.write_u32::<LittleEndian>((label_bytes.len() * 2) as u32)?;
                        // SupportsObjects
                        buf.write_u8(0)?;
                        // Reserved
                        buf.write_u8(0)?;
                        // VolumeLabel (Unicode)
                        for c in label_bytes {
                            buf.write_u16::<LittleEndian>(c)?;
                        }
                        buf
                    }
                    FsInfoClass::Device => {
                        // FileFsDeviceInformation
                        let mut buf = Vec::new();
                        // DeviceType (FILE_DEVICE_DISK = 0x07)
                        buf.write_u32::<LittleEndian>(0x07)?;
                        // Characteristics (FILE_DEVICE_IS_MOUNTED = 0x20)
                        buf.write_u32::<LittleEndian>(0x20)?;
                        buf
                    }
                    FsInfoClass::Attribute => {
                        // FileFsAttributeInformation
                        let mut buf = Vec::new();
                        // FileSystemAttributes flags
                        // FILE_CASE_PRESERVED_NAMES = 0x00000002
                        // FILE_UNICODE_ON_DISK = 0x00000004
                        // FILE_PERSISTENT_ACLS = 0x00000008
                        let attrs: u32 = 0x00000002 | 0x00000004 | 0x00000008;
                        buf.write_u32::<LittleEndian>(attrs)?;
                        // MaximumComponentNameLength
                        buf.write_u32::<LittleEndian>(255)?;
                        // FileSystemNameLength (in bytes)
                        let fs_name = "NTFS";
                        let fs_name_bytes = fs_name.encode_utf16().collect::<Vec<u16>>();
                        buf.write_u32::<LittleEndian>((fs_name_bytes.len() as u32) * 2)?;
                        // FileSystemName (Unicode)
                        for c in fs_name_bytes {
                            buf.write_u16::<LittleEndian>(c)?;
                        }
                        buf
                    }
                    _ => Vec::new(), // Not implemented
                }
            }
            _ => Vec::new(), // Not implemented
        };

        Ok(Smb2QueryInfoResponse {
            structure_size: 9,
            output_buffer_offset: 72, // Header + response size
            output_buffer_length: output_buffer.len() as u32,
            output_buffer,
        })
    }

    /// Handle set info request
    pub fn handle_set_info_request(
        &mut self,
        req: &Smb2SetInfoRequest,
    ) -> Result<Smb2SetInfoResponse> {
        // Check file exists
        if let Some(open_file) = self.open_files.get_mut(&req.file_id) {
            // Process based on info type and class
            match req.info_type {
                InfoType::FILE => {
                    match req.file_info_class {
                        FileInfoClass::BASIC => {
                            // Update basic file information from buffer
                            if req.buffer.len() >= 40 {
                                // Parse times and attributes from buffer
                                // This is simplified - real implementation would parse properly
                                let mut cursor = Cursor::new(&req.buffer[32..36]);
                                open_file.file_attributes = cursor.read_u32::<LittleEndian>()?;
                            }
                        }
                        FileInfoClass::EndOfFile => {
                            // Update end of file
                            if req.buffer.len() >= 8 {
                                let mut cursor = Cursor::new(&req.buffer[0..8]);
                                open_file.end_of_file = cursor.read_u64::<LittleEndian>()?;
                            }
                        }
                        _ => {} // Not implemented
                    }
                }
                _ => {} // Not implemented
            }

            Ok(Smb2SetInfoResponse { structure_size: 2 })
        } else {
            Err(Error::InvalidParameter("Invalid file ID".to_string()))
        }
    }

    /// Handle query directory request
    pub fn handle_query_directory_request(
        &mut self,
        req: &Smb2QueryDirectoryRequest,
    ) -> Result<Smb2QueryDirectoryResponse> {
        // Check file exists and is a directory
        if !self.open_files.contains_key(&req.file_id) {
            return Err(Error::InvalidParameter("Invalid file ID".to_string()));
        }

        // For now, return empty directory listing
        // Real implementation would enumerate actual directory contents
        Ok(Smb2QueryDirectoryResponse {
            structure_size: 9,
            output_buffer_offset: 0,
            output_buffer_length: 0,
            output_buffer: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_state_machine_creation() {
        let sm = Smb2StateMachine::new();
        assert_eq!(sm.state, ConnectionState::Disconnected);
        assert!(sm.sessions.is_empty());
        assert!(sm.trees.is_empty());
        assert!(sm.open_files.is_empty());
    }

    #[test]
    fn test_connection_state_transitions() {
        let mut sm = Smb2StateMachine::new();

        // Connect
        assert!(sm.on_connect().is_ok());
        assert_eq!(sm.state, ConnectionState::Connected);

        // Can't connect again
        assert!(sm.on_connect().is_err());
    }

    #[test]
    fn test_negotiate_flow() {
        let mut sm = Smb2StateMachine::new();
        sm.on_connect().unwrap();

        let req = Smb2NegotiateRequest {
            structure_size: 36,
            dialect_count: 1,
            security_mode: SecurityMode::SIGNING_ENABLED,
            reserved: 0,
            capabilities: Smb2Capabilities::DFS,
            client_guid: Uuid::new_v4(),
            client_start_time: 0,
            dialects: vec![Smb2Dialect::Smb210],
            negotiate_contexts: None,
        };

        let resp = sm.handle_negotiate_request(&req).unwrap();
        assert_eq!(resp.dialect_revision, Smb2Dialect::Smb210);
        assert_eq!(sm.state, ConnectionState::Negotiated);
    }

    #[test]
    fn test_session_setup() {
        let mut sm = Smb2StateMachine::new();
        sm.on_connect().unwrap();

        // Negotiate first
        let neg_req = Smb2NegotiateRequest {
            structure_size: 36,
            dialect_count: 1,
            security_mode: SecurityMode::SIGNING_ENABLED,
            reserved: 0,
            capabilities: Smb2Capabilities::DFS,
            client_guid: Uuid::new_v4(),
            client_start_time: 0,
            dialects: vec![Smb2Dialect::Smb210],
            negotiate_contexts: None,
        };
        sm.handle_negotiate_request(&neg_req).unwrap();

        // Session setup
        let sess_req = Smb2SessionSetupRequest {
            structure_size: 25,
            flags: 0,
            security_mode: SecurityMode::SIGNING_ENABLED,
            capabilities: Smb2Capabilities::DFS,
            channel: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            previous_session_id: 0,
            security_blob: Vec::new(),
        };

        let resp = sm.handle_session_setup_request(&sess_req).unwrap();
        assert_eq!(resp.session_flags, SessionFlags::IS_GUEST.bits());
        assert_eq!(sm.state, ConnectionState::SessionEstablished);
        assert_eq!(sm.sessions.len(), 1);
    }
}
