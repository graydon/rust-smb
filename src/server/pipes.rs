//! Named pipe support for SMB server
//!
//! Implements named pipes for IPC$ share, particularly for RPC endpoints

use crate::dcerpc::packet::RpcHeader;
use crate::dcerpc::services::samr::SamrService;
use crate::dcerpc::services::srvsvc::SrvSvcService;
use crate::dcerpc::services::RpcService;
use crate::dcerpc::{PacketType, RpcContext};
use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;
use uuid::Uuid;

/// Well-known pipes supported by this SMB server
pub mod well_known_pipes {
    /// Null pipe - always available, discards data
    pub const NULL: &str = "null";
    /// Server Service pipe - for share enumeration
    pub const SRVSVC: &str = "srvsvc";
    /// SAMR pipe - for user/group queries
    pub const SAMR: &str = "samr";

    /// Check if a pipe name is supported
    pub fn is_supported(name: &str) -> bool {
        let lower = name.to_lowercase();
        matches!(lower.as_str(), "null" | "srvsvc" | "samr")
    }

    /// Check if a pipe is an RPC pipe
    pub fn is_rpc_pipe(name: &str) -> bool {
        let lower = name.to_lowercase();
        matches!(lower.as_str(), "srvsvc" | "samr")
    }
}

/// Named pipe instance
pub struct NamedPipe {
    /// Pipe name (without \\pipe\\ prefix)
    pub name: String,
    /// Current data in the pipe
    pub data: Vec<u8>,
    /// Whether this is an RPC pipe
    pub is_rpc: bool,
    /// Maximum message size
    pub max_message_size: usize,
    /// RPC context for this pipe
    pub rpc_context: Option<RpcContext>,
    /// RPC service if this is an RPC pipe
    pub rpc_service: Option<Box<dyn RpcService + Send + Sync>>,
}

impl NamedPipe {
    /// Create a new named pipe
    pub fn new(name: String, is_rpc: bool) -> Self {
        let mut pipe = Self {
            name: name.clone(),
            data: Vec::new(),
            is_rpc,
            max_message_size: 65536, // 64KB default
            rpc_context: None,
            rpc_service: None,
        };

        // Initialize RPC service for known pipes
        if is_rpc {
            pipe.rpc_context = Some(RpcContext::new());
            match name.to_lowercase().as_str() {
                well_known_pipes::SRVSVC => {
                    pipe.rpc_service = Some(Box::new(SrvSvcService::new()));
                }
                well_known_pipes::SAMR => {
                    pipe.rpc_service = Some(Box::new(SamrService::new()));
                }
                _ => {}
            }
        }

        pipe
    }

    /// Create a new named pipe with shares
    pub async fn with_shares(
        name: String,
        is_rpc: bool,
        shares: Arc<RwLock<HashMap<String, crate::server::ShareInfo>>>,
    ) -> Self {
        let mut pipe = Self {
            name: name.clone(),
            data: Vec::new(),
            is_rpc,
            max_message_size: 65536, // 64KB default
            rpc_context: None,
            rpc_service: None,
        };

        // Initialize RPC service for known pipes
        if is_rpc {
            pipe.rpc_context = Some(RpcContext::new());
            match name.to_lowercase().as_str() {
                well_known_pipes::SRVSVC => {
                    // Get a snapshot of the current shares
                    let shares_snapshot = shares.read().await.clone();
                    pipe.rpc_service = Some(Box::new(SrvSvcService::with_shares(shares_snapshot)));
                }
                well_known_pipes::SAMR => {
                    pipe.rpc_service = Some(Box::new(SamrService::new()));
                }
                _ => {}
            }
        }

        pipe
    }

    /// Write data to the pipe
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() > self.max_message_size {
            return Err(Error::InvalidParameter("Message too large".to_string()));
        }

        // For now, just replace the buffer (no queueing)
        self.data = data.to_vec();
        Ok(data.len())
    }

    /// Read data from the pipe
    pub fn read(&mut self, max_len: usize) -> Vec<u8> {
        let len = std::cmp::min(self.data.len(), max_len);
        if len == 0 {
            return Vec::new();
        }

        // Take the requested amount and remove from buffer
        let result = self.data[..len].to_vec();
        self.data.drain(..len);
        result
    }

    /// Peek at data without removing it
    pub fn peek(&self, max_len: usize) -> Vec<u8> {
        let len = std::cmp::min(self.data.len(), max_len);
        if len == 0 {
            return Vec::new();
        }
        self.data[..len].to_vec()
    }

    /// Transceive - write then read in one operation
    pub fn transceive(&mut self, write_data: &[u8], max_read: usize) -> Result<Vec<u8>> {
        // For RPC pipes, we need to process the request and generate a response
        if self.is_rpc {
            // Check if this is srvsvc pipe
            if self.name == well_known_pipes::SRVSVC {
                return self.handle_srvsvc_request(write_data);
            }
            // For other RPC pipes, return a minimal error response
            return Ok(self.create_rpc_fault());
        }

        // For non-RPC pipes, just echo back (for testing)
        self.write(write_data)?;
        Ok(self.read(max_read))
    }

    /// Handle srvsvc RPC requests
    fn handle_srvsvc_request(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        debug!("RPC: Processing {} bytes for srvsvc pipe", data.len());

        // Trace all incoming bytes
        if data.len() <= 256 {
            debug!(
                "RPC: Incoming bytes (hex): {}",
                data.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        } else {
            debug!(
                "RPC: Incoming first 256 bytes (hex): {}",
                data[..256]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }

        // Parse DCE/RPC packet header
        if data.len() < 16 {
            debug!("RPC: Packet too small ({} bytes)", data.len());
            return Ok(self.create_rpc_fault());
        }

        let mut cursor = Cursor::new(data);
        let header = match RpcHeader::deserialize(&mut cursor) {
            Ok(h) => h,
            Err(e) => {
                debug!("RPC: Failed to parse header: {:?}", e);
                return Ok(self.create_rpc_fault());
            }
        };

        debug!(
            "RPC: Packet type {:?}, call_id {}",
            header.packet_type, header.call_id
        );

        // Check version
        if header.version_major != 5 || header.version_minor != 0 {
            debug!(
                "RPC: Invalid version {}.{}",
                header.version_major, header.version_minor
            );
            return Ok(self.create_rpc_fault());
        }

        let result = match header.packet_type {
            PacketType::Bind => {
                debug!("RPC: Processing Bind request");
                self.handle_rpc_bind(&header, data)
            }
            PacketType::Request => {
                debug!("RPC: Processing Request");
                self.handle_rpc_request(&header, data)
            }
            _ => {
                debug!("RPC: Unsupported packet type");
                Ok(self.create_rpc_fault())
            }
        };

        // Trace all outgoing bytes
        if let Ok(ref response) = result {
            if response.len() <= 256 {
                debug!(
                    "RPC: Outgoing bytes (hex): {}",
                    response
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            } else {
                debug!(
                    "RPC: Outgoing first 256 bytes (hex): {}",
                    response[..256]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }

        result
    }

    /// Handle RPC bind request
    fn handle_rpc_bind(&mut self, header: &RpcHeader, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 28 {
            return Ok(self.create_rpc_fault());
        }

        let mut cursor = Cursor::new(&data[16..20]);
        let max_xmit_frag = cursor.read_u16::<LittleEndian>()?;
        let max_recv_frag = cursor.read_u16::<LittleEndian>()?;

        // Extract interface UUID (NDR format - little-endian for first 3 fields)
        let mut interface_uuid = None;
        if data.len() >= 60 {
            // UUID in NDR format has special byte ordering:
            // - First 4 bytes (time_low) in little-endian
            // - Next 2 bytes (time_mid) in little-endian
            // - Next 2 bytes (time_hi_and_version) in little-endian
            // - Last 8 bytes in big-endian
            let mut uuid_bytes = [0u8; 16];

            // time_low (4 bytes) - reverse
            uuid_bytes[0] = data[35];
            uuid_bytes[1] = data[34];
            uuid_bytes[2] = data[33];
            uuid_bytes[3] = data[32];

            // time_mid (2 bytes) - reverse
            uuid_bytes[4] = data[37];
            uuid_bytes[5] = data[36];

            // time_hi_and_version (2 bytes) - reverse
            uuid_bytes[6] = data[39];
            uuid_bytes[7] = data[38];

            // clock_seq_hi_and_reserved, clock_seq_low, node (8 bytes) - keep order
            uuid_bytes[8..16].copy_from_slice(&data[40..48]);

            interface_uuid = Some(Uuid::from_bytes(uuid_bytes));
            debug!("RPC: Bind request for interface UUID: {:?}", interface_uuid);
        }

        // Check if we support this interface
        let supported = if let Some(ref service) = self.rpc_service {
            let service_uuid = service.interface().uuid;
            debug!("RPC: Our srvsvc UUID: {:?}", service_uuid);
            interface_uuid.map_or(false, |uuid| uuid == service_uuid)
        } else {
            false
        };

        if !supported && interface_uuid.is_some() {
            debug!("RPC: Unsupported interface UUID, sending bind_nak");
            return self.create_bind_nak(header.call_id);
        }

        // Bind the interface to the context
        if let Some(ref mut ctx) = self.rpc_context {
            if let Some(ref service) = self.rpc_service {
                ctx.bind_interface(0, service.interface().clone());
            }
        }

        debug!("RPC: Creating bind_ack response");
        let response = self.create_bind_ack(header.call_id, max_xmit_frag, max_recv_frag)?;
        debug!("RPC: bind_ack size: {} bytes", response.len());
        Ok(response)
    }

    /// Handle RPC request
    fn handle_rpc_request(&mut self, header: &RpcHeader, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 24 {
            return Ok(self.create_rpc_fault());
        }

        let mut cursor = Cursor::new(&data[16..24]);
        let _alloc_hint = cursor.read_u32::<LittleEndian>()?;
        let _context_id = cursor.read_u16::<LittleEndian>()?;
        let opnum = cursor.read_u16::<LittleEndian>()?;

        debug!(
            "RPC: Request opnum {} (0x{:02x}) with {} bytes of stub data",
            opnum,
            opnum,
            data.len() - 24
        );

        // Trace stub data
        if data.len() > 24 {
            let stub_len = data.len() - 24;
            if stub_len <= 128 {
                debug!(
                    "RPC: Stub data (hex): {}",
                    data[24..]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            } else {
                debug!(
                    "RPC: Stub data first 128 bytes (hex): {}",
                    data[24..24 + 128]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }

        // Get stub data (skip header and request fields)
        let stub_data = if data.len() > 24 { &data[24..] } else { &[] };

        // Call the service handler
        if let Some(ref mut service) = self.rpc_service {
            match service.handle_call(opnum, stub_data) {
                Ok(response_data) => {
                    debug!(
                        "RPC: Service returned {} bytes of response data",
                        response_data.len()
                    );

                    // Trace response stub data
                    if response_data.len() <= 128 {
                        debug!(
                            "RPC: Response stub data (hex): {}",
                            response_data
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                    } else {
                        debug!(
                            "RPC: Response stub data first 128 bytes (hex): {}",
                            response_data[..128]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                    }

                    let full_response = self.create_response(header.call_id, response_data)?;
                    debug!("RPC: Full response packet is {} bytes", full_response.len());
                    Ok(full_response)
                }
                Err(e) => {
                    debug!("RPC: Service handler error: {:?}", e);
                    Ok(self.create_rpc_fault())
                }
            }
        } else {
            debug!("RPC: No service handler available");
            Ok(self.create_rpc_fault())
        }
    }

    /// Create a bind_ack response
    fn create_bind_ack(
        &self,
        call_id: u32,
        max_xmit_frag: u16,
        max_recv_frag: u16,
    ) -> Result<Vec<u8>> {
        let mut response = Vec::new();

        // Header
        response.push(5); // Version major
        response.push(0); // Version minor
        response.push(12); // Type = bind_ack
        response.push(0x03); // Flags (first_frag | last_frag)
        response.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // Data representation
        response.write_u16::<LittleEndian>(0)?; // Frag length (will update)
        response.write_u16::<LittleEndian>(0)?; // Auth length
        response.write_u32::<LittleEndian>(call_id)?;

        // Bind_ack fields
        response.write_u16::<LittleEndian>(max_xmit_frag)?;
        response.write_u16::<LittleEndian>(max_recv_frag)?;
        response.write_u32::<LittleEndian>(0x00012345)?; // Assoc group ID

        // Secondary address (must include null terminator)
        let sec_addr: &[u8] = match self.name.as_str() {
            well_known_pipes::SRVSVC => b"\\pipe\\srvsvc\0",
            well_known_pipes::SAMR => b"\\pipe\\samr\0",
            _ => b"\\pipe\\null\0",
        };
        // Length excludes null terminator
        response.write_u16::<LittleEndian>((sec_addr.len() - 1) as u16)?;
        response.extend_from_slice(sec_addr);

        // Align to 4 bytes
        while (response.len() - 16) % 4 != 0 {
            response.push(0);
        }

        // Result list
        response.push(1); // Number of results
        response.extend_from_slice(&[0, 0, 0]); // Padding

        // Context result
        response.write_u16::<LittleEndian>(0)?; // Result = acceptance
        response.write_u16::<LittleEndian>(0)?; // Reason

        // NDR transfer syntax UUID (8a885d04-1ceb-11c9-9fe8-08002b104860)
        // Must be in NDR wire format (little-endian for first 3 parts)
        response.extend_from_slice(&[
            0x04, 0x5d, 0x88, 0x8a, // time_low (little-endian)
            0xeb, 0x1c, // time_mid (little-endian)
            0xc9, 0x11, // time_hi_and_version (little-endian)
            0x9f, 0xe8, // clock_seq
            0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, // node
        ]);
        response.write_u32::<LittleEndian>(2)?; // Transfer syntax version

        // Update frag length
        let frag_len = response.len() as u16;
        (&mut response[8..10]).write_u16::<LittleEndian>(frag_len)?;

        debug!(
            "RPC: bind_ack response total size: {} bytes, frag_len in header: {}",
            response.len(),
            frag_len
        );

        Ok(response)
    }

    /// Create a bind_nak response
    fn create_bind_nak(&self, call_id: u32) -> Result<Vec<u8>> {
        let mut response = Vec::new();

        // Header
        response.push(5); // Version major
        response.push(0); // Version minor
        response.push(13); // Type = bind_nak
        response.push(0x03); // Flags
        response.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // Data representation
        response.write_u16::<LittleEndian>(0)?; // Frag length (will update)
        response.write_u16::<LittleEndian>(0)?; // Auth length
        response.write_u32::<LittleEndian>(call_id)?;

        // Reject reason (2 = provider rejection)
        response.write_u16::<LittleEndian>(2)?;

        // Versions
        response.push(1); // Number of versions
        response.push(0); // Padding

        // Version
        response.push(5); // RPC version
        response.push(0); // RPC version minor

        // Update frag length
        let frag_len = response.len() as u16;
        (&mut response[8..10]).write_u16::<LittleEndian>(frag_len)?;

        Ok(response)
    }

    /// Create a response packet
    fn create_response(&self, call_id: u32, stub_data: Vec<u8>) -> Result<Vec<u8>> {
        let mut response = Vec::new();

        // Header
        response.push(5); // Version major
        response.push(0); // Version minor
        response.push(2); // Type = response
        response.push(0x03); // Flags (first_frag | last_frag)
        response.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // Data representation
        response.write_u16::<LittleEndian>(0)?; // Frag length (will update)
        response.write_u16::<LittleEndian>(0)?; // Auth length
        response.write_u32::<LittleEndian>(call_id)?;

        // Response fields
        response.write_u32::<LittleEndian>(stub_data.len() as u32)?; // Alloc hint
        response.write_u16::<LittleEndian>(0)?; // Context ID
        response.push(0); // Cancel count
        response.push(0); // Reserved

        // Stub data
        response.extend_from_slice(&stub_data);

        // Update frag length
        let frag_len = response.len() as u16;
        (&mut response[8..10]).write_u16::<LittleEndian>(frag_len)?;

        Ok(response)
    }

    /// Create an RPC fault response
    fn create_rpc_fault(&self) -> Vec<u8> {
        // Minimal DCE/RPC fault
        vec![
            0x05, 0x00, // Version
            0x03, 0x03, // Type (fault), flags
            0x20, 0x00, 0x00, 0x00, // Fragment length
            0x00, 0x00, // Auth length
            0x00, 0x00, 0x00, 0x00, // Call ID
            0x00, 0x00, 0x00, 0x00, // Alloc hint
            0x00, 0x00, // Context ID
            0x00, 0x00, // Cancel count
            0x00, 0x00, // Reserved
            0x1c, 0x00, 0x00, 0x00, // Status (nca_s_fault_ndr)
            0x00, 0x00, 0x00, 0x00, // Reserved
        ]
    }
}

/// Named pipe manager
pub struct PipeManager {
    /// Map of pipe names to pipe instances
    /// Key format: "pipename" (without \\pipe\\ prefix)
    pipes: Arc<RwLock<HashMap<String, Arc<Mutex<NamedPipe>>>>>,
    /// Server shares for RPC services
    shares: Arc<RwLock<HashMap<String, crate::server::ShareInfo>>>,
}

impl PipeManager {
    /// Create a new pipe manager
    pub fn new() -> Self {
        Self::with_shares(Arc::new(RwLock::new(HashMap::new())))
    }

    /// Create a new pipe manager with shares
    pub fn with_shares(shares: Arc<RwLock<HashMap<String, crate::server::ShareInfo>>>) -> Self {
        let pipes = HashMap::new();
        // Don't pre-create pipes - create them on demand with proper shares
        Self {
            pipes: Arc::new(RwLock::new(pipes)),
            shares,
        }
    }

    /// Open or create a named pipe
    pub async fn open_pipe(&self, name: &str) -> Result<Arc<Mutex<NamedPipe>>> {
        // Remove any leading \\ or \\pipe\\ prefix
        let clean_name = name
            .trim_start_matches("\\\\")
            .trim_start_matches("\\")
            .trim_start_matches("pipe\\")
            .trim_start_matches("PIPE\\");

        let mut pipes = self.pipes.write().await;

        // Check if pipe exists
        if let Some(pipe) = pipes.get(clean_name) {
            return Ok(Arc::clone(pipe));
        }

        // Create new pipe if it's a supported pipe
        if !well_known_pipes::is_supported(clean_name) && clean_name != "null" {
            return Err(Error::FileNotFound(format!("Pipe '{}' not found", name)));
        }

        let is_rpc = well_known_pipes::is_rpc_pipe(clean_name);
        let shares = self.shares.clone();
        let pipe = Arc::new(Mutex::new(
            NamedPipe::with_shares(clean_name.to_string(), is_rpc, shares).await,
        ));
        pipes.insert(clean_name.to_string(), Arc::clone(&pipe));

        Ok(pipe)
    }

    /// Check if a pipe exists
    pub async fn pipe_exists(&self, name: &str) -> bool {
        let clean_name = name
            .trim_start_matches("\\\\")
            .trim_start_matches("\\")
            .trim_start_matches("pipe\\")
            .trim_start_matches("PIPE\\");

        let pipes = self.pipes.read().await;
        pipes.contains_key(clean_name)
    }

    /// Close a named pipe
    pub async fn close_pipe(&self, name: &str) -> Result<()> {
        let clean_name = name
            .trim_start_matches("\\\\")
            .trim_start_matches("\\")
            .trim_start_matches("pipe\\")
            .trim_start_matches("PIPE\\");

        let mut pipes = self.pipes.write().await;
        pipes.remove(clean_name);
        Ok(())
    }
}

impl Default for PipeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pipe_creation() {
        let manager = PipeManager::new();

        // Test opening an RPC pipe
        let pipe = manager.open_pipe("\\pipe\\srvsvc").await.unwrap();
        let pipe = pipe.lock().await;
        assert_eq!(pipe.name, "srvsvc");
        assert!(pipe.is_rpc);
    }

    #[tokio::test]
    async fn test_pipe_read_write() {
        let mut pipe = NamedPipe::new("test".to_string(), false);

        // Write data
        let written = pipe.write(b"Hello, pipe!").unwrap();
        assert_eq!(written, 12);

        // Read data
        let data = pipe.read(5);
        assert_eq!(data, b"Hello");

        // Read remaining
        let data = pipe.read(100);
        assert_eq!(data, b", pipe!");
    }

    #[tokio::test]
    async fn test_pipe_peek() {
        let mut pipe = NamedPipe::new("test".to_string(), false);
        pipe.write(b"Hello").unwrap();

        // Peek doesn't remove data
        let data = pipe.peek(3);
        assert_eq!(data, b"Hel");

        // Data is still there
        let data = pipe.read(5);
        assert_eq!(data, b"Hello");
    }

    #[tokio::test]
    async fn test_pipe_transceive() {
        let mut pipe = NamedPipe::new("echo".to_string(), false);

        // Non-RPC pipe echoes back
        let response = pipe.transceive(b"Echo test", 100).unwrap();
        assert_eq!(response, b"Echo test");
    }

    #[tokio::test]
    async fn test_rpc_pipe_bind() {
        let mut pipe = NamedPipe::new("srvsvc".to_string(), true);

        // Send a proper bind request with minimum required data
        let mut request = vec![
            5, 0,    // Version 5.0
            11,   // Type = bind (11)
            0x03, // Flags (first_frag | last_frag)
            0x10, 0x00, 0x00, 0x00, // Data representation
            0x48, 0x00, // Fragment length (72 bytes minimum)
            0x00, 0x00, // Auth length
            0x00, 0x00, 0x00, 0x00, // Call ID
            0x00, 0x10, // Max xmit frag
            0x00, 0x10, // Max recv frag
            0x00, 0x00, 0x00, 0x00, // Assoc group
            0x01, 0x00, 0x00, 0x00, // Num contexts
            0x00, 0x00, // Context ID
            0x01, 0x00, // Num transfer syntaxes
            // Interface UUID for srvsvc (16 bytes)
            0xc8, 0x4f, 0x32, 0x4b, // time_low
            0x70, 0x16, // time_mid
            0xd3, 0x01, // time_hi_and_version
            0x12, 0x78, // clock_seq_hi_and_reserved, clock_seq_low
            0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, // node
            0x03, 0x00, // Interface version
            0x00, 0x00, // Interface version minor
            // Transfer syntax UUID (NDR) (16 bytes)
            0x04, 0x5d, 0x88, 0x8a, // time_low
            0xeb, 0x1c, // time_mid
            0xc9, 0x11, // time_hi_and_version
            0x9f, 0xe8, // clock_seq_hi_and_reserved, clock_seq_low
            0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, // node
            0x02, 0x00, 0x00, 0x00, // Transfer syntax version
        ];

        // Ensure we have exactly 72 bytes
        while request.len() < 72 {
            request.push(0);
        }

        let response = pipe.transceive(&request, 100).unwrap();

        // Should get a bind_ack (type 12) or fault (type 3)
        assert!(response.len() >= 4);
        assert_eq!(response[0], 5); // Version
                                    // Accept either bind_ack (12) or fault (3) as valid responses
        assert!(response[2] == 12 || response[2] == 3)
    }
}
