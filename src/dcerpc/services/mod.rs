//! DCE/RPC services implementation
//!
//! Only services essential for SMB file service are implemented:
//! - SRVSVC: Server Service for share enumeration and server info
//! - SAMR: Security Account Manager for basic user/group queries

pub mod common;
pub mod samr;
pub mod srvsvc;

use crate::dcerpc::ndr::{NdrDecoder, NdrEncoder};
use crate::dcerpc::RpcInterface;
use crate::error::Result;
use std::collections::HashMap;

/// RPC service trait
pub trait RpcService: Send + Sync {
    /// Get the interface definition
    fn interface(&self) -> &RpcInterface;

    /// Handle an RPC call
    fn handle_call(&mut self, opnum: u16, input: &[u8]) -> Result<Vec<u8>>;

    /// Get service name
    fn name(&self) -> &str;
}

/// RPC service registry
pub struct ServiceRegistry {
    services: HashMap<uuid::Uuid, Box<dyn RpcService>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Register a service
    pub fn register(&mut self, service: Box<dyn RpcService>) {
        let uuid = service.interface().uuid;
        self.services.insert(uuid, service);
    }

    /// Get a service by UUID
    pub fn get(&self, uuid: &uuid::Uuid) -> Option<&dyn RpcService> {
        self.services.get(uuid).map(|s| s.as_ref())
    }

    /// Get a mutable service by UUID
    pub fn get_mut(&mut self, uuid: &uuid::Uuid) -> Option<&mut (dyn RpcService + 'static)> {
        self.services.get_mut(uuid).map(|s| s.as_mut())
    }

    /// Initialize with default services
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();

        // Register only essential services for SMB file service
        registry.register(Box::new(srvsvc::SrvSvcService::new()));
        registry.register(Box::new(samr::SamrService::new()));

        registry
    }
}

/// Common RPC status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcStatus {
    Success = 0,
    AccessDenied = 0xC0000022,
    InvalidParameter = 0xC000000D,
    InvalidHandle = 0xC0000008,
    NotSupported = 0xC00000BB,
    BufferTooSmall = 0xC0000023,
    NoSuchUser = 0xC0000064,
    NoSuchGroup = 0xC0000066,
    NoSuchDomain = 0xC00000DF,
    ObjectNameNotFound = 0xC0000034,
    ObjectNameCollision = 0xC0000035,
}

/// Security descriptor for RPC objects
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub sbz1: u8,
    pub control: u16,
    pub owner_sid: Option<Vec<u8>>,
    pub group_sid: Option<Vec<u8>>,
    pub sacl: Option<Vec<u8>>,
    pub dacl: Option<Vec<u8>>,
}

impl SecurityDescriptor {
    pub fn new() -> Self {
        Self {
            revision: 1,
            sbz1: 0,
            control: 0x8004, // SE_DACL_PRESENT | SE_SELF_RELATIVE
            owner_sid: None,
            group_sid: None,
            sacl: None,
            dacl: None,
        }
    }

    pub fn encode(&self, encoder: &mut NdrEncoder) -> Result<()> {
        encoder.encode_u8(self.revision)?;
        encoder.encode_u8(self.sbz1)?;
        encoder.encode_u16(self.control)?;

        // Encode offsets (simplified - would need proper calculation)
        encoder.encode_u32(0)?; // Owner offset
        encoder.encode_u32(0)?; // Group offset
        encoder.encode_u32(0)?; // SACL offset
        encoder.encode_u32(0)?; // DACL offset

        Ok(())
    }

    pub fn decode(decoder: &mut NdrDecoder) -> Result<Self> {
        let revision = decoder.decode_u8()?;
        let sbz1 = decoder.decode_u8()?;
        let control = decoder.decode_u16()?;

        // Skip offsets for now
        let _owner_offset = decoder.decode_u32()?;
        let _group_offset = decoder.decode_u32()?;
        let _sacl_offset = decoder.decode_u32()?;
        let _dacl_offset = decoder.decode_u32()?;

        Ok(Self {
            revision,
            sbz1,
            control,
            owner_sid: None,
            group_sid: None,
            sacl: None,
            dacl: None,
        })
    }
}

/// Well-known SIDs
pub mod sids {
    pub const EVERYONE: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    pub const ADMINISTRATORS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
    pub const USERS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];
    pub const GUESTS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 34, 2, 0, 0];
    pub const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    pub const LOCAL_SERVICE: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0];
    pub const NETWORK_SERVICE: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 20, 0, 0, 0];
}

/// Access mask constants
pub mod access_masks {
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_ALL: u32 = 0x10000000;
    pub const MAXIMUM_ALLOWED: u32 = 0x02000000;
    pub const ACCESS_SYSTEM_SECURITY: u32 = 0x01000000;
    pub const SYNCHRONIZE: u32 = 0x00100000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const DELETE: u32 = 0x00010000;
}
