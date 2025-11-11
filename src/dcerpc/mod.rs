//! DCE/RPC (Distributed Computing Environment / Remote Procedure Call) implementation
//! This is essential for SMB named pipes and various services like SAMR, LSARPC, SRVSVC, etc.

pub mod ndr;
pub mod packet;
pub mod services;
pub mod transport;

#[cfg(test)]
mod tests;

use crate::error::Result;
use std::collections::HashMap;
use std::convert::TryFrom;
use uuid::Uuid;

/// DCE/RPC protocol version
pub const DCERPC_VERSION_MAJOR: u8 = 5;
pub const DCERPC_VERSION_MINOR: u8 = 0;

/// DCE/RPC packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Request = 0,
    Response = 2,
    Fault = 3,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
    Auth3 = 16,
    Shutdown = 17,
    CancelRequest = 18,
    Orphaned = 19,
}

impl TryFrom<u8> for PacketType {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketType::Request),
            2 => Ok(PacketType::Response),
            3 => Ok(PacketType::Fault),
            11 => Ok(PacketType::Bind),
            12 => Ok(PacketType::BindAck),
            13 => Ok(PacketType::BindNak),
            14 => Ok(PacketType::AlterContext),
            15 => Ok(PacketType::AlterContextResp),
            16 => Ok(PacketType::Auth3),
            17 => Ok(PacketType::Shutdown),
            18 => Ok(PacketType::CancelRequest),
            19 => Ok(PacketType::Orphaned),
            _ => Err(crate::error::Error::ParseError(format!(
                "Unknown packet type: {}",
                value
            ))),
        }
    }
}

/// DCE/RPC packet flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags(u8);

impl PacketFlags {
    pub const FIRST_FRAG: u8 = 0x01;
    pub const LAST_FRAG: u8 = 0x02;
    pub const PENDING_CANCEL: u8 = 0x04;
    pub const RESERVED: u8 = 0x08;
    pub const CONC_MPX: u8 = 0x10;
    pub const DID_NOT_EXECUTE: u8 = 0x20;
    pub const MAYBE: u8 = 0x40;
    pub const OBJECT_UUID: u8 = 0x80;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_flags(flags: u8) -> Self {
        Self(flags)
    }

    pub fn is_first_frag(&self) -> bool {
        self.0 & Self::FIRST_FRAG != 0
    }

    pub fn is_last_frag(&self) -> bool {
        self.0 & Self::LAST_FRAG != 0
    }

    pub fn set_first_frag(&mut self) {
        self.0 |= Self::FIRST_FRAG;
    }

    pub fn set_last_frag(&mut self) {
        self.0 |= Self::LAST_FRAG;
    }
}

/// DCE/RPC authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthType {
    None = 0,
    KrbAp = 1,
    KrbIntegrity = 2,
    KrbPrivacy = 3,
    DceSecurity = 4,
    MsKerberos = 9,
    Ntlm = 10,
    Schannel = 68,
    Msmq = 100,
}

/// DCE/RPC authentication level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthLevel {
    None = 1,
    Connect = 2,
    Call = 3,
    Packet = 4,
    PacketIntegrity = 5,
    PacketPrivacy = 6,
}

/// DCE/RPC interface definition
#[derive(Debug, Clone)]
pub struct RpcInterface {
    pub uuid: Uuid,
    pub version_major: u16,
    pub version_minor: u16,
    pub name: String,
}

/// Well-known RPC interfaces
/// Only includes interfaces essential for SMB file service
pub mod interfaces {
    use super::*;
    use uuid::uuid;

    /// Security Account Manager - for basic user/group queries
    pub fn samr() -> RpcInterface {
        RpcInterface {
            uuid: uuid!("12345778-1234-ABCD-EF00-0123456789AC"),
            version_major: 1,
            version_minor: 0,
            name: "SAMR".to_string(),
        }
    }

    /// Server Service - for share enumeration and server info
    pub fn srvsvc() -> RpcInterface {
        RpcInterface {
            uuid: uuid!("4B324FC8-1670-01D3-1278-5A47BF6EE188"),
            version_major: 3,
            version_minor: 0,
            name: "SRVSVC".to_string(),
        }
    }
}

/// DCE/RPC context
pub struct RpcContext {
    /// Current call ID
    call_id: u32,
    /// Active context handles
    context_handles: HashMap<u32, ContextHandle>,
    /// Bound interfaces
    bound_interfaces: HashMap<u16, RpcInterface>,
    /// Authentication context
    auth_context: Option<AuthContext>,
    /// Fragment reassembly buffer
    fragment_buffer: HashMap<u32, FragmentReassembly>,
}

/// Context handle for stateful RPC operations
#[derive(Debug, Clone)]
pub struct ContextHandle {
    pub uuid: Uuid,
    pub attributes: u32,
}

/// Authentication context
#[derive(Debug)]
pub struct AuthContext {
    pub auth_type: AuthType,
    pub auth_level: AuthLevel,
    pub context_id: u32,
    pub session_key: Vec<u8>,
}

/// Fragment reassembly state
#[derive(Debug)]
struct FragmentReassembly {
    _packet_type: PacketType,
    _expected_fragments: usize,
    received_fragments: Vec<Vec<u8>>,
    total_size: usize,
}

impl RpcContext {
    /// Create a new RPC context
    pub fn new() -> Self {
        Self {
            call_id: 1,
            context_handles: HashMap::new(),
            bound_interfaces: HashMap::new(),
            auth_context: None,
            fragment_buffer: HashMap::new(),
        }
    }

    /// Get next call ID
    pub fn next_call_id(&mut self) -> u32 {
        let id = self.call_id;
        self.call_id = self.call_id.wrapping_add(1);
        id
    }

    /// Bind an interface
    pub fn bind_interface(&mut self, context_id: u16, interface: RpcInterface) {
        self.bound_interfaces.insert(context_id, interface);
    }

    /// Get bound interface
    pub fn get_interface(&self, context_id: u16) -> Option<&RpcInterface> {
        self.bound_interfaces.get(&context_id)
    }

    /// Set authentication context
    pub fn set_auth(&mut self, auth: AuthContext) {
        self.auth_context = Some(auth);
    }

    /// Add fragment for reassembly
    pub fn add_fragment(
        &mut self,
        call_id: u32,
        packet_type: PacketType,
        fragment: Vec<u8>,
        is_first: bool,
        is_last: bool,
    ) -> Result<Option<Vec<u8>>> {
        if is_first && is_last {
            // Single fragment, return immediately
            return Ok(Some(fragment));
        }

        let entry = self
            .fragment_buffer
            .entry(call_id)
            .or_insert_with(|| FragmentReassembly {
                _packet_type: packet_type,
                _expected_fragments: 0,
                received_fragments: Vec::new(),
                total_size: 0,
            });

        entry.received_fragments.push(fragment);
        // We just pushed to the vector, so last() will always return Some
        if let Some(last_frag) = entry.received_fragments.last() {
            entry.total_size += last_frag.len();
        }

        if is_last {
            // Reassemble all fragments
            let mut complete = Vec::with_capacity(entry.total_size);
            for frag in &entry.received_fragments {
                complete.extend_from_slice(frag);
            }
            self.fragment_buffer.remove(&call_id);
            Ok(Some(complete))
        } else {
            Ok(None)
        }
    }

    /// Create a new context handle
    pub fn create_context_handle(&mut self) -> ContextHandle {
        ContextHandle {
            uuid: Uuid::new_v4(),
            attributes: 0,
        }
    }

    /// Store a context handle
    pub fn store_context_handle(&mut self, id: u32, handle: ContextHandle) {
        self.context_handles.insert(id, handle);
    }

    /// Retrieve a context handle
    pub fn get_context_handle(&self, id: u32) -> Option<&ContextHandle> {
        self.context_handles.get(&id)
    }
}

/// RPC error codes (subset of Windows error codes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcError {
    Success = 0,
    AccessDenied = 5,
    InvalidHandle = 6,
    OutOfMemory = 14,
    InvalidParameter = 87,
    BufferTooSmall = 122,
    CallFailed = 1726,
    ProtocolError = 1728,
    UnsupportedType = 1732,
    InvalidTag = 1733,
    InvalidBound = 1734,
    NoEntryName = 1735,
    InvalidNameSyntax = 1736,
    UnsupportedNameSyntax = 1737,
    NoNetworkAddress = 1739,
    DuplicateEndpoint = 1740,
    UnknownAuthType = 1741,
    MaxCallsToSmall = 1742,
    StringTooLong = 1743,
    ProtSeqNotSupported = 1744,
    ProcNumOutOfRange = 1745,
    BindingHasNoAuth = 1746,
    UnknownAuthService = 1747,
    UnknownAuthLevel = 1748,
    InvalidAuthIdentity = 1749,
    UnknownAuthorizationService = 1750,
    InvalidEntry = 1751,
    CantPerformOp = 1752,
    NotRegistered = 1753,
    NothingToExport = 1754,
    IncompleteName = 1755,
    InvalidVersOption = 1756,
    NoMoreMembers = 1757,
    NotAllObjsUnexported = 1758,
    InterfaceNotFound = 1759,
    EntryAlreadyExists = 1760,
    EntryNotFound = 1761,
    NameServiceUnavailable = 1762,
    InvalidNafId = 1763,
    CannotSupport = 1764,
    NoContextAvailable = 1765,
    InternalError = 1766,
    ZeroDivide = 1767,
    AddressError = 1768,
    FpDivZero = 1769,
    FpUnderflow = 1770,
    FpOverflow = 1771,
    NtCallFailed = 1772,
    GroupMemberNotFound = 1898,
    EndpointMapperUnavailable = 1908,
    InvalidStringBinding = 1700,
    WrongKindOfBinding = 1701,
}

impl TryFrom<u32> for RpcError {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(RpcError::Success),
            5 => Ok(RpcError::AccessDenied),
            6 => Ok(RpcError::InvalidHandle),
            14 => Ok(RpcError::OutOfMemory),
            87 => Ok(RpcError::InvalidParameter),
            122 => Ok(RpcError::BufferTooSmall),
            1726 => Ok(RpcError::CallFailed),
            1728 => Ok(RpcError::ProtocolError),
            1732 => Ok(RpcError::UnsupportedType),
            1733 => Ok(RpcError::InvalidTag),
            1734 => Ok(RpcError::InvalidBound),
            1735 => Ok(RpcError::NoEntryName),
            1736 => Ok(RpcError::InvalidNameSyntax),
            1737 => Ok(RpcError::UnsupportedNameSyntax),
            1739 => Ok(RpcError::NoNetworkAddress),
            1740 => Ok(RpcError::DuplicateEndpoint),
            1741 => Ok(RpcError::UnknownAuthType),
            1742 => Ok(RpcError::MaxCallsToSmall),
            1743 => Ok(RpcError::StringTooLong),
            1744 => Ok(RpcError::ProtSeqNotSupported),
            1745 => Ok(RpcError::ProcNumOutOfRange),
            1746 => Ok(RpcError::BindingHasNoAuth),
            1747 => Ok(RpcError::UnknownAuthService),
            1748 => Ok(RpcError::UnknownAuthLevel),
            1749 => Ok(RpcError::InvalidAuthIdentity),
            1750 => Ok(RpcError::UnknownAuthorizationService),
            1751 => Ok(RpcError::InvalidEntry),
            1752 => Ok(RpcError::CantPerformOp),
            1753 => Ok(RpcError::NotRegistered),
            1754 => Ok(RpcError::NothingToExport),
            1755 => Ok(RpcError::IncompleteName),
            1756 => Ok(RpcError::InvalidVersOption),
            1757 => Ok(RpcError::NoMoreMembers),
            1758 => Ok(RpcError::NotAllObjsUnexported),
            1759 => Ok(RpcError::InterfaceNotFound),
            1760 => Ok(RpcError::EntryAlreadyExists),
            1761 => Ok(RpcError::EntryNotFound),
            1762 => Ok(RpcError::NameServiceUnavailable),
            1763 => Ok(RpcError::InvalidNafId),
            1764 => Ok(RpcError::CannotSupport),
            1765 => Ok(RpcError::NoContextAvailable),
            1766 => Ok(RpcError::InternalError),
            1767 => Ok(RpcError::ZeroDivide),
            1768 => Ok(RpcError::AddressError),
            1769 => Ok(RpcError::FpDivZero),
            1770 => Ok(RpcError::FpUnderflow),
            1771 => Ok(RpcError::FpOverflow),
            1772 => Ok(RpcError::NtCallFailed),
            1898 => Ok(RpcError::GroupMemberNotFound),
            1908 => Ok(RpcError::EndpointMapperUnavailable),
            1700 => Ok(RpcError::InvalidStringBinding),
            1701 => Ok(RpcError::WrongKindOfBinding),
            _ => Ok(RpcError::InternalError),
        }
    }
}

impl RpcError {
    /// Convert from u32
    pub fn from_u32(value: u32) -> Self {
        value.try_into().unwrap_or(RpcError::InternalError)
    }
}
