//! SMB2/3 protocol constants

use bitflags::bitflags;

/// SMB2 magic as bytes
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// SMB2 magic as u32
pub const SMB2_MAGIC_U32: u32 = 0x424D53FE;

/// SMB2 header size
pub const SMB2_HEADER_SIZE: usize = 64;

/// Structure sizes for SMB2 messages
/// SMB2 protocol layout constants
pub mod protocol_offsets {
    /// SMB2 header size
    pub const SMB2_HEADER_SIZE: usize = 64;
    /// Security buffer offset in SessionSetup response (after header and response structure)
    pub const SESSION_SETUP_SECURITY_OFFSET: u16 = 72;
    /// Default max transaction size (1MB)
    pub const DEFAULT_MAX_TRANSACT_SIZE: u32 = 1048576;
    /// Default max read size (1MB)
    pub const DEFAULT_MAX_READ_SIZE: u32 = 1048576;
    /// Default max write size (1MB)
    pub const DEFAULT_MAX_WRITE_SIZE: u32 = 1048576;
}

pub mod structure_size {
    pub const NEGOTIATE_REQUEST: u16 = 36;
    pub const NEGOTIATE_RESPONSE: u16 = 65;
    pub const SESSION_SETUP_REQUEST: u16 = 25;
    pub const SESSION_SETUP_RESPONSE: u16 = 9;
    pub const TREE_CONNECT_REQUEST: u16 = 9;
    pub const TREE_CONNECT_RESPONSE: u16 = 16;
    pub const CREATE_REQUEST: u16 = 57;
    pub const CREATE_RESPONSE: u16 = 89;
    pub const CLOSE_REQUEST: u16 = 24;
    pub const CLOSE_RESPONSE: u16 = 60;
    pub const READ_REQUEST: u16 = 49;
    pub const READ_RESPONSE: u16 = 17;
    pub const WRITE_REQUEST: u16 = 49;
    pub const WRITE_RESPONSE: u16 = 17;
}

/// SMB2 Header Flags  
pub mod header_flags {
    pub const RESPONSE: u32 = 0x00000001;
    pub const ASYNC_COMMAND: u32 = 0x00000002;
    pub const RELATED_OPERATIONS: u32 = 0x00000004;
    pub const SIGNED: u32 = 0x00000008;
    pub const DFS_OPERATIONS: u32 = 0x10000000;
    pub const REPLAY_OPERATION: u32 = 0x20000000;
}

bitflags! {
    /// File attributes as defined in MS-FSCC
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileAttributes: u32 {
        const READONLY            = 0x00000001;
        const HIDDEN              = 0x00000002;
        const SYSTEM              = 0x00000004;
        const DIRECTORY           = 0x00000010;
        const ARCHIVE             = 0x00000020;
        const NORMAL              = 0x00000080;
        const TEMPORARY           = 0x00000100;
        const SPARSE_FILE         = 0x00000200;
        const REPARSE_POINT       = 0x00000400;
        const COMPRESSED          = 0x00000800;
        const OFFLINE             = 0x00001000;
        const NOT_CONTENT_INDEXED = 0x00002000;
        const ENCRYPTED           = 0x00004000;
        const INTEGRITY_STREAM    = 0x00008000;
        const NO_SCRUB_DATA       = 0x00020000;
    }
}

bitflags! {
    /// File access rights
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DesiredAccess: u32 {
        // Standard rights
        const DELETE                   = 0x00010000;
        const READ_CONTROL             = 0x00020000;
        const WRITE_DAC                = 0x00040000;
        const WRITE_OWNER              = 0x00080000;
        const SYNCHRONIZE              = 0x00100000;

        // Specific rights
        const FILE_READ_DATA           = 0x00000001;
        const FILE_WRITE_DATA          = 0x00000002;
        const FILE_APPEND_DATA         = 0x00000004;
        const FILE_READ_EA             = 0x00000008;
        const FILE_WRITE_EA            = 0x00000010;
        const FILE_EXECUTE             = 0x00000020;
        const FILE_DELETE_CHILD        = 0x00000040;
        const FILE_READ_ATTRIBUTES     = 0x00000080;
        const FILE_WRITE_ATTRIBUTES    = 0x00000100;

        // Generic rights
        const GENERIC_ALL              = 0x10000000;
        const GENERIC_EXECUTE          = 0x20000000;
        const GENERIC_WRITE            = 0x40000000;
        const GENERIC_READ             = 0x80000000;

        // Common combinations
        const FILE_GENERIC_READ        = Self::SYNCHRONIZE.bits() |
                                         Self::FILE_READ_DATA.bits() |
                                         Self::FILE_READ_ATTRIBUTES.bits() |
                                         Self::FILE_READ_EA.bits() |
                                         Self::READ_CONTROL.bits();

        const FILE_GENERIC_WRITE       = Self::SYNCHRONIZE.bits() |
                                         Self::FILE_WRITE_DATA.bits() |
                                         Self::FILE_WRITE_ATTRIBUTES.bits() |
                                         Self::FILE_WRITE_EA.bits() |
                                         Self::FILE_APPEND_DATA.bits() |
                                         Self::READ_CONTROL.bits();

        const FILE_GENERIC_EXECUTE     = Self::SYNCHRONIZE.bits() |
                                         Self::FILE_EXECUTE.bits() |
                                         Self::FILE_READ_ATTRIBUTES.bits() |
                                         Self::READ_CONTROL.bits();

        const FILE_ALL_ACCESS          = 0x001F01FF;
    }
}

bitflags! {
    /// File share access rights
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ShareAccess: u32 {
        const FILE_SHARE_READ   = 0x00000001;
        const FILE_SHARE_WRITE  = 0x00000002;
        const FILE_SHARE_DELETE = 0x00000004;
        const FILE_SHARE_ALL    = 0x00000007;
    }
}

/// Create disposition values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CreateDisposition {
    /// If file exists, supersede. If file doesn't exist, create.
    SUPERSEDE = 0x00000000,
    /// If file exists, open. If file doesn't exist, fail.
    OPEN = 0x00000001,
    /// If file exists, fail. If file doesn't exist, create.
    CREATE = 0x00000002,
    /// If file exists, open. If file doesn't exist, create.
    OpenIf = 0x00000003,
    /// If file exists, overwrite. If file doesn't exist, fail.
    OVERWRITE = 0x00000004,
    /// If file exists, overwrite. If file doesn't exist, create.
    OverwriteIf = 0x00000005,
}

impl TryFrom<u32> for CreateDisposition {
    type Error = crate::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x00000000 => Ok(CreateDisposition::SUPERSEDE),
            0x00000001 => Ok(CreateDisposition::OPEN),
            0x00000002 => Ok(CreateDisposition::CREATE),
            0x00000003 => Ok(CreateDisposition::OpenIf),
            0x00000004 => Ok(CreateDisposition::OVERWRITE),
            0x00000005 => Ok(CreateDisposition::OverwriteIf),
            _ => Err(crate::Error::ParseError(format!(
                "Invalid create disposition: {}",
                value
            ))),
        }
    }
}

impl CreateDisposition {
    /// Convert from u32
    pub fn from_u32(value: u32) -> crate::Result<Self> {
        value.try_into()
    }

    /// Convert to u32
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

/// Create action constants (returned by the server)
pub mod create_action {
    pub const SUPERSEDED: u32 = 0x00000000;
    pub const OPENED_EXISTING: u32 = 0x00000001;
    pub const CREATED: u32 = 0x00000002;
    pub const OVERWRITTEN: u32 = 0x00000003;
}

/// Query Directory flags
pub mod query_directory_flags {
    pub const SMB2_RESTART_SCANS: u8 = 0x01; // Restart the enumeration from the beginning
    pub const SMB2_RETURN_SINGLE_ENTRY: u8 = 0x02; // Return only a single entry
    pub const SMB2_INDEX_SPECIFIED: u8 = 0x04; // Resume from specified FileIndex
    pub const SMB2_REOPEN: u8 = 0x10; // Restart enumeration (file spec changed)
}

bitflags! {
    /// File create options
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CreateOptions: u32 {
        const FILE_DIRECTORY_FILE            = 0x00000001;
        const FILE_WRITE_THROUGH             = 0x00000002;
        const FILE_SEQUENTIAL_ONLY           = 0x00000004;
        const FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008;
        const FILE_SYNCHRONOUS_IO_ALERT      = 0x00000010;
        const FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020;
        const FILE_NON_DIRECTORY_FILE        = 0x00000040;
        const FILE_CREATE_TREE_CONNECTION    = 0x00000080;
        const FILE_COMPLETE_IF_OPLOCKED      = 0x00000100;
        const FILE_NO_EA_KNOWLEDGE           = 0x00000200;
        const FILE_RANDOM_ACCESS             = 0x00000800;
        const FILE_DELETE_ON_CLOSE           = 0x00001000;
        const FILE_OPEN_BY_FILE_ID           = 0x00002000;
        const FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000;
        const FILE_NO_COMPRESSION            = 0x00008000;
        const FILE_RESERVE_OPFILTER          = 0x00100000;
        const FILE_OPEN_REPARSE_POINT        = 0x00200000;
        const FILE_OPEN_NO_RECALL            = 0x00400000;
    }
}

/// Impersonation levels
pub mod impersonation_level {
    pub const ANONYMOUS: u32 = 0x00000000;
    pub const IDENTIFICATION: u32 = 0x00000001;
    pub const IMPERSONATION: u32 = 0x00000002;
    pub const DELEGATION: u32 = 0x00000003;
}

/// Oplock levels
pub mod oplock_level {
    pub const NONE: u8 = 0x00;
    pub const LEVEL_II: u8 = 0x01;
    pub const EXCLUSIVE: u8 = 0x08;
    pub const BATCH: u8 = 0x09;
    pub const LEASE: u8 = 0xFF;
}

/// SMB2 Commands (opcodes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    Negotiate = 0x00,
    SessionSetup = 0x01,
    Logoff = 0x02,
    TreeConnect = 0x03,
    TreeDisconnect = 0x04,
    Create = 0x05,
    Close = 0x06,
    Flush = 0x07,
    Read = 0x08,
    Write = 0x09,
    Lock = 0x0A,
    Ioctl = 0x0B,
    Cancel = 0x0C,
    KeepAlive = 0x0D,
    QueryDirectory = 0x0E,
    Notify = 0x0F,
    GetInfo = 0x10,
    SetInfo = 0x11,
    Break = 0x12,
}

impl TryFrom<u16> for Smb2Command {
    type Error = crate::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Negotiate),
            0x01 => Ok(Self::SessionSetup),
            0x02 => Ok(Self::Logoff),
            0x03 => Ok(Self::TreeConnect),
            0x04 => Ok(Self::TreeDisconnect),
            0x05 => Ok(Self::Create),
            0x06 => Ok(Self::Close),
            0x07 => Ok(Self::Flush),
            0x08 => Ok(Self::Read),
            0x09 => Ok(Self::Write),
            0x0A => Ok(Self::Lock),
            0x0B => Ok(Self::Ioctl),
            0x0C => Ok(Self::Cancel),
            0x0D => Ok(Self::KeepAlive),
            0x0E => Ok(Self::QueryDirectory),
            0x0F => Ok(Self::Notify),
            0x10 => Ok(Self::GetInfo),
            0x11 => Ok(Self::SetInfo),
            0x12 => Ok(Self::Break),
            _ => Err(crate::Error::ParseError(format!(
                "Invalid SMB2 command: 0x{:04x}",
                value
            ))),
        }
    }
}

impl Smb2Command {
    pub fn from_u16(value: u16) -> crate::Result<Self> {
        value.try_into()
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

bitflags! {
    /// SMB2 header flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Smb2HeaderFlags: u32 {
        const SERVER_TO_REDIR = 0x00000001;
        const ASYNC_COMMAND = 0x00000002;
        const RELATED_OPERATIONS = 0x00000004;
        const SIGNED = 0x00000008;
        const DFS_OPERATIONS = 0x10000000;
        const REPLAY_OPERATION = 0x20000000;
    }
}

bitflags! {
    /// SMB2 negotiate security mode
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecurityMode: u16 {
        const SIGNING_ENABLED = 0x0001;
        const SIGNING_REQUIRED = 0x0002;
    }
}

bitflags! {
    /// SMB2 capabilities
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Smb2Capabilities: u32 {
        const DFS = 0x00000001;
        const LEASING = 0x00000002;
        const LARGE_MTU = 0x00000004;
        const MULTI_CHANNEL = 0x00000008;
        const PERSISTENT_HANDLES = 0x00000010;
        const DIRECTORY_LEASING = 0x00000020;
        const ENCRYPTION = 0x00000040;
    }
}

bitflags! {
    /// Share flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ShareFlags: u32 {
        const MANUAL_CACHING = 0x00000000;
        const AUTO_CACHING = 0x00000010;
        const VDO_CACHING = 0x00000020;
        const NO_CACHING = 0x00000030;
        const DFS = 0x00000001;
        const DFS_ROOT = 0x00000002;
        const RESTRICT_EXCLUSIVE_OPENS = 0x00000100;
        const FORCE_SHARED_DELETE = 0x00000200;
        const ALLOW_NAMESPACE_CACHING = 0x00000400;
        const ACCESS_BASED_DIRECTORY_ENUM = 0x00000800;
        const FORCE_LEVELII_OPLOCK = 0x00001000;
        const ENABLE_HASH_V1 = 0x00002000;
        const ENABLE_HASH_V2 = 0x00004000;
        const ENCRYPT_DATA = 0x00008000;
        const IDENTITY_REMOTING = 0x00040000;
        const COMPRESS_DATA = 0x00100000;
    }
}

bitflags! {
    /// Share capabilities
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ShareCapabilities: u32 {
        const DFS = 0x00000008;
        const CONTINUOUS_AVAILABILITY = 0x00000010;
        const SCALEOUT = 0x00000020;
        const CLUSTER = 0x00000040;
        const ASYMMETRIC = 0x00000080;
        const REDIRECT_TO_OWNER = 0x00000100;
    }
}

/// SMB2 dialect versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum Smb2Dialect {
    Smb202 = 0x0202,
    Smb210 = 0x0210,
    Smb224 = 0x0224,
    Smb300 = 0x0300,
    Smb302 = 0x0302,
    Smb310 = 0x0310,
    Smb311 = 0x0311,
}

impl TryFrom<u16> for Smb2Dialect {
    type Error = crate::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0202 => Ok(Self::Smb202),
            0x0210 => Ok(Self::Smb210),
            0x0224 => Ok(Self::Smb224),
            0x0300 => Ok(Self::Smb300),
            0x0302 => Ok(Self::Smb302),
            0x0310 => Ok(Self::Smb310),
            0x0311 => Ok(Self::Smb311),
            _ => Err(crate::Error::ParseError(format!(
                "Unknown SMB2 dialect: 0x{:04x}",
                value
            ))),
        }
    }
}

impl Smb2Dialect {
    pub fn from_u16(value: u16) -> crate::Result<Self> {
        value.try_into()
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Security Tracking
pub mod security_tracking {
    pub const STATIC: u8 = 0x00;
    pub const DYNAMIC: u8 = 0x01;
}

bitflags! {
    /// SMB2 close flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CloseFlags: u16 {
        const POSTQUERY_ATTRIB = 0x0001;
    }
}

/// Read/Write Channel Info
pub mod channel_info {
    pub const NONE: u32 = 0x00000000;
    pub const RDMA_V1: u32 = 0x00000001;
    pub const RDMA_V1_INVALIDATE: u32 = 0x00000002;
    pub const RDMA_TRANSFORM: u32 = 0x00000003;
}

bitflags! {
    /// SMB2 write flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WriteFlags: u32 {
        const WRITE_THROUGH       = 0x00000001;
        const WRITE_UNBUFFERED    = 0x00000002;
    }
}

/// SMB2 Create Action values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CreateAction {
    /// File was superseded (replaced)
    Superseded = 0x00000000,
    /// File was opened
    Opened = 0x00000001,
    /// File was created
    Created = 0x00000002,
    /// File was overwritten
    Overwritten = 0x00000003,
    /// File existed
    Exists = 0x00000004,
    /// File did not exist
    DoesNotExist = 0x00000005,
}

impl From<CreateAction> for u32 {
    fn from(action: CreateAction) -> u32 {
        action as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb2_magic() {
        assert_eq!(SMB2_MAGIC, [0xFE, b'S', b'M', b'B']);
        assert_eq!(SMB2_MAGIC_U32, 0x424D53FE);
    }

    #[test]
    fn test_smb2_commands() {
        assert_eq!(Smb2Command::Negotiate as u16, 0x00);
        assert_eq!(Smb2Command::Create as u16, 0x05);
        assert_eq!(Smb2Command::Read as u16, 0x08);
    }

    #[test]
    fn test_structure_sizes() {
        assert_eq!(structure_size::CREATE_REQUEST, 57);
        assert_eq!(structure_size::CREATE_RESPONSE, 89);
        assert_eq!(structure_size::TREE_CONNECT_REQUEST, 9);
        assert_eq!(structure_size::TREE_CONNECT_RESPONSE, 16);
    }

    #[test]
    fn test_access_masks() {
        assert_eq!(DesiredAccess::FILE_ALL_ACCESS.bits(), 0x001F01FF);
        assert!(DesiredAccess::GENERIC_READ.bits() & 0x80000000 != 0);
        assert!(DesiredAccess::GENERIC_WRITE.bits() & 0x40000000 != 0);
    }

    #[test]
    fn test_create_disposition() {
        assert_eq!(CreateDisposition::OPEN as u32, 1);
        assert_eq!(CreateDisposition::CREATE as u32, 2);
        assert_eq!(CreateDisposition::OpenIf as u32, 3);
    }

    #[test]
    fn test_close_flags() {
        let flags = CloseFlags::POSTQUERY_ATTRIB;
        assert_eq!(flags.bits(), 0x0001);
    }

    #[test]
    fn test_write_flags() {
        let flags = WriteFlags::WRITE_THROUGH | WriteFlags::WRITE_UNBUFFERED;
        assert!(flags.contains(WriteFlags::WRITE_THROUGH));
        assert!(flags.contains(WriteFlags::WRITE_UNBUFFERED));
    }
}
