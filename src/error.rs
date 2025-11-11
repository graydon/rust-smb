//! Error types for the SMB protocol implementation

use std::convert::TryFrom;
use std::fmt;
use std::io;
use thiserror::Error;

/// Result type for SMB operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for SMB protocol operations
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Protocol parsing error
    #[error("Protocol parsing error: {0}")]
    ParseError(String),

    /// Invalid SMB header
    #[error("Invalid SMB header: {0}")]
    InvalidHeader(String),

    /// Unsupported protocol version
    #[error("Unsupported protocol version: {0}")]
    UnsupportedProtocol(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authentication error
    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// State machine error
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    /// Buffer too small
    #[error("Buffer too small: need {need} bytes, have {have}")]
    BufferTooSmall { need: usize, have: usize },

    /// Timeout occurred
    #[error("Operation timed out")]
    Timeout,

    /// Not implemented
    #[error("Feature not implemented: {0}")]
    NotImplemented(String),

    /// Access denied
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Encryption error
    #[error("Encryption/Decryption error: {0}")]
    CryptoError(String),

    /// Signing error
    #[error("Message signing error: {0}")]
    SigningError(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Invalid NetBIOS name
    #[error("Invalid NetBIOS name: {0}")]
    InvalidNetBiosName(String),

    /// Connection closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// File or directory already exists
    #[error("Already exists: {0}")]
    AlreadyExists(String),

    /// File exists
    #[error("File exists: {0}")]
    FileExists(String),
}

/// SMB protocol status codes (subset of NTSTATUS)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NtStatus {
    /// The operation completed successfully
    Success = 0x00000000,
    /// The request is not supported
    NotSupported = 0xC00000BB,
    /// Access denied
    AccessDenied = 0xC0000022,
    /// The object name is not found
    ObjectNameNotFound = 0xC0000034,
    /// The specified handle is invalid
    InvalidHandle = 0xC0000008,
    /// The parameter is incorrect
    InvalidParameter = 0xC000000D,
    /// No more files
    NoMoreFiles = 0x80000006,
    /// Cannot create a file that already exists
    ObjectNameCollision = 0xC0000035,
    /// The buffer is too small
    BufferTooSmall = 0xC0000023,
    /// The user name or password is incorrect
    LogonFailure = 0xC000006D,
    /// Account is disabled
    AccountDisabled = 0xC0000072,
    /// The specified network name is no longer available
    NetworkNameDeleted = 0xC00000C9,
    /// The remote system is not reachable
    HostUnreachable = 0xC000023D,
    /// Protocol error
    ProtocolUnreachable = 0xC000023E,
    /// Bad network path
    BadNetworkPath = 0xC00000BE,
    /// Bad network name
    BadNetworkName = 0xC00000CC,
    /// The request timed out
    IoTimeout = 0xC00000B5,
    /// More processing required
    MoreProcessingRequired = 0xC0000016,
    /// Pipe disconnected
    PipeDisconnected = 0xC00000B0,
    /// Invalid pipe state
    InvalidPipeState = 0xC00000AD,
    /// Pipe busy
    PipeBusy = 0xC00000AE,
    /// Insufficient resources
    InsufficientResources = 0xC000009A,
}

impl TryFrom<u32> for NtStatus {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00000000 => Ok(NtStatus::Success),
            0xC00000BB => Ok(NtStatus::NotSupported),
            0xC0000022 => Ok(NtStatus::AccessDenied),
            0xC0000034 => Ok(NtStatus::ObjectNameNotFound),
            0xC0000008 => Ok(NtStatus::InvalidHandle),
            0xC000000D => Ok(NtStatus::InvalidParameter),
            0x80000006 => Ok(NtStatus::NoMoreFiles),
            0xC0000035 => Ok(NtStatus::ObjectNameCollision),
            0xC0000023 => Ok(NtStatus::BufferTooSmall),
            0xC000006D => Ok(NtStatus::LogonFailure),
            0xC0000072 => Ok(NtStatus::AccountDisabled),
            0xC00000C9 => Ok(NtStatus::NetworkNameDeleted),
            0xC000023D => Ok(NtStatus::HostUnreachable),
            0xC000023E => Ok(NtStatus::ProtocolUnreachable),
            0xC00000BE => Ok(NtStatus::BadNetworkPath),
            0xC00000CC => Ok(NtStatus::BadNetworkName),
            0xC00000B5 => Ok(NtStatus::IoTimeout),
            0xC0000016 => Ok(NtStatus::MoreProcessingRequired),
            0xC00000B0 => Ok(NtStatus::PipeDisconnected),
            0xC00000AD => Ok(NtStatus::InvalidPipeState),
            0xC00000AE => Ok(NtStatus::PipeBusy),
            0xC000009A => Ok(NtStatus::InsufficientResources),
            _ => Ok(NtStatus::InvalidParameter), // Default for unknown values
        }
    }
}

impl NtStatus {
    /// Check if this is a success status
    pub fn is_success(self) -> bool {
        self == NtStatus::Success
    }

    /// Check if this is an error status
    pub fn is_error(self) -> bool {
        (self as u32) & 0xC0000000 == 0xC0000000
    }

    /// Check if this is a warning status
    pub fn is_warning(self) -> bool {
        (self as u32) & 0x80000000 == 0x80000000 && !self.is_error()
    }

    /// Create from a raw u32 value
    pub fn from_u32(value: u32) -> Self {
        value.try_into().unwrap_or(NtStatus::InvalidParameter)
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            NtStatus::Success => "Success",
            NtStatus::NotSupported => "Not supported",
            NtStatus::AccessDenied => "Access denied",
            NtStatus::ObjectNameNotFound => "Object name not found",
            NtStatus::InvalidHandle => "Invalid handle",
            NtStatus::InvalidParameter => "Invalid parameter",
            NtStatus::NoMoreFiles => "No more files",
            NtStatus::ObjectNameCollision => "Object name collision",
            NtStatus::BufferTooSmall => "Buffer too small",
            NtStatus::LogonFailure => "Logon failure",
            NtStatus::AccountDisabled => "Account disabled",
            NtStatus::NetworkNameDeleted => "Network name deleted",
            NtStatus::HostUnreachable => "Host unreachable",
            NtStatus::ProtocolUnreachable => "Protocol unreachable",
            NtStatus::BadNetworkPath => "Bad network path",
            NtStatus::BadNetworkName => "Bad network name",
            NtStatus::IoTimeout => "I/O timeout",
            NtStatus::MoreProcessingRequired => "More processing required",
            NtStatus::PipeDisconnected => "Pipe disconnected",
            NtStatus::InvalidPipeState => "Invalid pipe state",
            NtStatus::PipeBusy => "Pipe busy",
            NtStatus::InsufficientResources => "Insufficient resources",
        };
        write!(f, "{} (0x{:08X})", msg, *self as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntstatus_success() {
        assert!(NtStatus::Success.is_success());
        assert!(!NtStatus::Success.is_error());
        assert!(!NtStatus::Success.is_warning());
    }

    #[test]
    fn test_ntstatus_error() {
        assert!(!NtStatus::AccessDenied.is_success());
        assert!(NtStatus::AccessDenied.is_error());
        assert!(!NtStatus::AccessDenied.is_warning());
    }

    #[test]
    fn test_ntstatus_warning() {
        assert!(!NtStatus::NoMoreFiles.is_success());
        assert!(!NtStatus::NoMoreFiles.is_error());
        assert!(NtStatus::NoMoreFiles.is_warning());
    }

    #[test]
    fn test_ntstatus_from_u32() {
        assert_eq!(NtStatus::from_u32(0x00000000), NtStatus::Success);
        assert_eq!(NtStatus::from_u32(0xC0000022), NtStatus::AccessDenied);
        assert_eq!(NtStatus::from_u32(0x80000006), NtStatus::NoMoreFiles);
        // Unknown value should default to InvalidParameter
        assert_eq!(NtStatus::from_u32(0xFFFFFFFF), NtStatus::InvalidParameter);
    }

    #[test]
    fn test_ntstatus_display() {
        let status = NtStatus::AccessDenied;
        let display = format!("{}", status);
        assert!(display.contains("Access denied"));
        assert!(display.contains("0xC0000022"));
    }
}
