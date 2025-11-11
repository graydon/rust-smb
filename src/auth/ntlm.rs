//! NTLM authentication implementation
//!
//! This module implements the NTLM (NT LAN Manager) authentication protocol
//! as used in SMB/CIFS. It supports NTLMv1 and NTLMv2 authentication.

use crate::error::{Error, Result};
use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{self, Read, Write};

/// NTLM signature - "NTLMSSP\0"
pub const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

/// NTLM message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NtlmMessageType {
    /// Type 1: Negotiate message (client -> server)
    Negotiate = 0x00000001,
    /// Type 2: Challenge message (server -> client)
    Challenge = 0x00000002,
    /// Type 3: Authenticate message (client -> server)
    Authenticate = 0x00000003,
}

impl TryFrom<u32> for NtlmMessageType {
    type Error = Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00000001 => Ok(Self::Negotiate),
            0x00000002 => Ok(Self::Challenge),
            0x00000003 => Ok(Self::Authenticate),
            _ => Err(Error::ParseError(format!(
                "Invalid NTLM message type: {}",
                value
            ))),
        }
    }
}

bitflags! {
    /// NTLM negotiation flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NtlmFlags: u32 {
        /// Negotiate Unicode encoding
        const NEGOTIATE_UNICODE = 0x00000001;
        /// Negotiate OEM encoding
        const NEGOTIATE_OEM = 0x00000002;
        /// Request target name from server
        const REQUEST_TARGET = 0x00000004;
        /// Sign messages
        const NEGOTIATE_SIGN = 0x00000010;
        /// Seal (encrypt) messages
        const NEGOTIATE_SEAL = 0x00000020;
        /// Use datagram style authentication
        const NEGOTIATE_DATAGRAM = 0x00000040;
        /// Use LAN Manager session key
        const NEGOTIATE_LAN_MANAGER_KEY = 0x00000080;
        /// Use NTLM v1
        const NEGOTIATE_NTLM = 0x00000200;
        /// Anonymous connection
        const NEGOTIATE_ANONYMOUS = 0x00000800;
        /// Domain name supplied
        const NEGOTIATE_DOMAIN_SUPPLIED = 0x00001000;
        /// Workstation name supplied
        const NEGOTIATE_WORKSTATION_SUPPLIED = 0x00002000;
        /// Always sign messages
        const NEGOTIATE_ALWAYS_SIGN = 0x00008000;
        /// Target type is domain
        const TARGET_TYPE_DOMAIN = 0x00010000;
        /// Target type is server
        const TARGET_TYPE_SERVER = 0x00020000;
        /// Target type is share
        const TARGET_TYPE_SHARE = 0x00040000;
        /// Extended security negotiation
        const NEGOTIATE_EXTENDED_SECURITY = 0x00080000;
        /// Identify level security
        const NEGOTIATE_IDENTIFY = 0x00100000;
        /// Request non-NT session key
        const REQUEST_NON_NT_SESSION_KEY = 0x00400000;
        /// Target info present
        const NEGOTIATE_TARGET_INFO = 0x00800000;
        /// Version info present
        const NEGOTIATE_VERSION = 0x02000000;
        /// 128-bit encryption
        const NEGOTIATE_128 = 0x20000000;
        /// Explicit key exchange
        const NEGOTIATE_KEY_EXCHANGE = 0x40000000;
        /// 56-bit encryption
        const NEGOTIATE_56 = 0x80000000;
    }
}

/// Security buffer descriptor for NTLM messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityBuffer {
    /// Length of the buffer data
    pub length: u16,
    /// Maximum length of the buffer
    pub max_length: u16,
    /// Offset from the beginning of the NTLM message
    pub offset: u32,
}

impl SecurityBuffer {
    pub fn new() -> Self {
        Self {
            length: 0,
            max_length: 0,
            offset: 0,
        }
    }

    pub fn with_data(data_len: usize, offset: u32) -> Self {
        Self {
            length: data_len as u16,
            max_length: data_len as u16,
            offset,
        }
    }

    pub fn parse(cursor: &mut io::Cursor<&[u8]>) -> Result<Self> {
        let length = cursor.read_u16::<LittleEndian>()?;
        let max_length = cursor.read_u16::<LittleEndian>()?;
        let offset = cursor.read_u32::<LittleEndian>()?;

        Ok(Self {
            length,
            max_length,
            offset,
        })
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) -> Result<()> {
        buf.write_u16::<LittleEndian>(self.length)?;
        buf.write_u16::<LittleEndian>(self.max_length)?;
        buf.write_u32::<LittleEndian>(self.offset)?;
        Ok(())
    }

    pub fn extract_data<'a>(&self, message: &'a [u8]) -> Result<&'a [u8]> {
        let start = self.offset as usize;
        let end = start + self.length as usize;

        if end > message.len() {
            return Err(Error::ParseError(
                "Security buffer extends beyond message".into(),
            ));
        }

        Ok(&message[start..end])
    }
}

/// NTLM Type 1 Message - Negotiate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmNegotiateMessage {
    pub signature: [u8; 8],
    pub message_type: NtlmMessageType,
    pub flags: NtlmFlags,
    pub domain: SecurityBuffer,
    pub workstation: SecurityBuffer,
    pub domain_name: String,
    pub workstation_name: String,
    pub version: Option<NtlmVersion>,
}

impl NtlmNegotiateMessage {
    pub fn new(domain: String, workstation: String) -> Self {
        Self {
            signature: *b"NTLMSSP\0",
            message_type: NtlmMessageType::Negotiate,
            flags: NtlmFlags::NEGOTIATE_UNICODE
                | NtlmFlags::NEGOTIATE_NTLM
                | NtlmFlags::REQUEST_TARGET
                | NtlmFlags::NEGOTIATE_EXTENDED_SECURITY
                | NtlmFlags::NEGOTIATE_ALWAYS_SIGN
                | NtlmFlags::NEGOTIATE_128
                | NtlmFlags::NEGOTIATE_56,
            domain: SecurityBuffer::new(),
            workstation: SecurityBuffer::new(),
            domain_name: domain,
            workstation_name: workstation,
            version: None,
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(Error::ParseError("NTLM negotiate message too short".into()));
        }

        let mut cursor = io::Cursor::new(data);

        // Check signature
        let mut signature = [0u8; 8];
        cursor.read_exact(&mut signature)?;
        if &signature != b"NTLMSSP\0" {
            return Err(Error::ParseError("Invalid NTLM signature".into()));
        }

        // Message type
        let message_type = NtlmMessageType::try_from(cursor.read_u32::<LittleEndian>()?)?;
        if message_type != NtlmMessageType::Negotiate {
            return Err(Error::ParseError("Not a negotiate message".into()));
        }

        // Flags
        let flags = NtlmFlags::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid NTLM flags".into()))?;

        // Domain and workstation security buffers
        let domain = SecurityBuffer::parse(&mut cursor)?;
        let workstation = SecurityBuffer::parse(&mut cursor)?;

        // Extract domain and workstation names
        let domain_name = if domain.length > 0 {
            String::from_utf8_lossy(domain.extract_data(data)?).into_owned()
        } else {
            String::new()
        };

        let workstation_name = if workstation.length > 0 {
            String::from_utf8_lossy(workstation.extract_data(data)?).into_owned()
        } else {
            String::new()
        };

        Ok(Self {
            signature,
            message_type,
            flags,
            domain,
            workstation,
            domain_name,
            workstation_name,
            version: None,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Fixed part
        buf.write_all(&self.signature)?;
        buf.write_u32::<LittleEndian>(self.message_type as u32)?;
        buf.write_u32::<LittleEndian>(self.flags.bits())?;

        // Calculate offsets for variable data
        let mut offset = 32; // Size of fixed part (8 + 4 + 4 + 8 + 8)

        // Domain security buffer
        let domain_buffer = if !self.domain_name.is_empty() {
            let domain_bytes = self.domain_name.as_bytes();
            SecurityBuffer::with_data(domain_bytes.len(), offset as u32)
        } else {
            SecurityBuffer::new()
        };
        domain_buffer.serialize(&mut buf)?;
        if !self.domain_name.is_empty() {
            offset += self.domain_name.len();
        }

        // Workstation security buffer
        let workstation_buffer = if !self.workstation_name.is_empty() {
            let workstation_bytes = self.workstation_name.as_bytes();
            SecurityBuffer::with_data(workstation_bytes.len(), offset as u32)
        } else {
            SecurityBuffer::new()
        };
        workstation_buffer.serialize(&mut buf)?;

        // Append variable data
        if !self.domain_name.is_empty() {
            buf.write_all(self.domain_name.as_bytes())?;
        }
        if !self.workstation_name.is_empty() {
            buf.write_all(self.workstation_name.as_bytes())?;
        }

        Ok(buf)
    }
}

/// NTLM Type 2 Message - Challenge
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmChallengeMessage {
    pub signature: [u8; 8],
    pub message_type: NtlmMessageType,
    pub target_name: SecurityBuffer,
    pub flags: NtlmFlags,
    pub challenge: [u8; 8],
    pub context: u64,
    pub target_info: SecurityBuffer,
    pub target_name_str: String,
    pub target_info_data: Vec<u8>,
    pub version: Option<NtlmVersion>,
}

impl NtlmChallengeMessage {
    pub fn new(target_name: String, challenge: [u8; 8]) -> Self {
        Self {
            signature: *b"NTLMSSP\0",
            message_type: NtlmMessageType::Challenge,
            target_name: SecurityBuffer::new(),
            flags: NtlmFlags::NEGOTIATE_UNICODE
                | NtlmFlags::NEGOTIATE_NTLM
                | NtlmFlags::TARGET_TYPE_DOMAIN
                | NtlmFlags::NEGOTIATE_TARGET_INFO
                | NtlmFlags::NEGOTIATE_EXTENDED_SECURITY,
            challenge,
            context: 0,
            target_info: SecurityBuffer::new(),
            target_name_str: target_name,
            target_info_data: Vec::new(),
            version: None,
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 48 {
            return Err(Error::ParseError("NTLM challenge message too short".into()));
        }

        let mut cursor = io::Cursor::new(data);

        // Check signature
        let mut signature = [0u8; 8];
        cursor.read_exact(&mut signature)?;
        if &signature != b"NTLMSSP\0" {
            return Err(Error::ParseError("Invalid NTLM signature".into()));
        }

        // Message type
        let message_type = NtlmMessageType::try_from(cursor.read_u32::<LittleEndian>()?)?;
        if message_type != NtlmMessageType::Challenge {
            return Err(Error::ParseError("Not a challenge message".into()));
        }

        // Target name security buffer
        let target_name = SecurityBuffer::parse(&mut cursor)?;

        // Flags
        let flags = NtlmFlags::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid NTLM flags".into()))?;

        // Challenge
        let mut challenge = [0u8; 8];
        cursor.read_exact(&mut challenge)?;

        // Context (8 bytes, usually 0)
        let context = cursor.read_u64::<LittleEndian>()?;

        // Target info security buffer
        let target_info = SecurityBuffer::parse(&mut cursor)?;

        // Extract target name
        let target_name_str = if target_name.length > 0 {
            let name_bytes = target_name.extract_data(data)?;
            if flags.contains(NtlmFlags::NEGOTIATE_UNICODE) {
                // UTF-16LE decode
                let mut cursor = std::io::Cursor::new(&name_bytes);
                let mut name_u16 = Vec::new();
                while cursor.position() < name_bytes.len() as u64 {
                    if let Ok(ch) = cursor.read_u16::<byteorder::LittleEndian>() {
                        name_u16.push(ch);
                    } else {
                        break;
                    }
                }
                String::from_utf16_lossy(&name_u16)
            } else {
                String::from_utf8_lossy(name_bytes).into_owned()
            }
        } else {
            String::new()
        };

        // Extract target info
        let target_info_data = if target_info.length > 0 {
            target_info.extract_data(data)?.to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            signature,
            message_type,
            target_name,
            flags,
            challenge,
            context,
            target_info,
            target_name_str,
            target_info_data,
            version: None,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Fixed part
        buf.write_all(&self.signature)?;
        buf.write_u32::<LittleEndian>(self.message_type as u32)?;

        // Calculate offsets for variable data
        let mut offset = 48; // Size of fixed part

        // Target name security buffer
        let target_name_utf16: Vec<u16> = self.target_name_str.encode_utf16().collect();
        let target_name_bytes: Vec<u8> = target_name_utf16
            .iter()
            .flat_map(|&c| c.to_le_bytes())
            .collect();

        let target_name_buffer = if !target_name_bytes.is_empty() {
            SecurityBuffer::with_data(target_name_bytes.len(), offset as u32)
        } else {
            SecurityBuffer::new()
        };
        target_name_buffer.serialize(&mut buf)?;
        if !target_name_bytes.is_empty() {
            offset += target_name_bytes.len();
        }

        // Flags
        buf.write_u32::<LittleEndian>(self.flags.bits())?;

        // Challenge
        buf.write_all(&self.challenge)?;

        // Context
        buf.write_u64::<LittleEndian>(self.context)?;

        // Target info security buffer
        let target_info_buffer = if !self.target_info_data.is_empty() {
            SecurityBuffer::with_data(self.target_info_data.len(), offset as u32)
        } else {
            SecurityBuffer::new()
        };
        target_info_buffer.serialize(&mut buf)?;

        // Append variable data
        if !target_name_bytes.is_empty() {
            buf.write_all(&target_name_bytes)?;
        }
        if !self.target_info_data.is_empty() {
            buf.write_all(&self.target_info_data)?;
        }

        Ok(buf)
    }
}

/// NTLM Type 3 Message - Authenticate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmAuthenticateMessage {
    pub signature: [u8; 8],
    pub message_type: NtlmMessageType,
    pub lm_response: SecurityBuffer,
    pub nt_response: SecurityBuffer,
    pub target_name: SecurityBuffer,
    pub user_name: SecurityBuffer,
    pub workstation: SecurityBuffer,
    pub session_key: SecurityBuffer,
    pub flags: NtlmFlags,
    pub lm_response_data: Vec<u8>,
    pub nt_response_data: Vec<u8>,
    pub target_name_str: String,
    pub user_name_str: String,
    pub workstation_str: String,
    pub session_key_data: Vec<u8>,
    pub version: Option<NtlmVersion>,
}

impl NtlmAuthenticateMessage {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            return Err(Error::ParseError(
                "NTLM authenticate message too short".into(),
            ));
        }

        let mut cursor = io::Cursor::new(data);

        // Check signature
        let mut signature = [0u8; 8];
        cursor.read_exact(&mut signature)?;
        if &signature != b"NTLMSSP\0" {
            return Err(Error::ParseError("Invalid NTLM signature".into()));
        }

        // Message type
        let message_type = NtlmMessageType::try_from(cursor.read_u32::<LittleEndian>()?)?;
        if message_type != NtlmMessageType::Authenticate {
            return Err(Error::ParseError("Not an authenticate message".into()));
        }

        // Security buffers
        let lm_response = SecurityBuffer::parse(&mut cursor)?;
        let nt_response = SecurityBuffer::parse(&mut cursor)?;
        let target_name = SecurityBuffer::parse(&mut cursor)?;
        let user_name = SecurityBuffer::parse(&mut cursor)?;
        let workstation = SecurityBuffer::parse(&mut cursor)?;
        let session_key = SecurityBuffer::parse(&mut cursor)?;

        // Flags
        let flags = NtlmFlags::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid NTLM flags".into()))?;

        // Extract data from security buffers
        let lm_response_data = if lm_response.length > 0 {
            lm_response.extract_data(data)?.to_vec()
        } else {
            Vec::new()
        };

        let nt_response_data = if nt_response.length > 0 {
            nt_response.extract_data(data)?.to_vec()
        } else {
            Vec::new()
        };

        // Extract strings (handle Unicode if flag is set)
        let extract_string = |buffer: &SecurityBuffer| -> Result<String> {
            if buffer.length > 0 {
                let bytes = buffer.extract_data(data)?;
                if flags.contains(NtlmFlags::NEGOTIATE_UNICODE) {
                    // UTF-16LE decode
                    let mut cursor = std::io::Cursor::new(&bytes);
                    let mut text_u16 = Vec::new();
                    while cursor.position() < bytes.len() as u64 {
                        if let Ok(ch) = cursor.read_u16::<byteorder::LittleEndian>() {
                            text_u16.push(ch);
                        } else {
                            break;
                        }
                    }
                    Ok(String::from_utf16_lossy(&text_u16))
                } else {
                    Ok(String::from_utf8_lossy(bytes).into_owned())
                }
            } else {
                Ok(String::new())
            }
        };

        let target_name_str = extract_string(&target_name)?;
        let user_name_str = extract_string(&user_name)?;
        let workstation_str = extract_string(&workstation)?;

        let session_key_data = if session_key.length > 0 {
            session_key.extract_data(data)?.to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            signature,
            message_type,
            lm_response,
            nt_response,
            target_name,
            user_name,
            workstation,
            session_key,
            flags,
            lm_response_data,
            nt_response_data,
            target_name_str,
            user_name_str,
            workstation_str,
            session_key_data,
            version: None,
        })
    }

    /// Serialize the authenticate message
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Signature
        buf.extend_from_slice(&self.signature);

        // Message type
        buf.write_u32::<LittleEndian>(self.message_type as u32)?;

        // We'll calculate offsets as we go
        let mut offset = 64; // Base size of authenticate message (before optional fields)

        // LM response
        let lm_response = if !self.lm_response_data.is_empty() {
            let buffer = SecurityBuffer::with_data(self.lm_response_data.len(), offset as u32);
            offset += self.lm_response_data.len();
            buffer
        } else {
            SecurityBuffer::new()
        };
        lm_response.serialize(&mut buf)?;

        // NT response
        let nt_response = if !self.nt_response_data.is_empty() {
            let buffer = SecurityBuffer::with_data(self.nt_response_data.len(), offset as u32);
            offset += self.nt_response_data.len();
            buffer
        } else {
            SecurityBuffer::new()
        };
        nt_response.serialize(&mut buf)?;

        // Target name (domain)
        let target_bytes = if self.flags.contains(NtlmFlags::NEGOTIATE_UNICODE) {
            let mut bytes = Vec::new();
            for ch in self.target_name_str.encode_utf16() {
                bytes.write_u16::<LittleEndian>(ch)?;
            }
            bytes
        } else {
            self.target_name_str.as_bytes().to_vec()
        };

        let target_name = if !target_bytes.is_empty() {
            let buffer = SecurityBuffer::with_data(target_bytes.len(), offset as u32);
            offset += target_bytes.len();
            buffer
        } else {
            SecurityBuffer::new()
        };
        target_name.serialize(&mut buf)?;

        // User name
        let user_bytes = if self.flags.contains(NtlmFlags::NEGOTIATE_UNICODE) {
            let mut bytes = Vec::new();
            for ch in self.user_name_str.encode_utf16() {
                bytes.write_u16::<LittleEndian>(ch)?;
            }
            bytes
        } else {
            self.user_name_str.as_bytes().to_vec()
        };

        let user_name = if !user_bytes.is_empty() {
            let buffer = SecurityBuffer::with_data(user_bytes.len(), offset as u32);
            offset += user_bytes.len();
            buffer
        } else {
            SecurityBuffer::new()
        };
        user_name.serialize(&mut buf)?;

        // Workstation
        let workstation_bytes = if self.flags.contains(NtlmFlags::NEGOTIATE_UNICODE) {
            let mut bytes = Vec::new();
            for ch in self.workstation_str.encode_utf16() {
                bytes.write_u16::<LittleEndian>(ch)?;
            }
            bytes
        } else {
            self.workstation_str.as_bytes().to_vec()
        };

        let workstation = if !workstation_bytes.is_empty() {
            let buffer = SecurityBuffer::with_data(workstation_bytes.len(), offset as u32);
            offset += workstation_bytes.len();
            buffer
        } else {
            SecurityBuffer::new()
        };
        workstation.serialize(&mut buf)?;

        // Session key
        let session_key = if !self.session_key_data.is_empty() {
            let buffer = SecurityBuffer::with_data(self.session_key_data.len(), offset as u32);
            // offset += self.session_key_data.len(); // Not needed as this is the last field
            buffer
        } else {
            SecurityBuffer::new()
        };
        session_key.serialize(&mut buf)?;

        // Flags
        buf.write_u32::<LittleEndian>(self.flags.bits())?;

        // Version (optional) - skip for now

        // Append the actual data
        buf.extend_from_slice(&self.lm_response_data);
        buf.extend_from_slice(&self.nt_response_data);
        buf.extend_from_slice(&target_bytes);
        buf.extend_from_slice(&user_bytes);
        buf.extend_from_slice(&workstation_bytes);
        buf.extend_from_slice(&self.session_key_data);

        Ok(buf)
    }
}

/// NTLM version information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmVersion {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
    pub ntlm_revision: u8,
}

/// NTLM authentication context
#[derive(Debug, Clone)]
pub struct NtlmAuth {
    /// Client or server role
    pub role: NtlmRole,
    /// Current authentication state
    pub state: NtlmState,
    /// Negotiation flags
    pub flags: NtlmFlags,
    /// Username for authentication
    pub username: Option<String>,
    /// Domain name
    pub domain: Option<String>,
    /// Workstation name
    pub workstation: Option<String>,
    /// Server challenge (8 bytes)
    pub server_challenge: Option<[u8; 8]>,
    /// Session key
    pub session_key: Option<Vec<u8>>,
}

/// NTLM role (client or server)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmRole {
    Client,
    Server,
}

/// NTLM authentication state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmState {
    Initial,
    NegotiateSent,
    ChallengeSent,
    Authenticated,
    Failed,
}

impl NtlmAuth {
    /// Create a new NTLM client context
    pub fn new_client(username: String, domain: String, workstation: String) -> Self {
        Self {
            role: NtlmRole::Client,
            state: NtlmState::Initial,
            flags: NtlmFlags::NEGOTIATE_UNICODE
                | NtlmFlags::NEGOTIATE_NTLM
                | NtlmFlags::REQUEST_TARGET
                | NtlmFlags::NEGOTIATE_EXTENDED_SECURITY,
            username: Some(username),
            domain: Some(domain),
            workstation: Some(workstation),
            server_challenge: None,
            session_key: None,
        }
    }

    /// Create a new NTLM server context
    pub fn new_server() -> Self {
        Self {
            role: NtlmRole::Server,
            state: NtlmState::Initial,
            flags: NtlmFlags::NEGOTIATE_UNICODE
                | NtlmFlags::NEGOTIATE_NTLM
                | NtlmFlags::TARGET_TYPE_DOMAIN
                | NtlmFlags::NEGOTIATE_TARGET_INFO,
            username: None,
            domain: None,
            workstation: None,
            server_challenge: None,
            session_key: None,
        }
    }

    /// Generate Type 1 (Negotiate) message
    pub fn create_negotiate_message(&mut self) -> Result<Vec<u8>> {
        if self.role != NtlmRole::Client {
            return Err(Error::AuthenticationError(
                "Only clients send negotiate messages".into(),
            ));
        }

        let domain = self.domain.clone().unwrap_or_default();
        let workstation = self.workstation.clone().unwrap_or_default();

        let msg = NtlmNegotiateMessage::new(domain, workstation);
        self.state = NtlmState::NegotiateSent;

        msg.serialize()
    }

    /// Process Type 1 message and generate Type 2 (Challenge) message
    pub fn create_challenge_message(&mut self, negotiate_data: &[u8]) -> Result<Vec<u8>> {
        if self.role != NtlmRole::Server {
            return Err(Error::AuthenticationError(
                "Only servers send challenge messages".into(),
            ));
        }

        // Parse negotiate message
        let _negotiate = NtlmNegotiateMessage::parse(negotiate_data)?;

        // Generate secure random challenge
        let mut challenge = [0u8; 8];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge);

        self.server_challenge = Some(challenge);

        let msg = NtlmChallengeMessage::new("DOMAIN".into(), challenge);
        self.state = NtlmState::ChallengeSent;

        msg.serialize()
    }

    /// Process Type 2 message and generate Type 3 (Authenticate) message
    pub fn create_authenticate_message(
        &mut self,
        challenge_data: &[u8],
        password: &str,
    ) -> Result<Vec<u8>> {
        use crate::auth::ntlm_crypto::*;

        if self.role != NtlmRole::Client {
            return Err(Error::AuthenticationError(
                "Only clients send authenticate messages".into(),
            ));
        }

        // Parse challenge message
        let challenge = NtlmChallengeMessage::parse(challenge_data)?;
        self.server_challenge = Some(challenge.challenge);

        let username = self.username.as_deref().unwrap_or("Guest");
        let domain = self.domain.as_deref().unwrap_or("WORKGROUP");
        let workstation = self.workstation.as_deref().unwrap_or("WORKSTATION");

        // Generate NTLMv2 responses
        let client_challenge = generate_client_challenge();
        let timestamp = get_windows_timestamp();

        // Calculate NTLMv2 hash
        let ntlmv2_hash = ntlmv2_hash(username, domain, password)?;

        // Create NTLMv2 blob
        let blob = NtlmV2Blob::new(
            timestamp,
            client_challenge,
            challenge.target_info_data.clone(),
        );

        // Calculate responses
        let nt_response = ntlmv2_response(&ntlmv2_hash, &challenge.challenge, &blob)?;
        let lm_response = lmv2_response(&ntlmv2_hash, &challenge.challenge, &client_challenge)?;

        // Build authenticate message
        let auth = NtlmAuthenticateMessage {
            signature: *b"NTLMSSP\0",
            message_type: NtlmMessageType::Authenticate,
            lm_response: SecurityBuffer::new(),
            nt_response: SecurityBuffer::new(),
            target_name: SecurityBuffer::new(),
            user_name: SecurityBuffer::new(),
            workstation: SecurityBuffer::new(),
            session_key: SecurityBuffer::new(),
            flags: challenge.flags,
            lm_response_data: lm_response,
            nt_response_data: nt_response,
            target_name_str: domain.to_string(),
            user_name_str: username.to_string(),
            workstation_str: workstation.to_string(),
            session_key_data: Vec::new(),
            version: None,
        };

        // Serialize
        auth.serialize()
    }

    /// Process Type 3 message and verify authentication
    pub fn verify_authenticate_message(&mut self, auth_data: &[u8]) -> Result<bool> {
        if self.role != NtlmRole::Server {
            return Err(Error::AuthenticationError(
                "Only servers verify authenticate messages".into(),
            ));
        }

        let auth = NtlmAuthenticateMessage::parse(auth_data)?;

        // Store the username and domain
        self.username = Some(auth.user_name_str);
        self.domain = Some(auth.target_name_str);
        self.workstation = Some(auth.workstation_str);

        // Verify the NTLM response (simplified verification)
        // In production, this would check against a password database
        // For now, accept any valid NTLM response structure
        if auth.nt_response.length > 0 && auth.nt_response.offset > 0 {
            // Valid NTLM response provided
            self.state = NtlmState::Authenticated;
            Ok(true)
        } else {
            // No valid response
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_buffer() {
        let buffer = SecurityBuffer::with_data(10, 100);
        assert_eq!(buffer.length, 10);
        assert_eq!(buffer.max_length, 10);
        assert_eq!(buffer.offset, 100);

        let mut buf = Vec::new();
        buffer.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), 8);

        let mut cursor = io::Cursor::new(&buf[..]);
        let parsed = SecurityBuffer::parse(&mut cursor).unwrap();
        assert_eq!(parsed, buffer);
    }

    #[test]
    fn test_negotiate_message() {
        let msg = NtlmNegotiateMessage::new("DOMAIN".into(), "WORKSTATION".into());
        assert_eq!(&msg.signature, b"NTLMSSP\0");
        assert_eq!(msg.message_type, NtlmMessageType::Negotiate);

        let serialized = msg.serialize().unwrap();
        assert!(serialized.len() >= 32);

        // Check signature in serialized data
        assert_eq!(&serialized[0..8], b"NTLMSSP\0");

        let parsed = NtlmNegotiateMessage::parse(&serialized).unwrap();
        assert_eq!(parsed.domain_name, "DOMAIN");
        assert_eq!(parsed.workstation_name, "WORKSTATION");
    }

    #[test]
    fn test_challenge_message() {
        let challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let msg = NtlmChallengeMessage::new("SERVER".into(), challenge);

        assert_eq!(&msg.signature, b"NTLMSSP\0");
        assert_eq!(msg.message_type, NtlmMessageType::Challenge);
        assert_eq!(msg.challenge, challenge);

        let serialized = msg.serialize().unwrap();
        assert!(serialized.len() >= 48);

        let parsed = NtlmChallengeMessage::parse(&serialized).unwrap();
        assert_eq!(parsed.challenge, challenge);
        assert_eq!(parsed.target_name_str, "SERVER");
    }

    #[test]
    fn test_ntlm_flags() {
        let flags = NtlmFlags::NEGOTIATE_UNICODE | NtlmFlags::NEGOTIATE_NTLM;
        assert!(flags.contains(NtlmFlags::NEGOTIATE_UNICODE));
        assert!(flags.contains(NtlmFlags::NEGOTIATE_NTLM));
        assert!(!flags.contains(NtlmFlags::NEGOTIATE_OEM));
    }

    #[test]
    fn test_client_auth_flow() {
        let mut client = NtlmAuth::new_client("user".into(), "DOMAIN".into(), "WORKSTATION".into());

        assert_eq!(client.state, NtlmState::Initial);

        // Generate negotiate message
        let negotiate = client.create_negotiate_message().unwrap();
        assert!(negotiate.len() > 0);
        assert_eq!(client.state, NtlmState::NegotiateSent);
    }

    #[test]
    fn test_server_auth_flow() {
        let mut server = NtlmAuth::new_server();
        let mut client = NtlmAuth::new_client("user".into(), "DOMAIN".into(), "WORKSTATION".into());

        // Client sends negotiate
        let negotiate = client.create_negotiate_message().unwrap();

        // Server responds with challenge
        let challenge = server.create_challenge_message(&negotiate).unwrap();
        assert!(challenge.len() > 0);
        assert_eq!(server.state, NtlmState::ChallengeSent);

        // Parse the challenge to verify it's valid
        let parsed_challenge = NtlmChallengeMessage::parse(&challenge).unwrap();
        assert_eq!(parsed_challenge.message_type, NtlmMessageType::Challenge);
    }
}
