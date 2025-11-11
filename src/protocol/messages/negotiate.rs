//! SMB2 Negotiate messages

use super::common::SmbMessage;
use crate::error::{Error, Result};
use crate::protocol::smb2_constants::{
    structure_size, SecurityMode, Smb2Capabilities, Smb2Dialect,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{self, Read, Write};
use uuid::Uuid;

/// SMB2 Negotiate Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2NegotiateRequest {
    pub structure_size: u16,
    pub dialect_count: u16,
    pub security_mode: SecurityMode,
    pub reserved: u16,
    pub capabilities: Smb2Capabilities,
    pub client_guid: Uuid,
    pub client_start_time: u64,
    pub dialects: Vec<Smb2Dialect>,
    pub negotiate_contexts: Option<Vec<NegotiateContext>>,
}

impl Smb2NegotiateRequest {
    pub fn new(dialects: Vec<Smb2Dialect>) -> Self {
        Self {
            structure_size: structure_size::NEGOTIATE_REQUEST,
            dialect_count: dialects.len() as u16,
            security_mode: SecurityMode::SIGNING_ENABLED,
            reserved: 0,
            capabilities: Smb2Capabilities::DFS,
            client_guid: Uuid::new_v4(),
            client_start_time: 0,
            dialects,
            negotiate_contexts: None,
        }
    }

    pub fn with_smb3_contexts(mut self, contexts: Vec<NegotiateContext>) -> Self {
        self.negotiate_contexts = Some(contexts);
        self
    }
}

impl SmbMessage for Smb2NegotiateRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 36 {
            return Err(Error::ParseError("Negotiate request too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::NEGOTIATE_REQUEST {
            return Err(Error::ParseError(format!(
                "Invalid negotiate request structure size: {}",
                structure_size
            )));
        }

        let dialect_count = cursor.read_u16::<LittleEndian>()?;
        let security_mode = SecurityMode::from_bits(cursor.read_u16::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid security mode".into()))?;
        let reserved = cursor.read_u16::<LittleEndian>()?;
        let capabilities = Smb2Capabilities::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid capabilities".into()))?;

        let mut guid_bytes = [0u8; 16];
        cursor.read_exact(&mut guid_bytes)?;
        let client_guid = Uuid::from_bytes(guid_bytes);

        let client_start_time = cursor.read_u64::<LittleEndian>()?;

        let mut dialects = Vec::with_capacity(dialect_count as usize);
        for _ in 0..dialect_count {
            let dialect_val = cursor.read_u16::<LittleEndian>()?;
            dialects.push(Smb2Dialect::try_from(dialect_val)?);
        }

        // TODO: Parse negotiate contexts for SMB 3.1.1

        Ok(Self {
            structure_size,
            dialect_count,
            security_mode,
            reserved,
            capabilities,
            client_guid,
            client_start_time,
            dialects,
            negotiate_contexts: None,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.dialect_count)?;
        buf.write_u16::<LittleEndian>(self.security_mode.bits())?;
        buf.write_u16::<LittleEndian>(self.reserved)?;
        buf.write_u32::<LittleEndian>(self.capabilities.bits())?;
        buf.write_all(self.client_guid.as_bytes())?;
        buf.write_u64::<LittleEndian>(self.client_start_time)?;

        for dialect in &self.dialects {
            buf.write_u16::<LittleEndian>(dialect.to_u16())?;
        }

        // TODO: Serialize negotiate contexts for SMB 3.1.1

        Ok(buf)
    }

    fn size(&self) -> usize {
        36 + (self.dialect_count as usize * 2)
            + self
                .negotiate_contexts
                .as_ref()
                .map_or(0, |ctx| ctx.iter().map(|c| c.size()).sum())
    }
}

/// SMB2 Negotiate Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2NegotiateResponse {
    pub structure_size: u16,
    pub security_mode: SecurityMode,
    pub dialect_revision: Smb2Dialect,
    pub reserved: u16,
    pub server_guid: Uuid,
    pub capabilities: Smb2Capabilities,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub system_time: u64,
    pub server_start_time: u64,
    pub security_buffer_offset: u16,
    pub security_buffer_length: u16,
    pub reserved2: u32,
    pub security_blob: Vec<u8>,
    pub negotiate_contexts: Option<Vec<NegotiateContext>>,
}

impl Smb2NegotiateResponse {
    pub fn new(dialect: Smb2Dialect) -> Self {
        Self {
            structure_size: structure_size::NEGOTIATE_RESPONSE,
            security_mode: SecurityMode::SIGNING_ENABLED,
            dialect_revision: dialect,
            reserved: 0,
            server_guid: Uuid::new_v4(),
            capabilities: Smb2Capabilities::DFS,
            max_transact_size: 1048576,
            max_read_size: 1048576,
            max_write_size: 1048576,
            system_time: 0,
            server_start_time: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            reserved2: 0,
            security_blob: Vec::new(),
            negotiate_contexts: None,
        }
    }
}

impl SmbMessage for Smb2NegotiateResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 64 {
            return Err(Error::ParseError("Negotiate response too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::NEGOTIATE_RESPONSE {
            return Err(Error::ParseError(format!(
                "Invalid negotiate response structure size: {}",
                structure_size
            )));
        }

        let security_mode = SecurityMode::from_bits(cursor.read_u16::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid security mode".into()))?;
        let dialect_revision = Smb2Dialect::try_from(cursor.read_u16::<LittleEndian>()?)?;
        let reserved = cursor.read_u16::<LittleEndian>()?;

        let mut guid_bytes = [0u8; 16];
        cursor.read_exact(&mut guid_bytes)?;
        let server_guid = Uuid::from_bytes(guid_bytes);

        let capabilities = Smb2Capabilities::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid capabilities".into()))?;
        let max_transact_size = cursor.read_u32::<LittleEndian>()?;
        let max_read_size = cursor.read_u32::<LittleEndian>()?;
        let max_write_size = cursor.read_u32::<LittleEndian>()?;
        let system_time = cursor.read_u64::<LittleEndian>()?;
        let server_start_time = cursor.read_u64::<LittleEndian>()?;
        let security_buffer_offset = cursor.read_u16::<LittleEndian>()?;
        let security_buffer_length = cursor.read_u16::<LittleEndian>()?;
        let reserved2 = cursor.read_u32::<LittleEndian>()?;

        let security_blob = if security_buffer_length > 0 && security_buffer_offset > 0 {
            let body_start_offset = 64;
            let offset_in_body = security_buffer_offset as usize - body_start_offset;

            if offset_in_body >= buf.len() {
                return Err(Error::ParseError("Invalid security buffer offset".into()));
            }
            if offset_in_body + security_buffer_length as usize > buf.len() {
                return Err(Error::ParseError(
                    "Security buffer extends beyond message".into(),
                ));
            }
            buf[offset_in_body..offset_in_body + security_buffer_length as usize].to_vec()
        } else {
            Vec::new()
        };

        // TODO: Parse negotiate contexts for SMB 3.1.1

        Ok(Self {
            structure_size,
            security_mode,
            dialect_revision,
            reserved,
            server_guid,
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time,
            server_start_time,
            security_buffer_offset,
            security_buffer_length,
            reserved2,
            security_blob,
            negotiate_contexts: None,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.security_mode.bits())?;
        buf.write_u16::<LittleEndian>(self.dialect_revision.to_u16())?;
        buf.write_u16::<LittleEndian>(self.reserved)?;
        buf.write_all(self.server_guid.as_bytes())?;
        buf.write_u32::<LittleEndian>(self.capabilities.bits())?;
        buf.write_u32::<LittleEndian>(self.max_transact_size)?;
        buf.write_u32::<LittleEndian>(self.max_read_size)?;
        buf.write_u32::<LittleEndian>(self.max_write_size)?;
        buf.write_u64::<LittleEndian>(self.system_time)?;
        buf.write_u64::<LittleEndian>(self.server_start_time)?;

        let security_buffer_offset = if !self.security_blob.is_empty() {
            128 as u16
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(security_buffer_offset)?;
        buf.write_u16::<LittleEndian>(self.security_blob.len() as u16)?;
        buf.write_u32::<LittleEndian>(self.reserved2)?;

        if !self.security_blob.is_empty() {
            buf.write_all(&self.security_blob)?;
        }

        // TODO: Serialize negotiate contexts for SMB 3.1.1

        Ok(buf)
    }

    fn size(&self) -> usize {
        65 + self.security_blob.len()
            + self
                .negotiate_contexts
                .as_ref()
                .map_or(0, |ctx| ctx.iter().map(|c| c.size()).sum())
    }
}

/// SMB 3.1.1 Negotiate Context
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiateContext {
    PreauthIntegrityCapabilities {
        hash_algorithms: Vec<u16>,
        salt: Vec<u8>,
    },
    EncryptionCapabilities {
        ciphers: Vec<u16>,
    },
    CompressionCapabilities {
        algorithms: Vec<u16>,
    },
    NetNameNegotiateContext {
        net_name: String,
    },
}

impl NegotiateContext {
    fn size(&self) -> usize {
        match self {
            Self::PreauthIntegrityCapabilities {
                hash_algorithms,
                salt,
            } => 8 + 4 + hash_algorithms.len() * 2 + 4 + salt.len(),
            Self::EncryptionCapabilities { ciphers } => 8 + 4 + ciphers.len() * 2,
            Self::CompressionCapabilities { algorithms } => 8 + 4 + algorithms.len() * 2,
            Self::NetNameNegotiateContext { net_name } => 8 + net_name.len(),
        }
    }
}
