//! SMB2 Session Setup messages

use super::common::SmbMessage;
use crate::error::{Error, Result};
use crate::protocol::smb2_constants::{structure_size, SecurityMode, Smb2Capabilities};
use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Write};

/// SMB2 SessionSetup Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2SessionSetupRequest {
    pub structure_size: u16,
    pub flags: u8,
    pub security_mode: SecurityMode,
    pub capabilities: Smb2Capabilities,
    pub channel: u32,
    pub security_buffer_offset: u16,
    pub security_buffer_length: u16,
    pub previous_session_id: u64,
    pub security_blob: Vec<u8>,
}

impl Smb2SessionSetupRequest {
    pub fn new() -> Self {
        Self {
            structure_size: structure_size::SESSION_SETUP_REQUEST,
            flags: 0,
            security_mode: SecurityMode::SIGNING_ENABLED,
            capabilities: Smb2Capabilities::DFS,
            channel: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            previous_session_id: 0,
            security_blob: Vec::new(),
        }
    }

    pub fn with_security_blob(mut self, blob: Vec<u8>) -> Self {
        self.security_buffer_length = blob.len() as u16;
        self.security_blob = blob;
        self
    }
}

impl SmbMessage for Smb2SessionSetupRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 24 {
            return Err(Error::ParseError("SessionSetup request too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::SESSION_SETUP_REQUEST {
            return Err(Error::ParseError(format!(
                "Invalid SessionSetup request structure size: {}",
                structure_size
            )));
        }

        let flags = cursor.read_u8()?;
        let security_mode = SecurityMode::from_bits(cursor.read_u8()? as u16)
            .ok_or_else(|| Error::ParseError("Invalid security mode".into()))?;
        let capabilities = Smb2Capabilities::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid capabilities".into()))?;
        let channel = cursor.read_u32::<LittleEndian>()?;
        let security_buffer_offset = cursor.read_u16::<LittleEndian>()?;
        let security_buffer_length = cursor.read_u16::<LittleEndian>()?;
        let previous_session_id = cursor.read_u64::<LittleEndian>()?;

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

        Ok(Self {
            structure_size,
            flags,
            security_mode,
            capabilities,
            channel,
            security_buffer_offset,
            security_buffer_length,
            previous_session_id,
            security_blob,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.flags)?;
        buf.write_u8(self.security_mode.bits() as u8)?;
        buf.write_u32::<LittleEndian>(self.capabilities.bits())?;
        buf.write_u32::<LittleEndian>(self.channel)?;

        let security_buffer_offset = if !self.security_blob.is_empty() {
            (64 + 24) as u16
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(security_buffer_offset)?;
        buf.write_u16::<LittleEndian>(self.security_blob.len() as u16)?;
        buf.write_u64::<LittleEndian>(self.previous_session_id)?;

        if !self.security_blob.is_empty() {
            buf.write_all(&self.security_blob)?;
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        24 + self.security_blob.len()
    }
}

/// SMB2 SessionSetup Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2SessionSetupResponse {
    pub structure_size: u16,
    pub session_flags: u16,
    pub security_buffer_offset: u16,
    pub security_buffer_length: u16,
    pub security_blob: Vec<u8>,
}

impl Smb2SessionSetupResponse {
    pub fn new() -> Self {
        Self {
            structure_size: structure_size::SESSION_SETUP_RESPONSE,
            session_flags: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            security_blob: Vec::new(),
        }
    }

    pub fn with_security_blob(mut self, blob: Vec<u8>) -> Self {
        self.security_buffer_length = blob.len() as u16;
        self.security_blob = blob;
        self
    }
}

impl SmbMessage for Smb2SessionSetupResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(Error::ParseError("SessionSetup response too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::SESSION_SETUP_RESPONSE {
            return Err(Error::ParseError(format!(
                "Invalid SessionSetup response structure size: {}",
                structure_size
            )));
        }

        let session_flags = cursor.read_u16::<LittleEndian>()?;
        let security_buffer_offset = cursor.read_u16::<LittleEndian>()?;
        let security_buffer_length = cursor.read_u16::<LittleEndian>()?;

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

        Ok(Self {
            structure_size,
            session_flags,
            security_buffer_offset,
            security_buffer_length,
            security_blob,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.session_flags)?;

        let security_buffer_offset = if !self.security_blob.is_empty() {
            (64 + 8) as u16
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(security_buffer_offset)?;
        buf.write_u16::<LittleEndian>(self.security_blob.len() as u16)?;

        if !self.security_blob.is_empty() {
            buf.write_all(&self.security_blob)?;
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        8 + self.security_blob.len()
    }
}

bitflags! {
    /// SMB2 session flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SessionFlags: u16 {
        const IS_GUEST = 0x0001;
        const IS_NULL = 0x0002;
        const ENCRYPT_DATA = 0x0004;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_setup_request_serialization() {
        let req = Smb2SessionSetupRequest::new();
        let serialized = req.serialize().unwrap();

        println!("SessionSetup request serialized:");
        println!("Length: {} bytes", serialized.len());
        println!(
            "First 10 bytes: {:02x?}",
            &serialized[..10.min(serialized.len())]
        );

        // The structure_size should be the first 2 bytes
        assert!(serialized.len() >= 2);
        let structure_size = u16::from_le_bytes([serialized[0], serialized[1]]);
        println!(
            "Structure size: {} (0x{:04x})",
            structure_size, structure_size
        );
        assert_eq!(structure_size, structure_size::SESSION_SETUP_REQUEST);

        // Now test parsing
        let parsed = Smb2SessionSetupRequest::parse(&serialized).unwrap();
        assert_eq!(parsed.structure_size, structure_size::SESSION_SETUP_REQUEST);
    }
}
