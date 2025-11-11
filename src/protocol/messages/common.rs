//! Common types and traits for SMB2 messages

use crate::error::{Error, Result};
use crate::protocol::smb2_constants::{header_flags, Smb2Command};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{self, Read};

/// Trait for SMB messages that can be parsed from and serialized to bytes
pub trait SmbMessage: Sized {
    /// Parse message from bytes
    fn parse(buf: &[u8]) -> Result<Self>;

    /// Serialize message to bytes
    fn serialize(&self) -> Result<Vec<u8>>;

    /// Get the size of the message when serialized
    fn size(&self) -> usize;
}

/// SMB2 Protocol ID (0xFE 'S' 'M' 'B')
pub const SMB2_PROTOCOL_ID: u32 = 0x424D53FE;

/// SMB2 Transform header for encrypted messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2TransformHeader {
    pub protocol_id: [u8; 4],
    pub signature: [u8; 16],
    pub nonce: [u8; 16],
    pub original_message_size: u32,
    pub reserved: u16,
    pub flags: u16,
    pub session_id: u64,
}

impl Smb2TransformHeader {
    pub fn new() -> Self {
        Self {
            protocol_id: [0xFD, b'S', b'M', b'B'],
            signature: [0; 16],
            nonce: [0; 16],
            original_message_size: 0,
            reserved: 0,
            flags: 0,
            session_id: 0,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 52 {
            return Err(Error::BufferTooSmall {
                need: 52,
                have: buf.len(),
            });
        }

        let mut protocol_id = [0u8; 4];
        protocol_id.copy_from_slice(&buf[0..4]);

        if protocol_id != [0xFD, b'S', b'M', b'B'] {
            return Err(Error::ParseError("Invalid transform header".to_string()));
        }

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&buf[4..20]);

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&buf[20..36]);

        let mut cursor = io::Cursor::new(&buf[36..]);
        let original_message_size = cursor.read_u32::<LittleEndian>()?;
        let reserved = cursor.read_u16::<LittleEndian>()?;
        let flags = cursor.read_u16::<LittleEndian>()?;
        let session_id = cursor.read_u64::<LittleEndian>()?;

        Ok(Self {
            protocol_id,
            signature,
            nonce,
            original_message_size,
            reserved,
            flags,
            session_id,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(52);
        buf.extend_from_slice(&self.protocol_id);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.nonce);
        buf.write_u32::<LittleEndian>(self.original_message_size)?;
        buf.write_u16::<LittleEndian>(self.reserved)?;
        buf.write_u16::<LittleEndian>(self.flags)?;
        buf.write_u64::<LittleEndian>(self.session_id)?;
        Ok(buf)
    }
}

/// SMB2 Header (64 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Header {
    pub protocol_id: u32,
    pub structure_size: u16,
    pub credit_charge: u16,
    pub status: u32,
    pub command: Smb2Command,
    pub credits: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Smb2Header {
    pub fn new() -> Self {
        Self::new_with_command(Smb2Command::Negotiate)
    }

    pub fn new_with_command(command: Smb2Command) -> Self {
        Self {
            protocol_id: SMB2_PROTOCOL_ID,
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command,
            credits: 1,
            flags: 0,
            next_command: 0,
            message_id: 0,
            reserved: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 64 {
            return Err(Error::BufferTooSmall {
                need: 64,
                have: buf.len(),
            });
        }

        let mut cursor = io::Cursor::new(buf);
        let protocol_id = cursor.read_u32::<LittleEndian>()?;

        if protocol_id != SMB2_PROTOCOL_ID {
            return Err(Error::ParseError(format!(
                "Invalid protocol ID: 0x{:08x}",
                protocol_id
            )));
        }

        let structure_size = cursor.read_u16::<LittleEndian>()?;
        let credit_charge = cursor.read_u16::<LittleEndian>()?;
        let status = cursor.read_u32::<LittleEndian>()?;
        let command_u16 = cursor.read_u16::<LittleEndian>()?;
        let command = Smb2Command::try_from(command_u16)?;
        let credits = cursor.read_u16::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let next_command = cursor.read_u32::<LittleEndian>()?;
        let message_id = cursor.read_u64::<LittleEndian>()?;
        let reserved = cursor.read_u32::<LittleEndian>()?;
        let tree_id = cursor.read_u32::<LittleEndian>()?;
        let session_id = cursor.read_u64::<LittleEndian>()?;

        let mut signature = [0u8; 16];
        cursor.read_exact(&mut signature)?;

        Ok(Self {
            protocol_id,
            structure_size,
            credit_charge,
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            reserved,
            tree_id,
            session_id,
            signature,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(64);
        buf.write_u32::<LittleEndian>(self.protocol_id)?;
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.credit_charge)?;
        buf.write_u32::<LittleEndian>(self.status)?;
        buf.write_u16::<LittleEndian>(self.command as u16)?;
        buf.write_u16::<LittleEndian>(self.credits)?;
        buf.write_u32::<LittleEndian>(self.flags)?;
        buf.write_u32::<LittleEndian>(self.next_command)?;
        buf.write_u64::<LittleEndian>(self.message_id)?;
        buf.write_u32::<LittleEndian>(self.reserved)?;
        buf.write_u32::<LittleEndian>(self.tree_id)?;
        buf.write_u64::<LittleEndian>(self.session_id)?;
        buf.extend_from_slice(&self.signature);
        Ok(buf)
    }

    pub fn is_response(&self) -> bool {
        self.flags & header_flags::RESPONSE != 0
    }

    pub fn is_async(&self) -> bool {
        self.flags & header_flags::ASYNC_COMMAND != 0
    }
}

/// File ID for SMB2 operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

impl FileId {
    pub fn new() -> Self {
        Self {
            persistent: 0,
            volatile: 0,
        }
    }

    pub fn with_values(persistent: u64, volatile: u64) -> Self {
        Self {
            persistent,
            volatile,
        }
    }
}
