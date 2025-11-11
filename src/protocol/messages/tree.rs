//! SMB2 Tree Connect messages

use super::common::SmbMessage;
use crate::error::{Error, Result};
use crate::protocol::smb2_constants::{structure_size, DesiredAccess};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{self, Write};

/// SMB2 TreeConnect Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2TreeConnectRequest {
    pub structure_size: u16,
    pub flags: u16,
    pub path_offset: u16,
    pub path_length: u16,
    pub path: String,
}

impl Smb2TreeConnectRequest {
    pub fn new(path: String) -> Self {
        Self {
            structure_size: structure_size::TREE_CONNECT_REQUEST,
            flags: 0,
            path_offset: 0,
            path_length: 0,
            path,
        }
    }
}

impl SmbMessage for Smb2TreeConnectRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(Error::ParseError("TreeConnect request too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::TREE_CONNECT_REQUEST {
            return Err(Error::ParseError(format!(
                "Invalid TreeConnect request structure size: {}",
                structure_size
            )));
        }

        let flags = cursor.read_u16::<LittleEndian>()?;
        let path_offset = cursor.read_u16::<LittleEndian>()?;
        let path_length = cursor.read_u16::<LittleEndian>()?;

        let path = if path_length > 0 && path_offset > 0 {
            let body_start_offset = 64;
            let offset_in_body = path_offset as usize - body_start_offset;

            if offset_in_body + path_length as usize > buf.len() {
                return Err(Error::ParseError("Path extends beyond message".into()));
            }

            let path_bytes = &buf[offset_in_body..offset_in_body + path_length as usize];
            let mut cursor = std::io::Cursor::new(path_bytes);
            let mut path_u16 = Vec::new();
            while cursor.position() < path_bytes.len() as u64 {
                if let Ok(ch) = cursor.read_u16::<byteorder::LittleEndian>() {
                    path_u16.push(ch);
                } else {
                    break;
                }
            }
            String::from_utf16_lossy(&path_u16)
        } else {
            String::new()
        };

        Ok(Self {
            structure_size,
            flags,
            path_offset,
            path_length,
            path,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        let path_utf16: Vec<u16> = self.path.encode_utf16().collect();
        let path_bytes: Vec<u8> = path_utf16.iter().flat_map(|&c| c.to_le_bytes()).collect();

        let path_offset = if !path_bytes.is_empty() {
            (64 + 8) as u16
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.flags)?;
        buf.write_u16::<LittleEndian>(path_offset)?;
        buf.write_u16::<LittleEndian>(path_bytes.len() as u16)?;

        if !path_bytes.is_empty() {
            buf.write_all(&path_bytes)?;
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        8 + (self.path.encode_utf16().count() * 2)
    }
}

/// SMB2 TreeConnect Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2TreeConnectResponse {
    pub structure_size: u16,
    pub share_type: ShareType,
    pub reserved: u8,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

/// Share types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShareType {
    Disk = 0x01,
    Pipe = 0x02,
    Print = 0x03,
}

impl TryFrom<u8> for ShareType {
    type Error = Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Disk),
            0x02 => Ok(Self::Pipe),
            0x03 => Ok(Self::Print),
            _ => Err(Error::ParseError(format!("Invalid share type: {}", value))),
        }
    }
}

impl Smb2TreeConnectResponse {
    pub fn new(share_type: ShareType) -> Self {
        Self {
            structure_size: structure_size::TREE_CONNECT_RESPONSE,
            share_type,
            reserved: 0,
            share_flags: 0,
            capabilities: 0,
            maximal_access: DesiredAccess::FILE_ALL_ACCESS.bits(),
        }
    }
}

impl SmbMessage for Smb2TreeConnectResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(Error::ParseError("TreeConnect response too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::TREE_CONNECT_RESPONSE {
            return Err(Error::ParseError(format!(
                "Invalid TreeConnect response structure size: {}",
                structure_size
            )));
        }

        let share_type = ShareType::try_from(cursor.read_u8()?)?;
        let reserved = cursor.read_u8()?;
        let share_flags = cursor.read_u32::<LittleEndian>()?;
        let capabilities = cursor.read_u32::<LittleEndian>()?;
        let maximal_access = cursor.read_u32::<LittleEndian>()?;

        Ok(Self {
            structure_size,
            share_type,
            reserved,
            share_flags,
            capabilities,
            maximal_access,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.share_type as u8)?;
        buf.write_u8(self.reserved)?;
        buf.write_u32::<LittleEndian>(self.share_flags)?;
        buf.write_u32::<LittleEndian>(self.capabilities)?;
        buf.write_u32::<LittleEndian>(self.maximal_access)?;
        Ok(buf)
    }

    fn size(&self) -> usize {
        16
    }
}
