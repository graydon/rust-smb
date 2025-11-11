//! SMB2 File Operation messages (Create, Close, Read, Write)

use super::common::{FileId, SmbMessage};
use crate::error::{Error, Result};
use crate::protocol::smb2_constants::{
    create_action, impersonation_level, oplock_level, structure_size, CreateDisposition,
    CreateOptions, DesiredAccess, FileAttributes, ShareAccess,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{self, Write};
use tracing::debug;

/// SMB2 Create (Open) Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CreateRequest {
    pub structure_size: u16,
    pub security_flags: u8,
    pub requested_oplock_level: u8,
    pub impersonation_level: u32,
    pub smb_create_flags: u64,
    pub reserved: u64,
    pub desired_access: DesiredAccess,
    pub file_attributes: FileAttributes,
    pub share_access: ShareAccess,
    pub create_disposition: CreateDisposition,
    pub create_options: CreateOptions,
    pub name_offset: u16,
    pub name_length: u16,
    pub create_contexts_offset: u32,
    pub create_contexts_length: u32,
    pub file_name: String,
    pub create_contexts: Vec<CreateContext>,
}

impl Smb2CreateRequest {
    pub fn new(file_name: String) -> Self {
        Self {
            structure_size: structure_size::CREATE_REQUEST,
            security_flags: 0,
            requested_oplock_level: oplock_level::NONE,
            impersonation_level: impersonation_level::ANONYMOUS,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::FILE_GENERIC_READ | DesiredAccess::FILE_GENERIC_WRITE,
            file_attributes: FileAttributes::NORMAL,
            share_access: ShareAccess::FILE_SHARE_READ | ShareAccess::FILE_SHARE_WRITE,
            create_disposition: CreateDisposition::OpenIf,
            create_options: CreateOptions::empty(),
            name_offset: 0,
            name_length: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name,
            create_contexts: Vec::new(),
        }
    }
}

impl SmbMessage for Smb2CreateRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 56 {
            return Err(Error::ParseError("Create request too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::CREATE_REQUEST {
            return Err(Error::ParseError(format!(
                "Invalid Create request structure size: {}",
                structure_size
            )));
        }

        let security_flags = cursor.read_u8()?;
        let requested_oplock_level = cursor.read_u8()?;
        let impersonation_level = cursor.read_u32::<LittleEndian>()?;
        let smb_create_flags = cursor.read_u64::<LittleEndian>()?;
        let reserved = cursor.read_u64::<LittleEndian>()?;
        let desired_access = DesiredAccess::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid desired access".into()))?;
        let file_attributes = FileAttributes::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid file attributes".into()))?;
        let share_access = ShareAccess::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid share access".into()))?;
        let create_disposition = CreateDisposition::try_from(cursor.read_u32::<LittleEndian>()?)?;
        let create_options = CreateOptions::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid create options".into()))?;
        let name_offset = cursor.read_u16::<LittleEndian>()?;
        let name_length = cursor.read_u16::<LittleEndian>()?;
        let create_contexts_offset = cursor.read_u32::<LittleEndian>()?;
        let create_contexts_length = cursor.read_u32::<LittleEndian>()?;

        let file_name = if name_length > 0 && name_offset > 0 {
            let body_start_offset = 64;
            let offset_in_body = name_offset as usize - body_start_offset;

            if offset_in_body + name_length as usize > buf.len() {
                return Err(Error::ParseError("File name extends beyond message".into()));
            }

            let name_bytes = &buf[offset_in_body..offset_in_body + name_length as usize];
            let mut cursor = std::io::Cursor::new(name_bytes);
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
            String::new()
        };

        // TODO: Parse create contexts
        let create_contexts = Vec::new();

        Ok(Self {
            structure_size,
            security_flags,
            requested_oplock_level,
            impersonation_level,
            smb_create_flags,
            reserved,
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            name_offset,
            name_length,
            create_contexts_offset,
            create_contexts_length,
            file_name,
            create_contexts,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        let name_utf16: Vec<u16> = self.file_name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_utf16.iter().flat_map(|&c| c.to_le_bytes()).collect();

        let name_offset = if !name_bytes.is_empty() {
            (64 + 56) as u16
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.security_flags)?;
        buf.write_u8(self.requested_oplock_level)?;
        buf.write_u32::<LittleEndian>(self.impersonation_level)?;
        buf.write_u64::<LittleEndian>(self.smb_create_flags)?;
        buf.write_u64::<LittleEndian>(self.reserved)?;
        buf.write_u32::<LittleEndian>(self.desired_access.bits())?;
        buf.write_u32::<LittleEndian>(self.file_attributes.bits())?;
        buf.write_u32::<LittleEndian>(self.share_access.bits())?;
        buf.write_u32::<LittleEndian>(self.create_disposition.to_u32())?;
        buf.write_u32::<LittleEndian>(self.create_options.bits())?;
        buf.write_u16::<LittleEndian>(name_offset)?;
        buf.write_u16::<LittleEndian>(name_bytes.len() as u16)?;
        buf.write_u32::<LittleEndian>(self.create_contexts_offset)?;
        buf.write_u32::<LittleEndian>(self.create_contexts_length)?;

        if !name_bytes.is_empty() {
            buf.write_all(&name_bytes)?;
        }

        // TODO: Serialize create contexts

        Ok(buf)
    }

    fn size(&self) -> usize {
        56 + (self.file_name.encode_utf16().count() * 2)
            + self.create_contexts.iter().map(|c| c.size()).sum::<usize>()
    }
}

/// SMB2 Create (Open) Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CreateResponse {
    pub structure_size: u16,
    pub oplock_level: u8,
    pub flags: u8,
    pub create_action: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: FileAttributes,
    pub reserved2: u32,
    pub file_id: FileId,
    pub create_contexts_offset: u32,
    pub create_contexts_length: u32,
    pub create_contexts: Vec<CreateContext>,
}

impl Smb2CreateResponse {
    pub fn new(file_id: FileId) -> Self {
        Self {
            structure_size: structure_size::CREATE_RESPONSE,
            oplock_level: oplock_level::NONE,
            flags: 0,
            create_action: create_action::OPENED_EXISTING,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: FileAttributes::NORMAL,
            reserved2: 0,
            file_id,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            create_contexts: Vec::new(),
        }
    }
}

impl SmbMessage for Smb2CreateResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 88 {
            return Err(Error::ParseError("Create response too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::CREATE_RESPONSE {
            return Err(Error::ParseError(format!(
                "Invalid Create response structure size: {}",
                structure_size
            )));
        }

        let oplock_level = cursor.read_u8()?;
        let flags = cursor.read_u8()?;
        let create_action = cursor.read_u32::<LittleEndian>()?;
        let creation_time = cursor.read_u64::<LittleEndian>()?;
        let last_access_time = cursor.read_u64::<LittleEndian>()?;
        let last_write_time = cursor.read_u64::<LittleEndian>()?;
        let change_time = cursor.read_u64::<LittleEndian>()?;
        let allocation_size = cursor.read_u64::<LittleEndian>()?;
        let end_of_file = cursor.read_u64::<LittleEndian>()?;
        let file_attributes = FileAttributes::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid file attributes".into()))?;
        let reserved2 = cursor.read_u32::<LittleEndian>()?;
        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };
        let create_contexts_offset = cursor.read_u32::<LittleEndian>()?;
        let create_contexts_length = cursor.read_u32::<LittleEndian>()?;

        // TODO: Parse create contexts
        let create_contexts = Vec::new();

        Ok(Self {
            structure_size,
            oplock_level,
            flags,
            create_action,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
            file_attributes,
            reserved2,
            file_id,
            create_contexts_offset,
            create_contexts_length,
            create_contexts,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.oplock_level)?;
        buf.write_u8(self.flags)?;
        buf.write_u32::<LittleEndian>(self.create_action)?;
        buf.write_u64::<LittleEndian>(self.creation_time)?;
        buf.write_u64::<LittleEndian>(self.last_access_time)?;
        buf.write_u64::<LittleEndian>(self.last_write_time)?;
        buf.write_u64::<LittleEndian>(self.change_time)?;
        buf.write_u64::<LittleEndian>(self.allocation_size)?;
        buf.write_u64::<LittleEndian>(self.end_of_file)?;
        buf.write_u32::<LittleEndian>(self.file_attributes.bits())?;
        buf.write_u32::<LittleEndian>(self.reserved2)?;
        buf.write_u64::<LittleEndian>(self.file_id.persistent)?;
        buf.write_u64::<LittleEndian>(self.file_id.volatile)?;
        buf.write_u32::<LittleEndian>(self.create_contexts_offset)?;
        buf.write_u32::<LittleEndian>(self.create_contexts_length)?;

        // TODO: Serialize create contexts

        Ok(buf)
    }

    fn size(&self) -> usize {
        88 + self.create_contexts.iter().map(|c| c.size()).sum::<usize>()
    }
}

/// SMB2 Close Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CloseRequest {
    pub structure_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub file_id: FileId,
}

impl Smb2CloseRequest {
    pub fn new(file_id: FileId) -> Self {
        Self {
            structure_size: structure_size::CLOSE_REQUEST,
            flags: 0,
            reserved: 0,
            file_id,
        }
    }
}

impl SmbMessage for Smb2CloseRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 24 {
            return Err(Error::ParseError("Close request too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::CLOSE_REQUEST {
            return Err(Error::ParseError(format!(
                "Invalid Close request structure size: {}",
                structure_size
            )));
        }

        let flags = cursor.read_u16::<LittleEndian>()?;
        let reserved = cursor.read_u32::<LittleEndian>()?;
        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };

        Ok(Self {
            structure_size,
            flags,
            reserved,
            file_id,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.flags)?;
        buf.write_u32::<LittleEndian>(self.reserved)?;
        buf.write_u64::<LittleEndian>(self.file_id.persistent)?;
        buf.write_u64::<LittleEndian>(self.file_id.volatile)?;
        Ok(buf)
    }

    fn size(&self) -> usize {
        24
    }
}

/// SMB2 Close Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CloseResponse {
    pub structure_size: u16,
    pub flags: u16,
    pub reserved: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: FileAttributes,
}

impl Smb2CloseResponse {
    pub fn new() -> Self {
        Self {
            structure_size: structure_size::CLOSE_RESPONSE,
            flags: 0,
            reserved: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: FileAttributes::NORMAL,
        }
    }
}

impl SmbMessage for Smb2CloseResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 60 {
            return Err(Error::ParseError("Close response too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::CLOSE_RESPONSE {
            return Err(Error::ParseError(format!(
                "Invalid Close response structure size: {}",
                structure_size
            )));
        }

        let flags = cursor.read_u16::<LittleEndian>()?;
        let reserved = cursor.read_u32::<LittleEndian>()?;
        let creation_time = cursor.read_u64::<LittleEndian>()?;
        let last_access_time = cursor.read_u64::<LittleEndian>()?;
        let last_write_time = cursor.read_u64::<LittleEndian>()?;
        let change_time = cursor.read_u64::<LittleEndian>()?;
        let allocation_size = cursor.read_u64::<LittleEndian>()?;
        let end_of_file = cursor.read_u64::<LittleEndian>()?;
        let file_attributes = FileAttributes::from_bits(cursor.read_u32::<LittleEndian>()?)
            .ok_or_else(|| Error::ParseError("Invalid file attributes".into()))?;

        Ok(Self {
            structure_size,
            flags,
            reserved,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
            file_attributes,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.flags)?;
        buf.write_u32::<LittleEndian>(self.reserved)?;
        buf.write_u64::<LittleEndian>(self.creation_time)?;
        buf.write_u64::<LittleEndian>(self.last_access_time)?;
        buf.write_u64::<LittleEndian>(self.last_write_time)?;
        buf.write_u64::<LittleEndian>(self.change_time)?;
        buf.write_u64::<LittleEndian>(self.allocation_size)?;
        buf.write_u64::<LittleEndian>(self.end_of_file)?;
        buf.write_u32::<LittleEndian>(self.file_attributes.bits())?;
        Ok(buf)
    }

    fn size(&self) -> usize {
        60
    }
}

/// SMB2 Read Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2ReadRequest {
    pub structure_size: u16,
    pub padding: u8,
    pub flags: u8,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub minimum_count: u32,
    pub channel: u32,
    pub remaining_bytes: u32,
    pub read_channel_info_offset: u16,
    pub read_channel_info_length: u16,
    pub read_channel_info: Vec<u8>,
}

impl Smb2ReadRequest {
    pub fn new(file_id: FileId, offset: u64, length: u32) -> Self {
        Self {
            structure_size: structure_size::READ_REQUEST,
            padding: 0,
            flags: 0,
            length,
            offset,
            file_id,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            read_channel_info: Vec::new(),
        }
    }
}

impl SmbMessage for Smb2ReadRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 48 {
            return Err(Error::ParseError("Read request too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::READ_REQUEST {
            return Err(Error::ParseError(format!(
                "Invalid Read request structure size: {}",
                structure_size
            )));
        }

        let padding = cursor.read_u8()?;
        let flags = cursor.read_u8()?;
        let length = cursor.read_u32::<LittleEndian>()?;
        let offset = cursor.read_u64::<LittleEndian>()?;
        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };
        let minimum_count = cursor.read_u32::<LittleEndian>()?;
        let channel = cursor.read_u32::<LittleEndian>()?;
        let remaining_bytes = cursor.read_u32::<LittleEndian>()?;
        let read_channel_info_offset = cursor.read_u16::<LittleEndian>()?;
        let read_channel_info_length = cursor.read_u16::<LittleEndian>()?;

        // TODO: Parse read channel info if present
        let read_channel_info = Vec::new();

        Ok(Self {
            structure_size,
            padding,
            flags,
            length,
            offset,
            file_id,
            minimum_count,
            channel,
            remaining_bytes,
            read_channel_info_offset,
            read_channel_info_length,
            read_channel_info,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.padding)?;
        buf.write_u8(self.flags)?;
        buf.write_u32::<LittleEndian>(self.length)?;
        buf.write_u64::<LittleEndian>(self.offset)?;
        buf.write_u64::<LittleEndian>(self.file_id.persistent)?;
        buf.write_u64::<LittleEndian>(self.file_id.volatile)?;
        buf.write_u32::<LittleEndian>(self.minimum_count)?;
        buf.write_u32::<LittleEndian>(self.channel)?;
        buf.write_u32::<LittleEndian>(self.remaining_bytes)?;
        buf.write_u16::<LittleEndian>(self.read_channel_info_offset)?;
        buf.write_u16::<LittleEndian>(self.read_channel_info_length)?;

        // Add padding if needed (optional 1 byte)
        if self.read_channel_info_offset > 0 {
            buf.write_u8(0)?; // padding byte
        }

        if !self.read_channel_info.is_empty() {
            buf.write_all(&self.read_channel_info)?;
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        48 + if self.read_channel_info_offset > 0 {
            1
        } else {
            0
        } + self.read_channel_info.len()
    }
}

/// SMB2 Read Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2ReadResponse {
    pub structure_size: u16,
    pub data_offset: u8,
    pub reserved: u8,
    pub data_length: u32,
    pub data_remaining: u32,
    pub reserved2: u32,
    pub data: Vec<u8>,
}

impl Smb2ReadResponse {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            structure_size: structure_size::READ_RESPONSE,
            data_offset: 80,
            reserved: 0,
            data_length: data.len() as u32,
            data_remaining: 0,
            reserved2: 0,
            data,
        }
    }
}

impl SmbMessage for Smb2ReadResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(Error::ParseError("Read response too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::READ_RESPONSE {
            return Err(Error::ParseError(format!(
                "Invalid Read response structure size: {}",
                structure_size
            )));
        }

        let data_offset = cursor.read_u8()?;
        let reserved = cursor.read_u8()?;
        let data_length = cursor.read_u32::<LittleEndian>()?;
        let data_remaining = cursor.read_u32::<LittleEndian>()?;
        let reserved2 = cursor.read_u32::<LittleEndian>()?;

        let data = if data_length > 0 && data_offset as usize >= 64 {
            let offset_in_body = data_offset as usize - 64;
            if offset_in_body + data_length as usize > buf.len() {
                return Err(Error::ParseError("Data extends beyond message".into()));
            }
            buf[offset_in_body..offset_in_body + data_length as usize].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            structure_size,
            data_offset,
            reserved,
            data_length,
            data_remaining,
            reserved2,
            data,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Write the fixed fields (16 bytes total)
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.data_offset)?;
        buf.write_u8(self.reserved)?;
        buf.write_u32::<LittleEndian>(self.data.len() as u32)?;
        buf.write_u32::<LittleEndian>(self.data_remaining)?;
        buf.write_u32::<LittleEndian>(self.reserved2)?;

        // Debug: Check buffer size after fixed fields
        debug!(
            "After fixed fields, buffer size: {} (should be 16)",
            buf.len()
        );

        // Write the data
        if !self.data.is_empty() {
            debug!(
                "Writing data: {:02x?} ({}  bytes)",
                &self.data[..4.min(self.data.len())],
                self.data.len()
            );
            buf.write_all(&self.data)?;
        }

        debug!("Final buffer size: {}", buf.len());

        Ok(buf)
    }

    fn size(&self) -> usize {
        16 + self.data.len()
    }
}

/// SMB2 Write Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2WriteRequest {
    pub structure_size: u16,
    pub data_offset: u16,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub channel: u32,
    pub remaining_bytes: u32,
    pub write_channel_info_offset: u16,
    pub write_channel_info_length: u16,
    pub flags: u32,
    pub data: Vec<u8>,
}

impl Smb2WriteRequest {
    pub fn new(file_id: FileId, offset: u64, data: Vec<u8>) -> Self {
        Self {
            structure_size: structure_size::WRITE_REQUEST,
            data_offset: 112,
            length: data.len() as u32,
            offset,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data,
        }
    }
}

impl SmbMessage for Smb2WriteRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 48 {
            return Err(Error::ParseError("Write request too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::WRITE_REQUEST {
            return Err(Error::ParseError(format!(
                "Invalid Write request structure size: {}",
                structure_size
            )));
        }

        let data_offset = cursor.read_u16::<LittleEndian>()?;
        let length = cursor.read_u32::<LittleEndian>()?;
        let offset = cursor.read_u64::<LittleEndian>()?;
        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };
        let channel = cursor.read_u32::<LittleEndian>()?;
        let remaining_bytes = cursor.read_u32::<LittleEndian>()?;
        let write_channel_info_offset = cursor.read_u16::<LittleEndian>()?;
        let write_channel_info_length = cursor.read_u16::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;

        let data = if length > 0 && data_offset as usize >= 64 {
            let offset_in_body = data_offset as usize - 64;
            if offset_in_body + length as usize > buf.len() {
                return Err(Error::ParseError("Data extends beyond message".into()));
            }
            buf[offset_in_body..offset_in_body + length as usize].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            structure_size,
            data_offset,
            length,
            offset,
            file_id,
            channel,
            remaining_bytes,
            write_channel_info_offset,
            write_channel_info_length,
            flags,
            data,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.data_offset)?;
        buf.write_u32::<LittleEndian>(self.data.len() as u32)?;
        buf.write_u64::<LittleEndian>(self.offset)?;
        buf.write_u64::<LittleEndian>(self.file_id.persistent)?;
        buf.write_u64::<LittleEndian>(self.file_id.volatile)?;
        buf.write_u32::<LittleEndian>(self.channel)?;
        buf.write_u32::<LittleEndian>(self.remaining_bytes)?;
        buf.write_u16::<LittleEndian>(self.write_channel_info_offset)?;
        buf.write_u16::<LittleEndian>(self.write_channel_info_length)?;
        buf.write_u32::<LittleEndian>(self.flags)?;

        if !self.data.is_empty() {
            buf.write_all(&self.data)?;
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        48 + self.data.len()
    }
}

/// SMB2 Write Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2WriteResponse {
    pub structure_size: u16,
    pub reserved: u16,
    pub count: u32,
    pub remaining: u32,
    pub write_channel_info_offset: u16,
    pub write_channel_info_length: u16,
}

impl Smb2WriteResponse {
    pub fn new(count: u32) -> Self {
        Self {
            structure_size: structure_size::WRITE_RESPONSE,
            reserved: 0,
            count,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        }
    }
}

impl SmbMessage for Smb2WriteResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(Error::ParseError("Write response too short".into()));
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        if structure_size != structure_size::WRITE_RESPONSE {
            return Err(Error::ParseError(format!(
                "Invalid Write response structure size: {}",
                structure_size
            )));
        }

        let reserved = cursor.read_u16::<LittleEndian>()?;
        let count = cursor.read_u32::<LittleEndian>()?;
        let remaining = cursor.read_u32::<LittleEndian>()?;
        let write_channel_info_offset = cursor.read_u16::<LittleEndian>()?;
        let write_channel_info_length = cursor.read_u16::<LittleEndian>()?;

        Ok(Self {
            structure_size,
            reserved,
            count,
            remaining,
            write_channel_info_offset,
            write_channel_info_length,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u16::<LittleEndian>(self.reserved)?;
        buf.write_u32::<LittleEndian>(self.count)?;
        buf.write_u32::<LittleEndian>(self.remaining)?;
        buf.write_u16::<LittleEndian>(self.write_channel_info_offset)?;
        buf.write_u16::<LittleEndian>(self.write_channel_info_length)?;
        Ok(buf)
    }

    fn size(&self) -> usize {
        16
    }
}

/// Create Context
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateContext {
    pub name: String,
    pub data: Vec<u8>,
}

impl CreateContext {
    fn size(&self) -> usize {
        16 + self.name.len() + self.data.len()
    }
}
