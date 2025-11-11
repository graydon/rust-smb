//! SMB2 Query/Set Info messages

use super::common::{FileId, SmbMessage};
use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io;

/// Info types for QueryInfo/SetInfo
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InfoType {
    FILE = 0x01,
    FILESYSTEM = 0x02,
    SECURITY = 0x03,
    QUOTA = 0x04,
}

impl TryFrom<u8> for InfoType {
    type Error = Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(InfoType::FILE),
            0x02 => Ok(InfoType::FILESYSTEM),
            0x03 => Ok(InfoType::SECURITY),
            0x04 => Ok(InfoType::QUOTA),
            _ => Err(Error::InvalidParameter(format!(
                "Invalid info type: {}",
                value
            ))),
        }
    }
}
/// Filesystem information classes  
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FsInfoClass {
    Volume = 0x01,    // FileFsVolumeInformation
    Size = 0x03,      // FileFsSizeInformation
    Device = 0x04,    // FileFsDeviceInformation
    Attribute = 0x05, // FileFsAttributeInformation
    Control = 0x06,   // FileFsControlInformation
    FullSize = 0x07,  // FileFsFullSizeInformation
    ObjectId = 0x08,  // FileFsObjectIdInformation
}

impl TryFrom<u8> for FsInfoClass {
    type Error = Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(FsInfoClass::Volume),
            0x03 => Ok(FsInfoClass::Size),
            0x04 => Ok(FsInfoClass::Device),
            0x05 => Ok(FsInfoClass::Attribute),
            0x06 => Ok(FsInfoClass::Control),
            0x07 => Ok(FsInfoClass::FullSize),
            0x08 => Ok(FsInfoClass::ObjectId),
            _ => Err(Error::InvalidParameter(format!(
                "Invalid fs info class: {}",
                value
            ))),
        }
    }
}
/// File information classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileInfoClass {
    DirectoryInfo = 0x01,
    FullDirectoryInfo = 0x02,
    BothDirectoryInfo = 0x03,
    BASIC = 0x04,
    STANDARD = 0x05,
    INTERNAL = 0x06,
    EA = 0x07,
    ACCESS = 0x08,
    NAME = 0x09,
    RENAME = 0x0A,
    LINK = 0x0B,
    NAMES = 0x0C,
    DISPOSITION = 0x0D,
    POSITION = 0x0E,
    FullEa = 0x0F,
    MODE = 0x10,
    ALIGNMENT = 0x11,
    ALL = 0x12,
    ALLOCATION = 0x13,
    EndOfFile = 0x14,
    AlternateName = 0x15,
    STREAM = 0x16,
    PIPE = 0x17,
    PipeLocal = 0x18,
    PipeRemote = 0x19,
    COMPRESSION = 0x1C,
    NetworkOpen = 0x22,
    AttributeTag = 0x23,
}

impl TryFrom<u8> for FileInfoClass {
    type Error = Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(FileInfoClass::DirectoryInfo),
            0x02 => Ok(FileInfoClass::FullDirectoryInfo),
            0x03 => Ok(FileInfoClass::BothDirectoryInfo),
            0x04 => Ok(FileInfoClass::BASIC),
            0x05 => Ok(FileInfoClass::STANDARD),
            0x06 => Ok(FileInfoClass::INTERNAL),
            0x07 => Ok(FileInfoClass::EA),
            0x08 => Ok(FileInfoClass::ACCESS),
            0x09 => Ok(FileInfoClass::NAME),
            0x0A => Ok(FileInfoClass::RENAME),
            0x0B => Ok(FileInfoClass::LINK),
            0x0C => Ok(FileInfoClass::NAMES),
            0x0D => Ok(FileInfoClass::DISPOSITION),
            0x0E => Ok(FileInfoClass::POSITION),
            0x0F => Ok(FileInfoClass::FullEa),
            0x10 => Ok(FileInfoClass::MODE),
            0x11 => Ok(FileInfoClass::ALIGNMENT),
            0x12 => Ok(FileInfoClass::ALL),
            0x13 => Ok(FileInfoClass::ALLOCATION),
            0x14 => Ok(FileInfoClass::EndOfFile),
            0x15 => Ok(FileInfoClass::AlternateName),
            0x16 => Ok(FileInfoClass::STREAM),
            0x17 => Ok(FileInfoClass::PIPE),
            0x18 => Ok(FileInfoClass::PipeLocal),
            0x19 => Ok(FileInfoClass::PipeRemote),
            0x1C => Ok(FileInfoClass::COMPRESSION),
            0x22 => Ok(FileInfoClass::NetworkOpen),
            0x23 => Ok(FileInfoClass::AttributeTag),
            _ => Err(Error::InvalidParameter(format!(
                "Invalid file info class: {}",
                value
            ))),
        }
    }
}
/// SMB2 QUERY_INFO Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2QueryInfoRequest {
    pub structure_size: u16,
    pub info_type: InfoType,
    pub file_info_class: FileInfoClass,
    pub output_buffer_length: u32,
    pub input_buffer_offset: u16,
    pub reserved: u16,
    pub input_buffer_length: u32,
    pub additional_information: u32,
    pub flags: u32,
    pub file_id: FileId,
    pub input_buffer: Vec<u8>,
}

impl SmbMessage for Smb2QueryInfoRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 40 {
            return Err(Error::BufferTooSmall {
                need: 40,
                have: buf.len(),
            });
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;
        let info_type = InfoType::try_from(cursor.read_u8()?)?;
        let file_info_class = FileInfoClass::try_from(cursor.read_u8()?)?;
        let output_buffer_length = cursor.read_u32::<LittleEndian>()?;
        let input_buffer_offset = cursor.read_u16::<LittleEndian>()?;
        let reserved = cursor.read_u16::<LittleEndian>()?;
        let input_buffer_length = cursor.read_u32::<LittleEndian>()?;
        let additional_information = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };

        let input_buffer = if input_buffer_length > 0 && input_buffer_offset as usize >= 64 {
            let start = (input_buffer_offset as usize) - 64;
            let end = start + input_buffer_length as usize;
            if end <= buf.len() {
                buf[start..end].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            structure_size,
            info_type,
            file_info_class,
            output_buffer_length,
            input_buffer_offset,
            reserved,
            input_buffer_length,
            additional_information,
            flags,
            file_id,
            input_buffer,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.info_type as u8)?;
        buf.write_u8(self.file_info_class as u8)?;
        buf.write_u32::<LittleEndian>(self.output_buffer_length)?;

        let input_buffer_offset = if !self.input_buffer.is_empty() {
            64 + 40 // Header + fixed part of request
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(input_buffer_offset as u16)?;
        buf.write_u16::<LittleEndian>(self.reserved)?;
        buf.write_u32::<LittleEndian>(self.input_buffer.len() as u32)?;
        buf.write_u32::<LittleEndian>(self.additional_information)?;
        buf.write_u32::<LittleEndian>(self.flags)?;
        buf.write_u64::<LittleEndian>(self.file_id.persistent)?;
        buf.write_u64::<LittleEndian>(self.file_id.volatile)?;

        if !self.input_buffer.is_empty() {
            buf.extend_from_slice(&self.input_buffer);
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        40 + self.input_buffer.len()
    }
}

/// SMB2 QUERY_INFO Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2QueryInfoResponse {
    pub structure_size: u16,
    pub output_buffer_offset: u16,
    pub output_buffer_length: u32,
    pub output_buffer: Vec<u8>,
}

impl SmbMessage for Smb2QueryInfoResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(Error::BufferTooSmall {
                need: 8,
                have: buf.len(),
            });
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;
        let output_buffer_offset = cursor.read_u16::<LittleEndian>()?;
        let output_buffer_length = cursor.read_u32::<LittleEndian>()?;

        let output_buffer = if output_buffer_length > 0 && output_buffer_offset as usize >= 64 {
            let start = (output_buffer_offset as usize) - 64;
            let end = start + output_buffer_length as usize;
            if end <= buf.len() {
                buf[start..end].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            structure_size,
            output_buffer_offset,
            output_buffer_length,
            output_buffer,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_u16::<LittleEndian>(self.structure_size)?;

        let output_buffer_offset = if !self.output_buffer.is_empty() {
            64 + 8 // Header + fixed part of response
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(output_buffer_offset as u16)?;
        buf.write_u32::<LittleEndian>(self.output_buffer.len() as u32)?;

        if !self.output_buffer.is_empty() {
            buf.extend_from_slice(&self.output_buffer);
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        8 + self.output_buffer.len()
    }
}

/// SMB2 SET_INFO Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2SetInfoRequest {
    pub structure_size: u16,
    pub info_type: InfoType,
    pub file_info_class: FileInfoClass,
    pub buffer_length: u32,
    pub buffer_offset: u16,
    pub reserved: u16,
    pub additional_information: u32,
    pub file_id: FileId,
    pub buffer: Vec<u8>,
}

impl SmbMessage for Smb2SetInfoRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 32 {
            return Err(Error::BufferTooSmall {
                need: 32,
                have: buf.len(),
            });
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;
        let info_type = InfoType::try_from(cursor.read_u8()?)?;
        let file_info_class = FileInfoClass::try_from(cursor.read_u8()?)?;
        let buffer_length = cursor.read_u32::<LittleEndian>()?;
        let buffer_offset = cursor.read_u16::<LittleEndian>()?;
        let reserved = cursor.read_u16::<LittleEndian>()?;
        let additional_information = cursor.read_u32::<LittleEndian>()?;
        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };

        let buffer = if buffer_length > 0 && buffer_offset as usize >= 64 {
            let start = (buffer_offset as usize) - 64;
            let end = start + buffer_length as usize;
            if end <= buf.len() {
                buf[start..end].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            structure_size,
            info_type,
            file_info_class,
            buffer_length,
            buffer_offset,
            reserved,
            additional_information,
            file_id,
            buffer,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.info_type as u8)?;
        buf.write_u8(self.file_info_class as u8)?;
        buf.write_u32::<LittleEndian>(self.buffer.len() as u32)?;

        let buffer_offset = if !self.buffer.is_empty() {
            64 + 32 // Header + fixed part of request
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(buffer_offset as u16)?;
        buf.write_u16::<LittleEndian>(self.reserved)?;
        buf.write_u32::<LittleEndian>(self.additional_information)?;
        buf.write_u64::<LittleEndian>(self.file_id.persistent)?;
        buf.write_u64::<LittleEndian>(self.file_id.volatile)?;

        if !self.buffer.is_empty() {
            buf.extend_from_slice(&self.buffer);
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        32 + self.buffer.len()
    }
}

/// SMB2 SET_INFO Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2SetInfoResponse {
    pub structure_size: u16,
}

impl SmbMessage for Smb2SetInfoResponse {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(Error::BufferTooSmall {
                need: 2,
                have: buf.len(),
            });
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;

        Ok(Self { structure_size })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u16::<LittleEndian>(self.structure_size)?;
        Ok(buf)
    }

    fn size(&self) -> usize {
        2
    }
}
