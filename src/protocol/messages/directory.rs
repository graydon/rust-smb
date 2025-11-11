//! SMB2 Directory operations messages

use super::common::{FileId, SmbMessage};
use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;

/// SMB2 QUERY_DIRECTORY Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2QueryDirectoryRequest {
    pub structure_size: u16,
    pub file_information_class: u8,
    pub flags: u8,
    pub file_index: u32,
    pub file_id: FileId,
    pub file_name_offset: u16,
    pub file_name_length: u16,
    pub output_buffer_length: u32,
    pub file_name: String,
}

impl SmbMessage for Smb2QueryDirectoryRequest {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 32 {
            return Err(Error::BufferTooSmall {
                need: 32,
                have: buf.len(),
            });
        }

        let mut cursor = io::Cursor::new(buf);
        let structure_size = cursor.read_u16::<LittleEndian>()?;
        let file_information_class = cursor.read_u8()?;
        let flags = cursor.read_u8()?;
        let file_index = cursor.read_u32::<LittleEndian>()?;
        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };
        let file_name_offset = cursor.read_u16::<LittleEndian>()?;
        let file_name_length = cursor.read_u16::<LittleEndian>()?;
        let output_buffer_length = cursor.read_u32::<LittleEndian>()?;

        let file_name = if file_name_length > 0 && file_name_offset as usize >= 64 {
            let start = (file_name_offset as usize) - 64;
            let end = start + file_name_length as usize;
            if end <= buf.len() {
                let name_bytes = &buf[start..end];
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
            }
        } else {
            String::new()
        };

        Ok(Self {
            structure_size,
            file_information_class,
            flags,
            file_index,
            file_id,
            file_name_offset,
            file_name_length,
            output_buffer_length,
            file_name,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_u16::<LittleEndian>(self.structure_size)?;
        buf.write_u8(self.file_information_class)?;
        buf.write_u8(self.flags)?;
        buf.write_u32::<LittleEndian>(self.file_index)?;
        buf.write_u64::<LittleEndian>(self.file_id.persistent)?;
        buf.write_u64::<LittleEndian>(self.file_id.volatile)?;

        let file_name_utf16: Vec<u16> = self.file_name.encode_utf16().collect();
        let file_name_bytes: Vec<u8> = file_name_utf16
            .iter()
            .flat_map(|&c| c.to_le_bytes())
            .collect();

        let file_name_offset = if !file_name_bytes.is_empty() {
            64 + 32
        } else {
            0
        };

        buf.write_u16::<LittleEndian>(file_name_offset as u16)?;
        buf.write_u16::<LittleEndian>(file_name_bytes.len() as u16)?;
        buf.write_u32::<LittleEndian>(self.output_buffer_length)?;

        if !file_name_bytes.is_empty() {
            buf.extend_from_slice(&file_name_bytes);
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        32 + (self.file_name.len() * 2)
    }
}

/// SMB2 QUERY_DIRECTORY Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2QueryDirectoryResponse {
    pub structure_size: u16,
    pub output_buffer_offset: u16,
    pub output_buffer_length: u32,
    pub output_buffer: Vec<u8>,
}

impl SmbMessage for Smb2QueryDirectoryResponse {
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
        buf.write_u16::<LittleEndian>(self.output_buffer_offset)?;
        buf.write_u32::<LittleEndian>(self.output_buffer_length)?;

        // If there's output buffer data and an offset is specified,
        // we need to pad to reach the correct offset
        if !self.output_buffer.is_empty() && self.output_buffer_offset > 0 {
            // The offset is from the beginning of the SMB2 header (64 bytes)
            // We've written 8 bytes of response structure so far
            // So we need to pad to reach (output_buffer_offset - 64) total bytes
            let target_position = (self.output_buffer_offset as usize).saturating_sub(64);
            let current_position = buf.len();

            if target_position > current_position {
                // Add padding bytes
                let padding_needed = target_position - current_position;
                buf.extend(vec![0u8; padding_needed]);
            }

            // Now add the output buffer data
            buf.extend_from_slice(&self.output_buffer);
        } else if !self.output_buffer.is_empty() {
            // No offset specified but there's data - just append it
            buf.extend_from_slice(&self.output_buffer);
        }

        Ok(buf)
    }

    fn size(&self) -> usize {
        if !self.output_buffer.is_empty() && self.output_buffer_offset > 0 {
            // Size includes padding to reach the offset
            let target_position = (self.output_buffer_offset as usize).saturating_sub(64);
            let base_size = 8; // Response structure size
            let padded_size = if target_position > base_size {
                target_position + self.output_buffer.len()
            } else {
                base_size + self.output_buffer.len()
            };
            padded_size
        } else {
            8 + self.output_buffer.len()
        }
    }
}
