//! SMB2 IOCTL request and response messages

use crate::error::{Error, Result};
use crate::protocol::messages::common::FileId;
use crate::protocol::messages::common::SmbMessage;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

/// IOCTL control codes for pipe operations
pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011c017; // For reading/writing to named pipes
pub const FSCTL_PIPE_WAIT: u32 = 0x00110018; // Wait for pipe to be available
pub const FSCTL_PIPE_PEEK: u32 = 0x0011400c; // Peek at pipe data

/// Other common IOCTL control codes
pub const FSCTL_DFS_GET_REFERRALS: u32 = 0x00060194;
pub const FSCTL_SRV_ENUMERATE_SNAPSHOTS: u32 = 0x00144064;
pub const FSCTL_SRV_REQUEST_RESUME_KEY: u32 = 0x00140078;
pub const FSCTL_SRV_COPYCHUNK: u32 = 0x001440F2;

/// SMB2 IOCTL request structure
#[derive(Debug, Clone)]
pub struct Smb2IoctlRequest {
    pub structure_size: u16, // Must be 57
    pub reserved: u16,
    pub ctl_code: u32,            // FSCTL code
    pub file_id: FileId,          // File handle
    pub input_offset: u32,        // Offset to input data
    pub input_count: u32,         // Size of input data
    pub max_input_response: u32,  // Max input buffer size for response
    pub output_offset: u32,       // Offset to output data (usually 0 for request)
    pub output_count: u32,        // Size of output data (usually 0 for request)
    pub max_output_response: u32, // Max output buffer size for response
    pub flags: u32,               // IOCTL flags
    pub reserved2: u32,
    pub input_buffer: Vec<u8>, // Input data
}

impl SmbMessage for Smb2IoctlRequest {
    fn size(&self) -> usize {
        56 + self.input_buffer.len()
    }

    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 56 {
            return Err(Error::ParseError("IOCTL request too short".into()));
        }

        let mut cursor = Cursor::new(data);

        let structure_size = cursor.read_u16::<LittleEndian>()?;
        if structure_size != 57 {
            return Err(Error::ParseError(format!(
                "Invalid IOCTL request structure size: {}",
                structure_size
            )));
        }

        let reserved = cursor.read_u16::<LittleEndian>()?;
        let ctl_code = cursor.read_u32::<LittleEndian>()?;

        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };

        let input_offset = cursor.read_u32::<LittleEndian>()?;
        let input_count = cursor.read_u32::<LittleEndian>()?;
        let max_input_response = cursor.read_u32::<LittleEndian>()?;
        let output_offset = cursor.read_u32::<LittleEndian>()?;
        let output_count = cursor.read_u32::<LittleEndian>()?;
        let max_output_response = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let reserved2 = cursor.read_u32::<LittleEndian>()?;

        // Parse input buffer if present
        let input_buffer = if input_count > 0 && input_offset > 0 {
            let offset = (input_offset - 64) as usize; // Offset is from start of SMB2 header
            if data.len() >= offset + input_count as usize {
                data[offset..offset + input_count as usize].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            structure_size,
            reserved,
            ctl_code,
            file_id,
            input_offset,
            input_count,
            max_input_response,
            output_offset,
            output_count,
            max_output_response,
            flags,
            reserved2,
            input_buffer,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(56 + self.input_buffer.len());

        result.write_u16::<LittleEndian>(self.structure_size)?;
        result.write_u16::<LittleEndian>(self.reserved)?;
        result.write_u32::<LittleEndian>(self.ctl_code)?;
        result.write_u64::<LittleEndian>(self.file_id.persistent)?;
        result.write_u64::<LittleEndian>(self.file_id.volatile)?;

        // Calculate actual offsets for input data
        let input_offset: u32 = if !self.input_buffer.is_empty() {
            120 // 64 (header) + 56 (request structure)
        } else {
            0
        };

        result.write_u32::<LittleEndian>(input_offset)?;
        result.write_u32::<LittleEndian>(self.input_buffer.len() as u32)?;
        result.write_u32::<LittleEndian>(self.max_input_response)?;
        result.write_u32::<LittleEndian>(0)?; // output_offset (0 for request)
        result.write_u32::<LittleEndian>(0)?; // output_count (0 for request)
        result.write_u32::<LittleEndian>(self.max_output_response)?;
        result.write_u32::<LittleEndian>(self.flags)?;
        result.write_u32::<LittleEndian>(self.reserved2)?;

        // Add input buffer
        result.extend_from_slice(&self.input_buffer);

        Ok(result)
    }
}

/// SMB2 IOCTL response structure
#[derive(Debug, Clone)]
pub struct Smb2IoctlResponse {
    pub structure_size: u16, // Must be 49
    pub reserved: u16,
    pub ctl_code: u32,      // FSCTL code
    pub file_id: FileId,    // File handle
    pub input_offset: u32,  // Offset to input data
    pub input_count: u32,   // Size of input data
    pub output_offset: u32, // Offset to output data
    pub output_count: u32,  // Size of output data
    pub flags: u32,         // IOCTL flags
    pub reserved2: u32,
    pub input_buffer: Vec<u8>,  // Input data (if any)
    pub output_buffer: Vec<u8>, // Output data
}

impl SmbMessage for Smb2IoctlResponse {
    fn size(&self) -> usize {
        48 + self.input_buffer.len() + self.output_buffer.len()
    }

    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 48 {
            return Err(Error::ParseError("IOCTL response too short".into()));
        }

        let mut cursor = Cursor::new(data);

        let structure_size = cursor.read_u16::<LittleEndian>()?;
        if structure_size != 49 {
            return Err(Error::ParseError(format!(
                "Invalid IOCTL response structure size: {}",
                structure_size
            )));
        }

        let reserved = cursor.read_u16::<LittleEndian>()?;
        let ctl_code = cursor.read_u32::<LittleEndian>()?;

        let file_id = FileId {
            persistent: cursor.read_u64::<LittleEndian>()?,
            volatile: cursor.read_u64::<LittleEndian>()?,
        };

        let input_offset = cursor.read_u32::<LittleEndian>()?;
        let input_count = cursor.read_u32::<LittleEndian>()?;
        let output_offset = cursor.read_u32::<LittleEndian>()?;
        let output_count = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let reserved2 = cursor.read_u32::<LittleEndian>()?;

        // Parse input buffer if present
        let input_buffer = if input_count > 0 && input_offset > 0 {
            let offset = (input_offset - 64) as usize; // Offset is from start of SMB2 header
            if data.len() >= offset + input_count as usize {
                data[offset..offset + input_count as usize].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Parse output buffer if present
        let output_buffer = if output_count > 0 && output_offset > 0 {
            let offset = (output_offset - 64) as usize; // Offset is from start of SMB2 header
            if data.len() >= offset + output_count as usize {
                data[offset..offset + output_count as usize].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            structure_size,
            reserved,
            ctl_code,
            file_id,
            input_offset,
            input_count,
            output_offset,
            output_count,
            flags,
            reserved2,
            input_buffer,
            output_buffer,
        })
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut result =
            Vec::with_capacity(48 + self.input_buffer.len() + self.output_buffer.len());

        result.write_u16::<LittleEndian>(self.structure_size)?;
        result.write_u16::<LittleEndian>(self.reserved)?;
        result.write_u32::<LittleEndian>(self.ctl_code)?;
        result.write_u64::<LittleEndian>(self.file_id.persistent)?;
        result.write_u64::<LittleEndian>(self.file_id.volatile)?;

        // Calculate actual offsets for input and output data
        let input_offset: u32 = if !self.input_buffer.is_empty() {
            112 // 64 (header) + 48 (response structure)
        } else {
            0
        };

        let output_offset: u32 = if !self.output_buffer.is_empty() {
            if !self.input_buffer.is_empty() {
                112 + self.input_buffer.len() as u32
            } else {
                112
            }
        } else {
            0
        };

        result.write_u32::<LittleEndian>(input_offset)?;
        result.write_u32::<LittleEndian>(self.input_buffer.len() as u32)?;
        result.write_u32::<LittleEndian>(output_offset)?;
        result.write_u32::<LittleEndian>(self.output_buffer.len() as u32)?;
        result.write_u32::<LittleEndian>(self.flags)?;
        result.write_u32::<LittleEndian>(self.reserved2)?;

        // Add input buffer
        result.extend_from_slice(&self.input_buffer);

        // Add output buffer
        result.extend_from_slice(&self.output_buffer);

        Ok(result)
    }
}

impl Default for Smb2IoctlRequest {
    fn default() -> Self {
        Self {
            structure_size: 57,
            reserved: 0,
            ctl_code: 0,
            file_id: FileId {
                persistent: 0,
                volatile: 0,
            },
            input_offset: 0,
            input_count: 0,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 65536, // Default max output
            flags: 0,
            reserved2: 0,
            input_buffer: Vec::new(),
        }
    }
}

impl Default for Smb2IoctlResponse {
    fn default() -> Self {
        Self {
            structure_size: 49,
            reserved: 0,
            ctl_code: 0,
            file_id: FileId {
                persistent: 0,
                volatile: 0,
            },
            input_offset: 0,
            input_count: 0,
            output_offset: 0,
            output_count: 0,
            flags: 0,
            reserved2: 0,
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_request_serialize_deserialize() {
        let req = Smb2IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code: FSCTL_PIPE_TRANSCEIVE,
            file_id: FileId {
                persistent: 0x1234567890abcdef,
                volatile: 0xfedcba0987654321,
            },
            input_offset: 0,
            input_count: 0,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 65536,
            flags: 0,
            reserved2: 0,
            input_buffer: Vec::new(),
        };

        let serialized = req.serialize().unwrap();
        assert_eq!(serialized.len(), 56);

        let parsed = Smb2IoctlRequest::parse(&serialized).unwrap();
        assert_eq!(parsed.structure_size, 57);
        assert_eq!(parsed.ctl_code, FSCTL_PIPE_TRANSCEIVE);
        assert_eq!(parsed.file_id.persistent, 0x1234567890abcdef);
        assert_eq!(parsed.file_id.volatile, 0xfedcba0987654321);
    }

    #[test]
    fn test_ioctl_response_with_data() {
        let resp = Smb2IoctlResponse {
            structure_size: 49,
            reserved: 0,
            ctl_code: FSCTL_PIPE_TRANSCEIVE,
            file_id: FileId {
                persistent: 0x1234567890abcdef,
                volatile: 0xfedcba0987654321,
            },
            input_offset: 0,
            input_count: 0,
            output_offset: 112,
            output_count: 5,
            flags: 0,
            reserved2: 0,
            input_buffer: Vec::new(),
            output_buffer: b"Hello".to_vec(),
        };

        let serialized = resp.serialize().unwrap();
        assert_eq!(serialized.len(), 48 + 5);

        let parsed = Smb2IoctlResponse::parse(&serialized).unwrap();
        assert_eq!(parsed.structure_size, 49);
        assert_eq!(parsed.ctl_code, FSCTL_PIPE_TRANSCEIVE);
        assert_eq!(parsed.output_buffer, b"Hello");
    }
}
