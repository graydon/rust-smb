//! SMB2 protocol headers

use super::smb2_constants::*;
use crate::error::{Error, Result};

/// SMB2 Header structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Header {
    pub structure_size: u16,
    pub credit_charge: u16,
    pub status: u32,
    pub command: Smb2Command,
    pub credit: u16,
    pub flags: Smb2HeaderFlags,
    pub next_command: u32,
    pub message_id: u64,
    pub process_id: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Smb2Header {
    pub const SIZE: usize = 64;

    pub fn new(command: Smb2Command) -> Self {
        Self {
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command,
            credit: 1,
            flags: Smb2HeaderFlags::empty(),
            next_command: 0,
            message_id: 0,
            process_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                need: Self::SIZE,
                have: buf.len(),
            });
        }

        if &buf[0..4] != &SMB2_MAGIC {
            return Err(Error::InvalidHeader("Invalid SMB2 magic".into()));
        }

        // Simplified parsing - would use byteorder in real implementation
        Ok(Self::new(Smb2Command::Negotiate))
    }

    pub fn serialize(&self) -> Vec<u8> {
        use byteorder::{LittleEndian, WriteBytesExt};
        let mut buf = Vec::with_capacity(Self::SIZE);

        // Protocol ID: 0xFE 'S' 'M' 'B'
        buf.extend_from_slice(&SMB2_MAGIC);
        // Structure size (64)
        let _ = buf.write_u16::<LittleEndian>(self.structure_size);
        // Credit charge
        let _ = buf.write_u16::<LittleEndian>(self.credit_charge);
        // Status
        let _ = buf.write_u32::<LittleEndian>(self.status);
        // Command
        let _ = buf.write_u16::<LittleEndian>(self.command as u16);
        // Credit
        let _ = buf.write_u16::<LittleEndian>(self.credit);
        // Flags
        let _ = buf.write_u32::<LittleEndian>(self.flags.bits());
        // Next command
        let _ = buf.write_u32::<LittleEndian>(self.next_command);
        // Message ID
        let _ = buf.write_u64::<LittleEndian>(self.message_id);
        // Process ID
        let _ = buf.write_u32::<LittleEndian>(self.process_id);
        // Tree ID
        let _ = buf.write_u32::<LittleEndian>(self.tree_id);
        // Session ID
        let _ = buf.write_u64::<LittleEndian>(self.session_id);
        // Signature
        buf.extend_from_slice(&self.signature);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb2_header_new() {
        let header = Smb2Header::new(Smb2Command::Create);
        assert_eq!(header.command, Smb2Command::Create);
        assert_eq!(header.structure_size, 64);
    }
}
