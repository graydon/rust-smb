//! NetBIOS over TCP (NBT) protocol implementation
//!
//! This module implements NetBIOS Session Service as defined in RFC 1001/1002

use crate::error::{Error, Result};
use crate::protocol::NetBiosMessageType;
use bytes::BufMut;
use std::convert::TryFrom;

pub mod frame;
pub mod name;

/// NetBIOS Session Service header (4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetBiosHeader {
    /// Message type
    pub message_type: NetBiosMessageType,
    /// Length of the message payload (17 bits max)
    pub length: u32,
}

impl NetBiosHeader {
    /// Maximum payload length (17 bits)
    pub const MAX_LENGTH: u32 = 0x1FFFF;

    /// Header size in bytes
    pub const SIZE: usize = 4;

    /// Create a new NetBIOS header
    pub fn new(message_type: NetBiosMessageType, length: u32) -> Result<Self> {
        if length > Self::MAX_LENGTH {
            return Err(Error::InvalidParameter(format!(
                "NetBIOS length {} exceeds maximum {}",
                length,
                Self::MAX_LENGTH
            )));
        }
        Ok(Self {
            message_type,
            length,
        })
    }

    /// Create a session message header
    pub fn session_message(length: u32) -> Result<Self> {
        Self::new(NetBiosMessageType::SessionMessage, length)
    }

    /// Parse a NetBIOS header from bytes
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                need: Self::SIZE,
                have: buf.len(),
            });
        }

        let message_type = NetBiosMessageType::try_from(buf[0])?;

        // Length is in the lower 17 bits of bytes 1-3
        let length = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32);
        let length = length & 0x1FFFF; // Mask to 17 bits

        Ok(Self {
            message_type,
            length,
        })
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0] = self.message_type as u8;

        // Length goes in the lower 17 bits
        bytes[1] = ((self.length >> 16) & 0x01) as u8;
        bytes[2] = ((self.length >> 8) & 0xFF) as u8;
        bytes[3] = (self.length & 0xFF) as u8;

        bytes
    }

    /// Write the header to a buffer
    pub fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        if buf.remaining_mut() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                need: Self::SIZE,
                have: buf.remaining_mut(),
            });
        }
        buf.put_slice(&self.to_bytes());
        Ok(())
    }
}

/// NetBIOS session message wrapper
pub struct NetBiosMessage {
    pub header: NetBiosHeader,
    pub payload: Vec<u8>,
}

impl NetBiosMessage {
    /// Create a new session message
    pub fn session_message(payload: Vec<u8>) -> Result<Self> {
        let header = NetBiosHeader::session_message(payload.len() as u32)?;
        Ok(Self { header, payload })
    }

    /// Create a session request message
    pub fn session_request(called_name: &[u8], calling_name: &[u8]) -> Result<Self> {
        let mut payload = Vec::with_capacity(called_name.len() + calling_name.len());
        payload.extend_from_slice(called_name);
        payload.extend_from_slice(calling_name);

        let header = NetBiosHeader::new(NetBiosMessageType::SessionRequest, payload.len() as u32)?;
        Ok(Self { header, payload })
    }

    /// Create a positive session response
    pub fn positive_response() -> Result<Self> {
        let header = NetBiosHeader::new(NetBiosMessageType::PositiveResponse, 0)?;
        Ok(Self {
            header,
            payload: Vec::new(),
        })
    }

    /// Create a negative session response
    pub fn negative_response(error_code: u8) -> Result<Self> {
        let header = NetBiosHeader::new(NetBiosMessageType::NegativeResponse, 1)?;
        Ok(Self {
            header,
            payload: vec![error_code],
        })
    }

    /// Create a keepalive message
    pub fn keepalive() -> Result<Self> {
        let header = NetBiosHeader::new(NetBiosMessageType::Keepalive, 0)?;
        Ok(Self {
            header,
            payload: Vec::new(),
        })
    }

    /// Serialize the entire message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NetBiosHeader::SIZE + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Parse a complete NetBIOS message from bytes
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let header = NetBiosHeader::parse(buf)?;

        let total_len = NetBiosHeader::SIZE + header.length as usize;
        if buf.len() < total_len {
            return Err(Error::BufferTooSmall {
                need: total_len,
                have: buf.len(),
            });
        }

        let payload = buf[NetBiosHeader::SIZE..total_len].to_vec();
        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netbios_header_parse() {
        // Session message with length 0x1234
        let bytes = [0x00, 0x00, 0x12, 0x34];
        let header = NetBiosHeader::parse(&bytes).unwrap();
        assert_eq!(header.message_type, NetBiosMessageType::SessionMessage);
        assert_eq!(header.length, 0x1234);
    }

    #[test]
    fn test_netbios_header_serialize() {
        let header = NetBiosHeader::session_message(0x5678).unwrap();
        let bytes = header.to_bytes();
        assert_eq!(bytes, [0x00, 0x00, 0x56, 0x78]);
    }

    #[test]
    fn test_netbios_header_max_length() {
        // Should succeed with max length
        let header = NetBiosHeader::session_message(0x1FFFF).unwrap();
        assert_eq!(header.length, 0x1FFFF);

        // Should fail with length > max
        let result = NetBiosHeader::session_message(0x20000);
        assert!(result.is_err());
    }

    #[test]
    fn test_netbios_message_types() {
        // Session request
        let bytes = [0x81, 0x00, 0x00, 0x10];
        let header = NetBiosHeader::parse(&bytes).unwrap();
        assert_eq!(header.message_type, NetBiosMessageType::SessionRequest);

        // Positive response
        let bytes = [0x82, 0x00, 0x00, 0x00];
        let header = NetBiosHeader::parse(&bytes).unwrap();
        assert_eq!(header.message_type, NetBiosMessageType::PositiveResponse);

        // Keepalive
        let bytes = [0x85, 0x00, 0x00, 0x00];
        let header = NetBiosHeader::parse(&bytes).unwrap();
        assert_eq!(header.message_type, NetBiosMessageType::Keepalive);
    }

    #[test]
    fn test_netbios_message_roundtrip() {
        let payload = vec![1, 2, 3, 4, 5];
        let msg = NetBiosMessage::session_message(payload.clone()).unwrap();

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), NetBiosHeader::SIZE + payload.len());

        let parsed = NetBiosMessage::parse(&bytes).unwrap();
        assert_eq!(
            parsed.header.message_type,
            NetBiosMessageType::SessionMessage
        );
        assert_eq!(parsed.header.length, payload.len() as u32);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_keepalive_message() {
        let msg = NetBiosMessage::keepalive().unwrap();
        assert_eq!(msg.header.message_type, NetBiosMessageType::Keepalive);
        assert_eq!(msg.header.length, 0);
        assert!(msg.payload.is_empty());

        let bytes = msg.to_bytes();
        assert_eq!(bytes, [0x85, 0x00, 0x00, 0x00]);
    }
}
