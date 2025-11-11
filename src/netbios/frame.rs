//! NetBIOS frame implementation for session messages

use crate::error::{Error, Result};
use crate::netbios::NetBiosHeader;
use crate::protocol::NetBiosMessageType;
use bytes::{BufMut, BytesMut};

/// NetBIOS frame for session messages
#[derive(Debug, Clone)]
pub struct NetBiosFrame {
    header: NetBiosHeader,
    payload: Vec<u8>,
}

impl NetBiosFrame {
    /// Create a new NetBIOS session message frame
    pub fn new_session_message(payload: Vec<u8>) -> Result<Self> {
        let header = NetBiosHeader::session_message(payload.len() as u32)?;
        Ok(Self { header, payload })
    }

    /// Create a new NetBIOS frame with specified message type
    pub fn new(message_type: NetBiosMessageType, payload: Vec<u8>) -> Result<Self> {
        let header = NetBiosHeader::new(message_type, payload.len() as u32)?;
        Ok(Self { header, payload })
    }

    /// Convert frame to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(NetBiosHeader::SIZE + self.payload.len());

        // Write header - NetBIOS format is already in network byte order
        buf.put_u8(self.header.message_type as u8);
        // Length is 17 bits in the lower 3 bytes
        buf.put_u8(((self.header.length >> 16) & 0x01) as u8);
        buf.put_u8(((self.header.length >> 8) & 0xFF) as u8);
        buf.put_u8((self.header.length & 0xFF) as u8);

        // Write payload
        buf.put_slice(&self.payload);

        buf.to_vec()
    }

    /// Parse a NetBIOS frame from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = NetBiosHeader::parse(data)?;

        let payload_start = NetBiosHeader::SIZE;
        let payload_end = payload_start + header.length as usize;

        if data.len() < payload_end {
            return Err(Error::BufferTooSmall {
                need: payload_end,
                have: data.len(),
            });
        }

        let payload = data[payload_start..payload_end].to_vec();
        Ok(Self { header, payload })
    }

    /// Get the payload
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Get the header
    pub fn header(&self) -> &NetBiosHeader {
        &self.header
    }

    /// Get the total frame size
    pub fn size(&self) -> usize {
        NetBiosHeader::SIZE + self.payload.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let payload = b"Hello, NetBIOS!".to_vec();
        let frame = NetBiosFrame::new_session_message(payload.clone()).unwrap();

        let bytes = frame.to_bytes();
        let parsed = NetBiosFrame::parse(&bytes).unwrap();

        assert_eq!(parsed.payload(), payload.as_slice());
        assert_eq!(
            parsed.header().message_type,
            NetBiosMessageType::SessionMessage
        );
    }
}
