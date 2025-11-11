//! Protocol constants for NetBIOS and general SMB

use std::convert::TryFrom;

/// NetBIOS header size
pub const NBT_HDR_SIZE: usize = 4;

/// Minimum SMB packet size
pub const MIN_SMB_SIZE: usize = 35;

/// NetBIOS message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetBiosMessageType {
    SessionMessage = 0x00,
    SessionRequest = 0x81,
    PositiveResponse = 0x82,
    NegativeResponse = 0x83,
    RetargetResponse = 0x84,
    Keepalive = 0x85,
}

impl TryFrom<u8> for NetBiosMessageType {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NetBiosMessageType::SessionMessage),
            0x81 => Ok(NetBiosMessageType::SessionRequest),
            0x82 => Ok(NetBiosMessageType::PositiveResponse),
            0x83 => Ok(NetBiosMessageType::NegativeResponse),
            0x84 => Ok(NetBiosMessageType::RetargetResponse),
            0x85 => Ok(NetBiosMessageType::Keepalive),
            _ => Err(crate::error::Error::Protocol(format!(
                "Invalid NetBIOS message type: 0x{:02x}",
                value
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netbios_message_types() {
        assert_eq!(NetBiosMessageType::SessionMessage as u8, 0x00);
        assert_eq!(NetBiosMessageType::SessionRequest as u8, 0x81);
    }
}
