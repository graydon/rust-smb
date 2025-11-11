//! NetBIOS name encoding and decoding
//!
//! NetBIOS names are 16 bytes, padded with spaces, and encoded using a special algorithm

use crate::error::{Error, Result};
use std::convert::TryFrom;

/// Maximum NetBIOS name length (before padding)
pub const NETBIOS_NAME_MAX_LEN: usize = 15;

/// NetBIOS name length after padding
pub const NETBIOS_NAME_LEN: usize = 16;

/// NetBIOS encoded name length (after encoding, each byte becomes 2 bytes)
pub const NETBIOS_ENCODED_NAME_LEN: usize = 32;

/// NetBIOS name types (16th byte)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetBiosNameType {
    /// Workstation service
    Workstation = 0x00,
    /// Messenger service
    Messenger = 0x03,
    /// File server service
    FileServer = 0x20,
    /// Domain master browser
    DomainMasterBrowser = 0x1B,
    /// Domain controller
    DomainController = 0x1C,
    /// Master browser
    MasterBrowser = 0x1D,
    /// Browser service elections
    BrowserElections = 0x1E,
}

impl TryFrom<u8> for NetBiosNameType {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NetBiosNameType::Workstation),
            0x03 => Ok(NetBiosNameType::Messenger),
            0x20 => Ok(NetBiosNameType::FileServer),
            0x1B => Ok(NetBiosNameType::DomainMasterBrowser),
            0x1C => Ok(NetBiosNameType::DomainController),
            0x1D => Ok(NetBiosNameType::MasterBrowser),
            0x1E => Ok(NetBiosNameType::BrowserElections),
            other => Err(other),
        }
    }
}

/// Encode a NetBIOS name using the RFC 1001 algorithm
///
/// Each byte is split into two 4-bit values and added to 'A' (0x41)
/// For example: 'A' (0x41) becomes "EB" (0x45, 0x42)
pub fn encode_netbios_name(
    name: &str,
    name_type: NetBiosNameType,
) -> Result<[u8; NETBIOS_ENCODED_NAME_LEN]> {
    if name.len() > NETBIOS_NAME_MAX_LEN {
        return Err(Error::InvalidNetBiosName(format!(
            "Name '{}' exceeds maximum length {}",
            name, NETBIOS_NAME_MAX_LEN
        )));
    }

    // Pad with spaces to 15 bytes, then add the type byte
    let mut padded = [0x20u8; NETBIOS_NAME_LEN]; // 0x20 = space
    padded[..name.len()].copy_from_slice(name.as_bytes());
    padded[15] = name_type as u8;

    // Encode each byte
    let mut encoded = [0u8; NETBIOS_ENCODED_NAME_LEN];
    for (i, &byte) in padded.iter().enumerate() {
        let high_nibble = (byte >> 4) & 0x0F;
        let low_nibble = byte & 0x0F;

        encoded[i * 2] = b'A' + high_nibble;
        encoded[i * 2 + 1] = b'A' + low_nibble;
    }

    Ok(encoded)
}

/// Decode a NetBIOS encoded name back to the original
pub fn decode_netbios_name(encoded: &[u8]) -> Result<(String, NetBiosNameType)> {
    if encoded.len() != NETBIOS_ENCODED_NAME_LEN {
        return Err(Error::InvalidNetBiosName(format!(
            "Encoded name length {} != {}",
            encoded.len(),
            NETBIOS_ENCODED_NAME_LEN
        )));
    }

    let mut decoded = [0u8; NETBIOS_NAME_LEN];

    for i in 0..NETBIOS_NAME_LEN {
        let high_char = encoded[i * 2];
        let low_char = encoded[i * 2 + 1];

        if high_char < b'A' || high_char > b'P' || low_char < b'A' || low_char > b'P' {
            return Err(Error::InvalidNetBiosName(format!(
                "Invalid encoded characters at position {}",
                i
            )));
        }

        let high_nibble = (high_char - b'A') & 0x0F;
        let low_nibble = (low_char - b'A') & 0x0F;

        decoded[i] = (high_nibble << 4) | low_nibble;
    }

    // Extract name (trim trailing spaces) and type
    let name_bytes = &decoded[..15];
    let name = String::from_utf8_lossy(name_bytes).trim_end().to_string();

    let name_type = NetBiosNameType::try_from(decoded[15]).unwrap_or(NetBiosNameType::FileServer); // Default to file server for unknown types

    Ok((name, name_type))
}

/// Create a NetBIOS scope identifier (usually empty)
pub fn encode_netbios_scope(scope: &str) -> Vec<u8> {
    if scope.is_empty() {
        return vec![0]; // Empty scope
    }

    // Encode as DNS-style labels
    let mut encoded = Vec::new();
    for part in scope.split('.') {
        if part.len() > 63 {
            continue; // Skip too-long labels
        }
        encoded.push(part.len() as u8);
        encoded.extend_from_slice(part.as_bytes());
    }
    encoded.push(0); // Terminator

    encoded
}

/// Create a complete NetBIOS name for session service
///
/// Format: length(1) + encoded_name(32) + scope
pub fn create_netbios_session_name(
    name: &str,
    name_type: NetBiosNameType,
    scope: &str,
) -> Result<Vec<u8>> {
    let encoded_name = encode_netbios_name(name, name_type)?;
    let encoded_scope = encode_netbios_scope(scope);

    let total_len = NETBIOS_ENCODED_NAME_LEN + encoded_scope.len();
    let mut result = Vec::with_capacity(1 + total_len);

    result.push(0x20); // Length byte for the encoded name part
    result.extend_from_slice(&encoded_name);
    result.extend_from_slice(&encoded_scope);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_netbios_name() {
        let encoded = encode_netbios_name("SERVER", NetBiosNameType::FileServer).unwrap();

        // "SERVER" padded to 15 bytes + 0x20 (file server type)
        // S=0x53, E=0x45, R=0x52, V=0x56, E=0x45, R=0x52, space=0x20...

        // First byte 'S' (0x53) should encode to "FC" (F=0x46, C=0x43)
        assert_eq!(encoded[0], b'F');
        assert_eq!(encoded[1], b'D');

        // Verify length
        assert_eq!(encoded.len(), NETBIOS_ENCODED_NAME_LEN);
    }

    #[test]
    fn test_decode_netbios_name() {
        let name = "WORKSTATION";
        let encoded = encode_netbios_name(name, NetBiosNameType::Workstation).unwrap();

        let (decoded_name, decoded_type) = decode_netbios_name(&encoded).unwrap();
        assert_eq!(decoded_name, name);
        assert_eq!(decoded_type, NetBiosNameType::Workstation);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let test_cases = vec![
            ("SERVER", NetBiosNameType::FileServer),
            ("WS1", NetBiosNameType::Workstation),
            ("DOMAIN", NetBiosNameType::DomainController),
            ("A", NetBiosNameType::Messenger),
            ("MAXLENGTHNAMEEE", NetBiosNameType::MasterBrowser), // 15 chars
        ];

        for (name, name_type) in test_cases {
            let encoded = encode_netbios_name(name, name_type).unwrap();
            let (decoded_name, decoded_type) = decode_netbios_name(&encoded).unwrap();
            assert_eq!(decoded_name, name);
            assert_eq!(decoded_type, name_type);
        }
    }

    #[test]
    fn test_name_too_long() {
        let long_name = "THISNAMEISWAYTOLONG";
        let result = encode_netbios_name(long_name, NetBiosNameType::Workstation);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_scope() {
        assert_eq!(encode_netbios_scope(""), vec![0]);

        let scope = encode_netbios_scope("example.com");
        // Should be: 7 "example" 3 "com" 0
        assert_eq!(scope[0], 7);
        assert_eq!(&scope[1..8], b"example");
        assert_eq!(scope[8], 3);
        assert_eq!(&scope[9..12], b"com");
        assert_eq!(scope[12], 0);
    }

    #[test]
    fn test_create_session_name() {
        let session_name =
            create_netbios_session_name("SERVER", NetBiosNameType::FileServer, "").unwrap();

        // Should start with 0x20 (length of encoded name)
        assert_eq!(session_name[0], 0x20);

        // Followed by 32 bytes of encoded name
        assert_eq!(session_name.len(), 1 + NETBIOS_ENCODED_NAME_LEN + 1); // +1 for empty scope terminator

        // Should end with 0 (empty scope)
        assert_eq!(session_name[session_name.len() - 1], 0);
    }
}
