//! NTLM cryptographic functions

use crate::error::{Error, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;

/// Convert password to NTLM hash (MD4 of UTF-16LE password)
pub fn ntlm_hash(password: &str) -> Result<[u8; 16]> {
    // Convert password to UTF-16LE
    let mut pwd_utf16 = Vec::new();
    for ch in password.encode_utf16() {
        pwd_utf16.write_u16::<LittleEndian>(ch)?;
    }

    // MD4 hash (proper NTLM hash)
    let mut hasher = Md4::new();
    hasher.update(&pwd_utf16);
    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Calculate NTLMv2 hash
pub fn ntlmv2_hash(username: &str, domain: &str, password: &str) -> Result<Vec<u8>> {
    let ntlm_hash = ntlm_hash(password)?;

    // Uppercase username and domain, convert to UTF-16LE
    let user_domain = format!("{}{}", username.to_uppercase(), domain.to_uppercase());
    let mut ud_utf16 = Vec::new();
    for ch in user_domain.encode_utf16() {
        ud_utf16.write_u16::<LittleEndian>(ch)?;
    }

    // HMAC-MD5(ntlm_hash, uppercase(username + domain))
    let mut mac = Hmac::<Md5>::new_from_slice(&ntlm_hash)
        .map_err(|e| Error::CryptoError(format!("HMAC error: {}", e)))?;
    mac.update(&ud_utf16);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Calculate LMv2 response
pub fn lmv2_response(
    ntlmv2_hash: &[u8],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> Result<Vec<u8>> {
    // HMAC-MD5(ntlmv2_hash, server_challenge + client_challenge)
    let mut mac = Hmac::<Md5>::new_from_slice(ntlmv2_hash)
        .map_err(|e| Error::CryptoError(format!("HMAC error: {}", e)))?;
    mac.update(server_challenge);
    mac.update(client_challenge);

    let mut response = mac.finalize().into_bytes().to_vec();
    response.extend_from_slice(client_challenge);
    Ok(response)
}

/// NTLMv2 blob structure
#[derive(Debug, Clone)]
pub struct NtlmV2Blob {
    pub timestamp: u64,
    pub client_challenge: [u8; 8],
    pub target_info: Vec<u8>,
}

impl NtlmV2Blob {
    /// Create a new NTLMv2 blob
    pub fn new(timestamp: u64, client_challenge: [u8; 8], target_info: Vec<u8>) -> Self {
        Self {
            timestamp,
            client_challenge,
            target_info,
        }
    }

    /// Serialize the blob
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut blob = Vec::new();

        // Blob signature
        blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);

        // Reserved
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Timestamp
        blob.write_u64::<LittleEndian>(self.timestamp)?;

        // Client challenge
        blob.extend_from_slice(&self.client_challenge);

        // Unknown
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Target info
        blob.extend_from_slice(&self.target_info);

        // Terminator
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        Ok(blob)
    }
}

/// Calculate NTLMv2 response
pub fn ntlmv2_response(
    ntlmv2_hash: &[u8],
    server_challenge: &[u8; 8],
    blob: &NtlmV2Blob,
) -> Result<Vec<u8>> {
    let blob_bytes = blob.to_bytes()?;

    // HMAC-MD5(ntlmv2_hash, server_challenge + blob)
    let mut mac = Hmac::<Md5>::new_from_slice(ntlmv2_hash)
        .map_err(|e| Error::CryptoError(format!("HMAC error: {}", e)))?;
    mac.update(server_challenge);
    mac.update(&blob_bytes);

    let mut response = mac.finalize().into_bytes().to_vec();
    response.extend_from_slice(&blob_bytes);
    Ok(response)
}

/// Calculate session key for NTLMv2
pub fn ntlmv2_session_key(ntlmv2_hash: &[u8], nt_response: &[u8]) -> Result<Vec<u8>> {
    // Session key = HMAC-MD5(ntlmv2_hash, first 16 bytes of NT response)
    let mut mac = Hmac::<Md5>::new_from_slice(ntlmv2_hash)
        .map_err(|e| Error::CryptoError(format!("HMAC error: {}", e)))?;
    mac.update(&nt_response[..16.min(nt_response.len())]);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Generate random client challenge
pub fn generate_client_challenge() -> [u8; 8] {
    let mut challenge = [0u8; 8];
    for byte in &mut challenge {
        *byte = rand::random();
    }
    challenge
}

/// Get current Windows timestamp (100ns intervals since 1601-01-01)
pub fn get_windows_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Windows epoch is 1601-01-01, Unix epoch is 1970-01-01
    // Difference in 100ns intervals
    const WINDOWS_EPOCH_DIFF: u64 = 116444736000000000;

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Convert to 100ns intervals and add difference
    (duration.as_secs() * 10_000_000 + duration.subsec_nanos() as u64 / 100) + WINDOWS_EPOCH_DIFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_hash() {
        // Test with known password
        let hash = ntlm_hash("password").unwrap();
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_ntlmv2_hash() {
        let hash = ntlmv2_hash("User", "Domain", "password").unwrap();
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_ntlmv2_blob() {
        let blob = NtlmV2Blob::new(
            0x0123456789ABCDEF,
            [1, 2, 3, 4, 5, 6, 7, 8],
            vec![0xAA, 0xBB, 0xCC],
        );

        let bytes = blob.to_bytes().unwrap();
        assert_eq!(&bytes[0..4], &[0x01, 0x01, 0x00, 0x00]); // Signature
        assert_eq!(&bytes[16..24], &[1, 2, 3, 4, 5, 6, 7, 8]); // Client challenge (after 4 bytes signature + 4 bytes reserved + 8 bytes timestamp)
    }

    #[test]
    fn test_generate_client_challenge() {
        let c1 = generate_client_challenge();
        let c2 = generate_client_challenge();
        assert_ne!(c1, c2); // Should be random
    }

    #[test]
    fn test_windows_timestamp() {
        let ts = get_windows_timestamp();
        assert!(ts > 0);
    }
}
