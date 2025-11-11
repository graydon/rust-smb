//! Simple end-to-end tests to verify basic functionality

use super::TestContext;
use crate::protocol::messages::{common::SmbMessage, negotiate::*};
use crate::protocol::smb2_constants::Smb2Dialect;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_negotiate() {
        let mut ctx = TestContext::new().await.unwrap();

        // Build a simple negotiate request
        let negotiate_req = Smb2NegotiateRequest::new(vec![Smb2Dialect::Smb210]);

        // Create SMB2 header + message
        let mut request = Vec::new();

        // SMB2 header (64 bytes)
        request.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol ID
        request.extend_from_slice(&64u16.to_le_bytes()); // Structure size
        request.extend_from_slice(&0u16.to_le_bytes()); // Credit charge
        request.extend_from_slice(&0u32.to_le_bytes()); // Status
        request.extend_from_slice(&0u16.to_le_bytes()); // Command = Negotiate
        request.extend_from_slice(&31u16.to_le_bytes()); // Credit request
        request.extend_from_slice(&0u32.to_le_bytes()); // Flags
        request.extend_from_slice(&0u32.to_le_bytes()); // Next command
        request.extend_from_slice(&0u64.to_le_bytes()); // Message ID
        request.extend_from_slice(&0u32.to_le_bytes()); // Process ID
        request.extend_from_slice(&0u32.to_le_bytes()); // Tree ID
        request.extend_from_slice(&0u64.to_le_bytes()); // Session ID
        request.extend_from_slice(&[0u8; 16]); // Signature

        // Add the negotiate request body
        request.extend_from_slice(&negotiate_req.serialize().unwrap());

        // Send with NetBIOS framing
        ctx.client_transport
            .send_netbios_message(&request)
            .await
            .unwrap();

        // Try to receive response
        let response = ctx
            .client_transport
            .receive_netbios_message()
            .await
            .unwrap();

        // Basic checks
        assert!(
            response.len() >= 64,
            "Response too short: {} bytes",
            response.len()
        );
        assert_eq!(&response[0..4], b"\xFESMB", "Invalid SMB2 header");

        // Check status (bytes 8-11) - should be 0 for success
        let status = u32::from_le_bytes([response[8], response[9], response[10], response[11]]);
        assert_eq!(status, 0, "Non-zero status: 0x{:08x}", status);

        ctx.shutdown().await.unwrap();
    }
}
