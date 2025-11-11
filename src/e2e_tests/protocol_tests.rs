//! Tests for SMB2 protocol negotiation and session setup

use super::TestContext;
use crate::protocol::messages::{common::SmbMessage, negotiate::*, session::*, tree::*};
use crate::protocol::smb2_constants::Smb2Dialect;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_negotiate() {
        let mut ctx = TestContext::new().await.unwrap();

        // Build negotiate request
        let negotiate_req = Smb2NegotiateRequest::new(vec![Smb2Dialect::Smb210]);

        // Send request with header
        let mut request = Vec::new();
        request.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol ID
        request.extend_from_slice(&[64, 0]); // Header size
        request.extend_from_slice(&[0; 58]); // Rest of header (zeros for negotiate)
        request.extend_from_slice(&negotiate_req.serialize().unwrap());

        ctx.client_transport
            .send_netbios_message(&request)
            .await
            .unwrap();

        // Receive response
        let response_bytes = ctx
            .client_transport
            .receive_netbios_message()
            .await
            .unwrap();

        // Should get a valid response (check header magic)
        assert!(response_bytes.len() >= 64);
        assert_eq!(&response_bytes[0..4], b"\xFESMB");

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_session_setup_anonymous() {
        let _ = env_logger::try_init();
        tracing::debug!("Starting test_session_setup_anonymous");

        let mut ctx = TestContext::new().await.unwrap();
        tracing::debug!("TestContext created");

        // First negotiate
        let negotiate_req = Smb2NegotiateRequest::new(vec![Smb2Dialect::Smb210]);
        let mut request = Vec::new();
        request.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol ID
        request.extend_from_slice(&[64, 0]); // Header size
        request.extend_from_slice(&[0; 58]); // Rest of header
        request.extend_from_slice(&negotiate_req.serialize().unwrap());

        tracing::debug!("Sending negotiate request");
        ctx.client_transport
            .send_netbios_message(&request)
            .await
            .unwrap();

        tracing::debug!("Waiting for negotiate response");
        let _response = ctx
            .client_transport
            .receive_netbios_message()
            .await
            .unwrap();
        tracing::debug!("Got negotiate response");

        // Then session setup
        let session_req = Smb2SessionSetupRequest::new();
        let mut request = Vec::new();
        request.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol ID (4 bytes)
        request.extend_from_slice(&[64, 0]); // Header size (2 bytes)
        request.extend_from_slice(&[0; 2]); // Credit charge (2 bytes)
        request.extend_from_slice(&[0; 4]); // Status (4 bytes)
        request.extend_from_slice(&[1, 0]); // Command = SessionSetup (2 bytes)
        request.extend_from_slice(&[0; 50]); // Rest of header (50 bytes to make 64 total)
        request.extend_from_slice(&session_req.serialize().unwrap());

        tracing::debug!("Sending session setup request");
        ctx.client_transport
            .send_netbios_message(&request)
            .await
            .unwrap();

        // Should get a response
        tracing::debug!("Waiting for session setup response");
        let response_bytes = match ctx.client_transport.receive_netbios_message().await {
            Ok(resp) => {
                tracing::debug!("Got session setup response: {} bytes", resp.len());
                resp
            }
            Err(e) => {
                tracing::error!("Failed to receive session setup response: {:?}", e);
                panic!("Failed to receive: {:?}", e);
            }
        };
        assert!(response_bytes.len() >= 64);
        assert_eq!(&response_bytes[0..4], b"\xFESMB");

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_tree_connect() {
        let mut ctx = TestContext::new().await.unwrap();

        // Negotiate
        let negotiate_req = Smb2NegotiateRequest::new(vec![Smb2Dialect::Smb210]);
        let mut request = Vec::new();
        request.extend_from_slice(&[0xFE, b'S', b'M', b'B']);
        request.extend_from_slice(&[64, 0]);
        request.extend_from_slice(&[0; 58]);
        request.extend_from_slice(&negotiate_req.serialize().unwrap());
        ctx.client_transport
            .send_netbios_message(&request)
            .await
            .unwrap();
        let _neg_resp = ctx
            .client_transport
            .receive_netbios_message()
            .await
            .unwrap();

        // Session setup
        let session_req = Smb2SessionSetupRequest::new();
        let mut request = Vec::new();
        request.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol ID (4 bytes)
        request.extend_from_slice(&[64, 0]); // Header size (2 bytes)
        request.extend_from_slice(&[0; 2]); // Credit charge (2 bytes)
        request.extend_from_slice(&[0; 4]); // Status (4 bytes)
        request.extend_from_slice(&[1, 0]); // Command = SessionSetup (2 bytes)
        request.extend_from_slice(&[0; 50]); // Rest of header (50 bytes to make 64 total)
        request.extend_from_slice(&session_req.serialize().unwrap());
        ctx.client_transport
            .send_netbios_message(&request)
            .await
            .unwrap();
        let session_resp = ctx
            .client_transport
            .receive_netbios_message()
            .await
            .unwrap();

        // Extract session ID from response header (bytes 40-47)
        let session_id = u64::from_le_bytes([
            session_resp[40],
            session_resp[41],
            session_resp[42],
            session_resp[43],
            session_resp[44],
            session_resp[45],
            session_resp[46],
            session_resp[47],
        ]);

        // Tree connect
        let tree_req = Smb2TreeConnectRequest::new("\\\\localhost\\public".to_string());
        let mut request = Vec::new();
        request.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol ID (4 bytes)
        request.extend_from_slice(&[64, 0]); // Header size (2 bytes)
        request.extend_from_slice(&[0; 2]); // Credit charge (2 bytes)
        request.extend_from_slice(&[0; 4]); // Status (4 bytes)
        request.extend_from_slice(&[3, 0]); // Command = TreeConnect (2 bytes)
        request.extend_from_slice(&[1, 0]); // Credits (2 bytes)
        request.extend_from_slice(&[0; 4]); // Flags (4 bytes)
        request.extend_from_slice(&[0; 4]); // Next command (4 bytes)
        request.extend_from_slice(&[0; 8]); // Message ID (8 bytes)
        request.extend_from_slice(&[0; 4]); // Reserved/Process ID (4 bytes)
        request.extend_from_slice(&[0; 4]); // Tree ID (4 bytes)
        request.extend_from_slice(&session_id.to_le_bytes()); // Session ID (8 bytes)
        request.extend_from_slice(&[0; 16]); // Signature (16 bytes)
        request.extend_from_slice(&tree_req.serialize().unwrap());

        ctx.client_transport
            .send_netbios_message(&request)
            .await
            .unwrap();
        let tree_resp = ctx
            .client_transport
            .receive_netbios_message()
            .await
            .unwrap();

        // Should get a valid response
        assert!(tree_resp.len() >= 64);
        assert_eq!(&tree_resp[0..4], b"\xFESMB");

        ctx.shutdown().await.unwrap();
    }
}
