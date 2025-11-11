//! Helper functions for building SMB2 messages in tests

use crate::error::Result;
use crate::protocol::messages::{common::SmbMessage, negotiate::*, session::*, tree::*};
use crate::protocol::smb2_constants::{Smb2Command, Smb2Dialect};
use crate::transport::tcp::TcpTransport;
use byteorder::{LittleEndian, WriteBytesExt};

/// Send an SMB2 request and receive response
pub async fn send_smb2_request(
    transport: &mut TcpTransport,
    command: Smb2Command,
    data: &[u8],
    session_id: u64,
    tree_id: u32,
    message_id: u64,
) -> Result<(Vec<u8>, u32)> {
    // Build SMB2 header
    let mut header = Vec::new();
    header.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // Protocol ID
    header.write_u16::<LittleEndian>(64)?; // Structure size
    header.write_u16::<LittleEndian>(0)?; // Credit charge
    header.write_u32::<LittleEndian>(0)?; // Status (0 for request)
    header.write_u16::<LittleEndian>(command as u16)?; // Command
    header.write_u16::<LittleEndian>(31)?; // Credit request
    header.write_u32::<LittleEndian>(0)?; // Flags
    header.write_u32::<LittleEndian>(0)?; // Next command
    header.write_u64::<LittleEndian>(message_id)?; // Message ID
    header.write_u32::<LittleEndian>(0)?; // Process ID
    header.write_u32::<LittleEndian>(tree_id)?; // Tree ID
    header.write_u64::<LittleEndian>(session_id)?; // Session ID
    header.extend_from_slice(&[0u8; 16]); // Signature

    // Combine header and data
    let mut request = header;
    request.extend_from_slice(data);

    // Send with NetBIOS framing
    transport.send_netbios_message(&request).await?;

    // Receive response
    let response = transport.receive_netbios_message().await?;

    // Extract status from response header
    let status = if response.len() >= 12 {
        u32::from_le_bytes([response[8], response[9], response[10], response[11]])
    } else {
        0xFFFFFFFF
    };

    // Return response body (after header) and status
    if response.len() > 64 {
        Ok((response[64..].to_vec(), status))
    } else {
        Ok((Vec::new(), status))
    }
}

/// Setup a connection (negotiate, session setup, tree connect)
pub async fn setup_connection(transport: &mut TcpTransport) -> Result<(u64, u32)> {
    let mut message_id = 0u64;

    // 1. Negotiate
    let negotiate_req = Smb2NegotiateRequest::new(vec![Smb2Dialect::Smb210]);
    let (_, status) = send_smb2_request(
        transport,
        Smb2Command::Negotiate,
        &negotiate_req.serialize()?,
        0,
        0,
        message_id,
    )
    .await?;

    if status != 0 {
        return Err(crate::error::Error::Protocol(format!(
            "Negotiate failed: 0x{:08x}",
            status
        )));
    }
    message_id += 1;

    // 2. Session setup (anonymous)
    let session_req = Smb2SessionSetupRequest::new();
    let (_resp_data, status) = send_smb2_request(
        transport,
        Smb2Command::SessionSetup,
        &session_req.serialize()?,
        0,
        0,
        message_id,
    )
    .await?;

    // Session setup might return STATUS_MORE_PROCESSING_REQUIRED for multi-step auth
    // For anonymous, we accept success or that status
    if status != 0 && status != 0xC0000016 {
        return Err(crate::error::Error::Protocol(format!(
            "Session setup failed: 0x{:08x}",
            status
        )));
    }
    message_id += 1;

    // For simplicity, assume session ID 1
    let session_id = 1u64;

    // 3. Tree connect to public share
    let tree_req = Smb2TreeConnectRequest::new("\\\\localhost\\public".to_string());
    let (_, status) = send_smb2_request(
        transport,
        Smb2Command::TreeConnect,
        &tree_req.serialize()?,
        session_id,
        0,
        message_id,
    )
    .await?;

    if status != 0 {
        return Err(crate::error::Error::Protocol(format!(
            "Tree connect failed: 0x{:08x}",
            status
        )));
    }

    // For simplicity, assume tree ID 1
    let tree_id = 1u32;

    Ok((session_id, tree_id))
}
