//! Tests for basic file operations (create, read, write, close)

use super::{smb2_helper::*, TestContext};
use crate::protocol::messages::{common::SmbMessage, file_ops::*};
use crate::protocol::smb2_constants::Smb2Command;
use crate::protocol::smb2_constants::{
    CreateDisposition, CreateOptions, DesiredAccess, FileAttributes, ShareAccess,
};
use tokio::fs;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_close_file() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Create a new file
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::GENERIC_ALL, // GENERIC_ALL
            file_attributes: FileAttributes::NORMAL,    // FILE_ATTRIBUTE_NORMAL
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE, // Read | Write | Delete
            create_disposition: CreateDisposition::CREATE,
            create_options: CreateOptions::empty(),
            name_offset: 120,
            name_length: (b"test_create.txt".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "test_create.txt".to_string(),
            create_contexts: vec![],
        };

        let (response, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Create,
            &create_req.serialize().unwrap(),
            session_id,
            tree_id,
            2,
        )
        .await
        .unwrap();

        assert_eq!(status, 0, "Create failed with status: 0x{:08x}", status);
        let create_resp = Smb2CreateResponse::parse(&response).unwrap();
        let file_id = create_resp.file_id;

        // Close the file
        let close_req = Smb2CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };

        let (_, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Close,
            &close_req.serialize().unwrap(),
            session_id,
            tree_id,
            3,
        )
        .await
        .unwrap();

        assert_eq!(status, 0, "Close failed with status: 0x{:08x}", status);

        // Verify file was created
        let file_path = test_path.join("test_create.txt");
        assert!(file_path.exists(), "File should have been created");

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_write_and_read_file() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Create a new file
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::GENERIC_ALL, // GENERIC_ALL
            file_attributes: FileAttributes::NORMAL,    // FILE_ATTRIBUTE_NORMAL
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE, // Read | Write | Delete
            create_disposition: CreateDisposition::CREATE,
            create_options: CreateOptions::empty(),
            name_offset: 120,
            name_length: (b"test_rw.txt".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "test_rw.txt".to_string(),
            create_contexts: vec![],
        };

        let (response, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Create,
            &create_req.serialize().unwrap(),
            session_id,
            tree_id,
            2,
        )
        .await
        .unwrap();

        assert_eq!(status, 0, "Create failed with status: 0x{:08x}", status);
        let create_resp = Smb2CreateResponse::parse(&response).unwrap();
        let file_id = create_resp.file_id;

        // Write data to file
        let test_data = b"Hello from SMB test!";
        let write_req = Smb2WriteRequest {
            structure_size: 49,
            data_offset: 112,
            length: test_data.len() as u32,
            offset: 0,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: test_data.to_vec(),
        };

        let (response, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Write,
            &write_req.serialize().unwrap(),
            session_id,
            tree_id,
            3,
        )
        .await
        .unwrap();

        assert_eq!(status, 0, "Write failed with status: 0x{:08x}", status);
        let write_resp = Smb2WriteResponse::parse(&response).unwrap();
        assert_eq!(write_resp.count, test_data.len() as u32);

        // Read data back
        let read_req = Smb2ReadRequest {
            structure_size: 49,
            padding: 0,
            flags: 0,
            length: test_data.len() as u32,
            offset: 0,
            file_id,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            read_channel_info: vec![],
        };

        let (response, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Read,
            &read_req.serialize().unwrap(),
            session_id,
            tree_id,
            4,
        )
        .await
        .unwrap();

        assert_eq!(status, 0, "Read failed with status: 0x{:08x}", status);
        let read_resp = Smb2ReadResponse::parse(&response).unwrap();
        assert_eq!(read_resp.data, test_data);

        // Close the file
        let close_req = Smb2CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };

        send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Close,
            &close_req.serialize().unwrap(),
            session_id,
            tree_id,
            5,
        )
        .await
        .unwrap();

        // Verify file content on filesystem
        let file_path = test_path.join("test_rw.txt");
        let fs_data = fs::read(&file_path).await.unwrap();
        assert_eq!(fs_data, test_data);

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_create_directory() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Create a directory
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::GENERIC_ALL, // GENERIC_ALL
            file_attributes: FileAttributes::DIRECTORY, // FILE_ATTRIBUTE_DIRECTORY
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE, // Read | Write | Delete
            create_disposition: CreateDisposition::CREATE,
            create_options: CreateOptions::FILE_DIRECTORY_FILE, // FILE_DIRECTORY_FILE
            name_offset: 120,
            name_length: (b"test_dir".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "test_dir".to_string(),
            create_contexts: vec![],
        };

        let (response, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Create,
            &create_req.serialize().unwrap(),
            session_id,
            tree_id,
            2,
        )
        .await
        .unwrap();

        assert_eq!(
            status, 0,
            "Create directory failed with status: 0x{:08x}",
            status
        );
        let create_resp = Smb2CreateResponse::parse(&response).unwrap();
        let dir_id = create_resp.file_id;

        // Close the directory handle
        let close_req = Smb2CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id: dir_id,
        };

        send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Close,
            &close_req.serialize().unwrap(),
            session_id,
            tree_id,
            3,
        )
        .await
        .unwrap();

        // Verify directory was created
        let dir_path = test_path.join("test_dir");
        assert!(
            dir_path.exists() && dir_path.is_dir(),
            "Directory should have been created"
        );

        ctx.shutdown().await.unwrap();
    }
}
