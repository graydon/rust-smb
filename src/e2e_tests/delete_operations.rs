//! Tests for delete operations (delete on close)

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
    async fn test_delete_file_on_close() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Create a test file
        let file_path = test_path.join("delete_me.txt");
        fs::write(&file_path, b"test content").await.unwrap();
        assert!(file_path.exists());

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Open file with DELETE_ON_CLOSE flag
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::DELETE,
            file_attributes: FileAttributes::NORMAL,
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE,
            create_disposition: CreateDisposition::OPEN,
            create_options: CreateOptions::FILE_DELETE_ON_CLOSE,
            name_offset: 120,
            name_length: (b"delete_me.txt".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "delete_me.txt".to_string(),
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

        // Close the file (should trigger deletion)
        let close_req = Smb2CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };

        let (_, _status) = send_smb2_request(
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

        // Give filesystem time to process deletion
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify file was deleted
        assert!(
            !file_path.exists(),
            "File should have been deleted on close"
        );

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_delete_empty_directory_on_close() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Create a test directory
        let dir_path = test_path.join("delete_dir");
        fs::create_dir(&dir_path).await.unwrap();
        assert!(dir_path.exists());

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Open directory with DELETE_ON_CLOSE flag
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::DELETE,
            file_attributes: FileAttributes::DIRECTORY,
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE,
            create_disposition: CreateDisposition::OPEN,
            create_options: CreateOptions::FILE_DIRECTORY_FILE
                | CreateOptions::FILE_DELETE_ON_CLOSE,
            name_offset: 120,
            name_length: (b"delete_dir".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "delete_dir".to_string(),
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

        // Close the directory (should trigger deletion)
        let close_req = Smb2CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };

        let (_, _status) = send_smb2_request(
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

        // Give filesystem time to process deletion
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify directory was deleted
        assert!(
            !dir_path.exists(),
            "Directory should have been deleted on close"
        );

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_delete_non_empty_directory_fails() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Create a directory with a file inside
        let dir_path = test_path.join("non_empty_dir");
        fs::create_dir(&dir_path).await.unwrap();
        let file_path = dir_path.join("file.txt");
        fs::write(&file_path, b"content").await.unwrap();
        assert!(dir_path.exists());
        assert!(file_path.exists());

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Try to open directory with DELETE_ON_CLOSE flag
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::DELETE,
            file_attributes: FileAttributes::DIRECTORY,
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE,
            create_disposition: CreateDisposition::OPEN,
            create_options: CreateOptions::FILE_DIRECTORY_FILE
                | CreateOptions::FILE_DELETE_ON_CLOSE,
            name_offset: 120,
            name_length: (b"non_empty_dir".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "non_empty_dir".to_string(),
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

        // Close the directory
        let close_req = Smb2CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };

        let (_, _status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Close,
            &close_req.serialize().unwrap(),
            session_id,
            tree_id,
            3,
        )
        .await
        .unwrap();

        // Close might succeed but directory shouldn't be deleted

        // Give filesystem time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify directory still exists (non-empty directories cannot be deleted)
        assert!(
            dir_path.exists(),
            "Non-empty directory should not be deleted"
        );
        assert!(
            file_path.exists(),
            "File inside directory should still exist"
        );

        ctx.shutdown().await.unwrap();
    }
}
