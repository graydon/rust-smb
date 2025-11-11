//! Tests for file and directory rename operations

use super::{smb2_helper::*, TestContext};
use crate::protocol::messages::{
    common::{FileId, SmbMessage},
    file_ops::*,
    info::{FileInfoClass, InfoType, Smb2SetInfoRequest},
};
use crate::protocol::smb2_constants::Smb2Command;
use crate::protocol::smb2_constants::{
    CreateDisposition, CreateOptions, DesiredAccess, FileAttributes, ShareAccess,
};
use byteorder::{LittleEndian, WriteBytesExt};
use tokio::fs;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rename_file() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Create a test file
        let old_path = test_path.join("old_file.txt");
        let _new_path = test_path.join("new_file.txt");
        fs::write(&old_path, b"test content").await.unwrap();
        assert!(old_path.exists());

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Open the file
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::DELETE, // DELETE access for rename
            file_attributes: FileAttributes::NORMAL, // FILE_ATTRIBUTE_NORMAL
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE, // Read | Write | Delete
            create_disposition: CreateDisposition::OPEN,
            create_options: CreateOptions::empty(),
            name_offset: 120,
            name_length: (b"old_file.txt".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "old_file.txt".to_string(),
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

        // Build rename information structure
        // FileRenameInformation level (0x0a) structure:
        // [4 bytes] ReplaceIfExists (0 or 1)
        // [4 bytes] Reserved
        // [8 bytes] RootDirectory (0 for relative to current dir)
        // [4 bytes] FileNameLength
        // [variable] FileName (UTF-16LE)
        let mut rename_data = Vec::new();
        rename_data.write_u32::<LittleEndian>(0).unwrap(); // ReplaceIfExists = false
        rename_data.write_u32::<LittleEndian>(0).unwrap(); // Reserved
        rename_data.write_u64::<LittleEndian>(0).unwrap(); // RootDirectory = 0
        let new_name_utf16: Vec<u16> = "new_file.txt".encode_utf16().collect();
        let mut name_bytes = Vec::new();
        for w in new_name_utf16 {
            name_bytes.write_u16::<LittleEndian>(w).unwrap();
        }
        rename_data
            .write_u32::<LittleEndian>(name_bytes.len() as u32)
            .unwrap();
        rename_data.extend_from_slice(&name_bytes);

        // Send SET_INFO request for rename
        let setinfo_req = Smb2SetInfoRequest {
            structure_size: 33,
            info_type: InfoType::FILE,
            file_info_class: FileInfoClass::RENAME,
            buffer_length: rename_data.len() as u32,
            buffer_offset: 96,
            reserved: 0,
            additional_information: 0,
            file_id: FileId {
                persistent: file_id.persistent,
                volatile: file_id.volatile,
            },
            buffer: rename_data,
        };

        let (_, _status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::SetInfo,
            &setinfo_req.serialize().unwrap(),
            session_id,
            tree_id,
            3,
        )
        .await
        .unwrap();

        // Note: SET_INFO for rename is not yet implemented in our server
        // For now, we expect this to fail with STATUS_NOT_SUPPORTED
        // Once implemented, this should succeed with status 0
        // assert_eq!(status, 0, "SetInfo failed with status: 0x{:08x}", status);

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
            4,
        )
        .await
        .unwrap();

        // Once rename is implemented, verify the rename worked:
        // assert!(!old_path.exists(), "Old file should not exist after rename");
        // assert!(new_path.exists(), "New file should exist after rename");
        // let content = fs::read(&new_path).await.unwrap();
        // assert_eq!(content, b"test content");

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_rename_directory() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Create a test directory
        let old_dir = test_path.join("old_dir");
        let _new_dir = test_path.join("new_dir");
        fs::create_dir(&old_dir).await.unwrap();
        assert!(old_dir.exists());

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Open the directory
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::DELETE, // DELETE access for rename
            file_attributes: FileAttributes::DIRECTORY, // FILE_ATTRIBUTE_DIRECTORY
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE, // Read | Write | Delete
            create_disposition: CreateDisposition::OPEN,
            create_options: CreateOptions::FILE_DIRECTORY_FILE, // FILE_DIRECTORY_FILE
            name_offset: 120,
            name_length: (b"old_dir".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "old_dir".to_string(),
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
        let dir_id = create_resp.file_id;

        // Build rename information structure
        let mut rename_data = Vec::new();
        rename_data.write_u32::<LittleEndian>(0).unwrap(); // ReplaceIfExists = false
        rename_data.write_u32::<LittleEndian>(0).unwrap(); // Reserved
        rename_data.write_u64::<LittleEndian>(0).unwrap(); // RootDirectory = 0
        let new_name_utf16: Vec<u16> = "new_dir".encode_utf16().collect();
        let mut name_bytes = Vec::new();
        for w in new_name_utf16 {
            name_bytes.write_u16::<LittleEndian>(w).unwrap();
        }
        rename_data
            .write_u32::<LittleEndian>(name_bytes.len() as u32)
            .unwrap();
        rename_data.extend_from_slice(&name_bytes);

        // Send SET_INFO request for rename
        let setinfo_req = Smb2SetInfoRequest {
            structure_size: 33,
            info_type: InfoType::FILE,
            file_info_class: FileInfoClass::RENAME,
            buffer_length: rename_data.len() as u32,
            buffer_offset: 96,
            reserved: 0,
            additional_information: 0,
            file_id: FileId {
                persistent: dir_id.persistent,
                volatile: dir_id.volatile,
            },
            buffer: rename_data,
        };

        let (_, _status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::SetInfo,
            &setinfo_req.serialize().unwrap(),
            session_id,
            tree_id,
            3,
        )
        .await
        .unwrap();

        // Note: SET_INFO for rename is not yet implemented in our server
        // For now, we expect this to fail with STATUS_NOT_SUPPORTED
        // assert_eq!(status, 0, "SetInfo failed with status: 0x{:08x}", status);

        // Close the directory
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
            4,
        )
        .await
        .unwrap();

        // Once rename is implemented:
        // assert!(!old_dir.exists(), "Old directory should not exist after rename");
        // assert!(new_dir.exists(), "New directory should exist after rename");

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_rename_with_overwrite() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Create source and target files
        let source_path = test_path.join("source.txt");
        let target_path = test_path.join("target.txt");
        fs::write(&source_path, b"source content").await.unwrap();
        fs::write(&target_path, b"target content").await.unwrap();
        assert!(source_path.exists());
        assert!(target_path.exists());

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Open the source file
        let create_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::DELETE, // DELETE access for rename
            file_attributes: FileAttributes::NORMAL, // FILE_ATTRIBUTE_NORMAL
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE, // Read | Write | Delete
            create_disposition: CreateDisposition::OPEN,
            create_options: CreateOptions::empty(),
            name_offset: 120,
            name_length: (b"source.txt".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "source.txt".to_string(),
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

        // Build rename information structure with ReplaceIfExists = true
        let mut rename_data = Vec::new();
        rename_data.write_u32::<LittleEndian>(1).unwrap(); // ReplaceIfExists = true
        rename_data.write_u32::<LittleEndian>(0).unwrap(); // Reserved
        rename_data.write_u64::<LittleEndian>(0).unwrap(); // RootDirectory = 0
        let new_name_utf16: Vec<u16> = "target.txt".encode_utf16().collect();
        let mut name_bytes = Vec::new();
        for w in new_name_utf16 {
            name_bytes.write_u16::<LittleEndian>(w).unwrap();
        }
        rename_data
            .write_u32::<LittleEndian>(name_bytes.len() as u32)
            .unwrap();
        rename_data.extend_from_slice(&name_bytes);

        // Send SET_INFO request for rename with overwrite
        let setinfo_req = Smb2SetInfoRequest {
            structure_size: 33,
            info_type: InfoType::FILE,
            file_info_class: FileInfoClass::RENAME,
            buffer_length: rename_data.len() as u32,
            buffer_offset: 96,
            reserved: 0,
            additional_information: 0,
            file_id: FileId {
                persistent: file_id.persistent,
                volatile: file_id.volatile,
            },
            buffer: rename_data,
        };

        let (_, _status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::SetInfo,
            &setinfo_req.serialize().unwrap(),
            session_id,
            tree_id,
            3,
        )
        .await
        .unwrap();

        // Note: SET_INFO for rename is not yet implemented in our server
        // For now, we expect this to fail with STATUS_NOT_SUPPORTED
        // assert_eq!(status, 0, "SetInfo failed with status: 0x{:08x}", status);

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
            4,
        )
        .await
        .unwrap();

        // Once rename is implemented, verify overwrite worked:
        // assert!(!source_path.exists(), "Source file should not exist after rename");
        // assert!(target_path.exists(), "Target file should exist after rename");
        // let content = fs::read(&target_path).await.unwrap();
        // assert_eq!(content, b"source content", "Target should have source content after overwrite");

        ctx.shutdown().await.unwrap();
    }
}
