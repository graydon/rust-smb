//! End-to-end test scenarios for SMB protocol
//!
//! This module contains comprehensive test scenarios that verify
//! the full SMB protocol stack works correctly.

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
    async fn test_full_file_workflow() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // 1. Create a new file
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
            name_length: (b"workflow.txt".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "workflow.txt".to_string(),
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

        // 2. Write data to the file
        let test_data = b"Hello from workflow test!";
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

        // 3. Read data back
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

        // 4. Close the file
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
            5,
        )
        .await
        .unwrap();

        assert_eq!(status, 0, "Close failed with status: 0x{:08x}", status);

        // Verify file exists on filesystem
        let file_path = test_path.join("workflow.txt");
        assert!(file_path.exists(), "File should exist after workflow");
        let fs_data = fs::read(&file_path).await.unwrap();
        assert_eq!(fs_data, test_data);

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_files_concurrent() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();

        // Create multiple files
        let mut file_ids = Vec::new();
        let mut message_id = 2u64;

        for i in 0..3 {
            let filename = format!("file_{}.txt", i);
            let create_req = Smb2CreateRequest {
                structure_size: 57,
                security_flags: 0,
                requested_oplock_level: 0,
                impersonation_level: 0x02,
                smb_create_flags: 0,
                reserved: 0,
                desired_access: DesiredAccess::GENERIC_ALL,
                file_attributes: FileAttributes::NORMAL,
                share_access: ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
                create_disposition: CreateDisposition::CREATE,
                create_options: CreateOptions::empty(),
                name_offset: 120,
                name_length: (filename.len() * 2) as u16,
                create_contexts_offset: 0,
                create_contexts_length: 0,
                file_name: filename.clone(),
                create_contexts: vec![],
            };

            let (response, status) = send_smb2_request(
                &mut ctx.client_transport,
                Smb2Command::Create,
                &create_req.serialize().unwrap(),
                session_id,
                tree_id,
                message_id,
            )
            .await
            .unwrap();
            message_id += 1;

            assert_eq!(status, 0, "Create file {} failed", i);
            let create_resp = Smb2CreateResponse::parse(&response).unwrap();
            file_ids.push(create_resp.file_id);
        }

        // Write different data to each file
        for (i, &file_id) in file_ids.iter().enumerate() {
            let data = format!("Content for file {}", i).into_bytes();
            let write_req = Smb2WriteRequest {
                structure_size: 49,
                data_offset: 112,
                length: data.len() as u32,
                offset: 0,
                file_id,
                channel: 0,
                remaining_bytes: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
                flags: 0,
                data: data.clone(),
            };

            let (_, status) = send_smb2_request(
                &mut ctx.client_transport,
                Smb2Command::Write,
                &write_req.serialize().unwrap(),
                session_id,
                tree_id,
                message_id,
            )
            .await
            .unwrap();
            message_id += 1;

            assert_eq!(status, 0, "Write to file {} failed", i);
        }

        // Close all files
        for file_id in file_ids {
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
                message_id,
            )
            .await
            .unwrap();
            message_id += 1;
        }

        // Verify all files exist
        for i in 0..3 {
            let file_path = test_path.join(format!("file_{}.txt", i));
            assert!(file_path.exists(), "File {} should exist", i);
            let content = fs::read_to_string(&file_path).await.unwrap();
            assert_eq!(content, format!("Content for file {}", i));
        }

        ctx.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_hierarchy() {
        let mut ctx = TestContext::new().await.unwrap();
        let test_path = ctx.test_dir.path();

        // Setup SMB connection
        let (session_id, tree_id) = setup_connection(&mut ctx.client_transport).await.unwrap();
        let mut message_id = 2u64;

        // Create a directory
        let create_dir_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::GENERIC_ALL,
            file_attributes: FileAttributes::DIRECTORY, // FILE_ATTRIBUTE_DIRECTORY
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE,
            create_disposition: CreateDisposition::CREATE,
            create_options: CreateOptions::FILE_DIRECTORY_FILE, // FILE_DIRECTORY_FILE
            name_offset: 120,
            name_length: (b"testdir".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "testdir".to_string(),
            create_contexts: vec![],
        };

        let (response, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Create,
            &create_dir_req.serialize().unwrap(),
            session_id,
            tree_id,
            message_id,
        )
        .await
        .unwrap();
        message_id += 1;

        assert_eq!(status, 0, "Create directory failed");
        let create_resp = Smb2CreateResponse::parse(&response).unwrap();
        let dir_id = create_resp.file_id;

        // Close directory handle
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
            message_id,
        )
        .await
        .unwrap();
        message_id += 1;

        // Create a file inside the directory
        let create_file_req = Smb2CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0x02,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: DesiredAccess::GENERIC_ALL,
            file_attributes: FileAttributes::NORMAL,
            share_access: ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE,
            create_disposition: CreateDisposition::CREATE,
            create_options: CreateOptions::empty(),
            name_offset: 120,
            name_length: (b"testdir\\file.txt".len() * 2) as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            file_name: "testdir\\file.txt".to_string(),
            create_contexts: vec![],
        };

        let (response, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Create,
            &create_file_req.serialize().unwrap(),
            session_id,
            tree_id,
            message_id,
        )
        .await
        .unwrap();
        message_id += 1;

        assert_eq!(status, 0, "Create file in directory failed");
        let create_resp = Smb2CreateResponse::parse(&response).unwrap();
        let file_id = create_resp.file_id;

        // Write data to the file
        let data = b"File in directory";
        let write_req = Smb2WriteRequest {
            structure_size: 49,
            data_offset: 112,
            length: data.len() as u32,
            offset: 0,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: data.to_vec(),
        };

        let (_, status) = send_smb2_request(
            &mut ctx.client_transport,
            Smb2Command::Write,
            &write_req.serialize().unwrap(),
            session_id,
            tree_id,
            message_id,
        )
        .await
        .unwrap();
        message_id += 1;

        assert_eq!(status, 0, "Write to file in directory failed");

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
            message_id,
        )
        .await
        .unwrap();

        // Verify directory structure on filesystem
        let dir_path = test_path.join("testdir");
        assert!(dir_path.exists() && dir_path.is_dir());

        let file_path = dir_path.join("file.txt");
        assert!(file_path.exists() && file_path.is_file());

        let content = fs::read(&file_path).await.unwrap();
        assert_eq!(content, b"File in directory");

        ctx.shutdown().await.unwrap();
    }
}
