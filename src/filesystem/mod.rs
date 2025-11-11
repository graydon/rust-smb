//! Filesystem abstraction layer for SMB

pub mod real_fs;

use crate::error::Result;
use crate::protocol::smb2_constants::{
    CreateDisposition, CreateOptions, DesiredAccess, ShareAccess,
};
use bitflags::bitflags;

/// File handle for open files
#[derive(Debug, Clone)]
pub struct FileHandle {
    /// Unique handle ID
    pub handle_id: [u8; 16],
    /// Path to the file
    pub path: String,
    /// Whether this is a directory
    pub is_directory: bool,
}

bitflags! {
    /// File attributes for filesystem operations
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileAttributes: u32 {
        const READONLY = 0x00000001;
        const HIDDEN = 0x00000002;
        const SYSTEM = 0x00000004;
        const DIRECTORY = 0x00000010;
        const ARCHIVE = 0x00000020;
        const NORMAL = 0x00000080;
        const TEMPORARY = 0x00000100;
        const SPARSE_FILE = 0x00000200;
        const REPARSE_POINT = 0x00000400;
        const COMPRESSED = 0x00000800;
        const OFFLINE = 0x00001000;
        const NOT_CONTENT_INDEXED = 0x00002000;
        const ENCRYPTED = 0x00004000;
    }
}

/// File information structure
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub attributes: FileAttributes,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub delete_pending: bool,
    pub is_directory: bool,
}

/// Filesystem trait for different backends
pub trait FileSystem: Send + Sync {
    /// Create or open a file
    fn create_file(
        &mut self,
        path: &str,
        desired_access: DesiredAccess,
        file_attributes: FileAttributes,
        share_access: ShareAccess,
        create_disposition: CreateDisposition,
        create_options: CreateOptions,
    ) -> Result<FileHandle>;

    /// Read from a file
    fn read_file(&mut self, handle: &FileHandle, offset: u64, length: u32) -> Result<Vec<u8>>;

    /// Write to a file
    fn write_file(&mut self, handle: &FileHandle, offset: u64, data: &[u8]) -> Result<u32>;

    /// Close a file handle
    fn close_file(&mut self, handle: &FileHandle) -> Result<()>;

    /// Delete a file or directory
    fn delete_file(&mut self, path: &str) -> Result<()>;

    /// Create a directory
    fn create_directory(&mut self, path: &str) -> Result<()>;

    /// List directory contents
    fn list_directory(&self, path: &str) -> Result<Vec<FileInfo>>;

    /// Get file information
    fn get_file_info(&self, path: &str) -> Result<FileInfo>;

    /// Set file information
    fn set_file_info(&mut self, path: &str, info: &FileInfo) -> Result<()>;

    /// Rename a file or directory
    fn rename_file(&mut self, old_path: &str, new_path: &str) -> Result<()>;

    /// Flush file buffers
    fn flush_file(&mut self, handle: &FileHandle) -> Result<()>;

    /// Lock a byte range in a file
    fn lock_file(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        length: u64,
        exclusive: bool,
        fail_immediately: bool,
    ) -> Result<()>;

    /// Unlock a byte range in a file
    fn unlock_file(&mut self, handle: &FileHandle, offset: u64, length: u64) -> Result<()>;

    /// Query directory with pattern matching
    fn query_directory(
        &self,
        path: &str,
        pattern: &str,
        restart_scan: bool,
        single_entry: bool,
        index: u32,
    ) -> Result<Vec<FileInfo>>;
}

pub use real_fs::{RealFileSystem, RealFsConfig};
