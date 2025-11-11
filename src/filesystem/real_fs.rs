//! Real filesystem backend implementation

use crate::error::{Error, Result};
use crate::filesystem::{FileAttributes as FsFileAttributes, FileHandle, FileInfo, FileSystem};
use crate::protocol::smb2_constants::{
    CreateDisposition, CreateOptions, DesiredAccess, ShareAccess,
};
use std::collections::HashMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Configuration for real filesystem backend
#[derive(Debug, Clone)]
pub struct RealFsConfig {
    /// Root directory to serve files from
    pub root_path: PathBuf,
    /// Whether to allow write operations
    pub read_only: bool,
    /// Whether to follow symlinks
    pub follow_symlinks: bool,
    /// Maximum file size for reads/writes
    pub max_file_size: u64,
    /// Whether to allow access outside root (via symlinks)
    pub jail: bool,
}

impl Default for RealFsConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("/"),
            read_only: false,
            follow_symlinks: false,
            max_file_size: 100 * 1024 * 1024 * 1024, // 100GB
            jail: true,
        }
    }
}

/// Open file descriptor
struct OpenFile {
    path: PathBuf,
    file: File,
    access_mask: DesiredAccess,
    _share_access: ShareAccess,
    delete_on_close: bool,
}

/// Real filesystem implementation
pub struct RealFileSystem {
    config: RealFsConfig,
    handles: Arc<Mutex<HashMap<[u8; 16], OpenFile>>>,
    locks: Arc<Mutex<HashMap<PathBuf, Vec<FileLock>>>>,
}

/// File lock information
#[derive(Debug, Clone)]
struct FileLock {
    handle: [u8; 16],
    offset: u64,
    length: u64,
    exclusive: bool,
    _pid: u32,
}

impl RealFileSystem {
    /// Create a new real filesystem backend
    pub fn new(config: RealFsConfig) -> Result<Self> {
        // Verify root path exists and is a directory
        if !config.root_path.exists() {
            return Err(Error::FileNotFound(format!(
                "Root path does not exist: {:?}",
                config.root_path
            )));
        }

        if !config.root_path.is_dir() {
            return Err(Error::InvalidParameter(format!(
                "Root path is not a directory: {:?}",
                config.root_path
            )));
        }

        // Canonicalize the root path
        let root_path = config.root_path.canonicalize().map_err(|e| Error::Io(e))?;

        Ok(Self {
            config: RealFsConfig {
                root_path,
                ..config
            },
            handles: Arc::new(Mutex::new(HashMap::new())),
            locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Resolve a path relative to the root, checking for jail escapes
    fn resolve_path(&self, path: &str) -> Result<PathBuf> {
        // Remove leading slashes and backslashes
        let clean_path = path.trim_start_matches('/').trim_start_matches('\\');

        // Convert Windows-style paths to Unix-style
        let clean_path = clean_path.replace('\\', "/");

        // Build the full path
        let mut full_path = self.config.root_path.clone();
        for component in clean_path.split('/') {
            if component.is_empty() || component == "." {
                continue;
            } else if component == ".." {
                if self.config.jail {
                    // Don't allow going above root
                    return Err(Error::AccessDenied(
                        "Path traversal outside root not allowed".to_string(),
                    ));
                }
                full_path.pop();
            } else {
                full_path.push(component);
            }
        }

        // Resolve symlinks if configured to do so
        if self.config.follow_symlinks && full_path.exists() {
            full_path = full_path.canonicalize().map_err(|e| Error::Io(e))?;
        }

        // Check jail constraint
        if self.config.jail {
            let canonical = if full_path.exists() {
                full_path.canonicalize().map_err(|e| Error::Io(e))?
            } else {
                // For non-existent files, we need to check the path components
                // to ensure they don't escape the jail
                // Just use the full_path as-is since we've already built it safely
                full_path.clone()
            };

            // For existing paths, check the canonical path
            // For non-existing paths, check the constructed path
            if canonical.exists() && !canonical.starts_with(&self.config.root_path) {
                return Err(Error::AccessDenied(
                    "Path escapes root directory".to_string(),
                ));
            }

            Ok(canonical)
        } else {
            Ok(full_path)
        }
    }

    /// Convert std Metadata to FileInfo
    fn metadata_to_fileinfo(&self, path: &Path, metadata: &Metadata) -> FileInfo {
        let modified = metadata
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let created = metadata
            .created()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let accessed = metadata
            .accessed()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut attributes = FsFileAttributes::empty();

        if metadata.is_dir() {
            attributes |= FsFileAttributes::DIRECTORY;
        }

        if metadata.permissions().readonly() {
            attributes |= FsFileAttributes::READONLY;
        }

        // Check if hidden (Unix convention: starts with dot)
        if let Some(name) = path.file_name() {
            if let Some(name_str) = name.to_str() {
                if name_str.starts_with('.') {
                    attributes |= FsFileAttributes::HIDDEN;
                }
            }
        }

        if attributes.is_empty() {
            attributes = FsFileAttributes::NORMAL;
        }

        FileInfo {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string(),
            size: metadata.len(),
            attributes,
            creation_time: created,
            last_access_time: accessed,
            last_write_time: modified,
            change_time: modified,
            allocation_size: metadata.len(),
            end_of_file: metadata.len(),
            number_of_links: 1,
            delete_pending: false,
            is_directory: metadata.is_dir(),
        }
    }

    /// Check if a lock conflicts with existing locks
    fn check_lock_conflict(&self, path: &Path, offset: u64, length: u64, exclusive: bool) -> bool {
        let locks = self.locks.lock().unwrap();

        if let Some(file_locks) = locks.get(path) {
            for lock in file_locks {
                // Check if ranges overlap
                let lock_end = lock.offset + lock.length;
                let request_end = offset + length;

                if lock.offset < request_end && offset < lock_end {
                    // Ranges overlap - check if conflict
                    if exclusive || lock.exclusive {
                        return true; // Conflict
                    }
                }
            }
        }

        false
    }
}

impl FileSystem for RealFileSystem {
    fn create_file(
        &mut self,
        path: &str,
        desired_access: DesiredAccess,
        _file_attributes: FsFileAttributes,
        share_access: ShareAccess,
        create_disposition: CreateDisposition,
        create_options: CreateOptions,
    ) -> Result<FileHandle> {
        let full_path = self.resolve_path(path)?;

        // Check read-only mode
        if self.config.read_only {
            let needs_write = desired_access.contains(DesiredAccess::GENERIC_WRITE)
                || desired_access.contains(DesiredAccess::FILE_WRITE_DATA)
                || desired_access.contains(DesiredAccess::FILE_APPEND_DATA)
                || create_disposition == CreateDisposition::CREATE
                || create_disposition == CreateDisposition::SUPERSEDE
                || create_disposition == CreateDisposition::OVERWRITE
                || create_disposition == CreateDisposition::OverwriteIf;

            if needs_write {
                return Err(Error::AccessDenied("Filesystem is read-only".to_string()));
            }
        }

        // Open the file with appropriate options
        let mut open_options = OpenOptions::new();

        // Set read/write based on desired access
        if desired_access.contains(DesiredAccess::GENERIC_READ)
            || desired_access.contains(DesiredAccess::FILE_READ_DATA)
        {
            open_options.read(true);
        }

        if desired_access.contains(DesiredAccess::GENERIC_WRITE)
            || desired_access.contains(DesiredAccess::FILE_WRITE_DATA)
            || desired_access.contains(DesiredAccess::FILE_APPEND_DATA)
        {
            open_options.write(true);
        }

        // Handle create disposition
        match create_disposition {
            CreateDisposition::SUPERSEDE => {
                open_options.create(true).truncate(true);
            }
            CreateDisposition::OPEN => {
                // File must exist
                if !full_path.exists() {
                    return Err(Error::FileNotFound(format!("{:?}", full_path)));
                }
            }
            CreateDisposition::CREATE => {
                // File must not exist
                if full_path.exists() {
                    return Err(Error::Protocol("File already exists".to_string()));
                }
                open_options.create_new(true);
            }
            CreateDisposition::OpenIf => {
                open_options.create(true);
            }
            CreateDisposition::OVERWRITE => {
                // File must exist
                if !full_path.exists() {
                    return Err(Error::FileNotFound(format!("{:?}", full_path)));
                }
                open_options.truncate(true);
            }
            CreateDisposition::OverwriteIf => {
                open_options.create(true).truncate(true);
            }
        }

        // Handle directories
        if create_options.contains(CreateOptions::FILE_DIRECTORY_FILE)
            || (full_path.exists() && full_path.is_dir())
        {
            // For directories, we don't actually open a file handle
            // Just verify it exists or create it
            if !full_path.exists() {
                if create_disposition == CreateDisposition::CREATE
                    || create_disposition == CreateDisposition::OpenIf
                    || create_disposition == CreateDisposition::SUPERSEDE
                {
                    fs::create_dir_all(&full_path).map_err(|e| Error::Io(e))?;
                } else {
                    return Err(Error::FileNotFound(format!("{:?}", full_path)));
                }
            }

            // Generate a handle for the directory
            let handle_id = Uuid::new_v4().as_bytes().clone();

            // Create a dummy file handle for tracking
            let file = OpenOptions::new()
                .read(true)
                .open(&full_path)
                .map_err(|e| Error::Io(e))?;

            let open_file = OpenFile {
                path: full_path.clone(),
                file,
                access_mask: desired_access,
                _share_access: share_access,
                delete_on_close: create_options.contains(CreateOptions::FILE_DELETE_ON_CLOSE),
            };

            self.handles.lock().unwrap().insert(handle_id, open_file);

            return Ok(FileHandle {
                handle_id,
                path: path.to_string(),
                is_directory: true,
            });
        }

        // Open the file
        let file = open_options.open(&full_path).map_err(|e| Error::Io(e))?;

        // Generate a unique handle
        let handle_id = Uuid::new_v4().as_bytes().clone();

        let open_file = OpenFile {
            path: full_path.clone(),
            file,
            access_mask: desired_access,
            _share_access: share_access,
            delete_on_close: create_options.contains(CreateOptions::FILE_DELETE_ON_CLOSE),
        };

        self.handles.lock().unwrap().insert(handle_id, open_file);

        Ok(FileHandle {
            handle_id,
            path: path.to_string(),
            is_directory: false,
        })
    }

    fn read_file(&mut self, handle: &FileHandle, offset: u64, length: u32) -> Result<Vec<u8>> {
        let mut handles = self.handles.lock().unwrap();

        let open_file = handles
            .get_mut(&handle.handle_id)
            .ok_or_else(|| Error::InvalidParameter("Invalid file handle".to_string()))?;

        // Check access rights
        if !open_file
            .access_mask
            .contains(DesiredAccess::FILE_READ_DATA)
            && !open_file.access_mask.contains(DesiredAccess::GENERIC_READ)
        {
            return Err(Error::AccessDenied("No read access".to_string()));
        }

        // Seek to offset
        open_file
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| Error::Io(e))?;

        // Read data
        let mut buffer = vec![0u8; length as usize];
        let bytes_read = open_file.file.read(&mut buffer).map_err(|e| Error::Io(e))?;

        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    fn write_file(&mut self, handle: &FileHandle, offset: u64, data: &[u8]) -> Result<u32> {
        if self.config.read_only {
            return Err(Error::AccessDenied("Filesystem is read-only".to_string()));
        }

        let mut handles = self.handles.lock().unwrap();

        let open_file = handles
            .get_mut(&handle.handle_id)
            .ok_or_else(|| Error::InvalidParameter("Invalid file handle".to_string()))?;

        // Check access rights
        if !open_file
            .access_mask
            .contains(DesiredAccess::FILE_WRITE_DATA)
            && !open_file
                .access_mask
                .contains(DesiredAccess::FILE_APPEND_DATA)
            && !open_file.access_mask.contains(DesiredAccess::GENERIC_WRITE)
        {
            return Err(Error::AccessDenied("No write access".to_string()));
        }

        // Check file size limit
        let _current_size = open_file.file.metadata().map_err(|e| Error::Io(e))?.len();

        if offset + data.len() as u64 > self.config.max_file_size {
            return Err(Error::Protocol("File size exceeds maximum".to_string()));
        }

        // Seek to offset
        open_file
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| Error::Io(e))?;

        // Write data
        let bytes_written = open_file.file.write(data).map_err(|e| Error::Io(e))?;

        open_file.file.flush().map_err(|e| Error::Io(e))?;

        Ok(bytes_written as u32)
    }

    fn close_file(&mut self, handle: &FileHandle) -> Result<()> {
        let mut handles = self.handles.lock().unwrap();

        if let Some(open_file) = handles.remove(&handle.handle_id) {
            // Handle delete-on-close
            if open_file.delete_on_close {
                drop(open_file.file); // Close file first
                fs::remove_file(&open_file.path)
                    .or_else(|_| fs::remove_dir(&open_file.path))
                    .map_err(|e| Error::Io(e))?;
            }

            // Remove any locks for this file
            let mut locks = self.locks.lock().unwrap();
            if let Some(file_locks) = locks.get_mut(&open_file.path) {
                file_locks.retain(|lock| lock.handle != handle.handle_id);
                if file_locks.is_empty() {
                    locks.remove(&open_file.path);
                }
            }
        }

        Ok(())
    }

    fn delete_file(&mut self, path: &str) -> Result<()> {
        if self.config.read_only {
            return Err(Error::AccessDenied("Filesystem is read-only".to_string()));
        }

        let full_path = self.resolve_path(path)?;

        if full_path.is_dir() {
            fs::remove_dir_all(&full_path).map_err(|e| Error::Io(e))?;
        } else {
            fs::remove_file(&full_path).map_err(|e| Error::Io(e))?;
        }

        Ok(())
    }

    fn create_directory(&mut self, path: &str) -> Result<()> {
        if self.config.read_only {
            return Err(Error::AccessDenied("Filesystem is read-only".to_string()));
        }

        let full_path = self.resolve_path(path)?;

        fs::create_dir_all(&full_path).map_err(|e| Error::Io(e))?;

        Ok(())
    }

    fn list_directory(&self, path: &str) -> Result<Vec<FileInfo>> {
        let full_path = self.resolve_path(path)?;

        if !full_path.is_dir() {
            return Err(Error::InvalidParameter("Not a directory".to_string()));
        }

        let mut entries = Vec::new();

        for entry in fs::read_dir(&full_path).map_err(|e| Error::Io(e))? {
            let entry = entry.map_err(|e| Error::Io(e))?;
            let metadata = entry.metadata().map_err(|e| Error::Io(e))?;
            let file_info = self.metadata_to_fileinfo(&entry.path(), &metadata);
            entries.push(file_info);
        }

        Ok(entries)
    }

    fn get_file_info(&self, path: &str) -> Result<FileInfo> {
        let full_path = self.resolve_path(path)?;

        let metadata = fs::metadata(&full_path).map_err(|e| Error::Io(e))?;

        Ok(self.metadata_to_fileinfo(&full_path, &metadata))
    }

    fn set_file_info(&mut self, path: &str, info: &FileInfo) -> Result<()> {
        if self.config.read_only {
            return Err(Error::AccessDenied("Filesystem is read-only".to_string()));
        }

        let full_path = self.resolve_path(path)?;

        // Set file times
        let modified =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(info.last_write_time);
        let accessed =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(info.last_access_time);

        filetime::set_file_times(
            &full_path,
            filetime::FileTime::from_system_time(accessed),
            filetime::FileTime::from_system_time(modified),
        )
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        // Set readonly attribute
        let metadata = fs::metadata(&full_path).map_err(|e| Error::Io(e))?;
        let mut permissions = metadata.permissions();
        permissions.set_readonly(info.attributes.contains(FsFileAttributes::READONLY));
        fs::set_permissions(&full_path, permissions).map_err(|e| Error::Io(e))?;

        Ok(())
    }

    fn rename_file(&mut self, old_path: &str, new_path: &str) -> Result<()> {
        if self.config.read_only {
            return Err(Error::AccessDenied("Filesystem is read-only".to_string()));
        }

        let old_full = self.resolve_path(old_path)?;
        let new_full = self.resolve_path(new_path)?;

        fs::rename(&old_full, &new_full).map_err(|e| Error::Io(e))?;

        Ok(())
    }

    fn flush_file(&mut self, handle: &FileHandle) -> Result<()> {
        let mut handles = self.handles.lock().unwrap();

        let open_file = handles
            .get_mut(&handle.handle_id)
            .ok_or_else(|| Error::InvalidParameter("Invalid file handle".to_string()))?;

        open_file.file.sync_all().map_err(|e| Error::Io(e))?;

        Ok(())
    }

    fn lock_file(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        length: u64,
        exclusive: bool,
        fail_immediately: bool,
    ) -> Result<()> {
        let handles = self.handles.lock().unwrap();

        let open_file = handles
            .get(&handle.handle_id)
            .ok_or_else(|| Error::InvalidParameter("Invalid file handle".to_string()))?;

        // Check for conflicts
        if self.check_lock_conflict(&open_file.path, offset, length, exclusive) {
            if fail_immediately {
                return Err(Error::Protocol("Lock conflict".to_string()));
            }
            // With fail_immediately = false, we could implement waiting/retry logic
            // For simplicity, we still return an error but could implement async waiting
            return Err(Error::Protocol(
                "Lock conflict - would retry in async implementation".to_string(),
            ));
        }

        // Add the lock
        let mut locks = self.locks.lock().unwrap();
        let file_locks = locks.entry(open_file.path.clone()).or_insert_with(Vec::new);

        file_locks.push(FileLock {
            handle: handle.handle_id,
            offset,
            length,
            exclusive,
            _pid: std::process::id(),
        });

        Ok(())
    }

    fn unlock_file(&mut self, handle: &FileHandle, offset: u64, length: u64) -> Result<()> {
        let handles = self.handles.lock().unwrap();

        let open_file = handles
            .get(&handle.handle_id)
            .ok_or_else(|| Error::InvalidParameter("Invalid file handle".to_string()))?;

        let mut locks = self.locks.lock().unwrap();

        if let Some(file_locks) = locks.get_mut(&open_file.path) {
            file_locks.retain(|lock| {
                !(lock.handle == handle.handle_id && lock.offset == offset && lock.length == length)
            });

            if file_locks.is_empty() {
                locks.remove(&open_file.path);
            }
        }

        Ok(())
    }

    fn query_directory(
        &self,
        path: &str,
        pattern: &str,
        _restart_scan: bool,
        _single_entry: bool,
        _index: u32,
    ) -> Result<Vec<FileInfo>> {
        let full_path = self.resolve_path(path)?;

        if !full_path.is_dir() {
            return Err(Error::InvalidParameter("Not a directory".to_string()));
        }

        let mut entries = Vec::new();
        let pattern_regex = glob_to_regex(pattern)?;

        for entry in fs::read_dir(&full_path).map_err(|e| Error::Io(e))? {
            let entry = entry.map_err(|e| Error::Io(e))?;

            // Check if name matches pattern
            if let Some(name) = entry.file_name().to_str() {
                if !pattern_regex.is_match(name) {
                    continue;
                }
            }

            let metadata = entry.metadata().map_err(|e| Error::Io(e))?;
            let file_info = self.metadata_to_fileinfo(&entry.path(), &metadata);
            entries.push(file_info);
        }

        Ok(entries)
    }
}

/// Convert a glob pattern to regex
fn glob_to_regex(pattern: &str) -> Result<regex::Regex> {
    let mut regex_str = String::from("^");

    for ch in pattern.chars() {
        match ch {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '[' => regex_str.push('['),
            ']' => regex_str.push(']'),
            c => {
                if regex::Regex::new(&c.to_string()).is_err() {
                    regex_str.push('\\');
                }
                regex_str.push(c);
            }
        }
    }

    regex_str.push('$');
    regex::Regex::new(&regex_str)
        .or_else(|_| regex::Regex::new(".*"))
        .map_err(|e| Error::InvalidParameter(format!("Invalid pattern: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_real_filesystem_create_and_read() {
        let temp_dir = TempDir::new().unwrap();
        let config = RealFsConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let mut fs = RealFileSystem::new(config).unwrap();

        // Create a file
        let handle = fs
            .create_file(
                "test.txt",
                DesiredAccess::GENERIC_READ | DesiredAccess::GENERIC_WRITE,
                FsFileAttributes::NORMAL,
                ShareAccess::FILE_SHARE_READ,
                CreateDisposition::CREATE,
                CreateOptions::FILE_NON_DIRECTORY_FILE,
            )
            .unwrap();

        // Write data
        let data = b"Hello, World!";
        let written = fs.write_file(&handle, 0, data).unwrap();
        assert_eq!(written, data.len() as u32);

        // Read data back
        let read_data = fs.read_file(&handle, 0, data.len() as u32).unwrap();
        assert_eq!(read_data, data);

        // Close file
        fs.close_file(&handle).unwrap();
    }

    #[test]
    fn test_directory_operations() {
        let temp_dir = TempDir::new().unwrap();
        let config = RealFsConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let mut fs = RealFileSystem::new(config).unwrap();

        // Create directory
        fs.create_directory("subdir").unwrap();

        // List root directory
        let entries = fs.list_directory("").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "subdir");
        assert!(entries[0].is_directory);
    }

    #[test]
    fn test_jail_protection() {
        let temp_dir = TempDir::new().unwrap();
        let config = RealFsConfig {
            root_path: temp_dir.path().to_path_buf(),
            jail: true,
            ..Default::default()
        };

        let fs = RealFileSystem::new(config).unwrap();

        // Try to escape jail
        let result = fs.resolve_path("../../../etc/passwd");
        assert!(result.is_err());

        // Try with absolute path
        let result = fs.resolve_path("/etc/passwd");
        assert!(result.is_ok()); // But it will resolve to root_path/etc/passwd
    }
}
