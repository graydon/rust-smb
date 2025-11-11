//! Real filesystem backend implementation

use crate::error::{Error, Result};
use crate::server::filesystem::{FileInfo, FileSystem};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{debug, error};

/// Extended file metadata for internal use
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub file_name: String,
    pub is_directory: bool,
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub attributes: u32,
}

/// A real filesystem backend that accesses actual files on disk
pub struct RealFileSystem {
    /// Root directory for the filesystem
    root_path: PathBuf,
    /// Open file handles
    open_files: Arc<RwLock<HashMap<String, tokio::fs::File>>>,
}

impl RealFileSystem {
    /// Create a new real filesystem backend
    pub fn new<P: AsRef<Path>>(root_path: P) -> Self {
        Self {
            root_path: root_path.as_ref().to_path_buf(),
            open_files: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Convert SMB path to filesystem path
    fn to_fs_path(&self, smb_path: &str) -> PathBuf {
        // Remove leading backslashes and convert to forward slashes
        let clean_path = smb_path
            .trim_start_matches('\\')
            .trim_start_matches('/')
            .replace('\\', "/");

        // Join with root path
        self.root_path.join(clean_path)
    }

    /// Normalize SMB path for use as a key
    fn normalize_path(path: &str) -> String {
        path.replace('\\', "/").trim_start_matches('/').to_string()
    }

    /// Internal helper to get file metadata
    pub async fn get_metadata(&self, path: &str) -> Result<FileMetadata> {
        let fs_path = self.to_fs_path(path);
        debug!("Getting metadata: SMB path={}, FS path={:?}", path, fs_path);

        // Get file metadata
        let metadata = fs::metadata(&fs_path).await.map_err(|e| {
            error!("Failed to get metadata for {:?}: {}", fs_path, e);
            Error::Io(e)
        })?;

        // Convert to our metadata format
        let file_metadata = FileMetadata {
            file_name: path.to_string(),
            is_directory: metadata.is_dir(),
            size: metadata.len(),
            created: metadata
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            modified: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            attributes: if metadata.is_dir() { 0x10 } else { 0x80 }, // Directory or Normal
        };

        Ok(file_metadata)
    }

    /// List directory and return detailed metadata
    pub async fn list_directory(&self, path: &str) -> Result<Vec<FileMetadata>> {
        let fs_path = self.to_fs_path(path);
        debug!(
            "Listing directory: SMB path={}, FS path={:?}",
            path, fs_path
        );

        let mut entries = Vec::new();
        let mut dir = fs::read_dir(&fs_path).await.map_err(|e| {
            error!("Failed to read directory {:?}: {}", fs_path, e);
            Error::Io(e)
        })?;

        while let Some(entry) = dir.next_entry().await.map_err(|e| {
            error!("Failed to read directory entry: {}", e);
            Error::Io(e)
        })? {
            let metadata = entry.metadata().await.map_err(|e| {
                error!("Failed to get entry metadata: {}", e);
                Error::Io(e)
            })?;

            let file_name = entry.file_name().to_string_lossy().to_string();

            entries.push(FileMetadata {
                file_name,
                is_directory: metadata.is_dir(),
                size: metadata.len(),
                created: metadata
                    .created()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                modified: metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                attributes: if metadata.is_dir() { 0x10 } else { 0x80 },
            });
        }

        debug!("Listed {} entries in directory {}", entries.len(), path);
        Ok(entries)
    }
}

#[async_trait]
impl FileSystem for RealFileSystem {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn read(&self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        let normalized_path = Self::normalize_path(path);
        let mut open_files = self.open_files.write().await;

        if let Some(file) = open_files.get_mut(&normalized_path) {
            // Seek to the specified offset
            file.seek(tokio::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| {
                    error!("Failed to seek in file {}: {}", path, e);
                    Error::Io(e)
                })?;

            // Read the requested amount of data
            let mut buffer = vec![0u8; length];
            let bytes_read = file.read(&mut buffer).await.map_err(|e| {
                error!("Failed to read from file {}: {}", path, e);
                Error::Io(e)
            })?;

            buffer.truncate(bytes_read);
            debug!(
                "Read {} bytes from {} at offset {}",
                bytes_read, path, offset
            );
            Ok(buffer)
        } else {
            // File not open, try to open it
            drop(open_files); // Release the lock

            let fs_path = self.to_fs_path(path);
            let mut file = fs::File::open(&fs_path).await.map_err(|e| {
                error!("Failed to open file {:?}: {}", fs_path, e);
                Error::Io(e)
            })?;

            // Seek and read
            file.seek(tokio::io::SeekFrom::Start(offset))
                .await
                .map_err(Error::Io)?;
            let mut buffer = vec![0u8; length];
            let bytes_read = file.read(&mut buffer).await.map_err(Error::Io)?;
            buffer.truncate(bytes_read);

            // Store the open file
            let mut open_files = self.open_files.write().await;
            open_files.insert(normalized_path, file);

            Ok(buffer)
        }
    }

    async fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        let normalized_path = Self::normalize_path(path);
        let mut open_files = self.open_files.write().await;

        if let Some(file) = open_files.get_mut(&normalized_path) {
            // Seek to the specified offset
            file.seek(tokio::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| {
                    error!("Failed to seek in file {}: {}", path, e);
                    Error::Io(e)
                })?;

            // Write the data
            let bytes_written = file.write(data).await.map_err(|e| {
                error!("Failed to write to file {}: {}", path, e);
                Error::Io(e)
            })?;

            // Flush to ensure data is written
            file.flush().await.map_err(|e| {
                error!("Failed to flush file {}: {}", path, e);
                Error::Io(e)
            })?;

            debug!(
                "Wrote {} bytes to {} at offset {}",
                bytes_written, path, offset
            );
            Ok(bytes_written)
        } else {
            // File not open, open it for writing
            drop(open_files); // Release the lock

            let fs_path = self.to_fs_path(path);
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&fs_path)
                .await
                .map_err(|e| {
                    error!("Failed to open file for writing {:?}: {}", fs_path, e);
                    Error::Io(e)
                })?;

            file.seek(tokio::io::SeekFrom::Start(offset))
                .await
                .map_err(Error::Io)?;
            let bytes_written = file.write(data).await.map_err(Error::Io)?;
            file.flush().await.map_err(Error::Io)?;

            let mut open_files = self.open_files.write().await;
            open_files.insert(normalized_path, file);

            Ok(bytes_written)
        }
    }

    async fn stat(&self, path: &str) -> Result<FileInfo> {
        let fs_path = self.to_fs_path(path);
        let metadata = fs::metadata(&fs_path).await.map_err(|e| {
            error!("Failed to get metadata for {:?}: {}", fs_path, e);
            Error::Io(e)
        })?;

        Ok(FileInfo {
            size: metadata.len(),
            is_directory: metadata.is_dir(),
            created: metadata
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            modified: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            accessed: metadata
                .accessed()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let fs_path = self.to_fs_path(path);
        let mut entries = Vec::new();
        let mut dir = fs::read_dir(&fs_path).await.map_err(|e| {
            error!("Failed to read directory {:?}: {}", fs_path, e);
            Error::Io(e)
        })?;

        while let Some(entry) = dir.next_entry().await.map_err(|e| {
            error!("Failed to read directory entry: {}", e);
            Error::Io(e)
        })? {
            let file_name = entry.file_name().to_string_lossy().to_string();
            entries.push(file_name);
        }

        Ok(entries)
    }

    async fn create(&self, path: &str, is_directory: bool) -> Result<()> {
        let fs_path = self.to_fs_path(path);
        debug!(
            "Creating {}: SMB path={}, FS path={:?}",
            if is_directory { "directory" } else { "file" },
            path,
            fs_path
        );

        if is_directory {
            // Create directory
            fs::create_dir_all(&fs_path).await.map_err(|e| {
                error!("Failed to create directory {:?}: {}", fs_path, e);
                Error::Io(e)
            })?;
        } else {
            // Ensure parent directory exists
            if let Some(parent) = fs_path.parent() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    error!("Failed to create parent directory {:?}: {}", parent, e);
                    Error::Io(e)
                })?;
            }

            // Create file (don't keep it open as it's write-only)
            fs::File::create(&fs_path).await.map_err(|e| {
                error!("Failed to create file {:?}: {}", fs_path, e);
                Error::Io(e)
            })?;
        }

        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let fs_path = self.to_fs_path(path);
        let normalized_path = Self::normalize_path(path);

        // Close the file if it's open
        {
            let mut open_files = self.open_files.write().await;
            open_files.remove(&normalized_path);
        }

        // Check if it's a file or directory
        let metadata = fs::metadata(&fs_path).await.map_err(|e| {
            error!("Failed to get metadata for deletion {:?}: {}", fs_path, e);
            Error::Io(e)
        })?;

        if metadata.is_dir() {
            // Try to remove as empty directory first (will fail if not empty)
            fs::remove_dir(&fs_path).await.map_err(|e| {
                error!("Failed to delete directory {:?}: {}", fs_path, e);
                Error::Io(e)
            })?;
            debug!("Deleted directory: {:?}", fs_path);
        } else {
            fs::remove_file(&fs_path).await.map_err(|e| {
                error!("Failed to delete file {:?}: {}", fs_path, e);
                Error::Io(e)
            })?;
            debug!("Deleted file: {:?}", fs_path);
        }

        Ok(())
    }

    async fn rename(&self, old_path: &str, new_path: &str, replace_if_exists: bool) -> Result<()> {
        let old_fs_path = self.to_fs_path(old_path);
        let new_fs_path = self.to_fs_path(new_path);
        let old_normalized = Self::normalize_path(old_path);
        let _new_normalized = Self::normalize_path(new_path);

        debug!(
            "Renaming: {} -> {} (replace={})",
            old_path, new_path, replace_if_exists
        );

        // Check if source exists
        if !old_fs_path.exists() {
            return Err(Error::FileNotFound(old_path.to_string()));
        }

        // Check if destination exists
        if new_fs_path.exists() && !replace_if_exists {
            return Err(Error::FileExists(new_path.to_string()));
        }

        // Close old file if open
        {
            let mut open_files = self.open_files.write().await;
            if let Some(file) = open_files.remove(&old_normalized) {
                drop(file); // Close the file
            }
        }

        // Rename the file/directory
        fs::rename(&old_fs_path, &new_fs_path).await.map_err(|e| {
            error!(
                "Failed to rename {:?} to {:?}: {}",
                old_fs_path, new_fs_path, e
            );
            Error::Io(e)
        })?;

        debug!("Renamed: {:?} -> {:?}", old_fs_path, new_fs_path);
        Ok(())
    }

    async fn truncate(&self, path: &str, size: u64) -> Result<()> {
        let fs_path = self.to_fs_path(path);
        let normalized_path = Self::normalize_path(path);

        debug!("Truncating {} to {} bytes", path, size);

        // Check if file is already open
        let mut open_files = self.open_files.write().await;

        if let Some(file) = open_files.get_mut(&normalized_path) {
            // File is open, truncate it
            file.set_len(size).await.map_err(|e| {
                error!("Failed to truncate open file {:?}: {}", fs_path, e);
                Error::Io(e)
            })?;
        } else {
            // File not open, open it temporarily to truncate
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&fs_path)
                .await
                .map_err(|e| {
                    error!("Failed to open file for truncation {:?}: {}", fs_path, e);
                    Error::Io(e)
                })?;

            file.set_len(size).await.map_err(|e| {
                error!("Failed to truncate file {:?}: {}", fs_path, e);
                Error::Io(e)
            })?;
        }

        debug!("Truncated {} to {} bytes", path, size);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_real_filesystem_create_and_read() {
        let temp_dir = TempDir::new().unwrap();
        let fs = RealFileSystem::new(temp_dir.path());

        // Create a file
        fs.create("test.txt", false).await.unwrap();

        // Write some data
        let data = b"Hello, SMB!";
        let written = fs.write("test.txt", 0, data).await.unwrap();
        assert_eq!(written, data.len());

        // Read it back
        let read_data = fs.read("test.txt", 0, data.len()).await.unwrap();
        assert_eq!(read_data, data);
    }

    #[tokio::test]
    async fn test_real_filesystem_directory_operations() {
        let temp_dir = TempDir::new().unwrap();
        let fs = RealFileSystem::new(temp_dir.path());

        // Create a directory
        fs.create("test_dir", true).await.unwrap();

        // Create a file in the directory
        fs.create("test_dir/file.txt", false).await.unwrap();

        // List the directory
        let entries = fs.list("test_dir").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "file.txt");
    }

    #[tokio::test]
    async fn test_real_filesystem_delete() {
        let temp_dir = TempDir::new().unwrap();
        let fs = RealFileSystem::new(temp_dir.path());

        // Create and delete a file
        fs.create("test.txt", false).await.unwrap();
        fs.delete("test.txt").await.unwrap();

        // Verify it's gone
        assert!(fs.stat("test.txt").await.is_err());
    }
}
