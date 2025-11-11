//! Filesystem abstraction for SMB server

use crate::error::Result;
use async_trait::async_trait;
use chrono;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Filesystem trait for SMB server
#[async_trait]
pub trait FileSystem: Send + Sync {
    /// Get the concrete type as Any for downcasting
    fn as_any(&self) -> &dyn Any;

    /// Read data from a file
    async fn read(&self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>>;

    /// Write data to a file
    async fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<usize>;

    /// Get file metadata
    async fn stat(&self, path: &str) -> Result<FileInfo>;

    /// List directory contents
    async fn list(&self, path: &str) -> Result<Vec<String>>;

    /// Create a file or directory
    async fn create(&self, path: &str, is_directory: bool) -> Result<()>;

    /// Delete a file or directory
    async fn delete(&self, path: &str) -> Result<()>;

    /// Rename a file or directory
    async fn rename(&self, old_path: &str, new_path: &str, replace_if_exists: bool) -> Result<()>;

    /// Truncate a file to the specified size
    async fn truncate(&self, path: &str, size: u64) -> Result<()>;
}

/// File information
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub size: u64,
    pub is_directory: bool,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
}

/// In-memory filesystem for testing
pub struct MemoryFileSystem {
    files: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    metadata: Arc<RwLock<HashMap<String, FileInfo>>>,
}

impl MemoryFileSystem {
    /// Create a new in-memory filesystem
    pub fn new() -> Self {
        let mut files = HashMap::new();
        let mut metadata = HashMap::new();

        // Add some default files for testing
        files.insert("\\test.txt".to_string(), b"Hello, SMB!".to_vec());
        metadata.insert(
            "\\test.txt".to_string(),
            FileInfo {
                size: 11,
                is_directory: false,
                created: 0,
                modified: 0,
                accessed: 0,
            },
        );

        // Add root directory
        metadata.insert(
            "\\".to_string(),
            FileInfo {
                size: 0,
                is_directory: true,
                created: 0,
                modified: 0,
                accessed: 0,
            },
        );

        Self {
            files: Arc::new(RwLock::new(files)),
            metadata: Arc::new(RwLock::new(metadata)),
        }
    }

    /// Normalize path (ensure it starts with backslash)
    fn normalize_path(path: &str) -> String {
        if path.starts_with('\\') {
            path.to_string()
        } else {
            format!("\\{}", path)
        }
    }
}

#[async_trait]
impl FileSystem for MemoryFileSystem {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn read(&self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        let path = Self::normalize_path(path);
        let files = self.files.read().await;

        if let Some(data) = files.get(&path) {
            let start = offset as usize;
            let end = (start + length).min(data.len());

            if start >= data.len() {
                Ok(Vec::new())
            } else {
                Ok(data[start..end].to_vec())
            }
        } else {
            Ok(Vec::new())
        }
    }

    async fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        let path = Self::normalize_path(path);
        let mut files = self.files.write().await;
        let mut metadata = self.metadata.write().await;

        let file_data = files.entry(path.clone()).or_insert_with(Vec::new);

        // Extend file if necessary
        let required_len = offset as usize + data.len();
        if file_data.len() < required_len {
            file_data.resize(required_len, 0);
        }

        // Write data
        let start = offset as usize;
        file_data[start..start + data.len()].copy_from_slice(data);

        // Update metadata
        metadata
            .entry(path)
            .and_modify(|info| {
                info.size = file_data.len() as u64;
                info.modified = chrono::Utc::now().timestamp() as u64;
            })
            .or_insert(FileInfo {
                size: file_data.len() as u64,
                is_directory: false,
                created: chrono::Utc::now().timestamp() as u64,
                modified: chrono::Utc::now().timestamp() as u64,
                accessed: chrono::Utc::now().timestamp() as u64,
            });

        Ok(data.len())
    }

    async fn stat(&self, path: &str) -> Result<FileInfo> {
        let path = Self::normalize_path(path);
        let metadata = self.metadata.read().await;

        metadata
            .get(&path)
            .cloned()
            .ok_or_else(|| crate::error::Error::FileNotFound(path))
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let path = Self::normalize_path(path);
        let metadata = self.metadata.read().await;

        let mut results = Vec::new();
        let prefix = if path == "\\" {
            "\\".to_string()
        } else {
            format!("{}\\", path)
        };

        for key in metadata.keys() {
            if key != &path && key.starts_with(&prefix) {
                // Get relative path
                let relative = &key[prefix.len()..];
                // Only include direct children (no additional backslashes)
                if !relative.contains('\\') {
                    results.push(relative.to_string());
                }
            }
        }

        Ok(results)
    }

    async fn create(&self, path: &str, is_directory: bool) -> Result<()> {
        let path = Self::normalize_path(path);
        let mut metadata = self.metadata.write().await;

        if !is_directory {
            let mut files = self.files.write().await;
            files.insert(path.clone(), Vec::new());
        }

        metadata.insert(
            path,
            FileInfo {
                size: 0,
                is_directory,
                created: chrono::Utc::now().timestamp() as u64,
                modified: chrono::Utc::now().timestamp() as u64,
                accessed: chrono::Utc::now().timestamp() as u64,
            },
        );

        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let path = Self::normalize_path(path);
        let mut files = self.files.write().await;
        let mut metadata = self.metadata.write().await;

        files.remove(&path);
        metadata.remove(&path);

        Ok(())
    }

    async fn rename(&self, old_path: &str, new_path: &str, replace_if_exists: bool) -> Result<()> {
        let old_path = Self::normalize_path(old_path);
        let new_path = Self::normalize_path(new_path);

        let mut files = self.files.write().await;
        let mut metadata = self.metadata.write().await;

        // Check if source exists
        if !metadata.contains_key(&old_path) {
            return Err(crate::error::Error::FileNotFound(old_path));
        }

        // Check if destination exists
        if metadata.contains_key(&new_path) && !replace_if_exists {
            return Err(crate::error::Error::FileExists(new_path));
        }

        // Move the file data if it exists
        if let Some(data) = files.remove(&old_path) {
            files.insert(new_path.clone(), data);
        }

        // Move the metadata
        if let Some(info) = metadata.remove(&old_path) {
            metadata.insert(new_path, info);
        }

        Ok(())
    }

    async fn truncate(&self, path: &str, size: u64) -> Result<()> {
        let path = Self::normalize_path(path);
        let mut files = self.files.write().await;
        let mut metadata = self.metadata.write().await;

        // Get or create the file
        let file_data = files.entry(path.clone()).or_insert_with(Vec::new);

        // Resize the file
        file_data.resize(size as usize, 0);

        // Update metadata
        metadata
            .entry(path)
            .and_modify(|info| {
                info.size = size;
                info.modified = chrono::Utc::now().timestamp() as u64;
            })
            .or_insert(FileInfo {
                size,
                is_directory: false,
                created: chrono::Utc::now().timestamp() as u64,
                modified: chrono::Utc::now().timestamp() as u64,
                accessed: chrono::Utc::now().timestamp() as u64,
            });

        Ok(())
    }
}
