//! File information structures for Query Directory responses

use crate::error::Result;
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Write;

/// File information classes for QueryDirectory
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileInformationClass {
    FileDirectoryInformation = 0x01,
    FileFullDirectoryInformation = 0x02,
    FileBothDirectoryInformation = 0x03,
    FileBasicInformation = 0x04,
    FileStandardInformation = 0x05,
    FileInternalInformation = 0x06,
    FileEaInformation = 0x07,
    FileAccessInformation = 0x08,
    FileNameInformation = 0x09,
    FileRenameInformation = 0x0A,
    FileLinkInformation = 0x0B,
    FileNamesInformation = 0x0C,
    FileDispositionInformation = 0x0D,
    FilePositionInformation = 0x0E,
    FileFullEaInformation = 0x0F,
    FileModeInformation = 0x10,
    FileAlignmentInformation = 0x11,
    FileAllInformation = 0x12,
    FileAllocationInformation = 0x13,
    FileEndOfFileInformation = 0x14,
    FileAlternateNameInformation = 0x15,
    FileStreamInformation = 0x16,
    FilePipeInformation = 0x17,
    FilePipeLocalInformation = 0x18,
    FilePipeRemoteInformation = 0x19,
    FileMailslotQueryInformation = 0x1A,
    FileMailslotSetInformation = 0x1B,
    FileCompressionInformation = 0x1C,
    FileObjectIdInformation = 0x1D,
    FileIdBothDirectoryInformation = 0x25,
    FileIdFullDirectoryInformation = 0x26,
    FileValidDataLengthInformation = 0x27,
    FileShortNameInformation = 0x28,
}

/// File attributes from MS-FSCC 2.6
#[derive(Debug, Clone, Copy)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    pub const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
    pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x00000002;
    pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x00000004;
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
    pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x00000020;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
    pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x00000100;
    pub const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x00000200;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
    pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x00000800;
    pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x00001000;
    pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x00002000;
    pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x00004000;
}

/// File directory information entry
#[derive(Debug, Clone)]
pub struct FileDirectoryInfo {
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name: String,
}

impl FileDirectoryInfo {
    /// Serialize to bytes for SMB2 response
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // We'll update this with the actual next entry offset
        buffer.write_u32::<LittleEndian>(0)?; // NextEntryOffset (will be updated)
        buffer.write_u32::<LittleEndian>(self.file_index)?;
        buffer.write_u64::<LittleEndian>(self.creation_time)?;
        buffer.write_u64::<LittleEndian>(self.last_access_time)?;
        buffer.write_u64::<LittleEndian>(self.last_write_time)?;
        buffer.write_u64::<LittleEndian>(self.change_time)?;
        buffer.write_u64::<LittleEndian>(self.end_of_file)?;
        buffer.write_u64::<LittleEndian>(self.allocation_size)?;
        buffer.write_u32::<LittleEndian>(self.file_attributes)?;

        // FileNameLength in bytes (UTF-16)
        let file_name_utf16: Vec<u16> = self.file_name.encode_utf16().collect();
        let file_name_len = (file_name_utf16.len() * 2) as u32;
        buffer.write_u32::<LittleEndian>(file_name_len)?;

        // FileName (UTF-16LE)
        for ch in file_name_utf16 {
            buffer.write_u16::<LittleEndian>(ch)?;
        }

        Ok(buffer)
    }
}

/// File ID Both Directory Information (0x25) - most commonly used by smbclient
#[derive(Debug, Clone)]
pub struct FileIdBothDirectoryInfo {
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub ea_size: u32,
    pub short_name: String, // 8.3 format name
    pub file_id: u64,
    pub file_name: String,
}

impl FileIdBothDirectoryInfo {
    /// Create from basic file info
    pub fn new(
        file_name: String,
        is_directory: bool,
        size: u64,
        creation_time: u64,
        modified_time: u64,
    ) -> Self {
        let attributes = if is_directory {
            FileAttributes::FILE_ATTRIBUTE_DIRECTORY
        } else {
            FileAttributes::FILE_ATTRIBUTE_NORMAL
        };

        // Generate a simple short name (8.3 format)
        let short_name = if file_name.len() <= 12 && !file_name.contains(' ') {
            String::new() // Empty if name is already short
        } else {
            // Simple 8.3 conversion
            let name_parts: Vec<&str> = file_name.splitn(2, '.').collect();
            let base = &name_parts[0];
            let ext = if name_parts.len() > 1 {
                name_parts[1]
            } else {
                ""
            };

            let short_base: String = base
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(6)
                .collect::<String>()
                .to_uppercase();

            let short_ext: String = ext
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(3)
                .collect::<String>()
                .to_uppercase();

            if short_ext.is_empty() {
                format!("{}~1", short_base)
            } else {
                format!("{}~1.{}", short_base, short_ext)
            }
        };

        Self {
            file_index: 0,
            creation_time,
            last_access_time: modified_time,
            last_write_time: modified_time,
            change_time: modified_time,
            end_of_file: if is_directory { 0 } else { size },
            allocation_size: if is_directory {
                0
            } else {
                (size + 4095) & !4095
            }, // Round up to 4K
            file_attributes: attributes,
            ea_size: 0,
            short_name,
            // Generate a unique file_id based on the filename hash
            file_id: {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                file_name.hash(&mut hasher);
                hasher.finish()
            },
            file_name,
        }
    }

    /// Serialize to bytes for SMB2 response
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // NextEntryOffset (will be updated if there are more entries)
        buffer.write_u32::<LittleEndian>(0)?;
        buffer.write_u32::<LittleEndian>(self.file_index)?;
        buffer.write_u64::<LittleEndian>(self.creation_time)?;
        buffer.write_u64::<LittleEndian>(self.last_access_time)?;
        buffer.write_u64::<LittleEndian>(self.last_write_time)?;
        buffer.write_u64::<LittleEndian>(self.change_time)?;
        buffer.write_u64::<LittleEndian>(self.end_of_file)?;
        buffer.write_u64::<LittleEndian>(self.allocation_size)?;
        buffer.write_u32::<LittleEndian>(self.file_attributes)?;

        // FileNameLength in bytes (UTF-16)
        let file_name_utf16: Vec<u16> = self.file_name.encode_utf16().collect();
        let file_name_len = (file_name_utf16.len() * 2) as u32;
        buffer.write_u32::<LittleEndian>(file_name_len)?;

        buffer.write_u32::<LittleEndian>(self.ea_size)?;

        // ShortNameLength (1 byte) at offset 68
        let short_utf16: Vec<u16> = if !self.short_name.is_empty() {
            self.short_name.encode_utf16().collect()
        } else {
            Vec::new()
        };
        let short_name_len = (short_utf16.len() * 2).min(24) as u8;
        buffer.write_u8(short_name_len)?;

        // Reserved (1 byte) at offset 69
        buffer.write_u8(0)?;

        // ShortName (24 bytes, but only 22 usable after the 2-byte header) at offset 70
        let mut short_name_field = vec![0u8; 24];
        for (i, ch) in short_utf16.iter().take(11).enumerate() {
            // Max 11 wide chars = 22 bytes
            let offset = i * 2;
            if offset + 1 < 24 {
                short_name_field[offset] = (*ch & 0xFF) as u8;
                short_name_field[offset + 1] = ((*ch >> 8) & 0xFF) as u8;
            }
        }
        buffer.write_all(&short_name_field)?;

        // Reserved2 (2 bytes) at offset 94
        buffer.write_u16::<LittleEndian>(0)?;

        // FileId
        buffer.write_u64::<LittleEndian>(self.file_id)?;

        // FileName (UTF-16LE)
        for ch in file_name_utf16 {
            buffer.write_u16::<LittleEndian>(ch)?;
        }

        Ok(buffer)
    }
}

/// Build a directory listing response buffer
pub fn build_directory_listing(entries: Vec<FileIdBothDirectoryInfo>) -> Result<Vec<u8>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut buffer = Vec::new();
    let mut entry_buffers = Vec::new();

    // Serialize all entries first
    for entry in &entries {
        entry_buffers.push(entry.serialize()?);
    }

    // Now concatenate them with proper NextEntryOffset values
    let total_entries = entry_buffers.len();
    for (i, entry_buf) in entry_buffers.into_iter().enumerate() {
        let mut entry_buf = entry_buf; // Make it mutable

        if i < total_entries - 1 {
            // Calculate the offset to the next entry (8-byte aligned)
            let current_size = entry_buf.len();
            let aligned_size = (current_size + 7) & !7; // Align to 8 bytes
            let next_offset = aligned_size as u32;

            // Update NextEntryOffset in the buffer
            entry_buf[0..4].copy_from_slice(&next_offset.to_le_bytes());

            // Add padding if needed
            while entry_buf.len() < aligned_size {
                entry_buf.push(0);
            }
        }
        // Last entry has NextEntryOffset = 0 (already set)

        buffer.extend_from_slice(&entry_buf);
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{LittleEndian, ReadBytesExt};
    use std::io::Cursor;

    #[test]
    fn test_file_id_both_directory_info_size() {
        // Test that we meet the minimum size requirement for smbclient
        let entry = FileIdBothDirectoryInfo::new(
            "a".to_string(), // Minimal filename
            false,
            0,
            116444736000000000,
            116444736000000000,
        );

        let serialized = entry.serialize().unwrap();

        // smbclient expects at least 105 bytes for each entry (excluding the file name)
        // The fixed structure is:
        // NextEntryOffset (4) + FileIndex (4) + Times (32) + EndOfFile (8) +
        // AllocationSize (8) + FileAttributes (4) + FileNameLength (4) +
        // EaSize (4) + ShortNameLength (1) + Reserved (1) + ShortName (24) +
        // Reserved2 (2) + FileId (8) = 104 bytes
        // Plus at least 1 byte for the filename (but it's UTF-16, so minimum 2)
        let fixed_size = 104; // Fixed structure size without filename
        let filename_size = 2; // "a" in UTF-16
        let expected_min = fixed_size + filename_size;

        println!("Serialized size: {} bytes", serialized.len());
        println!("Expected minimum: {} bytes", expected_min);
        assert!(
            serialized.len() >= 105,
            "Structure must be at least 105 bytes for smbclient compatibility"
        );
    }

    #[test]
    fn test_file_id_both_directory_info_serialize() {
        let entry = FileIdBothDirectoryInfo::new(
            "test.txt".to_string(),
            false,
            1024,
            116444736000000000,
            116444736000000000,
        );

        let serialized = entry.serialize().unwrap();

        // Check basic structure
        assert!(serialized.len() > 94); // Minimum size for the structure

        // Check NextEntryOffset is 0 (first 4 bytes)
        assert_eq!(&serialized[0..4], &[0, 0, 0, 0]);

        // Check file attributes at offset 56 (should be FILE_ATTRIBUTE_NORMAL = 0x80)
        // Structure: NextEntryOffset(4) + FileIndex(4) + Times(32) + EndOfFile(8) + AllocationSize(8) = 56
        let mut cursor = Cursor::new(&serialized[56..60]);
        let attrs = cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(attrs, 0x80);

        // Verify the structure is at least 106 bytes (104 fixed + 2 for minimal filename)
        assert!(serialized.len() >= 106);
    }

    #[test]
    fn test_directory_listing_single_entry() {
        let mut entries = Vec::new();
        entries.push(FileIdBothDirectoryInfo::new(
            ".".to_string(),
            true,
            0,
            116444736000000000,
            116444736000000000,
        ));

        let buffer = build_directory_listing(entries).unwrap();

        // Check that NextEntryOffset is 0 for single entry
        let mut cursor = Cursor::new(&buffer);
        let next_offset = cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(next_offset, 0);
    }

    #[test]
    fn test_directory_listing_multiple_entries() {
        let mut entries = Vec::new();

        entries.push(FileIdBothDirectoryInfo::new(
            ".".to_string(),
            true,
            0,
            116444736000000000,
            116444736000000000,
        ));

        entries.push(FileIdBothDirectoryInfo::new(
            "..".to_string(),
            true,
            0,
            116444736000000000,
            116444736000000000,
        ));

        entries.push(FileIdBothDirectoryInfo::new(
            "test.txt".to_string(),
            false,
            1024,
            116444736000000000,
            116444736000000000,
        ));

        let buffer = build_directory_listing(entries).unwrap();

        // Check first entry's NextEntryOffset is non-zero
        let mut cursor = Cursor::new(&buffer);
        let first_next_offset = cursor.read_u32::<LittleEndian>().unwrap();
        assert!(first_next_offset > 0);
        assert_eq!(first_next_offset % 8, 0); // Should be 8-byte aligned

        // Check second entry's NextEntryOffset
        let second_offset = first_next_offset as usize;
        let mut cursor = Cursor::new(&buffer[second_offset..]);
        let second_next_offset = cursor.read_u32::<LittleEndian>().unwrap();
        assert!(second_next_offset > 0);
        assert_eq!(second_next_offset % 8, 0); // Should be 8-byte aligned

        // Check last entry's NextEntryOffset is 0
        let third_offset = second_offset + second_next_offset as usize;
        let mut cursor = Cursor::new(&buffer[third_offset..]);
        let third_next_offset = cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(third_next_offset, 0);
    }

    #[test]
    fn test_directory_listing_alignment() {
        let mut entries = Vec::new();

        // Create entries with different name lengths to test alignment
        entries.push(FileIdBothDirectoryInfo::new(
            "a".to_string(),
            false,
            0,
            116444736000000000,
            116444736000000000,
        ));

        entries.push(FileIdBothDirectoryInfo::new(
            "longer_name.txt".to_string(),
            false,
            0,
            116444736000000000,
            116444736000000000,
        ));

        let buffer = build_directory_listing(entries).unwrap();

        // Check that first entry is padded to 8-byte alignment
        let mut cursor = Cursor::new(&buffer);
        let first_next_offset = cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(first_next_offset % 8, 0);

        // Verify padding bytes are zeros
        // Fixed structure is 104 bytes (including Reserved2 field), then comes the file name in UTF-16
        let first_entry_actual_size = 104 + 2; // Fixed size + "a" in UTF-16 (2 bytes)

        for i in first_entry_actual_size..first_next_offset as usize {
            assert_eq!(buffer[i], 0, "Padding byte at {} should be 0", i);
        }
    }
}
