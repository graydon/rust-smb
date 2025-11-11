//! NDR (Network Data Representation) encoding/decoding for DCE/RPC
//! This implements the actual wire format for RPC data

use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{Cursor, Read};

/// NDR format label
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatLabel {
    pub integer_representation: IntegerRepresentation,
    pub character_representation: CharacterRepresentation,
    pub floating_point_representation: FloatingPointRepresentation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntegerRepresentation {
    BigEndian = 0,
    LittleEndian = 1,
}

impl TryFrom<u8> for IntegerRepresentation {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(IntegerRepresentation::BigEndian),
            1 => Ok(IntegerRepresentation::LittleEndian),
            other => Err(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CharacterRepresentation {
    ASCII = 0,
    EBCDIC = 1,
}

impl TryFrom<u8> for CharacterRepresentation {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(CharacterRepresentation::ASCII),
            1 => Ok(CharacterRepresentation::EBCDIC),
            other => Err(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FloatingPointRepresentation {
    IEEE = 0,
    VAX = 1,
    Cray = 2,
    IBM = 3,
}

impl TryFrom<u8> for FloatingPointRepresentation {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(FloatingPointRepresentation::IEEE),
            1 => Ok(FloatingPointRepresentation::VAX),
            2 => Ok(FloatingPointRepresentation::Cray),
            3 => Ok(FloatingPointRepresentation::IBM),
            other => Err(other),
        }
    }
}

impl Default for FormatLabel {
    fn default() -> Self {
        Self {
            integer_representation: IntegerRepresentation::LittleEndian,
            character_representation: CharacterRepresentation::ASCII,
            floating_point_representation: FloatingPointRepresentation::IEEE,
        }
    }
}

impl FormatLabel {
    pub fn to_bytes(&self) -> [u8; 4] {
        [
            (self.integer_representation as u8) << 4 | self.character_representation as u8,
            self.floating_point_representation as u8,
            0, // Reserved
            0, // Reserved
        ]
    }

    pub fn from_bytes(bytes: &[u8; 4]) -> Self {
        Self {
            integer_representation: IntegerRepresentation::try_from(bytes[0] >> 4)
                .unwrap_or(IntegerRepresentation::LittleEndian),
            character_representation: CharacterRepresentation::try_from(bytes[0] & 0x0F)
                .unwrap_or(CharacterRepresentation::ASCII),
            floating_point_representation: FloatingPointRepresentation::try_from(bytes[1])
                .unwrap_or(FloatingPointRepresentation::IEEE),
        }
    }
}

/// NDR encoder
pub struct NdrEncoder {
    buffer: Vec<u8>,
    _format: FormatLabel,
}

impl NdrEncoder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            _format: FormatLabel::default(),
        }
    }

    pub fn with_format(format: FormatLabel) -> Self {
        Self {
            buffer: Vec::new(),
            _format: format,
        }
    }

    /// Get the encoded bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Encode alignment padding
    fn align(&mut self, alignment: usize) {
        let offset = self.buffer.len();
        let padding = (alignment - (offset % alignment)) % alignment;
        for _ in 0..padding {
            self.buffer.push(0);
        }
    }

    /// Encode a u8
    pub fn encode_u8(&mut self, value: u8) -> Result<()> {
        self.buffer.push(value);
        Ok(())
    }

    /// Encode a u16
    pub fn encode_u16(&mut self, value: u16) -> Result<()> {
        self.align(2);
        self.buffer
            .write_u16::<LittleEndian>(value)
            .map_err(|e| Error::Io(e))
    }

    /// Encode a u32
    pub fn encode_u32(&mut self, value: u32) -> Result<()> {
        self.align(4);
        self.buffer
            .write_u32::<LittleEndian>(value)
            .map_err(|e| Error::Io(e))
    }

    /// Encode a u64
    pub fn encode_u64(&mut self, value: u64) -> Result<()> {
        self.align(8);
        self.buffer
            .write_u64::<LittleEndian>(value)
            .map_err(|e| Error::Io(e))
    }

    /// Encode a conformant array (size at beginning)
    pub fn encode_conformant_array<T, F>(&mut self, array: &[T], encode_fn: F) -> Result<()>
    where
        F: Fn(&mut Self, &T) -> Result<()>,
    {
        self.encode_u32(array.len() as u32)?;
        for item in array {
            encode_fn(self, item)?;
        }
        Ok(())
    }

    /// Encode a varying array (offset and actual count)
    pub fn encode_varying_array<T, F>(&mut self, array: &[T], encode_fn: F) -> Result<()>
    where
        F: Fn(&mut Self, &T) -> Result<()>,
    {
        self.encode_u32(0)?; // Offset (usually 0)
        self.encode_u32(array.len() as u32)?; // Actual count
        for item in array {
            encode_fn(self, item)?;
        }
        Ok(())
    }

    /// Encode a conformant varying array
    pub fn encode_conformant_varying_array<T, F>(&mut self, array: &[T], encode_fn: F) -> Result<()>
    where
        F: Fn(&mut Self, &T) -> Result<()>,
    {
        self.encode_u32(array.len() as u32)?; // Max count
        self.encode_u32(0)?; // Offset
        self.encode_u32(array.len() as u32)?; // Actual count
        for item in array {
            encode_fn(self, item)?;
        }
        Ok(())
    }

    /// Encode a string (conformant varying array of u16)
    pub fn encode_string(&mut self, string: &str) -> Result<()> {
        let utf16: Vec<u16> = string.encode_utf16().chain(std::iter::once(0)).collect();
        self.encode_conformant_varying_array(&utf16, |enc, &ch| enc.encode_u16(ch))
    }

    /// Encode a unique pointer (can be null)
    pub fn encode_unique_ptr<T, F>(&mut self, value: Option<&T>, encode_fn: F) -> Result<()>
    where
        F: Fn(&mut Self, &T) -> Result<()>,
    {
        if let Some(val) = value {
            self.encode_u32(0x00020000)?; // Non-null referent ID
            encode_fn(self, val)?;
        } else {
            self.encode_u32(0)?; // Null pointer
        }
        Ok(())
    }

    /// Encode bytes
    pub fn encode_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Encode UUID
    pub fn encode_uuid(&mut self, uuid: &uuid::Uuid) -> Result<()> {
        let bytes = uuid.as_bytes();
        // UUID layout in NDR: time_low, time_mid, time_hi_and_version, clock_seq, node
        let mut cursor = Cursor::new(&bytes[0..4]);
        let time_low = cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| Error::Io(e))?;
        self.encode_u32(time_low)?;

        let mut cursor = Cursor::new(&bytes[4..6]);
        let time_mid = cursor
            .read_u16::<LittleEndian>()
            .map_err(|e| Error::Io(e))?;
        self.encode_u16(time_mid)?;

        let mut cursor = Cursor::new(&bytes[6..8]);
        let time_hi_and_version = cursor
            .read_u16::<LittleEndian>()
            .map_err(|e| Error::Io(e))?;
        self.encode_u16(time_hi_and_version)?;

        self.encode_bytes(&bytes[8..16])?;
        Ok(())
    }
}

/// NDR decoder
pub struct NdrDecoder<'a> {
    cursor: Cursor<&'a [u8]>,
    _format: FormatLabel,
}

impl<'a> NdrDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
            _format: FormatLabel::default(),
        }
    }

    pub fn with_format(data: &'a [u8], format: FormatLabel) -> Self {
        Self {
            cursor: Cursor::new(data),
            _format: format,
        }
    }

    /// Get current position
    pub fn position(&self) -> u64 {
        self.cursor.position()
    }

    /// Skip alignment padding
    pub fn align(&mut self, alignment: u64) -> Result<()> {
        let pos = self.cursor.position();
        let padding = (alignment - (pos % alignment)) % alignment;
        self.cursor.set_position(pos + padding);
        Ok(())
    }

    /// Decode a u8
    pub fn decode_u8(&mut self) -> Result<u8> {
        self.cursor.read_u8().map_err(|e| Error::Io(e))
    }

    /// Decode a u16
    pub fn decode_u16(&mut self) -> Result<u16> {
        self.align(2)?;
        self.cursor
            .read_u16::<LittleEndian>()
            .map_err(|e| Error::Io(e))
    }

    /// Decode a u32
    pub fn decode_u32(&mut self) -> Result<u32> {
        self.align(4)?;
        self.cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| Error::Io(e))
    }

    /// Decode a u64
    pub fn decode_u64(&mut self) -> Result<u64> {
        self.align(8)?;
        self.cursor
            .read_u64::<LittleEndian>()
            .map_err(|e| Error::Io(e))
    }

    /// Decode a conformant array
    pub fn decode_conformant_array<T, F>(&mut self, decode_fn: F) -> Result<Vec<T>>
    where
        F: Fn(&mut Self) -> Result<T>,
    {
        let count = self.decode_u32()? as usize;
        let mut array = Vec::with_capacity(count);
        for _ in 0..count {
            array.push(decode_fn(self)?);
        }
        Ok(array)
    }

    /// Decode a varying array
    pub fn decode_varying_array<T, F>(&mut self, decode_fn: F) -> Result<Vec<T>>
    where
        F: Fn(&mut Self) -> Result<T>,
    {
        let _offset = self.decode_u32()?;
        let count = self.decode_u32()? as usize;
        let mut array = Vec::with_capacity(count);
        for _ in 0..count {
            array.push(decode_fn(self)?);
        }
        Ok(array)
    }

    /// Decode a conformant varying array
    pub fn decode_conformant_varying_array<T, F>(&mut self, decode_fn: F) -> Result<Vec<T>>
    where
        F: Fn(&mut Self) -> Result<T>,
    {
        let _max_count = self.decode_u32()?;
        let _offset = self.decode_u32()?;
        let actual_count = self.decode_u32()? as usize;
        let mut array = Vec::with_capacity(actual_count);
        for _ in 0..actual_count {
            array.push(decode_fn(self)?);
        }
        Ok(array)
    }

    /// Decode a string
    pub fn decode_string(&mut self) -> Result<String> {
        let utf16 = self.decode_conformant_varying_array(|dec| dec.decode_u16())?;
        // Remove null terminator if present
        let len = utf16.iter().position(|&c| c == 0).unwrap_or(utf16.len());
        String::from_utf16(&utf16[..len])
            .map_err(|e| Error::ParseError(format!("Invalid UTF-16: {}", e)))
    }

    /// Decode a unique pointer
    pub fn decode_unique_ptr<T, F>(&mut self, decode_fn: F) -> Result<Option<T>>
    where
        F: Fn(&mut Self) -> Result<T>,
    {
        let referent_id = self.decode_u32()?;
        if referent_id == 0 {
            Ok(None)
        } else {
            Ok(Some(decode_fn(self)?))
        }
    }

    /// Get remaining bytes count
    pub fn remaining(&self) -> usize {
        let pos = self.cursor.position() as usize;
        let data = self.cursor.get_ref();
        if pos < data.len() {
            data.len() - pos
        } else {
            0
        }
    }

    /// Peek at bytes without advancing the cursor
    pub fn peek_bytes(&self, count: usize) -> Result<Vec<u8>> {
        let pos = self.cursor.position() as usize;
        let data = self.cursor.get_ref();
        let available = self.remaining();
        let to_read = std::cmp::min(count, available);

        if to_read == 0 {
            return Ok(Vec::new());
        }

        Ok(data[pos..pos + to_read].to_vec())
    }

    /// Decode bytes
    pub fn decode_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        self.cursor
            .read_exact(&mut bytes)
            .map_err(|e| Error::Io(e))?;
        Ok(bytes)
    }

    /// Decode UUID
    pub fn decode_uuid(&mut self) -> Result<uuid::Uuid> {
        let time_low = self.decode_u32()?;
        let time_mid = self.decode_u16()?;
        let time_hi_and_version = self.decode_u16()?;
        let clock_seq_and_node = self.decode_bytes(8)?;

        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&time_low.to_le_bytes());
        bytes[4..6].copy_from_slice(&time_mid.to_le_bytes());
        bytes[6..8].copy_from_slice(&time_hi_and_version.to_le_bytes());
        bytes[8..16].copy_from_slice(&clock_seq_and_node);

        Ok(uuid::Uuid::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndr_basic_types() {
        let mut encoder = NdrEncoder::new();
        encoder.encode_u8(0x42).unwrap();
        encoder.encode_u16(0x1234).unwrap();
        encoder.encode_u32(0xDEADBEEF).unwrap();
        encoder.encode_u64(0x123456789ABCDEF0).unwrap();

        let bytes = encoder.into_bytes();
        let mut decoder = NdrDecoder::new(&bytes);

        assert_eq!(decoder.decode_u8().unwrap(), 0x42);
        assert_eq!(decoder.decode_u16().unwrap(), 0x1234);
        assert_eq!(decoder.decode_u32().unwrap(), 0xDEADBEEF);
        assert_eq!(decoder.decode_u64().unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_ndr_string() {
        let mut encoder = NdrEncoder::new();
        encoder.encode_string("Hello, RPC!").unwrap();

        let bytes = encoder.into_bytes();
        let mut decoder = NdrDecoder::new(&bytes);

        assert_eq!(decoder.decode_string().unwrap(), "Hello, RPC!");
    }

    #[test]
    fn test_ndr_array() {
        let mut encoder = NdrEncoder::new();
        let data = vec![1u32, 2, 3, 4, 5];
        encoder
            .encode_conformant_array(&data, |enc, &val| enc.encode_u32(val))
            .unwrap();

        let bytes = encoder.into_bytes();
        let mut decoder = NdrDecoder::new(&bytes);

        let decoded = decoder
            .decode_conformant_array(|dec| dec.decode_u32())
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_ndr_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let mut encoder = NdrEncoder::new();
        encoder.encode_uuid(&uuid).unwrap();

        let bytes = encoder.into_bytes();
        let mut decoder = NdrDecoder::new(&bytes);

        let decoded = decoder.decode_uuid().unwrap();
        assert_eq!(decoded, uuid);
    }
}
