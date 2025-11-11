//! DCE/RPC packet structures and serialization

use crate::dcerpc::{
    AuthLevel, AuthType, PacketFlags, PacketType, RpcError, RpcInterface, DCERPC_VERSION_MAJOR,
    DCERPC_VERSION_MINOR,
};
use crate::error::{Error, Result};
// use crate::dcerpc::ndr::{NdrEncoder, NdrDecoder}; // Currently unused
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{Read, Write};
use uuid::Uuid;

/// Common DCE/RPC packet header
#[derive(Debug, Clone)]
pub struct RpcHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub packet_type: PacketType,
    pub packet_flags: PacketFlags,
    pub data_representation: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl RpcHeader {
    pub fn new(packet_type: PacketType, call_id: u32) -> Self {
        Self {
            version_major: DCERPC_VERSION_MAJOR,
            version_minor: DCERPC_VERSION_MINOR,
            packet_type,
            packet_flags: PacketFlags::with_flags(PacketFlags::FIRST_FRAG | PacketFlags::LAST_FRAG),
            data_representation: [0x10, 0x00, 0x00, 0x00], // Little-endian, ASCII, IEEE float
            frag_length: 16,                               // Will be updated
            auth_length: 0,
            call_id,
        }
    }

    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer
            .write_u8(self.version_major)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u8(self.version_minor)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u8(self.packet_type as u8)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u8(self.packet_flags.0)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_all(&self.data_representation)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u16::<LittleEndian>(self.frag_length)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u16::<LittleEndian>(self.auth_length)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u32::<LittleEndian>(self.call_id)
            .map_err(|e| Error::Io(e))?;
        Ok(())
    }

    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
        let version_major = reader.read_u8().map_err(|e| Error::Io(e))?;
        let version_minor = reader.read_u8().map_err(|e| Error::Io(e))?;
        let packet_type = reader.read_u8().map_err(|e| Error::Io(e))?;
        let packet_flags = reader.read_u8().map_err(|e| Error::Io(e))?;

        let mut data_representation = [0u8; 4];
        reader
            .read_exact(&mut data_representation)
            .map_err(|e| Error::Io(e))?;

        let frag_length = reader
            .read_u16::<LittleEndian>()
            .map_err(|e| Error::Io(e))?;
        let auth_length = reader
            .read_u16::<LittleEndian>()
            .map_err(|e| Error::Io(e))?;
        let call_id = reader
            .read_u32::<LittleEndian>()
            .map_err(|e| Error::Io(e))?;

        Ok(Self {
            version_major,
            version_minor,
            packet_type: PacketType::try_from(packet_type)?,
            packet_flags: PacketFlags(packet_flags),
            data_representation,
            frag_length,
            auth_length,
            call_id,
        })
    }
}

/// Bind packet - establishes context
#[derive(Debug, Clone)]
pub struct BindPacket {
    pub header: RpcHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub num_context_items: u8,
    pub contexts: Vec<ContextItem>,
    pub auth_verifier: Option<AuthVerifier>,
}

#[derive(Debug, Clone)]
pub struct ContextItem {
    pub context_id: u16,
    pub num_transfer_syntaxes: u8,
    pub abstract_syntax: SyntaxId,
    pub transfer_syntaxes: Vec<SyntaxId>,
}

#[derive(Debug, Clone)]
pub struct SyntaxId {
    pub uuid: Uuid,
    pub version: u32,
}

impl BindPacket {
    pub fn new(call_id: u32, interface: &RpcInterface) -> Self {
        let header = RpcHeader::new(PacketType::Bind, call_id);

        let context = ContextItem {
            context_id: 0,
            num_transfer_syntaxes: 1,
            abstract_syntax: SyntaxId {
                uuid: interface.uuid,
                version: ((interface.version_major as u32) << 16) | interface.version_minor as u32,
            },
            transfer_syntaxes: vec![SyntaxId {
                uuid: uuid::uuid!("8A885D04-1CEB-11C9-9FE8-08002B104860"), // NDR
                version: 2,
            }],
        };

        Self {
            header,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            num_context_items: 1,
            contexts: vec![context],
            auth_verifier: None,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Write header (will update frag_length later)
        self.header.serialize(&mut buffer)?;

        // Write bind fields
        buffer
            .write_u16::<LittleEndian>(self.max_xmit_frag)
            .map_err(|e| Error::Io(e))?;
        buffer
            .write_u16::<LittleEndian>(self.max_recv_frag)
            .map_err(|e| Error::Io(e))?;
        buffer
            .write_u32::<LittleEndian>(self.assoc_group_id)
            .map_err(|e| Error::Io(e))?;
        buffer
            .write_u8(self.num_context_items)
            .map_err(|e| Error::Io(e))?;

        // Padding
        buffer.write_all(&[0, 0, 0]).map_err(|e| Error::Io(e))?;

        // Write context items
        for context in &self.contexts {
            buffer
                .write_u16::<LittleEndian>(context.context_id)
                .map_err(|e| Error::Io(e))?;
            buffer
                .write_u8(context.num_transfer_syntaxes)
                .map_err(|e| Error::Io(e))?;
            buffer.write_u8(0).map_err(|e| Error::Io(e))?; // Reserved

            // Abstract syntax
            buffer
                .write_all(context.abstract_syntax.uuid.as_bytes())
                .map_err(|e| Error::Io(e))?;
            buffer
                .write_u32::<LittleEndian>(context.abstract_syntax.version)
                .map_err(|e| Error::Io(e))?;

            // Transfer syntaxes
            for syntax in &context.transfer_syntaxes {
                buffer
                    .write_all(syntax.uuid.as_bytes())
                    .map_err(|e| Error::Io(e))?;
                buffer
                    .write_u32::<LittleEndian>(syntax.version)
                    .map_err(|e| Error::Io(e))?;
            }
        }

        // Add auth verifier if present
        if let Some(auth) = &self.auth_verifier {
            auth.serialize(&mut buffer)?;
            // Update auth_length in header
            let auth_len = auth.auth_value.len() as u16;
            buffer[10..12].copy_from_slice(&auth_len.to_le_bytes());
        }

        // Update frag_length in header
        let frag_len = buffer.len() as u16;
        buffer[8..10].copy_from_slice(&frag_len.to_le_bytes());

        Ok(buffer)
    }
}

/// Bind acknowledgment packet
#[derive(Debug, Clone)]
pub struct BindAckPacket {
    pub header: RpcHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub secondary_addr_len: u16,
    pub secondary_addr: Vec<u8>,
    pub num_results: u8,
    pub results: Vec<ContextResult>,
    pub auth_verifier: Option<AuthVerifier>,
}

#[derive(Debug, Clone)]
pub struct ContextResult {
    pub ack_result: u16,
    pub ack_reason: u16,
    pub transfer_syntax: SyntaxId,
}

/// Request packet - actual RPC call
#[derive(Debug, Clone)]
pub struct RequestPacket {
    pub header: RpcHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub object: Option<Uuid>,
    pub stub_data: Vec<u8>,
    pub auth_verifier: Option<AuthVerifier>,
}

impl RequestPacket {
    pub fn new(call_id: u32, context_id: u16, opnum: u16, stub_data: Vec<u8>) -> Self {
        let header = RpcHeader::new(PacketType::Request, call_id);

        Self {
            header,
            alloc_hint: stub_data.len() as u32,
            context_id,
            opnum,
            object: None,
            stub_data,
            auth_verifier: None,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Write header
        self.header.serialize(&mut buffer)?;

        // Write request fields
        buffer
            .write_u32::<LittleEndian>(self.alloc_hint)
            .map_err(|e| Error::Io(e))?;
        buffer
            .write_u16::<LittleEndian>(self.context_id)
            .map_err(|e| Error::Io(e))?;
        buffer
            .write_u16::<LittleEndian>(self.opnum)
            .map_err(|e| Error::Io(e))?;

        // Write object UUID if present
        if let Some(uuid) = &self.object {
            buffer
                .write_all(uuid.as_bytes())
                .map_err(|e| Error::Io(e))?;
        }

        // Write stub data
        buffer
            .write_all(&self.stub_data)
            .map_err(|e| Error::Io(e))?;

        // Add auth verifier if present
        if let Some(auth) = &self.auth_verifier {
            auth.serialize(&mut buffer)?;
            // Update auth_length in header
            let auth_len = auth.auth_value.len() as u16;
            buffer[10..12].copy_from_slice(&auth_len.to_le_bytes());
        }

        // Update frag_length in header
        let frag_len = buffer.len() as u16;
        buffer[8..10].copy_from_slice(&frag_len.to_le_bytes());

        Ok(buffer)
    }
}

/// Response packet - RPC call result
#[derive(Debug, Clone)]
pub struct ResponsePacket {
    pub header: RpcHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub reserved: u8,
    pub stub_data: Vec<u8>,
    pub auth_verifier: Option<AuthVerifier>,
}

/// Fault packet - RPC error
#[derive(Debug, Clone)]
pub struct FaultPacket {
    pub header: RpcHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub reserved: u8,
    pub status: u32,
    pub reserved2: u32,
}

impl FaultPacket {
    pub fn new(call_id: u32, context_id: u16, error: RpcError) -> Self {
        let header = RpcHeader::new(PacketType::Fault, call_id);

        Self {
            header,
            alloc_hint: 0,
            context_id,
            cancel_count: 0,
            reserved: 0,
            status: error as u32,
            reserved2: 0,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Write header
        self.header.serialize(&mut buffer)?;

        // Write fault fields
        buffer
            .write_u32::<LittleEndian>(self.alloc_hint)
            .map_err(|e| Error::Io(e))?;
        buffer
            .write_u16::<LittleEndian>(self.context_id)
            .map_err(|e| Error::Io(e))?;
        buffer
            .write_u8(self.cancel_count)
            .map_err(|e| Error::Io(e))?;
        buffer.write_u8(self.reserved).map_err(|e| Error::Io(e))?;
        buffer
            .write_u32::<LittleEndian>(self.status)
            .map_err(|e| Error::Io(e))?;
        buffer
            .write_u32::<LittleEndian>(self.reserved2)
            .map_err(|e| Error::Io(e))?;

        // Update frag_length in header
        let frag_len = buffer.len() as u16;
        buffer[8..10].copy_from_slice(&frag_len.to_le_bytes());

        Ok(buffer)
    }
}

/// Authentication verifier
#[derive(Debug, Clone)]
pub struct AuthVerifier {
    pub auth_type: AuthType,
    pub auth_level: AuthLevel,
    pub auth_pad_length: u8,
    pub auth_reserved: u8,
    pub auth_context_id: u32,
    pub auth_value: Vec<u8>,
}

impl AuthVerifier {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer
            .write_u8(self.auth_type as u8)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u8(self.auth_level as u8)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u8(self.auth_pad_length)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u8(self.auth_reserved)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_u32::<LittleEndian>(self.auth_context_id)
            .map_err(|e| Error::Io(e))?;
        writer
            .write_all(&self.auth_value)
            .map_err(|e| Error::Io(e))?;
        Ok(())
    }

    pub fn deserialize<R: Read>(reader: &mut R, auth_length: u16) -> Result<Self> {
        let auth_type = reader.read_u8().map_err(|e| Error::Io(e))?;
        let auth_level = reader.read_u8().map_err(|e| Error::Io(e))?;
        let auth_pad_length = reader.read_u8().map_err(|e| Error::Io(e))?;
        let auth_reserved = reader.read_u8().map_err(|e| Error::Io(e))?;
        let auth_context_id = reader
            .read_u32::<LittleEndian>()
            .map_err(|e| Error::Io(e))?;

        let mut auth_value = vec![0u8; auth_length as usize];
        reader
            .read_exact(&mut auth_value)
            .map_err(|e| Error::Io(e))?;

        Ok(Self {
            auth_type: match auth_type {
                0 => AuthType::None,
                10 => AuthType::Ntlm,
                9 => AuthType::MsKerberos,
                68 => AuthType::Schannel,
                _ => AuthType::None,
            },
            auth_level: match auth_level {
                1 => AuthLevel::None,
                2 => AuthLevel::Connect,
                3 => AuthLevel::Call,
                4 => AuthLevel::Packet,
                5 => AuthLevel::PacketIntegrity,
                6 => AuthLevel::PacketPrivacy,
                _ => AuthLevel::None,
            },
            auth_pad_length,
            auth_reserved,
            auth_context_id,
            auth_value,
        })
    }
}
