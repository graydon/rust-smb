//! DCE/RPC transport layer - handles RPC over named pipes and TCP

use crate::dcerpc::packet::{BindPacket, RequestPacket};
use crate::dcerpc::{RpcContext, RpcInterface};
use crate::error::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// RPC transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// RPC over SMB named pipes
    NamedPipe,
    /// RPC over TCP (port 135 for endpoint mapper, dynamic ports for services)
    Tcp,
    /// RPC over HTTP
    Http,
}

/// RPC transport trait
#[async_trait::async_trait]
pub trait RpcTransport: Send + Sync {
    /// Send an RPC packet
    async fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Receive an RPC packet
    async fn receive(&mut self) -> Result<Vec<u8>>;

    /// Get transport type
    fn transport_type(&self) -> TransportType;

    /// Check if connected
    fn is_connected(&self) -> bool;

    /// Close the transport
    async fn close(&mut self) -> Result<()>;
}

/// Named pipe transport for RPC over SMB
///
/// For supported pipe names, see `server::pipes::well_known_pipes`
/// Only srvsvc and samr pipes are currently supported for file service.
pub struct NamedPipeTransport {
    _pipe_name: String,
    handle: Option<PipeHandle>,
    buffer: Vec<u8>,
}

/// Pipe handle (would connect to SMB in real implementation)
struct PipeHandle {
    _tree_id: u32,
    _file_id: [u8; 16],
}

impl NamedPipeTransport {
    pub fn new(pipe_name: &str) -> Self {
        Self {
            _pipe_name: pipe_name.to_string(),
            handle: None,
            buffer: Vec::new(),
        }
    }

    /// Connect to the named pipe
    pub async fn connect(&mut self, _tree_id: u32) -> Result<()> {
        // In real implementation, would open the pipe via SMB
        self.handle = Some(PipeHandle {
            _tree_id: 1,
            _file_id: [0; 16],
        });
        Ok(())
    }
}

#[async_trait::async_trait]
impl RpcTransport for NamedPipeTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.handle.is_none() {
            return Err(Error::ConnectionError("Pipe not connected".to_string()));
        }

        // In real implementation, would send via SMB Write
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        if self.handle.is_none() {
            return Err(Error::ConnectionError("Pipe not connected".to_string()));
        }

        // In real implementation, would receive via SMB Read
        if !self.buffer.is_empty() {
            Ok(self.buffer.drain(..).collect())
        } else {
            Ok(Vec::new())
        }
    }

    fn transport_type(&self) -> TransportType {
        TransportType::NamedPipe
    }

    fn is_connected(&self) -> bool {
        self.handle.is_some()
    }

    async fn close(&mut self) -> Result<()> {
        // In real implementation, would close the SMB file handle
        self.handle = None;
        self.buffer.clear();
        Ok(())
    }
}

/// TCP transport for RPC
pub struct TcpTransport {
    stream: Option<tokio::net::TcpStream>,
    endpoint: String,
}

impl TcpTransport {
    pub fn new(endpoint: &str) -> Self {
        Self {
            stream: None,
            endpoint: endpoint.to_string(),
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        let stream = tokio::net::TcpStream::connect(&self.endpoint)
            .await
            .map_err(|e| Error::Io(e))?;
        self.stream = Some(stream);
        Ok(())
    }
}

#[async_trait::async_trait]
impl RpcTransport for TcpTransport {
    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if let Some(ref mut stream) = self.stream {
            // Add fragment header for TCP transport
            let frag_header = [
                0x05,
                0x00, // Version
                0x00,
                0x00, // Flags
                (data.len() >> 8) as u8,
                data.len() as u8,
                0x00,
                0x00, // Auth length
            ];

            stream
                .write_all(&frag_header)
                .await
                .map_err(|e| Error::Io(e))?;
            stream.write_all(data).await.map_err(|e| Error::Io(e))?;
            Ok(())
        } else {
            Err(Error::ConnectionError("Not connected".to_string()))
        }
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        if let Some(ref mut stream) = self.stream {
            // Read fragment header
            let mut header = [0u8; 8];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|e| Error::Io(e))?;

            let length = ((header[4] as usize) << 8) | header[5] as usize;
            let mut data = vec![0u8; length - 8];
            stream
                .read_exact(&mut data)
                .await
                .map_err(|e| Error::Io(e))?;

            Ok(data)
        } else {
            Err(Error::ConnectionError("Not connected".to_string()))
        }
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tcp
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await.map_err(|e| Error::Io(e))?;
        }
        Ok(())
    }
}

/// RPC client over transport
pub struct RpcClient {
    transport: Box<dyn RpcTransport>,
    context: RpcContext,
}

impl RpcClient {
    pub fn new(transport: Box<dyn RpcTransport>) -> Self {
        Self {
            transport,
            context: RpcContext::new(),
        }
    }

    /// Bind to an interface
    pub async fn bind(&mut self, interface: &RpcInterface) -> Result<()> {
        let bind_packet = BindPacket::new(self.context.next_call_id(), interface);
        let data = bind_packet.serialize()?;

        self.transport.send(&data).await?;

        // Wait for bind ack
        let _response = self.transport.receive().await?;
        // Parse and validate bind ack

        self.context.bind_interface(0, interface.clone());
        Ok(())
    }

    /// Make an RPC call
    pub async fn call(&mut self, opnum: u16, input: &[u8]) -> Result<Vec<u8>> {
        let request = RequestPacket::new(
            self.context.next_call_id(),
            0, // context_id
            opnum,
            input.to_vec(),
        );

        let data = request.serialize()?;
        self.transport.send(&data).await?;

        // Wait for response
        let response = self.transport.receive().await?;
        // Parse response packet and extract stub data

        Ok(response)
    }

    /// Close the RPC connection
    pub async fn close(&mut self) -> Result<()> {
        self.transport.close().await
    }
}
