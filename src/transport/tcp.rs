//! TCP transport implementation for SMB

use super::SmbTransport;
use crate::error::{Error, Result};
use crate::netbios::{NetBiosHeader, NetBiosMessage};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// TCP transport for SMB protocol
pub struct TcpTransport {
    stream: Option<TcpStream>,
    read_buffer: BytesMut,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
}

impl TcpTransport {
    /// Create a new TCP transport
    pub fn new() -> Self {
        Self {
            stream: None,
            read_buffer: BytesMut::with_capacity(65536),
            local_addr: None,
            remote_addr: None,
        }
    }

    /// Create a TCP transport from an existing stream
    pub fn from_stream(stream: TcpStream) -> Self {
        let local_addr = stream.local_addr().ok();
        let remote_addr = stream.peer_addr().ok();

        Self {
            stream: Some(stream),
            read_buffer: BytesMut::with_capacity(65536),
            local_addr,
            remote_addr,
        }
    }

    /// Connect with NetBIOS session establishment
    pub async fn connect_with_netbios(
        &mut self,
        addr: SocketAddr,
        called_name: &[u8],
        calling_name: &[u8],
    ) -> Result<()> {
        // First establish TCP connection
        self.connect(addr).await?;

        // Send NetBIOS session request
        let session_request = NetBiosMessage::session_request(called_name, calling_name)?;
        self.send(Bytes::from(session_request.to_bytes())).await?;

        // Wait for response
        let response_data = self.receive().await?;
        let response_header = NetBiosHeader::parse(&response_data)?;

        match response_header.message_type {
            crate::protocol::NetBiosMessageType::PositiveResponse => Ok(()),
            crate::protocol::NetBiosMessageType::NegativeResponse => {
                let error_code = if response_data.len() > NetBiosHeader::SIZE {
                    response_data[NetBiosHeader::SIZE]
                } else {
                    0
                };
                Err(Error::Protocol(format!(
                    "NetBIOS session request rejected with error code: 0x{:02x}",
                    error_code
                )))
            }
            _ => Err(Error::Protocol(format!(
                "Unexpected NetBIOS response type: {:?}",
                response_header.message_type
            ))),
        }
    }

    /// Send a message with NetBIOS framing
    pub async fn send_netbios_message(&mut self, data: &[u8]) -> Result<()> {
        let msg = NetBiosMessage::session_message(data.to_vec())?;
        self.send(Bytes::from(msg.to_bytes())).await
    }

    /// Receive a message with NetBIOS framing
    pub async fn receive_netbios_message(&mut self) -> Result<Vec<u8>> {
        // First read the NetBIOS header
        while self.read_buffer.len() < NetBiosHeader::SIZE {
            self.read_more().await?;
        }

        let header = NetBiosHeader::parse(&self.read_buffer)?;
        let total_size = NetBiosHeader::SIZE + header.length as usize;

        // Read the rest of the message if needed
        while self.read_buffer.len() < total_size {
            self.read_more().await?;
        }

        // Extract the complete message
        let message_bytes = self.read_buffer.split_to(total_size);
        let message = NetBiosMessage::parse(&message_bytes)?;

        Ok(message.payload)
    }

    /// Read more data from the stream into the buffer
    async fn read_more(&mut self) -> Result<usize> {
        if let Some(ref mut stream) = self.stream {
            let mut temp_buf = vec![0u8; 8192];
            let n = stream.read(&mut temp_buf).await?;
            if n == 0 {
                return Err(Error::ConnectionClosed);
            }
            self.read_buffer.put_slice(&temp_buf[..n]);
            Ok(n)
        } else {
            Err(Error::Protocol("Not connected".to_string()))
        }
    }
}

#[async_trait]
impl SmbTransport for TcpTransport {
    async fn connect(&mut self, addr: SocketAddr) -> Result<()> {
        let stream = TcpStream::connect(addr).await?;
        self.local_addr = Some(stream.local_addr()?);
        self.remote_addr = Some(stream.peer_addr()?);
        self.stream = Some(stream);
        Ok(())
    }

    async fn send(&mut self, data: Bytes) -> Result<()> {
        if let Some(ref mut stream) = self.stream {
            stream.write_all(&data).await?;
            stream.flush().await?;
            Ok(())
        } else {
            Err(Error::Protocol("Not connected".to_string()))
        }
    }

    async fn receive(&mut self) -> Result<BytesMut> {
        if self.stream.is_none() {
            return Err(Error::Protocol("Not connected".to_string()));
        }

        // Read at least some data
        if self.read_buffer.is_empty() {
            self.read_more().await?;
        }

        // Return available data
        let available = self.read_buffer.split();
        Ok(available)
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await?;
        }
        self.local_addr = None;
        self.remote_addr = None;
        self.read_buffer.clear();
        Ok(())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr
            .ok_or_else(|| Error::Protocol("Not connected".to_string()))
    }

    fn remote_addr(&self) -> Result<SocketAddr> {
        self.remote_addr
            .ok_or_else(|| Error::Protocol("Not connected".to_string()))
    }
}

#[cfg(test)]
mod tests;
