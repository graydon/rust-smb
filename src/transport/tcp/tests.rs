use super::*;

#[tokio::test]
async fn test_tcp_transport_creation() {
    let transport = TcpTransport::new();
    assert!(!transport.is_connected());
    assert!(transport.local_addr().is_err());
    assert!(transport.remote_addr().is_err());
}
