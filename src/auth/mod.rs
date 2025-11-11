//! Authentication mechanisms for SMB

pub mod ntlm;
pub mod ntlm_crypto;

use crate::error::Result;

/// Authentication mechanism trait
pub trait AuthMechanism: Send + Sync {
    /// Initialize authentication
    fn initialize(&mut self) -> Result<()>;

    /// Generate authentication token
    fn generate_auth_token(&mut self, challenge: &[u8]) -> Result<Vec<u8>>;

    /// Verify authentication token
    fn verify_auth_token(&mut self, token: &[u8]) -> Result<bool>;
}
