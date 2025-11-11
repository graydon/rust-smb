//! SMB2 protocol messages organized by category

pub mod common;
pub mod directory;
pub mod file_info;
pub mod file_ops;
pub mod info;
pub mod ioctl;
pub mod negotiate;
pub mod session;
pub mod tree;

// Re-export commonly used types
pub use common::{FileId, Smb2Header, Smb2TransformHeader, SmbMessage, SMB2_PROTOCOL_ID};
pub use directory::{Smb2QueryDirectoryRequest, Smb2QueryDirectoryResponse};
pub use file_ops::{Smb2CloseRequest, Smb2CloseResponse, Smb2CreateRequest, Smb2CreateResponse};
pub use file_ops::{Smb2ReadRequest, Smb2ReadResponse, Smb2WriteRequest, Smb2WriteResponse};
pub use info::{FileInfoClass, InfoType};
pub use info::{
    Smb2QueryInfoRequest, Smb2QueryInfoResponse, Smb2SetInfoRequest, Smb2SetInfoResponse,
};
pub use ioctl::{
    Smb2IoctlRequest, Smb2IoctlResponse, FSCTL_DFS_GET_REFERRALS, FSCTL_PIPE_TRANSCEIVE,
};
pub use negotiate::{Smb2NegotiateRequest, Smb2NegotiateResponse};
pub use session::{Smb2SessionSetupRequest, Smb2SessionSetupResponse};
pub use tree::{Smb2TreeConnectRequest, Smb2TreeConnectResponse};
