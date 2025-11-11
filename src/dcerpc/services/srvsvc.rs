//! Server Service (SRVSVC) RPC implementation
//! Provides share enumeration, server info, and file/session management

use crate::dcerpc::ndr::{NdrDecoder, NdrEncoder};
use crate::dcerpc::services::{RpcService, RpcStatus};
use crate::dcerpc::{interfaces, RpcInterface};
use crate::error::Result;
use std::collections::HashMap;

/// SRVSVC operation numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SrvSvcOpnum {
    NetrConnectionEnum = 8,
    NetrFileEnum = 9,
    NetrFileGetInfo = 10,
    NetrFileClose = 11,
    NetrSessionEnum = 12,
    NetrSessionDel = 13,
    NetrShareAdd = 14,
    NetrShareEnum = 15,
    NetrShareGetInfo = 16,
    NetrShareSetInfo = 17,
    NetrShareDel = 18,
    NetrShareDelSticky = 19,
    NetrShareCheck = 20,
    NetrServerGetInfo = 21,
    NetrServerSetInfo = 22,
    NetrServerDiskEnum = 23,
    NetrServerStatisticsGet = 24,
    NetrServerTransportAdd = 25,
    NetrServerTransportEnum = 26,
    NetrServerTransportDel = 27,
    NetrRemoteTOD = 28,
    NetrServerTransport3Add = 30,
    NetrServerTransport3Enum = 31,
    NetrServerTransport3Del = 32,
    NetShareEnumSticky = 36,
    NetrShareDelStart = 37,
    NetrShareDelCommit = 38,
    NetrGetFileSecurity = 39,
    NetrSetFileSecurity = 40,
    NetrServerTransportAddEx = 41,
    NetrServerSetServiceBitsEx = 42,
}

/// Share information level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShareInfoLevel {
    Level0 = 0,
    Level1 = 1,
    Level2 = 2,
    Level501 = 501,
    Level502 = 502,
    Level503 = 503,
    Level1004 = 1004,
    Level1005 = 1005,
    Level1006 = 1006,
    Level1007 = 1007,
    Level1501 = 1501,
}

/// Share type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShareType {
    DiskTree = 0,
    PrintQueue = 1,
    Device = 2,
    IPC = 3,
    Special = 0x80000000,
}

/// Share info structure
#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub name: String,
    pub share_type: ShareType,
    pub comment: String,
    pub permissions: u32,
    pub max_users: u32,
    pub current_users: u32,
    pub path: String,
    pub password: Option<String>,
}

/// Server info level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServerInfoLevel {
    Level100 = 100,
    Level101 = 101,
    Level102 = 102,
    Level402 = 402,
    Level403 = 403,
    Level502 = 502,
    Level503 = 503,
    Level599 = 599,
    Level1005 = 1005,
    Level1010 = 1010,
    Level1016 = 1016,
    Level1017 = 1017,
    Level1018 = 1018,
    Level1107 = 1107,
    Level1501 = 1501,
    Level1502 = 1502,
    Level1503 = 1503,
    Level1506 = 1506,
    Level1510 = 1510,
    Level1511 = 1511,
    Level1512 = 1512,
    Level1513 = 1513,
    Level1514 = 1514,
    Level1515 = 1515,
    Level1516 = 1516,
}

/// Server platform ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PlatformId {
    DOS = 300,
    OS2 = 400,
    NT = 500,
    OSF = 600,
    VMS = 700,
}

/// SRVSVC service implementation
pub struct SrvSvcService {
    interface: RpcInterface,
    shares: HashMap<String, ShareInfo>,
    server_name: String,
    server_comment: String,
    version_major: u32,
    version_minor: u32,
}

impl SrvSvcService {
    pub fn new() -> Self {
        // For backward compatibility, create with default hardcoded shares
        Self::with_shares(HashMap::new())
    }

    pub fn with_shares(server_shares: HashMap<String, crate::server::ShareInfo>) -> Self {
        let mut shares = HashMap::new();

        // Always add the standard administrative shares
        shares.insert(
            "IPC$".to_string(),
            ShareInfo {
                name: "IPC$".to_string(),
                share_type: ShareType::IPC,
                comment: "Remote IPC".to_string(),
                permissions: 0,
                max_users: u32::MAX,
                current_users: 0,
                path: String::new(),
                password: None,
            },
        );

        shares.insert(
            "C$".to_string(),
            ShareInfo {
                name: "C$".to_string(),
                share_type: ShareType::Special,
                comment: "Default share".to_string(),
                permissions: 0,
                max_users: u32::MAX,
                current_users: 0,
                path: "C:\\".to_string(),
                password: None,
            },
        );

        shares.insert(
            "ADMIN$".to_string(),
            ShareInfo {
                name: "ADMIN$".to_string(),
                share_type: ShareType::Special,
                comment: "Remote Admin".to_string(),
                permissions: 0,
                max_users: u32::MAX,
                current_users: 0,
                path: "C:\\Windows".to_string(),
                password: None,
            },
        );

        // Add actual server shares
        for (key, server_share) in server_shares {
            shares.insert(
                key,
                ShareInfo {
                    name: server_share.name.clone(),
                    share_type: if server_share.share_type == 0 {
                        ShareType::DiskTree
                    } else {
                        ShareType::DiskTree // Default to disk for now
                    },
                    comment: server_share.description.clone(),
                    permissions: 0,
                    max_users: u32::MAX,
                    current_users: 0,
                    path: server_share.path.clone(),
                    password: None,
                },
            );
        }

        Self {
            interface: interfaces::srvsvc(),
            shares,
            server_name: "RUST-SMB-SERVER".to_string(),
            server_comment: "Rust SMB Server".to_string(),
            version_major: 10,
            version_minor: 0,
        }
    }

    /// Add a share
    pub fn add_share(&mut self, share: ShareInfo) {
        self.shares.insert(share.name.clone(), share);
    }

    /// Remove a share
    pub fn remove_share(&mut self, name: &str) -> bool {
        self.shares.remove(name).is_some()
    }

    /// Handle NetrShareEnum (actually NetrShareEnumAll for opnum 15)
    fn handle_share_enum(&self, _decoder: &mut NdrDecoder) -> Result<Vec<u8>> {
        use tracing::debug;

        debug!("NetrShareEnumAll: Building response with shares");

        // Create a proper NDR-encoded response
        let mut encoder = NdrEncoder::new();

        // Build the response
        // InfoStruct (level and union)
        encoder.encode_u32(1)?; // level = 1
        encoder.encode_u32(1)?; // union discriminator = 1

        // Pointer to NetShareCtr1
        encoder.encode_unique_ptr(Some(&()), |enc, _| {
            // NetShareCtr1 structure
            let share_count = self.shares.len() as u32;
            enc.encode_u32(share_count)?; // count

            // Pointer to array of SHARE_INFO_1 structures
            if share_count > 0 {
                enc.encode_unique_ptr(Some(&()), |enc2, _| {
                    // Conformant array: max count first
                    enc2.encode_u32(share_count)?;

                    // Each SHARE_INFO_1 structure has pointers that we'll fill later
                    let mut string_data = Vec::new();

                    // First pass: write the fixed part of each SHARE_INFO_1
                    for share in self.shares.values() {
                        // Pointer to netname (we'll use sequential referent IDs)
                        enc2.encode_u32(0x00020000 + string_data.len() as u32)?;
                        string_data.push(share.name.clone());

                        // Share type
                        enc2.encode_u32(share.share_type as u32)?;

                        // Pointer to comment
                        enc2.encode_u32(0x00020000 + string_data.len() as u32)?;
                        string_data.push(share.comment.clone());
                    }

                    // Second pass: write all the strings
                    for s in &string_data {
                        // Each string is a conformant/varying array
                        let chars: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
                        enc2.encode_u32(chars.len() as u32)?; // max count
                        enc2.encode_u32(0)?; // offset
                        enc2.encode_u32(chars.len() as u32)?; // actual count
                        for ch in chars {
                            enc2.encode_u16(ch)?;
                        }
                    }

                    Ok(())
                })?;
            } else {
                enc.encode_u32(0)?; // null pointer for array
            }
            Ok(())
        })?;

        // totalentries
        encoder.encode_u32(self.shares.len() as u32)?;

        // resume_handle (optional, we return NULL)
        encoder.encode_u32(0)?;

        // Return value (WERROR)
        encoder.encode_u32(0)?; // Success

        let response = encoder.into_bytes();

        debug!(
            "NetrShareEnumAll: Returning {} bytes with {} shares",
            response.len(),
            self.shares.len()
        );

        Ok(response)
    }

    /// Handle NetrServerGetInfo
    fn handle_server_get_info(&self, decoder: &mut NdrDecoder) -> Result<Vec<u8>> {
        // Decode server name
        let _server_name = decoder.decode_unique_ptr(|d| d.decode_string())?;

        // Decode info level
        let level = decoder.decode_u32()?;

        let mut encoder = NdrEncoder::new();

        match level {
            101 => {
                // ServerInfo101
                encoder.encode_u32(101)?; // Level
                encoder.encode_unique_ptr(Some(&()), |enc, _| {
                    enc.encode_u32(PlatformId::NT as u32)?; // Platform ID
                    enc.encode_string(&self.server_name)?; // Server name
                    enc.encode_u32(self.version_major)?; // Version major
                    enc.encode_u32(self.version_minor)?; // Version minor
                    enc.encode_u32(0x00000003)?; // Server type (workstation | server)
                    enc.encode_unique_ptr(Some(&self.server_comment), |e, c| e.encode_string(c))?;
                    Ok(())
                })?;
            }
            _ => {
                // Unsupported level
                encoder.encode_u32(level)?;
                encoder.encode_u32(0)?; // Null pointer
            }
        }

        encoder.encode_u32(RpcStatus::Success as u32)?;
        Ok(encoder.into_bytes())
    }

    /// Handle NetrShareGetInfo
    fn handle_share_get_info(&self, decoder: &mut NdrDecoder) -> Result<Vec<u8>> {
        // Decode server name
        let _server_name = decoder.decode_unique_ptr(|d| d.decode_string())?;

        // Decode share name
        let share_name = decoder.decode_string()?;

        // Decode info level
        let level = decoder.decode_u32()?;

        let mut encoder = NdrEncoder::new();

        if let Some(share) = self.shares.get(&share_name) {
            match level {
                1 => {
                    encoder.encode_u32(1)?; // Level
                    encoder.encode_unique_ptr(Some(&()), |enc, _| {
                        enc.encode_string(&share.name)?;
                        enc.encode_u32(share.share_type as u32)?;
                        enc.encode_unique_ptr(Some(&share.comment), |e, c| e.encode_string(c))?;
                        Ok(())
                    })?;
                }
                2 => {
                    encoder.encode_u32(2)?; // Level
                    encoder.encode_unique_ptr(Some(&()), |enc, _| {
                        enc.encode_string(&share.name)?;
                        enc.encode_u32(share.share_type as u32)?;
                        enc.encode_unique_ptr(Some(&share.comment), |e, c| e.encode_string(c))?;
                        enc.encode_u32(share.permissions)?;
                        enc.encode_u32(share.max_users)?;
                        enc.encode_u32(share.current_users)?;
                        enc.encode_unique_ptr(Some(&share.path), |e, p| e.encode_string(p))?;
                        enc.encode_unique_ptr(share.password.as_ref(), |e, p| e.encode_string(p))?;
                        Ok(())
                    })?;
                }
                _ => {
                    encoder.encode_u32(level)?;
                    encoder.encode_u32(0)?; // Null pointer
                }
            }
            encoder.encode_u32(RpcStatus::Success as u32)?;
        } else {
            encoder.encode_u32(level)?;
            encoder.encode_u32(0)?; // Null pointer
            encoder.encode_u32(RpcStatus::ObjectNameNotFound as u32)?;
        }

        Ok(encoder.into_bytes())
    }
}

impl RpcService for SrvSvcService {
    fn interface(&self) -> &RpcInterface {
        &self.interface
    }

    fn handle_call(&mut self, opnum: u16, input: &[u8]) -> Result<Vec<u8>> {
        use tracing::debug;

        debug!("SRVSVC: handle_call for opnum {} (0x{:02x})", opnum, opnum);
        debug!("SRVSVC: Input data {} bytes", input.len());

        let mut decoder = NdrDecoder::new(input);

        let result = match opnum {
            15 => {
                debug!("SRVSVC: Handling NetrShareEnumAll (opnum 15)");
                self.handle_share_enum(&mut decoder)
            }
            16 => {
                debug!("SRVSVC: Handling NetrShareGetInfo (opnum 16)");
                self.handle_share_get_info(&mut decoder)
            }
            21 => {
                debug!("SRVSVC: Handling NetrServerGetInfo (opnum 21)");
                self.handle_server_get_info(&mut decoder)
            }
            _ => {
                debug!("SRVSVC: Unsupported operation {}", opnum);
                // Unsupported operation
                let mut encoder = NdrEncoder::new();
                encoder.encode_u32(RpcStatus::NotSupported as u32)?;
                Ok(encoder.into_bytes())
            }
        };

        if let Ok(ref data) = result {
            debug!("SRVSVC: Returning {} bytes for opnum {}", data.len(), opnum);
        }

        result
    }

    fn name(&self) -> &str {
        "SRVSVC"
    }
}
