//! Security Account Manager (SAMR) RPC service
//! Manages users, groups, and domains

use crate::dcerpc::ndr::{NdrDecoder, NdrEncoder};
use crate::dcerpc::services::common::{
    samr_opcodes, user_account_control, well_known_rids, well_known_sids,
};
use crate::dcerpc::services::{RpcService, RpcStatus};
use crate::dcerpc::{interfaces, RpcInterface};
use crate::error::Result;
use std::collections::HashMap;

/// SAMR operation numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SamrOpnum {
    Connect = 0,
    Close = 1,
    SetSecurity = 2,
    QuerySecurity = 3,
    Shutdown = 4,
    LookupDomain = 5,
    EnumDomains = 6,
    OpenDomain = 7,
    QueryDomainInfo = 8,
    SetDomainInfo = 9,
    CreateDomainGroup = 10,
    EnumDomainGroups = 11,
    CreateUser = 12,
    EnumDomainUsers = 13,
    CreateDomainAlias = 14,
    EnumDomainAliases = 15,
    GetAliasMembership = 16,
    LookupNames = 17,
    LookupIds = 18,
    OpenGroup = 19,
    QueryGroupInfo = 20,
    SetGroupInfo = 21,
    AddMemberToGroup = 22,
    DeleteGroup = 23,
    RemoveMemberFromGroup = 24,
    QueryGroupMember = 25,
    SetMemberAttributesOfGroup = 26,
    OpenAlias = 27,
    QueryAliasInfo = 28,
    SetAliasInfo = 29,
    DeleteAlias = 30,
    AddMemberToAlias = 31,
    RemoveMemberFromAlias = 32,
    GetMembersInAlias = 33,
    OpenUser = 34,
    DeleteUser = 35,
    QueryUserInfo = 36,
    SetUserInfo = 37,
    ChangePasswordUser = 38,
    GetGroupsForUser = 39,
    QueryDisplayInfo = 40,
    GetDisplayEnumerationIndex = 41,
    TestPrivateFunctionsDomain = 42,
    TestPrivateFunctionsUser = 43,
    GetUserPwInfo = 44,
    RemoveMemberFromForeignDomain = 45,
    QueryDomainInfo2 = 46,
    QueryUserInfo2 = 47,
    QueryDisplayInfo2 = 48,
    GetDisplayEnumerationIndex2 = 49,
    CreateUser2 = 50,
    QueryDisplayInfo3 = 51,
    AddMultipleMembersToAlias = 52,
    RemoveMultipleMembersFromAlias = 53,
    OemChangePasswordUser2 = 54,
    ChangePasswordUser2 = 55,
    GetDomainPasswordInformation = 56,
    Connect2 = 57,
    SetUserInfo2 = 58,
    SetBootKeyInformation = 59,
    GetBootKeyInformation = 60,
    Connect3 = 61,
    Connect4 = 62,
    ChangePasswordUser3 = 63,
    Connect5 = 64,
    RidToSid = 65,
    SetDsrmPassword = 66,
    ValidatePassword = 67,
}

/// Domain information
#[derive(Debug, Clone)]
pub struct DomainInfo {
    pub name: String,
    pub sid: Vec<u8>,
    pub users: HashMap<u32, UserInfo>,
    pub groups: HashMap<u32, GroupInfo>,
}

/// User information
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub rid: u32,
    pub username: String,
    pub full_name: String,
    pub description: String,
    pub flags: u32,
    pub password_hash: Vec<u8>,
}

/// Group information
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub rid: u32,
    pub name: String,
    pub description: String,
    pub members: Vec<u32>,
}

/// SAMR service implementation
pub struct SamrService {
    interface: RpcInterface,
    domains: HashMap<String, DomainInfo>,
    handles: HashMap<[u8; 20], HandleType>,
    next_handle: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum HandleType {
    Server,
    Domain(String),
    User(String, u32),
    Group(String, u32),
    Alias(String, u32),
}

impl SamrService {
    pub fn new() -> Self {
        let mut domains = HashMap::new();

        // Create builtin domain
        let mut builtin = DomainInfo {
            name: "BUILTIN".to_string(),
            sid: well_known_sids::BUILTIN_DOMAIN.to_vec(),
            users: HashMap::new(),
            groups: HashMap::new(),
        };

        // Add Administrator user
        builtin.users.insert(
            well_known_rids::ADMINISTRATOR,
            UserInfo {
                rid: well_known_rids::ADMINISTRATOR,
                username: "Administrator".to_string(),
                full_name: "Administrator".to_string(),
                description: "Built-in administrator account".to_string(),
                flags: user_account_control::ADMIN_DEFAULT,
                password_hash: vec![0; 16],
            },
        );

        // Add Guest user
        builtin.users.insert(
            well_known_rids::GUEST,
            UserInfo {
                rid: well_known_rids::GUEST,
                username: "Guest".to_string(),
                full_name: "Guest".to_string(),
                description: "Built-in guest account".to_string(),
                flags: user_account_control::GUEST_DEFAULT,
                password_hash: vec![0; 16],
            },
        );

        // Add Administrators group
        builtin.groups.insert(
            well_known_rids::BUILTIN_ADMINISTRATORS,
            GroupInfo {
                rid: well_known_rids::BUILTIN_ADMINISTRATORS,
                name: "Administrators".to_string(),
                description: "Administrators have complete access".to_string(),
                members: vec![well_known_rids::ADMINISTRATOR],
            },
        );

        // Add Users group
        builtin.groups.insert(
            well_known_rids::BUILTIN_USERS,
            GroupInfo {
                rid: well_known_rids::BUILTIN_USERS,
                name: "Users".to_string(),
                description: "Users are prevented from making accidental changes".to_string(),
                members: vec![],
            },
        );

        domains.insert("BUILTIN".to_string(), builtin);

        // Create local domain
        let local = DomainInfo {
            name: "WORKGROUP".to_string(),
            sid: well_known_sids::create_domain_sid(0x04030201, 0x08070605, 0x0),
            users: HashMap::new(),
            groups: HashMap::new(),
        };

        domains.insert("WORKGROUP".to_string(), local);

        Self {
            interface: interfaces::samr(),
            domains,
            handles: HashMap::new(),
            next_handle: 1,
        }
    }

    fn create_handle(&mut self, handle_type: HandleType) -> [u8; 20] {
        let mut handle = [0u8; 20];
        handle[0..4].copy_from_slice(&self.next_handle.to_le_bytes());
        self.next_handle += 1;

        self.handles.insert(handle, handle_type);
        handle
    }

    fn handle_connect(&mut self, decoder: &mut NdrDecoder) -> Result<Vec<u8>> {
        // Decode machine name
        let _machine = decoder.decode_unique_ptr(|d| d.decode_string())?;

        // Decode desired access
        let _access = decoder.decode_u32()?;

        // Create server handle
        let handle = self.create_handle(HandleType::Server);

        let mut encoder = NdrEncoder::new();
        encoder.encode_bytes(&handle)?;
        encoder.encode_u32(RpcStatus::Success as u32)?;

        Ok(encoder.into_bytes())
    }

    fn handle_enum_domains(&mut self, decoder: &mut NdrDecoder) -> Result<Vec<u8>> {
        // Decode server handle
        let mut handle = [0u8; 20];
        let handle_bytes = decoder.decode_bytes(20)?;
        handle.copy_from_slice(&handle_bytes);

        // Decode resume handle
        let _resume = decoder.decode_u32()?;

        // Decode max size
        let _max_size = decoder.decode_u32()?;

        let mut encoder = NdrEncoder::new();

        // Encode resume handle
        encoder.encode_u32(0)?;

        // Encode domain array
        encoder.encode_unique_ptr(Some(&()), |enc, _| {
            enc.encode_u32(self.domains.len() as u32)?; // Count
            enc.encode_u32(self.domains.len() as u32)?; // Max count

            for (i, domain) in self.domains.keys().enumerate() {
                enc.encode_u32(i as u32)?; // Index
                enc.encode_string(domain)?; // Name
            }
            Ok(())
        })?;

        // Encode number of entries
        encoder.encode_u32(self.domains.len() as u32)?;

        encoder.encode_u32(RpcStatus::Success as u32)?;

        Ok(encoder.into_bytes())
    }

    fn handle_lookup_domain(&mut self, decoder: &mut NdrDecoder) -> Result<Vec<u8>> {
        // Decode server handle
        let mut _handle = [0u8; 20];
        let _handle_bytes = decoder.decode_bytes(20)?;

        // Decode domain name
        let domain_name = decoder.decode_string()?;

        let mut encoder = NdrEncoder::new();

        if let Some(domain) = self.domains.get(&domain_name) {
            // Encode SID
            encoder.encode_unique_ptr(Some(&domain.sid), |enc, sid| enc.encode_bytes(sid))?;
            encoder.encode_u32(RpcStatus::Success as u32)?;
        } else {
            encoder.encode_u32(0)?; // Null SID
            encoder.encode_u32(RpcStatus::NoSuchDomain as u32)?;
        }

        Ok(encoder.into_bytes())
    }

    fn handle_open_domain(&mut self, decoder: &mut NdrDecoder) -> Result<Vec<u8>> {
        // Decode server handle
        let mut _server_handle = [0u8; 20];
        let _handle_bytes = decoder.decode_bytes(20)?;

        // Decode desired access
        let _access = decoder.decode_u32()?;

        // Decode domain SID
        let sid = decoder.decode_unique_ptr(|d| {
            let len = d.decode_u32()? as usize;
            d.decode_bytes(len)
        })?;

        let mut encoder = NdrEncoder::new();

        // Find domain by SID
        let domain_name = self
            .domains
            .iter()
            .find(|(_, d)| sid.as_ref().map_or(false, |s| d.sid == *s))
            .map(|(name, _)| name.clone());

        if let Some(name) = domain_name {
            let handle = self.create_handle(HandleType::Domain(name));
            encoder.encode_bytes(&handle)?;
            encoder.encode_u32(RpcStatus::Success as u32)?;
        } else {
            encoder.encode_bytes(&[0u8; 20])?;
            encoder.encode_u32(RpcStatus::NoSuchDomain as u32)?;
        }

        Ok(encoder.into_bytes())
    }
}

impl RpcService for SamrService {
    fn interface(&self) -> &RpcInterface {
        &self.interface
    }

    fn handle_call(&mut self, opnum: u16, input: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = NdrDecoder::new(input);

        match opnum {
            samr_opcodes::CONNECT | samr_opcodes::CONNECT2 | samr_opcodes::CONNECT5 => {
                self.handle_connect(&mut decoder) // Connect variants
            }
            samr_opcodes::ENUM_DOMAINS => self.handle_enum_domains(&mut decoder),
            samr_opcodes::LOOKUP_DOMAIN => self.handle_lookup_domain(&mut decoder),
            samr_opcodes::OPEN_DOMAIN => self.handle_open_domain(&mut decoder),
            _ => {
                // Unsupported operation
                let mut encoder = NdrEncoder::new();
                encoder.encode_u32(RpcStatus::NotSupported as u32)?;
                Ok(encoder.into_bytes())
            }
        }
    }

    fn name(&self) -> &str {
        "SAMR"
    }
}
