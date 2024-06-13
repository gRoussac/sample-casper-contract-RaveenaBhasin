extern crate alloc;
use alloc::{boxed::Box, vec::Vec};
use casper_types::{CLType, U128};
use serde::{Deserialize, Serialize};

pub type Bytes20 = [u8; 20];
pub type Bytes32 = [u8; 32];
pub type Bytes = Vec<u8>;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ValsetArgs {
    pub validators: Vec<Bytes20>,
    pub powers: Vec<u64>,
    pub valset_nonce: U128,
}

pub mod contract {
    pub const PACKAGE_NAME: &str = "package_name";
    pub const ACCESS_UREF: &str = "access_uref";
    pub const VERSION_KEY: &str = "contract_version";
    pub const KEY: &str = "contract_hash";
}

pub mod init {
    pub const ENTRYPOINT: &str = "init";
    pub const INSTALLER: &str = "installer";
}

pub const VERIFY_SIG: &str = "verify_sig";
pub const MSG_PREFIX: &str = "\x19Ethereum Signed Message:\n32";
