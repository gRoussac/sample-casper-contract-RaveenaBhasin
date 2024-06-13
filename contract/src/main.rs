#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");
// We need to explicitly import the std alloc crate and `alloc::string::String` as we're in a
// `no_std` environment.
extern crate alloc;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use contract::constants;

#[allow(unused_imports, clippy::single_component_path_imports)]
use casper_contract::{
    contract_api::{runtime, storage},
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::{
    bytesrepr::FromBytes,
    contracts::{EntryPoints, NamedKeys},
    ApiError, CLType, CLTyped, CLValue, EntryPoint, EntryPointAccess, EntryPointType, Key,
    Parameter, RuntimeArgs, URef, U128, U256, U512,
};

/// An error enum which can be converted to a `u16` so it can be returned as an `ApiError::User`.
#[repr(u16)]
pub enum Error {
    FatalError = 1,
    SignatureValidatorsLengthMismatch = 2,
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        ApiError::User(error as u16)
    }
}

pub fn get_stored_value<T: FromBytes + CLTyped>(key_name: &str) -> T {
    let uref: URef = runtime::get_key(key_name)
        .unwrap_or_else(|| runtime::revert(ApiError::GetKey))
        .into_uref()
        .unwrap_or_else(|| runtime::revert(ApiError::UnexpectedKeyVariant));

    storage::read(uref)
        .unwrap_or_revert_with(ApiError::Read)
        .unwrap_or_revert_with(ApiError::ValueNotFound)
}

#[no_mangle]
pub extern "C" fn call() {
    install_contract();
}

fn install_contract() {
    let named_keys = {
        let mut named_keys = NamedKeys::new();
        named_keys.insert(
            constants::init::INSTALLER.to_string(),
            runtime::get_caller().into(),
        );
        named_keys
    };

    let mut entry_points = EntryPoints::new();

    let event_nonce: U128 = U128::one();
    let event_nonce_uref = storage::new_uref(event_nonce);
    runtime::put_key("event_nonce_key", event_nonce_uref.into());

    entry_points.add_entry_point(EntryPoint::new(
        constants::VERIFY_SIG,
        vec![
            Parameter::new("signer", CLType::ByteArray(20)),
            Parameter::new("message_digest", CLType::List(Box::new(CLType::U8))),
            Parameter::new("signature", CLType::List(Box::new(CLType::U8))),
        ],
        CLType::Bool,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    ));

    let (contract_hash, contract_version) = storage::new_contract(
        entry_points,
        Some(named_keys),
        Some(constants::contract::PACKAGE_NAME.to_string()),
        Some(constants::contract::ACCESS_UREF.to_string()),
    );
    runtime::put_key(constants::contract::KEY, contract_hash.into());
    runtime::put_key(
        constants::contract::VERSION_KEY,
        storage::new_uref(contract_version).into(),
    );
}
