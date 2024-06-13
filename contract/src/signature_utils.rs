#![no_std]
#![no_main]

use crate::constants::{self, MSG_PREFIX};
use crate::constants::{Bytes, Bytes20, ValsetArgs};
extern crate alloc;
use alloc::boxed::Box;
use alloc::{format, string::String, vec::Vec};
use casper_contract::contract_api::runtime;
use casper_types::{CLValue, U128};
// use k256::ecdsa::recoverable::Signature as RecoverableSignature;
use libsecp256k1::{recover, Message, RecoveryId, Signature};

// use secp256k1::Secp256k1;
// use secp256k1::{
//     ecdsa::RecoverableSignature as rec, Message as SecpMessage, Secp256k1 as Secp256k1Curve,
// };
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> Box<[u8]> {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.to_vec().into_boxed_slice()
}

pub fn make_digest(data: &Vec<u8>) -> Vec<u8> {
    let mut msg_data: Vec<u8> = data.clone();
    let mut input: Vec<u8> = Vec::new();
    let mut msg: Vec<u8> = Vec::from(MSG_PREFIX.as_bytes());
    input.append(&mut msg);
    input.append(&mut msg_data);
    let checkpoint = keccak256(&input);
    checkpoint.into()
}

//  #[no_mangle] // this will pack metadata of ecdsa_recover
pub fn verify_sig() {
    let signer: Bytes20 = runtime::get_named_arg("signer");
    let message_digest: Vec<u8> = runtime::get_named_arg("message_digest");
    let signature: Vec<u8> = runtime::get_named_arg("signature");
    let mut output: String = String::new();
    let res: (bool, Option<String>) = ecdsa_recover(&signature, &message_digest, &mut output);

    let result = if !res.0 {
        false
    } else {
        let decoded_output = hex::decode(output.clone());

        if decoded_output.is_err() {
            false
        } else {
            let output: Vec<u8> = decoded_output.unwrap();
            signer.as_slice() == output
        }
    };

    let cl_value = CLValue::from_t(result).unwrap();
    runtime::ret(cl_value);
}

pub fn ecdsa_recover(
    signature: &[u8],
    message_hash: &[u8],
    output: &mut String,
) -> (bool, Option<String>) {
    // In most implementations, the v is just 0 or 1 internally, but 27 was added
    // as an arbitrary number for signing Bitcoin messages and Ethereum adopted that as well.
    let recovery_byte: u8 = if signature[64] > 26 {
        signature[64] - 27
    } else {
        signature[64]
    };

    let recovery_id = RecoveryId::parse(recovery_byte);
    if recovery_id.is_err() {
        let err = recovery_id.unwrap_err();
        let str = format!("Unable to parse the recovery id: {err}");

        return (false, Some(str));
    }

    let recovery_id = recovery_id.unwrap();

    let message = Message::parse_slice(message_hash);
    if message.is_err() {
        let err = message.unwrap_err();
        let str: String = format!("Unable to create the message from hash: {err}");

        return (false, Some(str));
    }

    let message = message.unwrap();

    let sign = Signature::parse_standard_slice(&signature[0..64]);
    // if sign.is_err() {
    //     env::panic_str("Error in parsing signature");
    // }
    let sign = sign.unwrap();

    let pub_key = recover(&message, &sign, &recovery_id);

    let uncompressed_pub_key: [u8; 65];
    match pub_key {
        Ok(pub_key) => {
            uncompressed_pub_key = pub_key.serialize();
        }
        Err(err) => return (false, Some(format!("{:?}", err))),
    }
    // let hash: Vec<u8> = env::keccak256(&uncompressed_pub_key[1..]);
    // *output = hex::encode(&hash[12..]);
    let hash = keccak256(&uncompressed_pub_key[1..]);
    *output = hex::encode(&hash[12..]);

    return (true, None);
}
