#![allow(unused)]
// use core::hash;
// use std::io::repeat;
// use std::{i64, vec};
use std::{path::PathBuf, process::Command};


use bitcoin::{PrivateKey};
// use bitcoin::ecdsa::Signature;
// use bitcoin::p2p::message;
use bitcoin::script::{self, PushBytes, PushBytesBuf};
use bitcoin::{opcodes, script::Builder};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, ops::bytes};
use rand::seq;
use bitcoin::hashes::sha256;
use bitcoin::hashes::ripemd160;
use bitcoin::hashes::HashEngine;
use bitcoin::hashes::Hash;
use crate::eliptic_curve_math;
use crate::utils::{self, der_encoding, dsha256};


// use bitcoin::secp256k1::constants::{CURVE_ORDER, FIELD_SIZE, GENERATOR_X, GENERATOR_Y};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{secp256k1};
// use eliptic_curve_math::{Point, multiply, add, get_y_from_x};
// use num_traits::{Euclid};

#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    // Add relevant error variants for various cases.
}


pub fn encode_compact_size(size: usize) -> Vec<u8> {

    let mut leading: &str = "";
    let mut num_of_bytes: usize = 1;

    if size > 252 && size <= 65535 {
        leading = "FD";
        num_of_bytes = 2;
    } else if size > 65535 && size <= 4294967295 {
        leading = "FE";
        num_of_bytes = 4;
    } else if  size > 4294967295 {
        leading = "FF";
        num_of_bytes = 8;
    }

    let mut compact_leading: Vec<u8> = hex::decode(leading).expect("this number can be decoded");
    let mut compact_value: Vec<u8> = size.to_le_bytes().to_vec()[..num_of_bytes].to_vec();
    
    compact_leading.append(&mut compact_value);

    return compact_leading;
}

pub fn encode_inputs(outpoint_list: &Vec<Vec<u8>>) -> Vec<u8> {

    let input_count: usize = outpoint_list.len();
    let mut compact_input_count: Vec<u8> = encode_compact_size(input_count);
    let script_key_size: [u8; 1] = [0];
    let sequence: [u8; 4] = [255, 255, 255, 255];
    
    let mut inputs: Vec<u8> = vec![];

    inputs.append(&mut compact_input_count);


    for outpoint in outpoint_list {
        let mut current_outpoint:Vec<u8> = outpoint.clone();

        let mut bytes_outpoint: Vec<u8> = vec![];
        bytes_outpoint.append(&mut current_outpoint);
        bytes_outpoint.extend(script_key_size);
        bytes_outpoint.extend(sequence);
        
        inputs.append(&mut bytes_outpoint);
    }
    
    return inputs;
}

pub fn encode_outputs(outputs_list: Vec<(Vec<u8>, u64)>) -> Vec<u8> {

    let mut outputs: Vec<u8> = vec![];
    let mut output_count: Vec<u8> = encode_compact_size(outputs_list.len());
    outputs.append(&mut output_count);

    for output in outputs_list {
        let mut current_output: Vec<u8> = vec![];
        let  (mut script_pub_key, amount) = output;


        let mut amount_in_bytes: Vec<u8> = amount.to_le_bytes().to_vec();
        let mut script_pub_key_lenght: Vec<u8> = encode_compact_size(script_pub_key.len());

        current_output.append(&mut amount_in_bytes);
        current_output.append(&mut script_pub_key_lenght);
        current_output.append(&mut script_pub_key);

        outputs.append(&mut current_output);
    }

    return outputs;
}


pub fn build_script_pub_key_p2wpkh(pub_key: &bitcoin::PublicKey) -> Vec<u8> {

    println!("{:?}", pub_key.to_bytes());


    let bytes = pub_key.to_bytes();

    let mut hasher_256: sha256::HashEngine = sha256::HashEngine::default();
    hasher_256.input(&bytes.to_vec());

    let hash256: Vec<u8> = sha256::Hash::from_engine(hasher_256).as_byte_array().to_vec();

    let mut hasher_160: ripemd160::HashEngine = ripemd160::HashEngine::default();
    hasher_160.input(&hash256);

    let hash160 = ripemd160::Hash::from_engine(hasher_160).as_byte_array().to_vec();

    let pb: PushBytesBuf = PushBytesBuf::try_from(hash160)
    .expect("data must be ≤ 520 bytes");

    let script: Vec<u8> = Builder::new()
                            .push_opcode(opcodes::OP_0)
                            .push_slice(pb).as_bytes().to_vec();

    return script;

}


pub fn build_script_pub_key_p2wsh(script: &str) -> Vec<u8> {

    println!("{:?}", script);


    let bytes = match hex::decode(script) {
        Ok(value) => value,
        Err(e) => return vec![],
    };

    let mut hasher_256: sha256::HashEngine = sha256::HashEngine::default();
    hasher_256.input(&bytes.to_vec());

    let hash256: Vec<u8> = sha256::Hash::from_engine(hasher_256).as_byte_array().to_vec();


    let pb: PushBytesBuf = PushBytesBuf::try_from(hash256)
    .expect("data must be ≤ 520 bytes");

    let script: Vec<u8> = Builder::new()
                            .push_opcode(opcodes::OP_0)
                            .push_slice(&pb).as_bytes().to_vec();
    
    return script;

}


pub fn build_2_of_2_ms_script(sender_pub_key: &bitcoin::PublicKey, receiver_pub_key: &bitcoin::PublicKey) -> Vec<u8> {
    let mut ms_script: Vec<u8> = Builder::new()
                .push_opcode(opcodes::all::OP_PUSHNUM_2)
                .push_key(sender_pub_key)
                .push_key(receiver_pub_key)
                .push_opcode(opcodes::all::OP_PUSHNUM_2)
                .push_opcode(opcodes::all::OP_CHECKMULTISIG)
                .into_bytes();
    
    return ms_script;
}


pub fn build_p2wsh_script_pub_key(script: &Vec<u8>) -> Vec<u8> {

    let mut hasher_256: sha256::HashEngine = sha256::HashEngine::default();

    hasher_256.input(&script);

    let script_hash: PushBytesBuf = PushBytesBuf::try_from(sha256::Hash::from_engine(hasher_256).as_byte_array().to_vec())
    .expect("data must be ≤ 520 bytes");

    let mut ms_script = Builder::new()
                    .push_opcode(opcodes::OP_0)
                    .push_slice(script_hash)
                    .into_bytes();
                    
    
    return ms_script;
}


pub fn sign(private_key:&PrivateKey, message: &Vec<u8>) -> Vec<u8> {
    let signature: eliptic_curve_math::Signature = eliptic_curve_math::sign(private_key, message, false);
    let signature_hash_type: Vec<u8> = hex::decode("01").unwrap();
    let mut encoded_signature: Vec<u8> = der_encoding(signature.r, signature.s);

    let mut result_signature: Vec<u8> = signature_hash_type;
    result_signature.extend(&encoded_signature);

    return result_signature;
}


pub fn build_p2wsh_witness(prv_keys: Vec<&PrivateKey>, message: &Vec<u8>, script: &Vec<u8>) -> Vec<u8> {
    
    let secp: Secp256k1<secp256k1::All>  = Secp256k1::gen_new();
    let mut signatures: Vec<u8> = vec![];
    let mut pub_keys: Vec<u8> = vec![];

    for prv_key in prv_keys {
        let mut signature: Vec<u8> = sign(prv_key, &message);
        let mut sig_size: Vec<u8> = encode_compact_size(signature.len());
        signatures.append(&mut sig_size);
        signatures.append(&mut signature);
        pub_keys.append(&mut prv_key.public_key(&secp).to_bytes().to_vec());

    }

    let mut stack_size: Vec<u8> = vec![4];
    let mut script_size: Vec<u8> = encode_compact_size(script.len());

    let mut witness: Vec<u8> = vec![];

    witness.append(&mut stack_size);
    witness.append(&mut hex::decode(&"00").unwrap());
    witness.append(&mut signatures);
    witness.append(&mut script_size);
    witness.append(&mut script.clone());

    return witness;

}


pub fn get_commitment_hash(outpoints: &Vec<Vec<u8>>, scriptcodes: &Vec<Vec<u8>>, values: &Vec<Vec<u8>>, outputs: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {

    let mut commitment_hashes: Vec<Vec<u8>> = vec![];
    let outpoints_len: usize =  outpoints.len();
    let scriptcodes_len: usize =  scriptcodes.len();
    let values_len: usize =  values.len();
    let outputs_len: usize =  outputs.len();

    let version: Vec<u8> = hex::decode(&"02000000").unwrap();
    let n_lock_time: Vec<u8> = hex::decode(&"00000000").unwrap();
    let n_hash_type: Vec<u8> = hex::decode(&"01000000").unwrap();

    let hash_prev_out: Vec<u8> = utils::dsha256(&outpoints.clone().concat());
    
    let sequence: Vec<u8> = hex::decode(&"ffffffff".repeat(outpoints_len)).unwrap();
    let hashed_sequence = utils::dsha256(&sequence);
    let hashed_outputs = utils::dsha256(&outputs.clone().concat());

    let mut i: usize = 0;

    while i < outpoints_len {
        let mut current_outpoint = outpoints[i].clone();
        let mut current_scriptcode = scriptcodes[i].clone();
        let mut current_value = values[i].clone();
        let mut nsequence = hex::decode(&"ffffffff").unwrap();

        let mut preimage: Vec<u8> = vec![];

        preimage.extend( &version);
        preimage.extend( &hash_prev_out);
        preimage.extend( &hashed_sequence);
        preimage.append(&mut current_outpoint);
        preimage.append(&mut current_scriptcode);
        preimage.append(&mut current_value);
        preimage.append(&mut nsequence);
        preimage.extend( &hashed_outputs);
        preimage.extend( &n_lock_time);
        preimage.extend( &n_hash_type);

       
        let preimage_hash = dsha256(&preimage);

        commitment_hashes.push(preimage_hash);

    }


    return commitment_hashes;

}





// fn bcli(cmd: &str) -> Result<Vec<u8>, BalanceError> {
//     let args: Vec<&str> = cmd.split(' ').collect::<Vec<&str>>();

//     let result: std::process::Output = Command::new("bitcoin-cli")
//         .args(&args)
//         .output()
//         .map_err(|_| BalanceError::MissingCodeCantRun)?;

//     if result.status.success() {
//         return Ok(result.stdout);
//     } else {
//         return Ok(result.stderr);
//     }
// }