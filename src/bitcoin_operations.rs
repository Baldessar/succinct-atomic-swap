#![allow(unused)]
use std::{path::PathBuf, process::Command};


use bitcoin::script::{self, PushBytes, PushBytesBuf};
use bitcoin::{opcodes, script::Builder};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, ops::bytes};
use rand::seq;
use bitcoin::hashes::sha256;
use bitcoin::hashes::ripemd160;
use bitcoin::hashes::HashEngine;
use bitcoin::hashes::Hash;

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

pub fn encode_inputs(outpoint_list: &Vec<&str>) -> Vec<u8> {

    let input_count: usize = outpoint_list.len();
    let mut compact_input_count: Vec<u8> = encode_compact_size(input_count);
    let script_key_size: [u8; 1] = [0];
    let sequence: [u8; 4] = [255, 255, 255, 255];
    
    let mut inputs: Vec<u8> = vec![];

    inputs.append(&mut compact_input_count);


    for outpoint in outpoint_list {
        let current_outpoint: Vec<&str> = outpoint.split(":").collect();
        
        let mut hex_bytes: Vec<u8> = hex::decode(current_outpoint[0]).expect("invalid hex string: failed to decode");

        let mut vout_bytes:Vec<u8>  = (current_outpoint[1].parse::<u32>().expect("invalid string: failed to converse to number")).to_le_bytes().to_vec();

        let mut bytes_outpoint: Vec<u8> = vec![];
        bytes_outpoint.append(&mut hex_bytes);
        bytes_outpoint.append(&mut vout_bytes);
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


    let bytes = match hex::decode("cafe") {
        Ok(value) => value,
        Err(e) => return vec![],
    };

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
