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
