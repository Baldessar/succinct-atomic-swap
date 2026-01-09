use num_traits::{ToPrimitive};
use bitcoin::secp256k1::hashes::{sha256, Hash};
use bitcoin::hashes::HashEngine;

pub fn der_encoding(r: Vec<u8>, s: Vec<u8>) -> Vec<u8>{

    let mut hex_r = hex::encode(&r);
    let mut hex_s = hex::encode(&s);
    let mut r_lenght = hex::decode("20").unwrap();
    let mut s_lenght = hex::decode("20").unwrap();



    if u8::from_be_bytes(hex::decode(&"80").expect("msg").try_into().unwrap()) <= u8::from_be_bytes(hex::decode(&hex_r[0..2]).expect("msg").try_into().unwrap()) {
        hex_r = format!("{}{}", "00", hex_r);
        r_lenght = hex::decode("21").unwrap();
    }
    
    if u8::from_be_bytes(hex::decode(&"80").expect("msg").try_into().unwrap()) <= u8::from_be_bytes(hex::decode(&hex_s[0..2]).expect("msg").try_into().unwrap()) {
        hex_s = format!("{}{}", "00", hex_s);
        s_lenght = hex::decode("21").unwrap();
    }


    let outer_type: Vec<u8> = hex::decode("30").unwrap();
    let inner_type: Vec<u8> = hex::decode("02").unwrap();

    let bytes_r = hex::decode(&hex_r).unwrap();
    let bytes_s = hex::decode(&hex_s).unwrap();

    let total_lenght = (inner_type.len() + r_lenght.len() + bytes_r.len() + inner_type.len() + s_lenght.len() + bytes_s.len()).to_u8().unwrap().to_be_bytes().to_vec();

    let mut der_signature: Vec<u8> = vec![];


    der_signature.extend(outer_type);
    der_signature.extend(total_lenght);
    der_signature.extend(&inner_type);
    der_signature.extend(r_lenght);
    der_signature.extend(bytes_r);
    der_signature.extend(inner_type);
    der_signature.extend(s_lenght);
    der_signature.extend(bytes_s);

    return der_signature;
}

pub fn dsha256(message: &Vec<u8>) -> Vec<u8>{
    let mut hasher_256: sha256::HashEngine = sha256::HashEngine::default();
    hasher_256.input(&message);
    
    let hash256: Vec<u8> = sha256::Hash::from_engine(hasher_256).hash_again().as_byte_array().to_vec();

    return hash256;
}
