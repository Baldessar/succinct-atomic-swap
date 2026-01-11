use std::fs;

use bitcoin::{NetworkKind, PrivateKey, Script, network, secp256k1};
use bitcoin::{Sequence, opcodes, script::Builder};
use bitcoin::params::MAINNET;
use bitcoin::secp256k1::constants::{CURVE_ORDER, GENERATOR_X, GENERATOR_Y};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::Secp256k1;
use eliptic_curve_math::{add, multiply, get_y_from_x};
use num_bigint_dig::{RandBigInt};
use num_bigint::{BigInt};
use num_traits::{Euclid, sign};
use num_traits::ops::bytes;
use rand::RngCore;
use serde::Deserialize;
use serde::de::value;
use serde_json::Value;

use crate::bip32::test32;
use crate::bitcoin_operations::{build_script_pub_key_p2wpkh, build_script_pub_key_p2wsh, build_p2wsh_script_pub_key, build_2_of_2_ms_script, get_commitment_hash};
use crate::utils::der_encoding;

mod bitcoin_operations;
mod succinct_atomic_swap;
mod eliptic_curve_math;
mod utils;
mod bip32;
mod rpc;


fn main() {
    let secp: Secp256k1<secp256k1::All>  = Secp256k1::gen_new();


    let q: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &CURVE_ORDER);
    let generator: eliptic_curve_math::Point = eliptic_curve_math::Point {
        x: GENERATOR_X.to_vec(),
        y: GENERATOR_Y.to_vec(),
    };

    let (prv_key_alice, pub_key_alice) = secp.generate_keypair(&mut OsRng);
    let (prv_key_bob, pub_key_bob) = secp.generate_keypair(&mut OsRng);
    
    let bytes:[u8; 8]  =  OsRng.next_u64().to_be_bytes();
    let secret_t:BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);

    // SETUP

    let x_secret: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &prv_key_bob.secret_bytes());
    println!("{}", x_secret);
    let tG: eliptic_curve_math::Point = multiply(&generator, &secret_t);
    let xG: eliptic_curve_math::Point = get_y_from_x(&pub_key_bob.to_string());


    // PRE SIGN
    let message: &str = "hello world";

    let bytes2:[u8; 8]  =  OsRng.next_u64().to_be_bytes();
    let nonce_k: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes2).rem_euclid(&q);

        let r_line_kG = multiply(&generator, &nonce_k);
        let r_kT = multiply(&tG, &nonce_k);

        let r: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &r_kT.x);


        let z: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus,sha256::Hash::hash(message.as_bytes()).as_byte_array()).rem_euclid(&q);


        let s_line = (&z + (&r*&x_secret)).modinv(&nonce_k).unwrap();
        let s_line: BigInt = (nonce_k.modinv(&q).unwrap()*(&z + &r*x_secret)).rem_euclid(&q);
        println!("{:?}", s_line);

    let (r, s_line, pub_key, r_kT, r_line_kG) = eliptic_curve_math::pre_sign(&message.as_bytes().to_vec(), &nonce_k, &tG, &prv_key_bob, &secret_t);

    // PRE VERIFY
    let z: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus,sha256::Hash::hash(message.as_bytes()).as_byte_array()).rem_euclid(&q);

    let u: BigInt = (z*&s_line.modinv(&q).unwrap()).rem_euclid(&q);
    let v: BigInt = (r*&s_line.modinv(&q).unwrap()).rem_euclid(&q);

    let uG = multiply(&generator, &u);
    let vX = multiply(&xG, &v);

    let alice_r_line = add(&uG, &vX);

    eliptic_curve_math::pre_verify(&message.as_bytes().to_vec(), &s_line, &r, r_line_kG, &pub_key);

    // Adapt

    let s: BigInt = (&s_line*&secret_t.modinv(&q).unwrap()).rem_euclid(&q);
    
    // Extract
    
    let t: BigInt = (&s_line*&s.modinv(&q).unwrap()).rem_euclid(&q);
    
    println!("{}", s);
    println!("{}", s_line);
    println!("{}", secret_t);
    println!("{}", t);

}
