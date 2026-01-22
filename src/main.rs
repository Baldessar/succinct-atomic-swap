use std::str::FromStr;

use bitcoin::ecdsa::Signature;
use bitcoin::hashes::{sha256};
use bitcoin::hashes::Hash;
use bitcoin::p2p::message;
use bitcoin::{secp256k1};
use bitcoin::secp256k1::constants::{CURVE_ORDER, GENERATOR_X, GENERATOR_Y};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{Message, Secp256k1};
use eliptic_curve_math::{add, multiply, get_y_from_x};
use num_bigint::{BigInt, BigUint};
use num_traits::{Euclid, ToBytes};
use rand::RngCore;
mod bitcoin_operations;
mod succinct_atomic_swap;
mod eliptic_curve_math;
mod utils;


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
    
    // SETUP
    
    println!("Setup Alice");
    let secret_t: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &prv_key_alice.secret_bytes());
    println!("Alice Creates SecretAlice: {}", secret_t);
    let tG: eliptic_curve_math::Point = multiply(&generator, &secret_t);
    println!("Alice multiplies SecretAlice by the Generating point, getting T");

    println!("");
    println!("Setup Bob");
    let x_secret: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &prv_key_bob.secret_bytes());
    println!("Bob Creates SecretBob: {}", x_secret);
    let xG: eliptic_curve_math::Point = multiply(&generator, &x_secret);
    // let xG: eliptic_curve_math::Point = get_y_from_x(&pub_key_Bob.to_string());
    println!("Bob multiplies SecretBob by the Generating point");


    // PRE SIGN
    let message: &str = "hello world";
    let mut bytes2 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes2);

    let nonce_k: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes2).rem_euclid(&q);
    println!("Bob creates a nounce K: {}", nonce_k);

    
    let (r, s_line, pub_key, r_kT, r_line_kG) = eliptic_curve_math::pre_sign(&message.as_bytes().to_vec(), &nonce_k, &tG, &prv_key_bob);
    println!("");

    // PRE VERIFY
    println!("");
    println!("Pre Verify - Alice can now check if the partial signature was calculated correctly.");
    let z: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus,sha256::Hash::hash(message.as_bytes()).as_byte_array()).rem_euclid(&q);
    println!("She recomputes z by hashing her message with the same cryptographic hash function H that Bob used.");


    println!("Next up, the values u and v are calculated using the inverse of s' and multiplying it by the hashed message z and the value r respectively.");
    let u: BigInt = (&z*&s_line.modinv(&q).unwrap()).rem_euclid(&q);
    let v: BigInt = (&r*&s_line.modinv(&q).unwrap()).rem_euclid(&q);


    let uG = multiply(&generator, &u);
    let vX = multiply(&xG, &v);
    
    println!("Alice then checks if the R' value she received from Bob equals u multiplied by the generator G added to the multiplication of v by Bob's public key X.");
    let alice_r_line = add(&uG, &vX);

    println!("");

    println!("R'-X: {}, R'-Y:{}", hex::encode(&r_line_kG.x), hex::encode(&r_line_kG.y));
    println!("uG+vX-X: {}, uG+vX-Y:{}", hex::encode(alice_r_line.x), hex::encode(alice_r_line.y));
    println!("");

    eliptic_curve_math::pre_verify(&message.as_bytes().to_vec(), &s_line, &r, r_line_kG, &pub_key);

    // Adapt
    println!("Adapt");
    println!("Once the verification of the partial signature succeeds, Alice can turn it into a full signature by multiplying s' with the inverse of her witness t.");
    let s: BigInt = (&s_line*&secret_t.modinv(&q).unwrap()).rem_euclid(&q);
    let s_normalized: BigInt = if s.clone() > (&q / 2) {
        &q - s.clone()
    } else {
        s.clone()
    };

    println!("{}",s_normalized);
    println!("{}",r);

    let mut r_bytes = r.to_biguint().unwrap().to_be_bytes(); // your r as [u8; 32]
    let mut s_bytes = s_normalized.to_biguint().unwrap().to_be_bytes(); // your s as [u8; 32]

    println!("{}",r_bytes.len());
    println!("{}",s_bytes.len());

    // Combine into compact 64-byte format
    let mut sig_bytes = vec![];
    sig_bytes.append(&mut r_bytes);
    sig_bytes.append(&mut s_bytes);
    let signature = secp256k1::ecdsa::Signature::from_compact(&sig_bytes).unwrap();

    

    let verified = secp.verify_ecdsa(&Message::from_digest(sha256::Hash::hash(message.as_bytes()).to_byte_array()), &signature, &pub_key_bob);
    println!("{:?}", verified);

    // Extract
    println!("Extract");
    println!("When Alice shares the full, valid signature publicly Bob can recover Alice's witness t using both, the partial- and full signature.");

    let t: BigInt = (&s_line*&s.modinv(&q).unwrap()).rem_euclid(&q);
    println!("Generated AliceSecret: {}", secret_t);
    println!("Extracted AliceSecret: {}", t);


}
