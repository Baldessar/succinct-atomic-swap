
use core::slice;

use num_bigint::{BigInt};
use bitcoin::{script::Builder};
use secp256k1::constants::{CURVE_ORDER, FIELD_SIZE, GENERATOR_X, GENERATOR_Y};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use secp256k1::rand::rng;
use eliptic_curve_math::{Point, multiply, add, get_y_from_x};
use num_traits::{Euclid};
use secp256k1::hashes::{sha256, Hash};
use num_bigint_dig::{RandBigInt};
use crate::eliptic_curve_math;



pub fn pre_sign(message: &Vec<u8>, nonce: &BigInt, statement_t: &Point, prv_key: &SecretKey, secret_t: &BigInt) -> (BigInt, BigInt, PublicKey, Point, Point){
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

    let generator = Point { x: GENERATOR_X.to_vec(), y: GENERATOR_Y.to_vec() };
    let q: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &CURVE_ORDER);
    let pub_key = prv_key.public_key(&secp);


    // let tG = multiply(&generator, &secret_t);
    let x_secret = BigInt::from_bytes_be(num_bigint::Sign::Plus, &prv_key.secret_bytes());


    // let (sign2, bytes2) =  rng().gen_bigint(256).to_bytes_be();
    // let nonce_k = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes2).rem_euclid(&q);

    let r_line_kG = multiply(&generator, &nonce);
    let r_kT = multiply(statement_t, &nonce);

    let r: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &r_kT.x);


    let z: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus,sha256::Hash::hash(message).as_byte_array()).rem_euclid(&q);


    // let s_line = (&z + (&r*&x_secret)).modinv(&nonce).unwrap();
    let s_line: BigInt = (nonce.modinv(&q).unwrap()*(&z + &r*x_secret)).rem_euclid(&q);

    return (r, s_line, pub_key, r_kT, r_line_kG)
}

pub fn pre_verify(message: &Vec<u8>, s_line: &BigInt, r: &BigInt, r_line_kG: Point, pub_key: &PublicKey) -> bool {
    let generator = Point { x: GENERATOR_X.to_vec(), y: GENERATOR_Y.to_vec() };
    let q: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus, &CURVE_ORDER);

    let xG: eliptic_curve_math::Point = get_y_from_x(&pub_key.to_string());

    let message_hash: BigInt = BigInt::from_bytes_be(num_bigint::Sign::Plus,sha256::Hash::hash(message).as_byte_array()).rem_euclid(&q);
    
    let u: BigInt = (message_hash*&s_line.modinv(&q).unwrap()).rem_euclid(&q);
    let v: BigInt = (r*&s_line.modinv(&q).unwrap()).rem_euclid(&q);

    let uG = multiply(&generator, &u);
    let vX = multiply(&xG, &v);


    let verification_point: Point = add(&uG, &vX);

    // println!("{}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &r_line_kG.x));
    // println!("{}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &verification_point.x));
    // println!("{}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &r_line_kG.y));
    // println!("{}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &verification_point.y));
    return &r_line_kG.x == &verification_point.x && &r_line_kG.y == &verification_point.y;

}