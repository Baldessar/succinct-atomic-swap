
use core::slice;

use num_bigint::{BigInt};
use bitcoin::secp256k1::constants::{CURVE_ORDER, FIELD_SIZE, GENERATOR_X, GENERATOR_Y};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use eliptic_curve_math::{Point, multiply, add, get_y_from_x};
use num_traits::{Euclid};
use bitcoin::secp256k1::hashes::{sha256, Hash};
use bitcoin::secp256k1;
use crate::bitcoin_operations::{encode_inputs, encode_outputs, build_script_pub_key_p2wpkh};
use crate::{eliptic_curve_math, succinct_atomic_swap};



pub fn build_on_chain_transaction_btc(sender_pub_key: &bitcoin::PublicKey, receiver_pub_key: &bitcoin::PublicKey, inputs: &Vec<&str>, outputs:Vec<(Vec<u8>, u64)>) {

}

pub fn build_success_transaction() {

}

pub fn build_refund_transaction_1() { // Script do it later

}

pub fn build_refund_transaction_2() {

}

pub fn build_revoke_transaction() {

}

pub fn build_timeout_transaction() {

}
