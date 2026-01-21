mod succinct_atomic_swap;
use bitcoin::bip32::{Xpriv, Xpub, DerivationPath};
use bitcoin::Network;
use bitcoin::hashes::{sha256, ripemd160, Hash};
use std::str::FromStr;

fn main() {

use bitcoin::bip32::{Xpriv, Xpub, DerivationPath};
use bitcoin::Network;
use std::str::FromStr;

// Create master key from seed
let seed = [0u8; 32]; // Use proper entropy in production!
let master_key = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();

// Derive child keys using a path like m/84'/0'/0'/0/0
let path = DerivationPath::from_str("m/84'/1'/0'/0").unwrap();
let secp = bitcoin::secp256k1::Secp256k1::new();
let child_key = master_key.derive_priv(&secp, &path).unwrap();


let mut privs: Vec<String> = vec![];
let mut pubs: Vec<String> = vec![];
let mut pub_hashes: Vec<String> = vec![];

for i in 0..2000 {
    let priv_key = child_key.derive_priv(&secp, &DerivationPath::from_str(i.to_string().as_str()).unwrap()).unwrap().to_priv(); 
    let pub_key = priv_key.public_key(&secp);
    
    let sha256_hash  = priv_key.public_key(&secp).to_bytes();
    let ripemd160_hash  = sha256::Hash::hash(&sha256_hash );
    let pub_key_hash = hex::encode(ripemd160::Hash::hash(&ripemd160_hash .to_byte_array()).to_byte_array());



    privs.push(priv_key.to_string());
    pubs.push(pub_key.to_string());
    pub_hashes.push(pub_key_hash.clone());

    println!("{}", priv_key.to_string());
    println!("{}", pub_key.to_string());
    println!("{}", pub_key_hash);
}

// Get the private key

// Get extended public key
let xpub = Xpub::from_priv(&secp, &master_key);


}