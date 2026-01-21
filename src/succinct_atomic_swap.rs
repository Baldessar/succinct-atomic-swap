use std::{str::FromStr};
use bitcoin::{Amount, CompressedPublicKey, absolute::Time};
use bitcoincore_rpc::json::{ListUnspentResultEntry};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::{
    absolute::LockTime,
    transaction::Version,
    Address,
    Network,
    OutPoint,
    ScriptBuf,
    Sequence,
    Transaction,
    Txid,
    TxIn,
    TxOut,
    Witness,
    absolute,
    amount,
    opcodes::all::*,
    script::Builder,
    transaction,
};



pub fn build_on_chain_transaction_btc(
    alice_pub_key: &bitcoin::PublicKey,
    bob_pub_key: &bitcoin::PublicKey,
    change_pub_key: &bitcoin::PublicKey,
    utxos: &Vec<&ListUnspentResultEntry>,
    sats_amount: u64,
    fee: u64,
) -> (String, String) {

    let multisig_script = Builder::new()
        .push_opcode(OP_PUSHNUM_2)  // Require 2 signatures
        .push_key(&alice_pub_key)
        .push_key(&bob_pub_key)
        .push_opcode(OP_PUSHNUM_2)  // Out of 2 keys
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();

        // Create P2WSH address from the multisig script
    let p2wsh_address = Address::p2wsh(&multisig_script, Network::Signet);
    let p2wpkh_change_address = Address::p2wpkh(&CompressedPublicKey::from_str(&change_pub_key.to_string().as_str()).unwrap(), Network::Signet);

    let mut inputs: Vec<TxIn> = vec![];

    let mut available_amount: u64 = 0;

    for utxo in utxos {
        let input = TxIn {
            previous_output: OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };

        available_amount += utxo.amount.to_sat();

        inputs.push(input);
    }

    available_amount -= fee;
    available_amount -= sats_amount;
    // Create the transaction

    let output = TxOut {
        value: amount::Amount::from_sat(sats_amount), // Subtract fee (adjust as needed)
        script_pubkey: p2wsh_address.script_pubkey(),
    };

    let change_output = TxOut {
        value: amount::Amount::from_sat(available_amount), // Subtract fee (adjust as needed)
        script_pubkey: p2wpkh_change_address.script_pubkey(),
    };

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: vec![output, change_output],
    };

    
    return (tx.compute_txid().to_string(), bitcoin::consensus::encode::serialize_hex(&tx));

}

pub fn build_success_transaction(prev_txid: &str, amount: u64, fee: u64, bob_pub_key: &bitcoin::PublicKey) -> (String, String){
    let previous_txid = prev_txid.parse::<Txid>().unwrap();
    let previous_vout: u32 = 0;
    let input = TxIn {
        previous_output: OutPoint {
            txid: previous_txid,
            vout: previous_vout,
        },
        script_sig: ScriptBuf::new(), // Empty for SegWit
        sequence: Sequence::MAX,
        witness: Witness::new(), // Will fill this later
    };


    let recipient_address = Address::p2wpkh(&CompressedPublicKey::try_from(bob_pub_key.clone()).unwrap(), Network::Bitcoin);
    let output = TxOut {
        value: Amount::from_sat(amount - fee), // amount in satoshis
        script_pubkey: recipient_address.script_pubkey(),
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };


    return (tx.compute_txid().to_string(), bitcoin::consensus::encode::serialize_hex(&tx));

}

pub fn build_refund_transaction_1() { // Script do it later

}

pub fn build_revoke_transaction(prev_txid: &str, amount: u64, fee: u64, alice_pub_key: &bitcoin::PublicKey, bob_pub_key: &bitcoin::PublicKey) -> (String, String){
    let previous_txid = prev_txid.parse::<Txid>().unwrap();
    let previous_vout: u32 = 0;
    let multisig_script = Builder::new()
        .push_opcode(OP_PUSHNUM_2)  // Require 2 signatures
        .push_key(&alice_pub_key)
        .push_key(&bob_pub_key)
        .push_opcode(OP_PUSHNUM_2)  // Out of 2 keys
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();

    let input = TxIn {
        previous_output: OutPoint {
            txid: previous_txid,
            vout: previous_vout,
        },
        script_sig: ScriptBuf::new(), // Empty for SegWit
        sequence: Sequence::MAX,
        witness: Witness::new(), // Will fill this later
    };
    let p2wsh_address = Address::p2wsh(&multisig_script, Network::Signet);


    let output = TxOut {
        value: amount::Amount::from_sat(amount-fee), // Subtract fee (adjust as needed)
        script_pubkey: p2wsh_address.script_pubkey(),
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_time(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32).unwrap(),
        input: vec![input],
        output: vec![output],
    };

    return (tx.compute_txid().to_string(), bitcoin::consensus::encode::serialize_hex(&tx));


}

pub fn build_refund_transaction_2() {

}

pub fn build_timeout_transaction() {

}