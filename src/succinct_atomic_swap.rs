use std::str::FromStr;
use bitcoin::{Amount, CompressedPublicKey};
use bitcoincore_rpc::json::{ListUnspentResultEntry};

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
}

pub fn build_refund_transaction_1() { // Script do it later

}

pub fn build_refund_transaction_2() {

}

pub fn build_revoke_transaction() {

}

pub fn build_timeout_transaction() {

}
