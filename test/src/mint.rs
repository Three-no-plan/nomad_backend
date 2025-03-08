use std::ops::Add;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::script::{PushBytes, PushBytesBuf};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
use ic_agent::Agent;
use candid::{Principal, Encode, Decode};
use crate::ido_did::{MintBrc20Args, MintBrc20Result};
use crate::IDO_CANISTER_STR;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::All;
use crate::BTC_NETWORK;

// mint 需要构建两笔笔交易，拿到hex
// 第一笔交易包含：
// 1.用户向合约p2tr地址转 btc，需要在opreturn地址中嵌入 brc20 的接收地址
// 2.用户向一个p2tr中间地址转一定量 btc，用于中间地址来刻录 brc20_transfer inscription
// 第二笔交易为：
// 中间p2tr地址构建 brc20_transfer inscription 转给合约p2tr地址
pub async fn build_mint_tx(
    user_secp: Secp256k1<All>,
    user_private_key: PrivateKey,
    temp_p2tr_address_secp: Secp256k1<All>,
    utxo_txid: Txid,
    utxo_value: u64,
    utxo_vout: u32,
    canister_p2tr_address_str: &str,
    to_canister_value: u64,
    brc20_receive_address_str: &str,
    temporary_p2tr_address_str: &str,
    to_temporary_p2tr_value: u64,
) {
    // let user_public_key = user_private_key.public_key(&user_secp);
    
    // let user_p2tr_address = Address::p2tr(
    //     &user_secp, 
    //     XOnlyPublicKey::from_slice(&user_public_key.to_bytes()), 
    //     None, 
    //     BTC_NETWORK
    // );
    // let canister_p2tr_address = Address::from_str(canister_p2tr_address_str).unwrap().require_network(BTC_NETWORK).unwrap();
    // let temporary_p2tr_address = Address::from_str(temporary_p2tr_address_str).unwrap().require_network(BTC_NETWORK).unwrap();

    // let mut unsigned_tx_1 = Transaction {
    //     version: Version::TWO,
    //     lock_time: LockTime::ZERO,
    //     input: vec![TxIn {
    //         previous_output: OutPoint {
    //             txid: user_txid,
    //             vout: user_vout
    //         },
    //         script_sig: ScriptBuf::new(),
    //         sequence: Sequence::MAX,
    //         witness: Witness::new()
    //     }],
    //     output: vec![
    //         TxOut {
    //             value: Amount::from_sat(to_canister_value),
    //             script_pubkey: canister_p2tr_address.script_pubkey()
    //         },
    //         TxOut {
    //             value: Amount::ZERO,
    //             script_pubkey: ScriptBuf::new_op_return({
    //                 let mut buffer = PushBytesBuf::new();
    //                 buffer.extend_from_slice(brc20_receive_address_str.as_bytes()).unwrap();
    //                 buffer.as_push_bytes().to_owned()
    //             })
    //         },
    //         TxOut {
    //             value: Amount::from_sat(to_temporary_p2tr_value),
    //             script_pubkey: temporary_p2tr_address.script_pubkey()
    //         }
    //     ]
    // };

    // let tx_hex_1 = {
    //     let mut sighash_cache = SighashCache::new(unsigned_tx_1);
    //     let sighash = sighash_cache.taproot_key_spend_signature_hash(
    //         0, 
    //         &Prevouts::All(TxOut {
    //             value: Amount::from_sat(utxo_value),
    //             script_pubkey: 
    //         })), sighash_type)
    // }

}

pub async fn test_mint_brc20_token(
    agent: Agent,
    args: MintBrc20Args
) {
    let canister = Principal::from_text(IDO_CANISTER_STR).unwrap();

    let mint_res_blob = agent.update(
        &canister, "mint_brc20_token"
    )
    .with_arg(Encode!(&args).unwrap())
    .call_and_wait()
    .await.unwrap(); 

    let mint_res = Decode!(&mint_res_blob, MintBrc20Result).unwrap();

    match mint_res {
        MintBrc20Result::Ok(sig_hex) => println!("test_mint_brc20_token sig_hex: {}", sig_hex),
        MintBrc20Result::Err(err) => panic!("test_mint_brc20_token err : {}", err)
    }
}