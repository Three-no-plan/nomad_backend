use ic_cdk::api::management_canister::schnorr::{SchnorrAlgorithm, SchnorrKeyId};
use candid::{CandidType, Deserialize, Nat, Principal};
use psbt::types::InputUtxo;
use std::collections::HashMap;
use std::cell::RefCell;
use bitcoin::{psbt::PsbtSighashType, Network, Psbt, PublicKey};

mod psbt;
mod wallet;
mod tx;

pub use psbt::{
    types::{TransactionInput, TransactionOutput, TransactionResult},
    builder::PsbtBuilder,
    transaction::{create_transaction_multi, combine_psbt},
};

#[derive(CandidType, Deserialize, Clone)]
struct ContractInfo {
    contract_address: String,
    derivation_path: Vec<Vec<u8>>,
    token_name: String,
    token_amount: u64,
    deploy_tx_hash: String,
    ido_target_btc_amount: u64,
}

#[derive(CandidType, Deserialize, Clone)]
struct DeployBrc20Args {
    contract_address: String,
    token_name: String,
    token_amount: u64,
    deploy_tx_hash: String,
    ido_target_btc_amount: u64,
}

#[derive(CandidType, Deserialize, Debug)]
pub enum TxError {
    DecodeError(String),
    InvalidFormat(String),
    InvalidLength(String),
}

// 定义代币类型
#[derive(CandidType, Clone, Debug,Deserialize, PartialEq)]
pub enum TokenType {
    BRC20,
    RUNES,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
struct TokenInfo {
    token_type: TokenType,
    token_name: String,
    total_amount: u64,
    balance_map: HashMap<String, u64>,
    deploy_tx: String,
}

#[derive(CandidType, Clone, Debug)]
pub struct deployRecord {
    pub token_name: String,
    pub token_type: TokenType,
    pub deploy_hash: String,
    pub timestamp: u64,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct Transaction {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    lock_time: u32,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct Input {
    txid: String,
    vout: u32,
    script: String,
    sequence: u32,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct Output {
    value: u64,
    script: String,
    address: Option<String>,
}

#[derive(CandidType, Deserialize, Debug)]
pub enum QueryBrc20Result {
  #[serde(rename="ok")]
  Ok(String,candid::Nat,),
  #[serde(rename="err")]
  Err(String),
}

const BRC20_CANISTER_ID: &str = "wvwai-ziaaa-aaaaj-azxza-cai";
const SCHNORR_KEY_NAME: &str = "test_key_1";

thread_local! {
    static CONTRACT_MAP: RefCell<HashMap<String, ContractInfo>> = RefCell::new(HashMap::new());
    static TOKEN_MAP: RefCell<HashMap<String, TokenInfo>> = RefCell::new(HashMap::new());
    static IDO_RECEIVE_MAP: RefCell<HashMap<String, Vec<(String, u64)>>> = RefCell::new(HashMap::new());
}

#[ic_cdk::init]
fn init() {}

#[ic_cdk::update]
async fn create_contract() -> Result<String, String> {
    let derivation_path: Vec<Vec<u8>> = vec![ic_cdk::api::time().to_be_bytes().to_vec()];
    let schnorr_public_key = wallet::get_schnorr_public_key(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340secp256k1,
        name: SCHNORR_KEY_NAME.to_string()
    }, derivation_path.clone()).await;
    let contract_address = wallet::public_key_to_p2tr_script_spend_address(Network::Bitcoin, &schnorr_public_key);
    let contract_address_string = contract_address.to_string();
    CONTRACT_MAP.with(|map| {
        map.borrow_mut().insert(contract_address_string.clone(), ContractInfo {
            contract_address: contract_address_string.clone(),
            derivation_path: derivation_path.clone(),
            token_name: "".to_string(),
            token_amount: 0,
            deploy_tx_hash: "".to_string(),
            ido_target_btc_amount: 0
        })
    });
    Ok(contract_address_string)
}

#[ic_cdk::query]
fn get_contact_info(contract_address: String) -> Option<ContractInfo> {
    CONTRACT_MAP.with(|map| map.borrow().get(&contract_address).cloned())
}

#[ic_cdk::query]
fn get_contract_map_entries() -> Vec<ContractInfo> {
    CONTRACT_MAP.with(|map| map.borrow().values().cloned().collect())
}

#[ic_cdk::query]
fn get_ido_receive_vec(ido_address: String) -> Option<Vec<(String, u64)>> {
    IDO_RECEIVE_MAP.with(|map| map.borrow().get(&ido_address).cloned())
}

#[ic_cdk::update]
async fn deploy_brc20_token(args: DeployBrc20Args) -> Result<(), String> {
    // 去 brc20 canister 验证
    let tx = tx::decode::parse_tx_from_hash(args.deploy_tx_hash.clone()).unwrap();
    let std_btc_tx = tx.convert_to_std_bitcoin_tx();
    let tx_id = std_btc_tx.compute_ntxid().to_string();
    let call_res = ic_cdk::call::<(String, String, String, ), (QueryBrc20Result, )>(
        Principal::from_text(BRC20_CANISTER_ID).unwrap(), 
        "querybrc_20", 
        (args.contract_address.clone(), args.token_name.clone(), tx_id, )
    ).await.unwrap().0;
    match call_res {
        QueryBrc20Result::Err(err) => return Err(format!("querybrc_20 error : {}", err)),
        QueryBrc20Result::Ok(from_address, amount) => {
            if Nat::from(args.token_amount) != amount {
                return Err(format!("args.token_amount is {} but brc20 canister get amount is {}", args.token_amount, amount))
            }
        }
    }

    // 更新合约信息
    match CONTRACT_MAP.with(|map| map.borrow().get(&args.contract_address).cloned()) {
        None => Err(format!("Not Found The Contract !")),
        Some(info) => {
            CONTRACT_MAP.with(|map| map.borrow_mut().insert(args.contract_address, ContractInfo {
                contract_address: info.contract_address,
                derivation_path: info.derivation_path,
                token_name: args.token_name,
                token_amount: args.token_amount,
                deploy_tx_hash: args.deploy_tx_hash,
                ido_target_btc_amount: args.ido_target_btc_amount
            }));
            Ok(())
        }
    }
}

#[ic_cdk::update]
async fn mint_brc20_token(
    contract_address: String,
    user_address: String,
    mint_psbt_tx_hex: String,
) -> Result<String, String> {
    match CONTRACT_MAP.with(|map| map.borrow().get(&contract_address).cloned()) {
        None => Err(format!("Not Found The Contract !")),
        Some(info) => {
            let user_psbt = Psbt::deserialize(&hex::decode(mint_psbt_tx_hex.clone()).unwrap()).unwrap();
            let user_psbt_tx = user_psbt.unsigned_tx;
            let user_psbt_tx_id = user_psbt_tx.compute_txid(); 
        
            let mut contrcat_psbt_builder = psbt::builder::PsbtBuilder::new(Network::Bitcoin);
            contrcat_psbt_builder.add_input(
                InputUtxo {
                    tx_id: user_psbt_tx_id,
                    vout: 0,
                    value: user_psbt_tx.output[0].value
                }, 
                &contract_address, 
                Some(&wallet::get_schnorr_public_key(SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Bip340secp256k1,
                    name: SCHNORR_KEY_NAME.to_string()
                }, info.derivation_path.clone()).await),
                Some(PsbtSighashType::from_u32(2))
            ).unwrap();
            contrcat_psbt_builder.add_output(&user_address, user_psbt_tx.output[0].value.to_sat()).unwrap();

            let contract_psbt = contrcat_psbt_builder.build().unwrap();
            let contract_psbt_hex = contract_psbt.serialize_hex();

            let receive_amount = user_psbt_tx.output[1].value.to_sat();
        
            let mut old_vec: Vec<(String, u64)> = {
                match IDO_RECEIVE_MAP.with(|map| map.borrow().get(&contract_address).cloned()) {
                    None => Vec::new(),
                    Some(old_vec) => old_vec.clone(),
                }
            };
            old_vec.push((user_address, receive_amount));
            IDO_RECEIVE_MAP.with(|map| map.borrow_mut().insert(contract_address, old_vec));
        
            psbt::transaction::combine_psbt(&mint_psbt_tx_hex, &contract_psbt_hex)
        }
    }

}

#[ic_cdk::update]
async fn refund(contract_address: String, refund_message: Vec<u8>) -> Result<Vec<u8>, String> {
    match CONTRACT_MAP.with(|map| map.borrow().get(&contract_address).cloned()) {
        None => Err(format!("Not Found The Contract !")),
        Some(info) => {
            let sig = wallet::get_schnorr_signature(
                SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Bip340secp256k1,
                    name: SCHNORR_KEY_NAME.to_string()
                }, info.derivation_path.clone(), refund_message).await;
            Ok(sig)
        }
    }
}


pub fn process_external_transaction(
    network: &str,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>
) -> Result<TransactionResult, Box<dyn std::error::Error>> {
    if inputs.is_empty() {
        return Err("No transaction inputs provided".into());
    }

    if outputs.is_empty() {
        return Err("No transaction outputs provided".into());
    }


    let transaction_result = create_transaction_multi(network, inputs, outputs)?;

    Ok(transaction_result)
}



// fn process_tx(tx_hex: &str) -> Result<Transaction, String> {
//     parse_tx_from_hash(tx_hex)
// }

// #[ic_cdk::update]
// pub async fn create_transaction(
//     inputs: Vec<TransactionInput>,
//     outputs: Vec<TransactionOutput>
// ) -> Result<TransactionResult> {
//     create_transaction_impl(inputs, outputs)
//         .map_err(|e| Error::TransactionError(e.to_string()))
// }

ic_cdk::export_candid!();