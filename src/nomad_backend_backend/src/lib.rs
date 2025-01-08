use ic_cdk::api::management_canister::schnorr::{SchnorrAlgorithm, SchnorrKeyId};
use ic_cdk::{query, update};
use candid::{CandidType, Deserialize, Nat, Principal};
use std::collections::HashMap;
use std::cell::RefCell;
use bip39::Mnemonic;
use bitcoin::{Network, Address, PublicKey, PrivateKey, XOnlyPublicKey};
use bitcoin::bip32::{ExtendedPrivKey, DerivationPath};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha2::{Sha256, Digest};
use hex;
use bs58;

mod wallet;
mod tx;

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
        name: "Test_Key".to_string()
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
fn mint_brc20_token(
    contract_address: String,
    user_address: String,
    tx_hash: String,
) -> Result<String, String> {
    let tx = tx::decode::parse_tx_from_hash(tx_hash).unwrap();
    let receive_amount = {
        let mut amount = 0;
        for output in tx.outputs {
            if let Some(address) = output.address {
                if address == contract_address {
                    amount += output.value;
                }
            }
        }
        amount
    };

    let mut old_vec: Vec<(String, u64)> = {
        match IDO_RECEIVE_MAP.with(|map| map.borrow().get(&contract_address).cloned()) {
            None => Vec::new(),
            Some(old_vec) => old_vec.clone(),
        }
    };
    old_vec.push((user_address, receive_amount));
    IDO_RECEIVE_MAP.with(|map| map.borrow_mut().insert(contract_address, old_vec));

    // 构造 PSBT 签名
    Ok("PSBT Sig".to_string())
}

ic_cdk::export_candid!();
