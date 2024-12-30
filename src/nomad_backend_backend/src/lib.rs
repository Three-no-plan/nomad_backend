use ic_cdk::api::management_canister::schnorr::{SchnorrAlgorithm, SchnorrKeyId};
use ic_cdk::{query, update};
use candid::{CandidType, Deserialize};
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

#[derive(candid::CandidType, candid::Deserialize, Clone)]
struct ContractInfo {
    id: usize,
    contract_address: String,
}

#[derive(Clone)]
struct ContractDetails {
    contract_address: String,
    derivation_path: Vec<Vec<u8>>
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


thread_local! {
    static CONTRACT_DETAILS: RefCell<HashMap<usize, ContractDetails>> = RefCell::new(HashMap::new());
    static CONTRACT_COUNTER: RefCell<usize> = RefCell::new(0);
    static TOKEN_MAP: RefCell<HashMap<String, TokenInfo>> = RefCell::new(HashMap::new());
}

fn generate_contract_id() -> usize {
    CONTRACT_COUNTER.with(|counter| {
        let mut current_counter = counter.borrow_mut();
        *current_counter += 1;
        *current_counter
    })
}

#[ic_cdk::init]
fn init() {}

#[ic_cdk::update]
async fn create_contract() -> Result<ContractInfo, String> {
    let derivation_path: Vec<Vec<u8>> = vec![ic_cdk::api::time().to_be_bytes().to_vec()];
    let schnorr_public_key = wallet::get_schnorr_public_key(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340secp256k1,
        name: "Test_Key".to_string()
    }, derivation_path.clone()).await;
    let contract_address = wallet::public_key_to_p2tr_script_spend_address(Network::Bitcoin, &schnorr_public_key);
    let id = {
        CONTRACT_COUNTER.with(|counter| {
            let id = counter.borrow().clone();
            counter.replace(id + 1);
            id
        })
    };
    CONTRACT_DETAILS.with(|map| {
        map.borrow_mut().insert(id, ContractDetails {
            contract_address: contract_address.to_string(),
            derivation_path: derivation_path.clone()
        })
    });
    Ok(ContractInfo {
        id,
        contract_address: contract_address.to_string(),
    })
}

#[ic_cdk::query]
fn get_contract_address(contract_id: usize) -> Result<ContractInfo, String> {
    CONTRACT_DETAILS.with(|contracts| {
        contracts.borrow()
            .get(&contract_id)
            .map(|details| ContractInfo {
                id: contract_id,
                contract_address: details.contract_address.clone(),
            })
            .ok_or_else(|| "contract not found".to_string())
    })
}

#[ic_cdk::query]
fn list_contract() -> Vec<usize> {
    CONTRACT_DETAILS.with(|contracts| {
        contracts.borrow()
            .keys()
            .cloned()
            .collect()
    })
}

// #[ic_cdk::update]
// fn deploy_token(token_name: String, token_type: TokenType, deploy_hash: String) -> Result<deployRecord, String> {
//     if token_name.is_empty() || deploy_hash.is_empty() {
//         return Err("Token name and deploy hash cannot be empty".to_string());
//     }
//     // decode hash，找到部署者

//     // runes确定token有效

//     // brc20确认token有效


//     let record = deployRecord {
//         token_name,
//         token_type,
//         deploy_hash,
//         timestamp: ic_cdk::api::time(), 
//     };

//     Ok(record)
// }


// #[ic_cdk::update]
// fn process_tx(tx_hex: &str) -> Result<Transaction, String> {
//     parse_tx_from_hash(tx_hex)
// }

#[ic_cdk::update]
fn deploy_brc20_token(
    contract_address: String,
    token_name: String,
    deploy_tx: String
) {
    let token_info = TokenInfo {
        token_type: TokenType::BRC20,
        token_name,
        total_amount: 0u64,
        balance_map: HashMap::new(),
        deploy_tx
    };
    TOKEN_MAP.with(|map| map.borrow_mut().insert(contract_address, token_info));
}

#[ic_cdk::update]
fn mint_brc20_token(
    contract_address: String,
    user_btc_address: String,
    amount: u64,
    tx: String
) -> Result<(), String> {
    match TOKEN_MAP.with(|map| map.borrow().get(&contract_address).cloned()) {
        None => Err(format!("Not Found Contract !")),
        Some(mut token_info) => {
            let old_balance = {
                match token_info.balance_map.get(&user_btc_address) {
                    None => 0,
                    Some(balance) => balance.clone()
                }
            };
            token_info.balance_map.insert(user_btc_address, old_balance + amount);
            token_info.total_amount += amount;
            
            TOKEN_MAP.with(|map| map.borrow_mut().insert(contract_address, token_info));

            Ok(())
        }
    }
}

ic_cdk::export_candid!();
