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

#[derive(candid::CandidType, candid::Deserialize, Clone)]
struct contractInfo {
    id: usize,
    contract_address: String,
}

#[derive(Clone)]
struct contractDetails {
    entropy: Vec<u8>,
    mnemonic: String,
    seed: String,
    wif: String,
    contract_address: String,
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
    static contract_DETAILS: RefCell<HashMap<usize, contractDetails>> = RefCell::new(HashMap::new());
    static contract_COUNTER: RefCell<usize> = RefCell::new(0);
}

fn get_random_entropy() -> [u8; 16] {
    let now_millis = ic_cdk::api::time();
    let mut seed = [0u8; 32];
    
    for i in 0..4 {
        seed[i*8..(i+1)*8].copy_from_slice(&now_millis.to_be_bytes());
    }
    
    let mut rng = StdRng::from_seed(seed);
    let mut random_bytes = [0u8; 16];
    rng.fill_bytes(&mut random_bytes);
    random_bytes
}

fn generate_contract_id() -> usize {
    contract_COUNTER.with(|counter| {
        let mut current_counter = counter.borrow_mut();
        *current_counter += 1;
        *current_counter
    })
}



fn parse_varint(data: &[u8], offset: &mut usize) -> (usize, String) {
    let first_byte = data[*offset];
    let original_offset = *offset;
    *offset += 1;

    let (value, len) = match first_byte {
        0..=0xfc => (first_byte as usize, 1),
        0xfd => {
            let value = u16::from_le_bytes([data[*offset], data[*offset + 1]]) as usize;
            *offset += 2;
            (value, 3)
        }
        0xfe => {
            let value = u32::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]) as usize;
            *offset += 4;
            (value, 5)
        }
        _ => {
            let value = u64::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3], data[*offset + 4], data[*offset + 5], data[*offset + 6], data[*offset + 7]]) as usize;
            *offset += 8;
            (value, 9)
        }
    };

    let raw = hex::encode(&data[original_offset..original_offset + len]);
    (value, raw)
}

fn script_to_address(script: &[u8]) -> Option<String> {
    if script.is_empty() {
        return None;
    }

    if script.len() == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac {
        return Some(hash160_to_address(&script[3..23], 0x00));
    }

    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return Some(hash160_to_address(&script[2..22], 0x05));
    }

    None
}

fn hash160_to_address(hash: &[u8], version: u8) -> String {
    let mut address = vec![version];
    address.extend_from_slice(hash);

    let mut hasher = Sha256::new();
    hasher.update(&address);
    let temp = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(temp);
    let checksum = &hasher.finalize()[0..4];

    address.extend_from_slice(checksum);
    bs58::encode(address).into_string()
}

fn parse_tx_from_hash(hex_str: &str) -> Result<Transaction, Box<dyn std::error::Error>> {
    let data = hex::decode(hex_str)?;

    let mut offset = 0;
    offset += 4; // Skip version (we don't need it)

    let (input_count, _) = parse_varint(&data, &mut offset);
    let mut inputs = Vec::with_capacity(input_count);

    for _ in 0..input_count {
        let start_pos = offset;
        let raw_txid = hex::encode(&data[offset..offset + 32]);
        let txid = raw_txid.clone();
        offset += 32;

        let vout = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        let (script_len, _) = parse_varint(&data, &mut offset);
        let raw_script = hex::encode(&data[offset..offset + script_len]);
        let script = raw_script.clone();
        offset += script_len;

        let sequence = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        inputs.push(Input {
            txid,
            vout,
            script,
            sequence,
        });
    }

    let (output_count, _) = parse_varint(&data, &mut offset);
    let mut outputs = Vec::with_capacity(output_count);

    for _ in 0..output_count {
        let value = u64::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        offset += 8;

        let (script_len, _) = parse_varint(&data, &mut offset);
        let script_data = &data[offset..offset + script_len];
        let raw_script = hex::encode(script_data);
        let script = raw_script.clone();
        let address = script_to_address(script_data);
        offset += script_len;

        outputs.push(Output {
            value,
            script,
            address,
        });
    }

    let lock_time = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
    offset += 4;

    Ok(Transaction {
        inputs,
        outputs,
        lock_time,
    })
}


fn generate_contract(entropy: [u8; 16]) -> Result<contractInfo, String> {
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| format!("Mnemonic generation error: {}", e))?;
   
    let seed: [u8; 64] = mnemonic.to_seed("");
    let secp = bitcoin::secp256k1::Secp256k1::new();
   
    let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &seed)
        .map_err(|e| format!("Extended private key error: {}", e))?;
   
    let path = "m/86'/0'/0'/0/0".parse::<DerivationPath>()
        .map_err(|e| format!("Derivation path error: {}", e))?;
   
    let child_xpriv = xpriv.derive_priv(&secp, &path)
        .map_err(|e| format!("Child private key derivation error: {}", e))?;
   
    let private_key = PrivateKey::new(child_xpriv.private_key, Network::Bitcoin);
    let public_key = PublicKey::from_private_key(&secp, &private_key);
    let x_only_public_key: XOnlyPublicKey = public_key.inner.into();
   
    let contract_address = Address::p2tr(&secp, x_only_public_key, None, Network::Bitcoin);
   
    let contract_id = generate_contract_id();
   
    let contract_details = contractDetails {
        entropy: entropy.to_vec(),
        mnemonic: mnemonic.to_string(),
        seed: hex::encode(&seed),
        wif: private_key.to_string(),
        contract_address: contract_address.to_string(),
    };

    contract_DETAILS.with(|contracts| {
        contracts.borrow_mut().insert(contract_id, contract_details);
    });

    Ok(contractInfo {
        id: contract_id,
        contract_address: contract_address.to_string(),
    })
}

#[ic_cdk::init]
fn init() {}

#[ic_cdk::update]
async fn create_contract() -> Result<contractInfo, String> {
    let entropy = get_random_entropy();
    generate_contract(entropy)
}

#[ic_cdk::query]
fn get_contract_address(contract_id: usize) -> Result<contractInfo, String> {
    contract_DETAILS.with(|contracts| {
        contracts.borrow()
            .get(&contract_id)
            .map(|details| contractInfo {
                id: contract_id,
                contract_address: details.contract_address.clone(),
            })
            .ok_or_else(|| "contract not found".to_string())
    })
}

#[ic_cdk::query]
fn list_contract() -> Vec<usize> {
    contract_DETAILS.with(|contracts| {
        contracts.borrow()
            .keys()
            .cloned()
            .collect()
    })
}

#[ic_cdk::update]
fn upgrade_contract_data(contract_id: usize, new_data: Option<String>) -> Result<(), String> {
    contract_DETAILS.with(|contracts| {
        let mut contract_map = contracts.borrow_mut();
        
        match contract_map.get_mut(&contract_id) {
            Some(_contract) => {
                Ok(())
            },
            None => Err("contract not found".to_string())
        }
    })
}

#[ic_cdk::update]
fn deploy_token(token_name: String, token_type: TokenType, deploy_hash: String) -> Result<deployRecord, String> {
    if token_name.is_empty() || deploy_hash.is_empty() {
        return Err("Token name and deploy hash cannot be empty".to_string());
    }
    // decode hash，找到部署者

    // runes确定token有效

    // brc20确认token有效


    let record = deployRecord {
        token_name,
        token_type,
        deploy_hash,
        timestamp: ic_cdk::api::time(), 
    };

    Ok(record)
}


// #[ic_cdk::update]
// fn process_tx(tx_hex: &str) -> Result<Transaction, String> {
//     parse_tx_from_hash(tx_hex)
// }


ic_cdk::export_candid!();
