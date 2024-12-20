use ic_cdk::{query, update};
use candid::{CandidType, Deserialize};
use std::collections::HashMap;
use std::cell::RefCell;
use bip39::Mnemonic;
use bitcoin::{Network, Address, PublicKey, PrivateKey, XOnlyPublicKey};
use bitcoin::bip32::{ExtendedPrivKey, DerivationPath};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
// decode_tx
// mod tx; 
// use tx::decode::{Transaction, parse_tx_from_hash};

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
// #[derive(Clone)]  
// struct ParseResult {
//     success: bool,
//     transaction: Option<Transaction>,
//     error: Option<String>
// }


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

// #[ic_cdk::query]
// async fn parse_transaction(tx_hex: String) -> ParseResult {
//     match parse_tx_from_hash(tx_hex).await {
//         Ok(tx) => ParseResult {
//             success: true,
//             transaction: Some(tx),
//             error: None
//         },
//         Err(e) => ParseResult {
//             success: false,
//             transaction: None,
//             error: Some(e)
//         }
//     }
// }

ic_cdk::export_candid!();
