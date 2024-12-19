use ic_cdk::init;
use ic_cdk::{query, update};
use candid::{Principal, CandidType,Deserialize};
use std::collections::HashMap;
use std::cell::RefCell;
use bip39::Mnemonic;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, Address, PublicKey, PrivateKey, XOnlyPublicKey};
use bitcoin::bip32::{ExtendedPrivKey, DerivationPath};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use bitcoin::{Transaction, TxIn, TxOut, Witness};

#[derive(candid::CandidType, candid::Deserialize, Clone)]
struct WalletInfo {
    id: usize,
    taproot_address: String,
}

#[derive(Clone)]
struct WalletDetails {
    entropy: Vec<u8>,
    mnemonic: String,
    seed: String,
    wif: String,
    taproot_address: String,
}

thread_local! {
    static WALLET_DETAILS: RefCell<HashMap<usize, WalletDetails>> = RefCell::new(HashMap::new());
    static WALLET_COUNTER: RefCell<usize> = RefCell::new(0);
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

fn generate_wallet_id() -> usize {
    WALLET_COUNTER.with(|counter| {
        let mut current_counter = counter.borrow_mut();
        *current_counter += 1;
        *current_counter
    })
}

fn generate_wallet(entropy: [u8; 16]) -> Result<WalletInfo, String> {
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| format!("Mnemonic generation error: {}", e))?;
   
    let seed: [u8; 64] = mnemonic.to_seed("");
    let secp = Secp256k1::new();
   
    let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &seed)
        .map_err(|e| format!("Extended private key error: {}", e))?;
   
    let path = "m/86'/0'/0'/0/0".parse::<DerivationPath>()
        .map_err(|e| format!("Derivation path error: {}", e))?;
   
    let child_xpriv = xpriv.derive_priv(&secp, &path)
        .map_err(|e| format!("Child private key derivation error: {}", e))?;
   
    let private_key = PrivateKey::new(child_xpriv.private_key, Network::Bitcoin);
    let public_key = PublicKey::from_private_key(&secp, &private_key);
    let x_only_public_key: XOnlyPublicKey = public_key.inner.into();
   
    let taproot_address = Address::p2tr(&secp, x_only_public_key, None, Network::Bitcoin);
   
    let wallet_id = generate_wallet_id();
   
    let wallet_details = WalletDetails {
        entropy: entropy.to_vec(),
        mnemonic: mnemonic.to_string(),
        seed: hex::encode(&seed),
        wif: private_key.to_string(),
        taproot_address: taproot_address.to_string(),
    };

    WALLET_DETAILS.with(|wallets| {
        wallets.borrow_mut().insert(wallet_id, wallet_details);
    });

    Ok(WalletInfo {
        id: wallet_id,
        taproot_address: taproot_address.to_string(),
    })
}


#[ic_cdk::init]
fn init() {
}

#[ic_cdk::update]
async fn create_wallet() -> Result<WalletInfo, String> {
    let entropy = get_random_entropy();
    generate_wallet(entropy)
}

#[ic_cdk::query]
fn get_wallet_address(wallet_id: usize) -> Result<WalletInfo, String> {
    WALLET_DETAILS.with(|wallets| {
        wallets.borrow()
            .get(&wallet_id)
            .map(|details| WalletInfo {
                id: wallet_id,
                taproot_address: details.taproot_address.clone(),
            })
            .ok_or_else(|| "Wallet not found".to_string())
    })
}

#[ic_cdk::query]
fn list_wallet() -> Vec<usize> {
    WALLET_DETAILS.with(|wallets| {
        wallets.borrow()
            .keys()
            .cloned()
            .collect()
    })
}

#[ic_cdk::update]
fn upgrade_wallet_data(wallet_id: usize, new_data: Option<String>) -> Result<(), String> {
    WALLET_DETAILS.with(|wallets| {
        let mut wallet_map = wallets.borrow_mut();
        
        match wallet_map.get_mut(&wallet_id) {
            Some(_wallet) => {

                Ok(())
            },
            None => Err("Wallet not found".to_string())
        }
    })
}

ic_cdk::export_candid!();