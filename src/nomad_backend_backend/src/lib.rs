use bitcoin::hashes::Hash;
use ic_cdk::api::management_canister::bitcoin::{GetUtxosRequest, UtxoFilter};
use ic_cdk::api::management_canister::schnorr::{SchnorrAlgorithm, SchnorrKeyId};
use candid::{CandidType, Deserialize, Nat, Principal};
use psbt::types::{InputSignatureType, InputUtxo};
use std::cell::RefCell;
use bitcoin::{Network, Psbt};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use ic_stable_structures::storable::{Bound, Storable};
use std::borrow::Cow;
use candid::{Encode, Decode};

type Memory = VirtualMemory<DefaultMemoryImpl>;

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
    token_name: String,
    token_amount: u64,
    deploy_tx_hash: String,
    ido_target_btc_amount: u64,
    already_ido_btc_amount: u64
}

#[derive(CandidType, Deserialize, Clone)]
struct DeployBrc20Args {
    deploy_tx_hash: String,
    token_name: String,
    token_amount: u64,
    ido_target_btc_vol: u64,
}

#[derive(CandidType, Deserialize, Clone)]
struct MintBrc20Args {
    mint_psbt_tx_hex: String,
    user_address: String,
    token_name: String
}

#[derive(CandidType, Deserialize, Clone)]
enum RefundType {
    WrongTransfer,
    IDORefund
}

#[derive(CandidType, Deserialize, Clone)]
struct RefundArgs {
    refund_type: RefundType,
    token_name: Option<String>,
    tx_hex: String
}

#[derive(CandidType, Deserialize, Debug)]
pub enum QueryBrc20Result {
  #[serde(rename="ok")]
  Ok(String,candid::Nat,),
  #[serde(rename="err")]
  Err(String),
}

#[derive(CandidType, Deserialize, Clone)]
struct IdoReceiveVec(Vec<(String, u64)>);

impl Storable for ContractInfo {
    const BOUND: Bound = Bound::Unbounded;
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl Storable for IdoReceiveVec {
    const BOUND: Bound = Bound::Unbounded;
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

const BRC20_CANISTER_ID: &str = "wvwai-ziaaa-aaaaj-azxza-cai";
const SCHNORR_KEY_NAME: &str = "test_key_1";
const BITCOIN_NETWORK: Network = Network::Testnet4;
const IC_BITCOIN_NETWORK: ic_cdk::api::management_canister::bitcoin::BitcoinNetwork = ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Testnet;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // brc20_name -> Info
    static CONTRACT_MAP: RefCell<StableBTreeMap<String, ContractInfo, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static IDO_RECEIVE_MAP: RefCell<StableBTreeMap<String, IdoReceiveVec, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );
 
    static CONTRACT_ADDRESS: RefCell<String> = RefCell::new(String::new());
}

#[ic_cdk::init]
async fn init() {
    let derivation_path: Vec<Vec<u8>> = vec![ic_cdk::api::id().to_bytes().to_vec()];
    let schnorr_public_key = wallet::get_schnorr_public_key(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340secp256k1,
        name: SCHNORR_KEY_NAME.to_string()
    }, derivation_path.clone()).await;
    let contract_address = wallet::public_key_to_p2tr_script_spend_address(Network::Bitcoin, &schnorr_public_key);
    CONTRACT_ADDRESS.with(|address| address.borrow_mut().clone_from(&contract_address.to_string()));
}

// #[ic_cdk::update]
// async fn create_contract() -> Result<String, String> {
//     let derivation_path: Vec<Vec<u8>> = vec![ic_cdk::api::time().to_be_bytes().to_vec()];
//     let schnorr_public_key = wallet::get_schnorr_public_key(SchnorrKeyId {
//         algorithm: SchnorrAlgorithm::Bip340secp256k1,
//         name: SCHNORR_KEY_NAME.to_string()
//     }, derivation_path.clone()).await;
//     let contract_address = wallet::public_key_to_p2tr_script_spend_address(Network::Bitcoin, &schnorr_public_key);
//     let contract_address_string = contract_address.to_string();
//     CONTRACT_MAP.with(|map| {
//         map.borrow_mut().insert(contract_address_string.clone(), ContractInfo {
//             contract_address: contract_address_string.clone(),
//             derivation_path: derivation_path.clone(),
//             token_name: "".to_string(),
//             token_amount: 0,
//             deploy_tx_hash: "".to_string(),
//             ido_target_btc_amount: 0
//         })
//     });
//     Ok(contract_address_string)
// }

#[ic_cdk::query]
fn get_contract_address() -> String {
    CONTRACT_ADDRESS.with(|address| address.borrow().clone())
}

fn get_derivation_path() -> Vec<Vec<u8>> {
    vec![ic_cdk::api::id().to_bytes().to_vec()]
}

#[ic_cdk::query]
fn get_contact_info(contract_address: String) -> Option<ContractInfo> {
    CONTRACT_MAP.with(|map| map.borrow().get(&contract_address))
}

#[ic_cdk::query]
fn get_contract_map_entries() -> Vec<ContractInfo> {
    CONTRACT_MAP.with(|map| map.borrow().values().collect())
}

#[ic_cdk::query]
fn get_ido_receive_vec(ido_address: String) -> Option<IdoReceiveVec> {
    IDO_RECEIVE_MAP.with(|map| map.borrow().get(&ido_address))
}

#[ic_cdk::update]
async fn deploy_brc20_token(args: DeployBrc20Args) -> Result<(), String> {
    // 加密校验

    // 去 brc20 canister 验证
    let tx = tx::decode::parse_tx_from_hash(args.deploy_tx_hash.clone()).unwrap();
    let std_btc_tx = tx.convert_to_std_bitcoin_tx();
    let tx_id = std_btc_tx.compute_ntxid().to_string();
    let call_res = ic_cdk::call::<(String, String, String, ), (QueryBrc20Result, )>(
        Principal::from_text(BRC20_CANISTER_ID).unwrap(), 
        "querybrc_20", 
        (get_contract_address(), args.token_name.clone(), tx_id, )
    ).await.unwrap().0;
    match call_res {
        QueryBrc20Result::Err(err) => return Err(format!("querybrc_20 error : {}", err)),
        QueryBrc20Result::Ok(_, amount) => {
            if Nat::from(args.token_amount) != amount {
                return Err(format!("args.token_amount is {} but brc20 canister get amount is {}", args.token_amount, amount))
            }
        }
    }

    // 更新合约信息
    match CONTRACT_MAP.with(|map| map.borrow().get(&args.token_name)) {
        None => {
            CONTRACT_MAP.with(|map| map.borrow_mut().insert(args.token_name.clone(), ContractInfo {
                token_name: args.token_name,
                token_amount: args.token_amount,
                deploy_tx_hash: args.deploy_tx_hash,
                ido_target_btc_amount: args.ido_target_btc_vol,
                already_ido_btc_amount: 0
            }));
            Ok(())
        }
        Some(_) => Err(format!("The Contract Already Exists !"))
    }
}

#[ic_cdk::update]
async fn mint_brc20_token(args: MintBrc20Args) -> Result<String, String> {
    match CONTRACT_MAP.with(|map| map.borrow().get(&args.token_name)) {
        None => Err(format!("Not Found The Contract !")),
        Some(info) => {
            let user_psbt = Psbt::deserialize(&hex::decode(args.mint_psbt_tx_hex.clone()).unwrap()).unwrap();
            let user_psbt_tx = user_psbt.unsigned_tx;
            let user_psbt_tx_id = user_psbt_tx.compute_txid(); 
        
            let mut contrcat_psbt_builder = psbt::builder::PsbtBuilder::new(Network::Bitcoin);
            contrcat_psbt_builder.add_input(
                InputUtxo {
                    tx_id: user_psbt_tx_id,
                    vout: 0,
                    value: user_psbt_tx.output[0].value // 第 0 个out是 Transfer的刻录utxo
                }, 
                &get_contract_address(), 
                Some(&wallet::get_schnorr_public_key(SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Bip340secp256k1,
                    name: SCHNORR_KEY_NAME.to_string()
                }, get_derivation_path()).await),
                Some(InputSignatureType::Taproot(bitcoin::TapSighashType::None))
            ).unwrap();
            contrcat_psbt_builder.add_output(&args.user_address, user_psbt_tx.output[0].value.to_sat(), None).unwrap();

            let contract_psbt = contrcat_psbt_builder.build().unwrap();
            let contract_psbt_hex = contract_psbt.serialize_hex();

            let receive_amount = user_psbt_tx.output[1].value.to_sat();
            let mut old_vec: Vec<(String, u64)> = {
                match IDO_RECEIVE_MAP.with(|map| map.borrow().get(&args.token_name)) {
                    None => Vec::new(),
                    Some(old_vec) => old_vec.clone().0,
                }
            };
            old_vec.push((args.user_address, receive_amount));
            IDO_RECEIVE_MAP.with(|map| map.borrow_mut().insert(args.token_name.clone(), IdoReceiveVec(old_vec)));
            CONTRACT_MAP.with(|map| {
                map.borrow_mut().insert(args.token_name, ContractInfo {
                    token_name: info.token_name,
                    deploy_tx_hash: info.deploy_tx_hash,
                    token_amount: info.token_amount,
                    ido_target_btc_amount: info.ido_target_btc_amount,
                    already_ido_btc_amount: info.already_ido_btc_amount + receive_amount
                })
            });

            let combine_psbt = psbt::transaction::combine_psbt(&args.mint_psbt_tx_hex, &contract_psbt_hex).unwrap();

            let sig = wallet::get_schnorr_signature(
                SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Bip340secp256k1,
                    name: SCHNORR_KEY_NAME.to_string()
                }, get_derivation_path(), base64::decode(combine_psbt).unwrap()).await;

            Ok(hex::encode(sig))
        }
    }

}

#[ic_cdk::update]
async fn refund(args: RefundArgs) -> Result<Vec<u8>, String> {
    let user_tx = tx::decode::parse_tx_from_hash(args.tx_hex).unwrap();
    let std_user_tx = user_tx.convert_to_std_bitcoin_tx();
    let txid_blob = std_user_tx.compute_txid().to_raw_hash().to_byte_array().to_vec();
    match args.refund_type {
        RefundType::WrongTransfer => {
            let contract_utxos = ic_cdk::api::management_canister::bitcoin::bitcoin_get_utxos(GetUtxosRequest {
                address: get_contract_address(),
                network: IC_BITCOIN_NETWORK,
                filter: None
            }).await.unwrap().0.utxos;
            for utxo in contract_utxos {
                if utxo.outpoint.txid == txid_blob && utxo.value > 0 {
                    
                }
            }
        },
        RefundType::IDORefund => {

        }
    }

    Ok(vec![])
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

ic_cdk::export_candid!();