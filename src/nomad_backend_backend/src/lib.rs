use bitcoin::absolute::LockTime;
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, EcdsaSighashType, Network, Psbt, ScriptBuf, Sequence, TapSighashType, TxOut};
use candid::{CandidType, Deserialize, Nat, Principal};
use candid::{Decode, Encode};
use ic_cdk::api::management_canister::bitcoin::{GetUtxosRequest, UtxoFilter};
use ic_cdk::api::management_canister::schnorr::{SchnorrAlgorithm, SchnorrKeyId, SignWithSchnorrArgument};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::{Bound, Storable};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
use psbt::types::{InputSignatureType, InputUtxo};
use std::borrow::Cow;
use std::cell::RefCell;
use std::str::FromStr;
use std::collections::HashMap;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::Txid;
use bitcoin::OutPoint;
use bitcoin::Witness;
use bitcoin::TapSighash;

type Memory = VirtualMemory<DefaultMemoryImpl>;

mod psbt;
mod tx;
mod wallet;
mod brc20_canister_did;

pub use psbt::{
    builder::PsbtBuilder,
    transaction::{combine_psbt, create_transaction_multi},
    types::{TransactionInput, TransactionOutput, TransactionResult},
};

#[derive(CandidType, Deserialize, Clone)]
struct MintInfo {
    to_address: String,
    btc_amount: u64,
    brc20_amount: u64
}

#[derive(CandidType, Deserialize, Clone)]
struct ContractInfo {
    contract_id: String,
    brc20_name: String,
    brc20_amount: u64,
    brc20_transfer_tx_hex: String,
    ido_target_btc_vol: u64,
    already_ido_btc_vol: u64,
    already_ido_brc20_amount: u64,
    mint_map: HashMap<String, MintInfo>
}

#[derive(CandidType, Deserialize, Clone)]
struct DeployBrc20Args {
    brc20_transfer_tx_hex: String,
    brc20_name: String,
    brc20_amount: u64,
    ido_target_btc_vol: u64,
}

#[derive(CandidType, Deserialize, Clone)]
struct MintBrc20Args {
    contract_id: String,
    minter_transfer_btc_tx_hex: String,
}

#[derive(CandidType, Deserialize, Clone)]
struct RefundArgs {
    token_name: Option<String>,
    tx_hex: String,
}

#[derive(CandidType, Deserialize, Clone)]
struct RefundInfo {
    token_name: Option<String>,
    tx_hex: String,
}

#[derive(CandidType, Deserialize, Debug)]
pub enum QueryBrc20Result {
    #[serde(rename = "ok")]
    Ok(String, candid::Nat),
    #[serde(rename = "err")]
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

const BRC20_CANISTER_ID: &str = "wvwai-ziaaa-aaaaj-azxza-cai";
const SCHNORR_KEY_NAME: &str = "abcd";
const BITCOIN_NETWORK: Network = Network::Testnet4;
const IC_BITCOIN_NETWORK: ic_cdk::api::management_canister::bitcoin::BitcoinNetwork =
    ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Testnet;
const BITCOIN_NETWORK_FEE: u64 = 2000;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // contract_id(brc20_name + contract_nonce) -> Info
    static CONTRACT_MAP: RefCell<StableBTreeMap<String, ContractInfo, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static CONTRACT_NONCE: RefCell<StableCell<u64, Memory>> = RefCell::new(
        StableCell::new(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            0
        ).unwrap()
    );

    static ERROR_RECEIVE_BTC_MAP: RefCell<StableBTreeMap<String, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        )
    );

    // // tx_hex -> refund_info
    // static REFUND_MAP: RefCell<StableBTreeMap<String, IdoReceiveVec, Memory>> = RefCell::new(
    //     StableBTreeMap::init(
    //         MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
    //     )
    // );

    static CONTRACT_ADDRESS: RefCell<String> = RefCell::new(String::new());
}

#[ic_cdk::update]
async fn init() {
    let derivation_path: Vec<Vec<u8>> = vec![ic_cdk::api::id().to_bytes().to_vec()];
    let schnorr_public_key = wallet::get_schnorr_public_key(
        SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: SCHNORR_KEY_NAME.to_string(),
        },
        derivation_path.clone(),
    )
    .await;
    let contract_address =
        wallet::public_key_to_p2tr_script_spend_address(BITCOIN_NETWORK, &schnorr_public_key);
    CONTRACT_ADDRESS.with(|address| {
        address
            .borrow_mut()
            .clone_from(&contract_address.to_string())
    });
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
fn get_contact_info(contract_id: String) -> Option<ContractInfo> {
    CONTRACT_MAP.with(|map| map.borrow().get(&contract_id))
}

#[ic_cdk::query]
fn get_contract_map_entries() -> Vec<ContractInfo> {
    CONTRACT_MAP.with(|map| map.borrow().values().collect())
}

// 用户将brc20转到canister的tp地址
// brc20_canister校验ido_canister是否收到相应的brc20
// Ok的话创建一笔ido_brc20 订单
// Result<Contract_id, Err>
#[ic_cdk::update]
async fn deploy_brc20_token(args: DeployBrc20Args) -> Result<String, String> {
    let deployer_transfer_brc20_tx = tx::decode::get_transaction_struct_from_tx_hex(&args.brc20_transfer_tx_hex);
    let deploy_transfer_brc20_tx_id = deployer_transfer_brc20_tx.compute_txid();

    // 去 brc20 canister 验证
    let brc20_canister = brc20_canister_did::Service(Principal::from_text(BRC20_CANISTER_ID).unwrap());
    let query_brc20_res = brc20_canister.querybrc_20(
        CONTRACT_ADDRESS.with(|contract_address| contract_address.borrow().clone()), // address
        args.brc20_name.clone(), // ticker
        deploy_transfer_brc20_tx_id.to_string() // txid
    ).await.unwrap().0;
    match query_brc20_res {
        brc20_canister_did::Result2::Err(err) => return Err(format!("querybrc_20 error : {}", err)),
        brc20_canister_did::Result2::Ok(_, amount) => {
            if Nat::from(args.brc20_amount) != amount {
                return Err(format!(
                    "args.token_amount is {} but brc20 canister get amount is {}",
                    args.brc20_amount, amount
                ));
            }
        }
    }

    // 更新合约信息
    let contract_id = {
        let nonce = CONTRACT_NONCE.with(|nonce| nonce.borrow().get().clone());
        let contract_id = format!("{}#{}", args.brc20_name.clone(), nonce);
        CONTRACT_NONCE.with(|value| value.borrow_mut().set(nonce + 1).unwrap());
        contract_id
    };
    match CONTRACT_MAP.with(|map| map.borrow().get(&contract_id)) {
        None => {
            CONTRACT_MAP.with(|map| {
                map.borrow_mut().insert(contract_id.clone(), ContractInfo {
                    contract_id: contract_id.clone(),
                    brc20_name: args.brc20_name,
                    brc20_amount: args.brc20_amount,
                    brc20_transfer_tx_hex: args.brc20_transfer_tx_hex,
                    ido_target_btc_vol: args.ido_target_btc_vol,
                    already_ido_btc_vol: 0,
                    already_ido_brc20_amount: 0,
                    mint_map: HashMap::new()
                })
            });
            Ok(contract_id)
        }
        Some(_) => Err(format!("The Contract Already Exists !")),
    }
}


#[ic_cdk::update]
async fn mint_brc20_token(args: MintBrc20Args) -> Result<String, String> {
    let (receive_address, btc_amount) = {
        let mut btc_amount = 0;
        let mut receive_adderss = "".to_string();
        let output_vec = tx::decode::parse_tx_from_hash(&args.minter_transfer_btc_tx_hex).unwrap();
        let contract_address = CONTRACT_ADDRESS.with(|address| address.borrow().clone());
        for output_info in output_vec {
            if output_info.address == contract_address {
                receive_adderss = output_info.op_return_data;
                btc_amount = output_info.amount;
                break;
            }
        }
        (receive_adderss, btc_amount)
    };    
    if receive_address == "".to_string() {
        return Err(format!("Decode receive brc20 address error !"));
    };
    if btc_amount <= 0 {
        return Err(format!("User did not transfer btc to ido canister !"));
    };

    ERROR_RECEIVE_BTC_MAP.with(|map| map.borrow_mut().insert(receive_address.clone(), btc_amount));

    let (distribute_brc20_amount, contract_info) = match CONTRACT_MAP.with(|map| map.borrow().get(&args.contract_id)) {
        None => return Err(format!("Contract id 's info not found")),
        Some(contract_info) => {
            let amount = contract_info.brc20_amount * btc_amount / contract_info.ido_target_btc_vol; // 注意下精度问题
            if amount + contract_info.already_ido_brc20_amount > contract_info.brc20_amount {
                (contract_info.brc20_amount - contract_info.already_ido_brc20_amount, contract_info)
            } else {
                (amount, contract_info)
            }
        }
    };

    let brc20_canister = brc20_canister_did::Service(Principal::from_text(BRC20_CANISTER_ID).unwrap());
    let query_transfer_res = brc20_canister.querytransfer({
        let minter_transfer_btc_tx = tx::decode::get_transaction_struct_from_tx_hex(&args.minter_transfer_btc_tx_hex);
        let tx_id = minter_transfer_btc_tx.compute_txid();
        tx_id.to_string()
    }).await.unwrap().0;
    match query_transfer_res {
        brc20_canister_did::Result1::Err(err) => return Err(format!("query_transfer_res : {}", err)),
        brc20_canister_did::Result1::Ok(tx_id, vout, value, ticker, amount) => {
            if ticker != contract_info.brc20_name {
                return Err(format!("Contract_info 's brc20_name is {}, but the transfer utxo 's ticker is {}", contract_info.brc20_name, ticker));
            }
            if amount != distribute_brc20_amount {
                return Err(format!("distribute_brc20_amount is {}, but the transfer utxo 's brc20_amount is {}", distribute_brc20_amount, amount));
            }

            let mut unsigned_tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_str(&tx_id).unwrap(),
                        vout: candid::Decode!(&candid::Encode!(&vout).unwrap(), u32).unwrap()
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new()
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(candid::Decode!(&candid::Encode!(&value).unwrap(), u64).unwrap() - BITCOIN_NETWORK_FEE),
                    script_pubkey: {
                        let std_receive_address = Address::from_str(&receive_address).unwrap().require_network(BITCOIN_NETWORK).unwrap();
                        std_receive_address.script_pubkey()
                    }
                }]
            };

            // 计算 Schnorr 签名哈希
            let mut sighash_cache = SighashCache::new(&unsigned_tx);
            let sighash = sighash_cache.taproot_key_spend_signature_hash(
                0, // 输入索引
                &bitcoin::sighash::Prevouts::All(&[TxOut {
                    value: Amount::from_sat(candid::Decode!(&candid::Encode!(&value).unwrap(), u64).unwrap()),
                    script_pubkey: {
                        let contract_address = CONTRACT_ADDRESS.with(|address| address.borrow().clone());
                        let std_contract_address = Address::from_str(&contract_address).unwrap().require_network(BITCOIN_NETWORK).unwrap();
                        std_contract_address.script_pubkey()
                    },
                }]),
                TapSighashType::All
            ).unwrap();

            let signature = ic_cdk::api::management_canister::schnorr::sign_with_schnorr(SignWithSchnorrArgument {
                message: <TapSighash as AsRef<[u8; 32]>>::as_ref(&sighash).to_vec(),
                derivation_path: vec![],
                key_id: SchnorrKeyId {
                    algorithm: SchnorrAlgorithm::Bip340secp256k1,
                    name: SCHNORR_KEY_NAME.to_string()
                }
            }).await.unwrap().0.signature;

            // 设置 witness 数据（Taproot key-path spending 只需 Schnorr 签名）
            unsigned_tx.input[0].witness.push(signature);

            // 序列化交易为十六进制
            let tx_hex = hex::encode(bitcoin::consensus::serialize(&unsigned_tx));
            ERROR_RECEIVE_BTC_MAP.with(|map| map.borrow_mut().remove(&receive_address));

            Ok(tx_hex)
        }
    }
}

// #[ic_cdk::update]
// async fn refund(args: RefundArgs) -> Result<String, String> {
//     let std_user_tx = tx::decode::parse_tx_from_hash(args.tx_hex.clone()).unwrap();
//     let txid_blob = std_user_tx
//         .compute_txid()
//         .to_raw_hash()
//         .to_byte_array()
//         .to_vec();
//     let tx_output_info = tx::decode::parse_bitcoin_transaction(&args.tx_hex).unwrap();
//     let user_address: String = {
//         let mut from_address = String::new();
//         for output in tx_output_info {
//             if output.op_return_data != "".to_string() {
//                 from_address = output.op_return_data;
//                 break;
//             }
//         }
//         from_address
//     };
//     if user_address == String::new() {
//         return Err(format!("Error Decode the from user address !"));
//     }

//     // 检查是否在 utxo 中
//     let contract_utxo =
//         ic_cdk::api::management_canister::bitcoin::bitcoin_get_utxos(GetUtxosRequest {
//             address: get_contract_address(),
//             network: bitcoin_network_to_ic_bitcoin_network(BITCOIN_NETWORK),
//             filter: None,
//         })
//         .await
//         .unwrap()
//         .0
//         .utxos;
//     for utxo in contract_utxo {
//         if utxo.outpoint.txid == txid_blob {
//             let fee = 2_000u64;
//             let to_address = bitcoin::Address::from_str(&user_address)
//                 .unwrap()
//                 .require_network(BITCOIN_NETWORK)
//                 .unwrap();
//             let mut unsigned_tx = bitcoin::Transaction {
//                 version: bitcoin::transaction::Version::TWO,
//                 lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
//                 input: vec![bitcoin::transaction::TxIn {
//                     previous_output: bitcoin::OutPoint {
//                         txid: bitcoin::Txid::from_slice(&utxo.outpoint.txid).unwrap(),
//                         vout: utxo.outpoint.vout,
//                     },
//                     script_sig: bitcoin::ScriptBuf::new(),
//                     sequence: bitcoin::Sequence::ZERO,
//                     witness: bitcoin::Witness::default(),
//                 }],
//                 output: vec![bitcoin::TxOut {
//                     value: bitcoin::Amount::from_sat(utxo.value - fee),
//                     script_pubkey: to_address.script_pubkey(),
//                 }],
//             };

//             // Get the sighash to sign.
//             let secp = bitcoin::secp256k1::Secp256k1::new();
//             let xonly_public_key = bitcoin::key::XOnlyPublicKey::from_slice(
//                 &wallet::get_schnorr_public_key(
//                     SchnorrKeyId {
//                         algorithm: SchnorrAlgorithm::Bip340secp256k1,
//                         name: SCHNORR_KEY_NAME.to_string(),
//                     },
//                     get_derivation_path(),
//                 )
//                 .await,
//             )
//             .unwrap();
//             let input_index = 0;
//             let sighash_type = bitcoin::TapSighashType::Default;
//             let prevouts: Vec<bitcoin::TxOut> = vec![bitcoin::TxOut {
//                 value: bitcoin::Amount::from_sat(utxo.value),
//                 script_pubkey: ScriptBuf::new_p2tr(&secp, xonly_public_key, None),
//             }];
//             let prevouts = bitcoin::sighash::Prevouts::All(&prevouts);

//             let mut sighasher = bitcoin::sighash::SighashCache::new(&mut unsigned_tx);
//             let sighash = sighasher
//                 .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
//                 .expect("failed to construct sighash");

//             // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
//             let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
//             let signature_blob = wallet::get_schnorr_signature(
//                 SchnorrKeyId {
//                     algorithm: SchnorrAlgorithm::Bip340secp256k1,
//                     name: SCHNORR_KEY_NAME.to_string(),
//                 },
//                 get_derivation_path(),
//                 Vec::from(msg.as_ref()),
//             )
//             .await;
//             let signature =
//                 bitcoin::secp256k1::schnorr::Signature::from_slice(&signature_blob).unwrap();

//             // Update the witness stack.
//             let signature = bitcoin::taproot::Signature {
//                 signature,
//                 sighash_type,
//             };
//             sighasher
//                 .witness_mut(input_index)
//                 .unwrap()
//                 .push(&signature.to_vec());

//             // Get the signed transaction.
//             let tx = sighasher.into_transaction();
//             let signed_tx = bitcoin::consensus::serialize(&unsigned_tx);

//             return Ok(hex::encode(signed_tx));
//         }
//     }

//     Err(format!("TX Not in contract address 's utxos !"))
// }

fn bitcoin_network_to_ic_bitcoin_network(
    network: Network,
) -> ic_cdk::api::management_canister::bitcoin::BitcoinNetwork {
    match network {
        Network::Bitcoin => ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Mainnet,
        Network::Testnet => ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Testnet,
        Network::Testnet4 => ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Testnet,
        Network::Signet => ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Testnet,
        Network::Regtest => ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Regtest,
        _ => ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Testnet,
    }
}

pub fn process_external_transaction(
    network: &str,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
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
