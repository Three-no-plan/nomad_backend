use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, ScriptBuf, Sequence, TapSighashType, TxOut};
use candid::{CandidType, Deserialize, Nat, Principal};
use candid::{Decode, Encode};
use ic_cdk::api::management_canister::schnorr::{SchnorrAlgorithm, SchnorrKeyId, SignWithSchnorrArgument};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::{Bound, Storable};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
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
mod bitcoin_wallet;
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
    deploy_transfer_brc20_tx_id: String,
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
    deploy_transfer_brc20_tx_id: String,
    minter_transfer_btc_tx_hex: String,
}

#[derive(CandidType, Deserialize, Clone)]
struct RefundArgs {
    deploy_transfer_brc20_tx_id: String,
    brc20_receive_address: String
}

#[derive(CandidType, Deserialize, Clone)]
struct RefundInfo {
    // deploy_transfer_brc20_tx_id -> (refund_tx_hex, amount)
    pub map: HashMap<String, (String, u64)>
}

#[derive(CandidType, Deserialize, Debug)]
pub enum QueryBrc20Result {
    #[serde(rename = "ok")]
    Ok(String, candid::Nat),
    #[serde(rename = "err")]
    Err(String),
}

impl Storable for ContractInfo {
    const BOUND: Bound = Bound::Unbounded;
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl Storable for RefundInfo {
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
const IC_BITCOIN_NETWORK: ic_cdk::api::management_canister::bitcoin::BitcoinNetwork =
    ic_cdk::api::management_canister::bitcoin::BitcoinNetwork::Testnet;
const BITCOIN_NETWORK_FEE: u64 = 2000;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // deploy_transfer_brc20_tx_id -> Info
    static CONTRACT_MAP: RefCell<StableBTreeMap<String, ContractInfo, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    // brc20_receive_address -> u64
    static ERROR_RECEIVE_BTC_MAP: RefCell<StableBTreeMap<String, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );

    // brc20_receive_address -> RefundInfo
    static REFUND_MAP: RefCell<StableBTreeMap<String, RefundInfo, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        )
    );

    static CONTRACT_ADDRESS: RefCell<String> = RefCell::new(String::new());

    static LOGS: RefCell<Vec<String>> = RefCell::new(Vec::new());
}

#[ic_cdk::update]
async fn init() {
    let contract_address = bitcoin_wallet::p2tr_key_only::get_address(
        IC_BITCOIN_NETWORK, 
        SCHNORR_KEY_NAME.to_string(), 
        get_derivation_path()
    ).await;
    CONTRACT_ADDRESS.with(|address| {
        address
            .borrow_mut()
            .clone_from(&contract_address.to_string())
    });
}

fn get_derivation_path() -> Vec<Vec<u8>> {
    vec![ic_cdk::api::id().to_bytes().to_vec()]
}

#[ic_cdk::query]
fn get_contract_address() -> String {
    CONTRACT_ADDRESS.with(|address| address.borrow().clone())
}

#[ic_cdk::query]
fn get_contact_info(tx_id: String) -> Option<ContractInfo> {
    CONTRACT_MAP.with(|map| map.borrow().get(&tx_id))
}

#[ic_cdk::query]
fn get_logs_entries() -> Vec<String> {
    LOGS.with(|logs| logs.borrow().to_vec())
}

#[ic_cdk::query]
fn get_contract_map_entries() -> Vec<ContractInfo> {
    CONTRACT_MAP.with(|map| map.borrow().values().collect())
}

// 用户将brc20转到canister的tp地址
// brc20_canister校验ido_canister是否收到相应的brc20
// Ok的话创建一笔ido_brc20 订单
// Result<tx_id, Err>
#[ic_cdk::update]
async fn deploy_brc20_token(args: DeployBrc20Args) -> Result<String, String> {
    let deployer_transfer_brc20_tx = tx::decode::get_transaction_struct_from_tx_hex(&args.brc20_transfer_tx_hex);
    let deploy_transfer_brc20_tx_id = deployer_transfer_brc20_tx.compute_txid().to_string();

    // 去 brc20 canister 验证
    let brc20_canister = brc20_canister_did::Service(Principal::from_text(BRC20_CANISTER_ID).unwrap());
    let query_brc20_res = brc20_canister.querybrc_20(
        deploy_transfer_brc20_tx_id.clone() // txid
    ).await.unwrap().0;
    match query_brc20_res {
        brc20_canister_did::Result2::Err(err) => return Err(format!("querybrc_20 error : {}", err)),
        brc20_canister_did::Result2::Ok(tx) => {
            if Nat::from(args.brc20_amount) != tx.amount {
                return Err(format!(
                    "args.token_amount is {} but brc20 canister get amount is {}",
                    args.brc20_amount, tx.amount
                ));
            }

            if args.brc20_name != tx.ticker {
                return Err(format!("args.brc20_name is {}, but tx.ticker is {}", args.brc20_name, tx.ticker));
            }
        }
    }

    // 更新合约信息
    match CONTRACT_MAP.with(|map| map.borrow().get(&deploy_transfer_brc20_tx_id)) {
        None => {
            CONTRACT_MAP.with(|map| {
                map.borrow_mut().insert(deploy_transfer_brc20_tx_id.clone(), ContractInfo {
                    deploy_transfer_brc20_tx_id: deploy_transfer_brc20_tx_id.clone(),
                    brc20_name: args.brc20_name,
                    brc20_amount: args.brc20_amount,
                    brc20_transfer_tx_hex: args.brc20_transfer_tx_hex,
                    ido_target_btc_vol: args.ido_target_btc_vol,
                    already_ido_btc_vol: 0,
                    already_ido_brc20_amount: 0,
                    mint_map: HashMap::new()
                })
            });
            Ok(deploy_transfer_brc20_tx_id)
        }
        Some(_) => Err(format!("The Contract Already Exists !")),
    }
}

// mint 交易 hex 需要在 opreturn 中包含 brc20 的接收地址
#[ic_cdk::update]
async fn mint_brc20_token(args: MintBrc20Args) -> Result<String, String> {
    let (receive_address, btc_amount) = {
        let mut btc_amount = 0;
        let mut receive_adderss = "".to_string();
        let output_vec = tx::decode::parse_tx_from_hash(&args.minter_transfer_btc_tx_hex, BITCOIN_NETWORK).unwrap();
        let contract_address = CONTRACT_ADDRESS.with(|address| address.borrow().clone());
        for output_info in output_vec {
            if output_info.address == contract_address {
                btc_amount = output_info.amount;
            }
            if output_info.op_return_data != "".to_string() {
                receive_adderss = output_info.op_return_data.clone();
            }
            LOGS.with(|logs| logs.borrow_mut().push(format!("tx output_info : {:?}", output_info)));
        }

        // *特殊处理
        if receive_adderss == "tb1qucyr6syge28n7wxshnm39p0am9q8mcrjfudewd}".to_string() {
            receive_adderss = "tb1qucyr6syge28n7wxshnm39p0am9q8mcrjfudewd".to_string();
        }

        LOGS.with(|logs| logs.borrow_mut().push(format!("receive_adderss : {}, btc_amount : {}", receive_adderss, btc_amount)));
        (receive_adderss, btc_amount)
    };    
    if receive_address == "".to_string() {
        return Err(format!("Decode receive brc20 address error !"));
    };
    if btc_amount <= 0 {
        return Err(format!("User did not transfer btc to ido canister !"));
    };

    ERROR_RECEIVE_BTC_MAP.with(|map| map.borrow_mut().insert(receive_address.clone(), btc_amount));

    let (distribute_brc20_amount, contract_info) = match CONTRACT_MAP.with(|map| map.borrow().get(&args.deploy_transfer_brc20_tx_id)) {
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
            LOGS.with(|logs| logs.borrow_mut().push(format!("query_transfer_res: {:?}", (tx_id.clone(), vout.clone(), value.clone(), ticker.clone(), amount.clone()))));
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
                        vout: nat_to_u32(&vout)
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new()
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(nat_to_u64(&value) - BITCOIN_NETWORK_FEE),
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
                    value: Amount::from_sat(nat_to_u64(&value)),
                    script_pubkey: {
                        let contract_address = CONTRACT_ADDRESS.with(|address| address.borrow().clone());
                        let std_contract_address = Address::from_str(&contract_address).unwrap().require_network(BITCOIN_NETWORK).unwrap();
                        std_contract_address.script_pubkey()
                    },
                }]),
                TapSighashType::All
            ).unwrap();
            
            let signature = bitcoin_wallet::schnorr_api::sign_with_schnorr(
                SCHNORR_KEY_NAME.to_string(), 
                get_derivation_path(), 
                Some(vec![]), 
                <TapSighash as AsRef<[u8; 32]>>::as_ref(&sighash).to_vec(),
            ).await;

            // 设置 witness 数据（Taproot key-path spending 只需 Schnorr 签名）
            unsigned_tx.input[0].witness.push(bitcoin::taproot::Signature {
                signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).unwrap(),
                sighash_type: TapSighashType::All
            }.to_vec());

            LOGS.with(|logs| logs.borrow_mut().push(format!("tx : {:?}", unsigned_tx)));
            // 序列化交易为十六进制
            let tx_hex = hex::encode(bitcoin::consensus::serialize(&unsigned_tx));
            ERROR_RECEIVE_BTC_MAP.with(|map| map.borrow_mut().remove(&receive_address));

            let new_contract_info = ContractInfo {
                deploy_transfer_brc20_tx_id: contract_info.deploy_transfer_brc20_tx_id,
                brc20_name: contract_info.brc20_name,
                brc20_amount: contract_info.brc20_amount,
                brc20_transfer_tx_hex: contract_info.brc20_transfer_tx_hex,
                ido_target_btc_vol: contract_info.ido_target_btc_vol,
                already_ido_btc_vol: contract_info.already_ido_btc_vol + btc_amount,
                already_ido_brc20_amount: contract_info.already_ido_brc20_amount + distribute_brc20_amount,
                mint_map: {
                    let mut old_mint_map = contract_info.mint_map;
                    match old_mint_map.get(&receive_address) {
                        None => {
                            old_mint_map.insert(receive_address.clone(), MintInfo {
                                to_address: receive_address,
                                btc_amount: btc_amount,
                                brc20_amount: distribute_brc20_amount
                            })
                        },
                        Some(old_mint_info) => {
                            old_mint_map.insert(receive_address, MintInfo {
                                to_address: old_mint_info.to_address.clone(),
                                btc_amount: old_mint_info.btc_amount + btc_amount,
                                brc20_amount: old_mint_info.brc20_amount + distribute_brc20_amount
                            })
                        }
                    };
                    old_mint_map
                }
            };
            CONTRACT_MAP.with(|map| map.borrow_mut().insert(args.deploy_transfer_brc20_tx_id, new_contract_info));

            Ok(tx_hex)
        }
    }
}

// 成功ido之后可以退款
#[ic_cdk::update]
async fn ido_refund_btc(args: RefundArgs) -> Result<String, String> {
    Ok("".to_string())
}

#[ic_cdk::update]
async fn error_transfer_refund_btc(brc20_receive_address: String) -> Result<(String, u64), String> {

    Ok(("".to_string(), 0))
}

// 不能随便将canister的utxo作为输入
// 尝试将当时用户转账过来的utxo作为输入
async fn transfer_btc_from_canister_to_tp_address(to_tp_address: String) -> Result<String, String> {
    Ok("".to_string())
} 

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

fn nat_to_u32(num: &Nat) -> u32 {
    if num == &Nat::from(0u32) {
        return 0;
    }
    num.0.to_u32_digits()[0]
}

fn nat_to_u64(num: &Nat) -> u64 {
    if num == &Nat::from(0u32) {
        return 0;
    }
    num.0.to_u64_digits()[0]
}

ic_cdk::export_candid!();