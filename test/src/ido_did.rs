// This is an experimental feature to generate Rust binding from Candid.
// You may want to manually adjust some of the types.
#![allow(dead_code, unused_imports)]
use candid::{self, CandidType, Deserialize, Principal, Encode, Decode};
use ic_cdk::api::call::CallResult as Result;

#[derive(CandidType, Deserialize)]
pub struct DeployBrc20Args {
  pub token_amount: u64,
  pub ido_target_btc_vol: u64,
  pub deploy_tx_hash: String,
  pub token_name: String,
}

#[derive(CandidType, Deserialize)]
pub enum DeployBrc20Result { Ok, Err(String) }

#[derive(CandidType, Deserialize)]
pub struct ContractInfo {
  pub token_amount: u64,
  pub contract_id: String,
  pub ido_target_btc_amount: u64,
  pub deploy_tx_hash: String,
  pub token_name: String,
  pub already_ido_btc_amount: u64,
}

#[derive(CandidType, Deserialize)]
pub struct MintBrc20Args {
  pub mint_psbt_tx_hex: String,
  pub contract_id: String,
  pub user_address: String,
  pub token_name: String,
}

#[derive(CandidType, Deserialize)]
pub enum MintBrc20Result { Ok(String), Err(String) }

#[derive(CandidType, Deserialize)]
pub struct RefundArgs { pub tx_hex: String, pub token_name: Option<String> }
