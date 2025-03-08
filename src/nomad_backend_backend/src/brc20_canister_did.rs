// This is an experimental feature to generate Rust binding from Candid.
// You may want to manually adjust some of the types.
#![allow(dead_code, unused_imports)]
use candid::{self, CandidType, Deserialize, Principal, Encode, Decode};
use ic_cdk::api::call::CallResult as Result;

#[derive(CandidType, Deserialize)]
pub struct BatchBrc20Data {
  pub ticker: String,
  pub from: String,
  pub txid: String,
  pub address: String,
  pub amount: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub enum Result_ {
  #[serde(rename="ok")]
  Ok(String),
  #[serde(rename="err")]
  Err(String),
}

#[derive(CandidType, Deserialize)]
pub struct BatchTransferData {
  pub ticker: String,
  pub value: candid::Nat,
  pub txid: String,
  pub vout: candid::Nat,
  pub p_txid: String,
  pub amount: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub struct Transaction {
  pub ticker: String,
  pub from: String,
  pub txid: String,
  pub address: String,
  pub amount: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub struct Transfer {
  pub ticker: String,
  pub value: candid::Nat,
  pub txid: String,
  pub vout: candid::Nat,
  pub p_txid: String,
  pub amount: candid::Nat,
}

#[derive(CandidType, Deserialize)]
pub enum Result2 {
  #[serde(rename="ok")]
  Ok(Transaction),
  #[serde(rename="err")]
  Err(String),
}

#[derive(CandidType, Deserialize)]
pub enum Result1 {
  #[serde(rename="ok")]
  Ok(String,candid::Nat,candid::Nat,String,candid::Nat,),
  #[serde(rename="err")]
  Err(String),
}

pub struct Service(pub Principal);
impl Service {
  pub async fn batch_upload_brc_20_data(
    &self,
    arg0: Vec<BatchBrc20Data>,
  ) -> Result<(Result_,)> {
    ic_cdk::call(self.0, "batchUploadBrc20Data", (arg0,)).await
  }
  pub async fn batch_upload_transfer_data(
    &self,
    arg0: Vec<BatchTransferData>,
  ) -> Result<(Result_,)> {
    ic_cdk::call(self.0, "batchUploadTransferData", (arg0,)).await
  }
  pub async fn clear_all_brc_20(&self) -> Result<(Result_,)> {
    ic_cdk::call(self.0, "clearAllBrc20", ()).await
  }
  pub async fn clear_all_transfers(&self) -> Result<(Result_,)> {
    ic_cdk::call(self.0, "clearAllTransfers", ()).await
  }
  pub async fn get_all_brc_20_transactions(&self) -> Result<
    (Vec<Transaction>,)
  > { ic_cdk::call(self.0, "getAllBrc20Transactions", ()).await }
  pub async fn get_all_transfers(&self) -> Result<(Vec<Transfer>,)> {
    ic_cdk::call(self.0, "getAllTransfers", ()).await
  }
  pub async fn get_brc_20_account(&self) -> Result<(candid::Nat,)> {
    ic_cdk::call(self.0, "getBrc20account", ()).await
  }
  pub async fn gettransferaccount(&self) -> Result<(candid::Nat,)> {
    ic_cdk::call(self.0, "gettransferaccount", ()).await
  }
  pub async fn querybrc_20(&self, arg0: String) -> Result<(Result2,)> {
    ic_cdk::call(self.0, "querybrc20", (arg0,)).await
  }
  pub async fn querytransfer(&self, arg0: String) -> Result<(Result1,)> {
    ic_cdk::call(self.0, "querytransfer", (arg0,)).await
  }
  pub async fn uploadbrc_20_data(
    &self,
    arg0: String,
    arg1: String,
    arg2: String,
    arg3: String,
    arg4: candid::Nat,
  ) -> Result<(Result_,)> {
    ic_cdk::call(self.0, "uploadbrc20data", (arg0,arg1,arg2,arg3,arg4,)).await
  }
  pub async fn uploadtransferdata(
    &self,
    arg0: String,
    arg1: String,
    arg2: candid::Nat,
    arg3: candid::Nat,
    arg4: String,
    arg5: candid::Nat,
  ) -> Result<(Result_,)> {
    ic_cdk::call(self.0, "uploadtransferdata", (
      arg0,arg1,arg2,arg3,arg4,arg5,
    )).await
  }
}
