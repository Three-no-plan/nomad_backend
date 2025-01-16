use bitcoin::psbt::PsbtSighashType;
use candid::{CandidType, Deserialize};

// #[derive(CandidType, Deserialize, Clone)]
#[derive(Clone)]
pub struct TransactionInput {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub public_key: Option<String>,
    pub sighash_type: Option<PsbtSighashType>,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct TransactionOutput {
    pub address: String,
    pub amount: u64,
}
#[derive(CandidType, Deserialize, Clone)]
pub struct TransactionResult {
    pub txid: String,
    pub psbt_base64: String,
    pub psbt_hex: String,
    pub vsize: u64,
    pub total_input: u64,
    pub total_output: u64,
    pub fee: u64,
}

// #[derive(CandidType, Deserialize, Clone)]
#[derive(Clone)]
pub struct InputUtxo {
    pub tx_id: bitcoin::Txid,
    pub vout: u32,
    pub value: bitcoin::Amount,
}

impl From<&InputUtxo> for bitcoin::OutPoint {
    fn from(utxo: &InputUtxo) -> Self {
        Self {
            txid: utxo.tx_id,
            vout: utxo.vout,
        }
    }
}
