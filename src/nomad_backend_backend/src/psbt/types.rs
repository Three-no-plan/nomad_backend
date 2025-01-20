use bitcoin::psbt::PsbtSighashType;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::TapSighashType;

use bitcoin::{
    absolute::LockTime,
    psbt,
    ScriptBuf,
    transaction::Version,
    Address,
    AddressType,
    Amount,
    CompressedPublicKey,
    Network,
    PublicKey,
    Script,
    Sequence,
    Transaction,
    TxIn,
    TxOut,
    Witness,
    OutPoint,
    Txid,
};
#[derive(Clone)]
pub enum InputSignatureType {
    Ecdsa(EcdsaSighashType),
    Taproot(TapSighashType),
}

#[derive(Clone)]
pub struct TransactionInput {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub public_key: Option<String>,
    pub signature_type: Option<InputSignatureType>,

    // pub sighash_type: Option<PsbtSighashType>, 
    // pub sighash_type: Option<TapSighashType>, // 改为 TapSighashType

}


#[derive(Clone)]
pub struct TransactionOutput {
    pub address: String,
    pub amount: u64,
    pub op_return: Option<Vec<u8>>,
}
pub struct TransactionResult {
    pub txid: String,
    pub psbt_base64: String,
    pub psbt_hex: String,
    pub vsize: u64,
    pub total_input: u64,
    pub total_output: u64,
    pub fee: u64,
}


#[derive(Clone)]
pub struct InputUtxo {
    pub tx_id: Txid,
    pub vout: u32,
    pub value: Amount,
}
impl From<&InputUtxo> for OutPoint {
    fn from(utxo: &InputUtxo) -> Self {
        Self {
            txid: utxo.tx_id,
            vout: utxo.vout,
        }
    }
}
impl InputSignatureType {
    pub  fn to_psbt_sighash_type(&self) -> PsbtSighashType {
        match self {
            InputSignatureType::Ecdsa(sighash) => PsbtSighashType::from(*sighash),
            InputSignatureType::Taproot(sighash) => PsbtSighashType::from(*sighash),
        }
    }
    pub fn from_str(sig_type: &str) -> Result<Self, String> {
        match sig_type.to_lowercase().as_str() {
            "ecdsa_all" => Ok(InputSignatureType::Ecdsa(EcdsaSighashType::All)),
            "ecdsa_none" => Ok(InputSignatureType::Ecdsa(EcdsaSighashType::None)),
            "ecdsa_single" => Ok(InputSignatureType::Ecdsa(EcdsaSighashType::Single)),
            "ecdsa_all_anyonecanpay" => Ok(InputSignatureType::Ecdsa(EcdsaSighashType::AllPlusAnyoneCanPay)),
            "ecdsa_none_anyonecanpay" => Ok(InputSignatureType::Ecdsa(EcdsaSighashType::NonePlusAnyoneCanPay)),
            "ecdsa_single_anyonecanpay" => Ok(InputSignatureType::Ecdsa(EcdsaSighashType::SinglePlusAnyoneCanPay)),
            "taproot_all" => Ok(InputSignatureType::Taproot(TapSighashType::All)),
            "taproot_none" => Ok(InputSignatureType::Taproot(TapSighashType::None)),
            "taproot_single" => Ok(InputSignatureType::Taproot(TapSighashType::Single)),
            "taproot_default" => Ok(InputSignatureType::Taproot(TapSighashType::Default)),
            "taproot_all_anyonecanpay" => Ok(InputSignatureType::Taproot(TapSighashType::AllPlusAnyoneCanPay)),
            "taproot_none_anyonecanpay" => Ok(InputSignatureType::Taproot(TapSighashType::NonePlusAnyoneCanPay)),
            "taproot_single_anyonecanpay" => Ok(InputSignatureType::Taproot(TapSighashType::SinglePlusAnyoneCanPay)),
            _ => Err(format!("Invalid signature type: {}", sig_type)),
        }
    }
}
