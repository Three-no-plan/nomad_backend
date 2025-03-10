use bitcoin::{
    consensus::encode::deserialize,
    transaction::{Transaction, TxOut},
    Address, Network
};
use hex;
use std::str::FromStr;
use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct TxOutputInfo {
    pub address: String,
    pub amount: u64,
    pub script_hex: String,
    pub op_return_data: String,
}
pub fn parse_tx_from_hash(tx_hex: &str, network: Network) -> Result<Vec<TxOutputInfo>, Box<dyn std::error::Error>> {
    let tx_bytes = hex::decode(tx_hex)?;
    let tx: Transaction = deserialize(&tx_bytes)?;
    let outputs_info: Vec<TxOutputInfo> = tx
        .output
        .iter()
        .map(|output| {
            let address =
                match Address::from_script(&output.script_pubkey, network) {
                    Ok(addr) => addr.to_string(),
                    Err(_) => "".to_string(),
                };

            let op_return_data = if output.script_pubkey.is_op_return() {
                let data_bytes = &output.script_pubkey.as_bytes()[2..];
                String::from_utf8_lossy(data_bytes).to_string()
            } else {
                "".to_string()
            };

            TxOutputInfo {
                address,
                amount: output.value.to_sat(),
                script_hex: hex::encode(output.script_pubkey.as_bytes()),
                op_return_data,
            }
        })
        .collect();

    Ok(outputs_info)
}

pub fn get_transaction_struct_from_tx_hex(tx_hex: &str) -> Transaction {
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let transaction = deserialize(&tx_bytes).unwrap();
    transaction
}