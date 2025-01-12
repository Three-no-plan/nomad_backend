use base64;
use hex;
use bitcoin::{Network, Txid, psbt::Psbt};
use std::str::FromStr;
use super::{
    types::{TransactionInput, TransactionOutput, TransactionResult, InputUtxo},
    builder::PsbtBuilder,
};

pub fn create_transaction_multi(
    network: Network,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
) -> Result<TransactionResult, String> {
    if inputs.is_empty() {
        return Err("No inputs provided".to_string());
    }
    if outputs.is_empty() {
        return Err("No outputs provided".to_string());
    }

    let mut builder = PsbtBuilder::new(network);
    let mut total_input = 0;
    let mut total_output = 0;
    
    for input in inputs {
        let tx_id = Txid::from_str(&input.txid)
            .map_err(|e| format!("Invalid input txid: {}", e))?;
        
        let input_utxo = InputUtxo {
            tx_id,
            vout: input.vout,
            value: bitcoin::Amount::from_sat(input.amount),
        };

        total_input += input.amount;

        let pubkey_bytes = if let Some(pk) = input.public_key {
            Some(hex::decode(&pk).map_err(|e| format!("Invalid public key hex: {}", e))?)
        } else {
            None
        };

        builder.add_input(
            input_utxo,
            &input.address,
            pubkey_bytes.as_deref(),
            input.sighash_type,
        )?;
    }

    for output in outputs {
        total_output += output.amount;
        builder.add_output(&output.address, output.amount)?;
    }

    if total_input < total_output {
        return Err("Input amount isnt enough".to_string());
    }

    let psbt = builder.build()?;
    let tx = psbt.extract_tx().map_err(|e| e.to_string())?;
    let txid = tx.txid().to_string();

    let fee = total_input - total_output;
    let vsize = builder.estimate_vbytes()?;

    let serialized = builder.serialize()?;
    let psbt_base64 = base64::encode(&serialized);
    let psbt_hex = hex::encode(&serialized);

    Ok(TransactionResult {
        txid,
        psbt_base64,
        psbt_hex,
        vsize,
        total_input,
        total_output,
        fee,
    })
}

pub fn combine_psbt(psbt1: &str, psbt2: &str) -> Result<String, String> {
    let psbt1_bytes = if psbt1.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(psbt1).map_err(|e| format!("Failed to decode hex PSBT1: {}", e))?
    } else {
        base64::decode(psbt1).map_err(|e| format!("Failed to decode base64 PSBT1: {}", e))?
    };

    let psbt2_bytes = if psbt2.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(psbt2).map_err(|e| format!("Failed to decode hex PSBT2: {}", e))?
    } else {
        base64::decode(psbt2).map_err(|e| format!("Failed to decode base64 PSBT2: {}", e))?
    };

    let mut psbt1 = Psbt::deserialize(&psbt1_bytes)
        .map_err(|e| format!("Failed to deserialize PSBT1: {}", e))?;
    let psbt2 = Psbt::deserialize(&psbt2_bytes)
        .map_err(|e| format!("Failed to deserialize PSBT2: {}", e))?;

    psbt1.combine(psbt2)
        .map_err(|e| format!("Failed to combine PSBTs: {}", e))?;

    let combined_bytes = psbt1.serialize();
    Ok(base64::encode(&combined_bytes))
}
