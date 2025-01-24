use std::str::FromStr;

use bitcoin::ScriptBuf;
use bitcoin::{
    consensus::encode::deserialize,
    Address,
 };
use sha2::{Sha256, Digest};
use bs58;
use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Clone)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn convert_to_std_bitcoin_tx(&self) -> bitcoin::Transaction {
        bitcoin::Transaction { 
            version: bitcoin::transaction::Version::TWO, 
            lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(self.lock_time), 
            input: self.inputs.iter().map(|input| bitcoin::transaction::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_str(input.txid.as_str()).unwrap(),
                    vout: input.vout
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(input.sequence),
                witness: bitcoin::Witness::new()
            }).collect(), 
            output: self.outputs.iter().map(|output| bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(output.value),
                script_pubkey: ScriptBuf::from_hex(&output.script).unwrap()
            }).collect()
        }
    }
}
#[derive(Debug, Clone, candid::CandidType, serde::Deserialize)]
pub struct Input {
    txid: String,
    vout: u32,
    script: String,
    sequence: u32,
}

#[derive(Debug, Clone, candid::CandidType, serde::Deserialize)]
pub struct Output {
    pub value: u64,
    pub script: String,
    pub address: Option<String>,
}

pub fn parse_varint(data: &[u8], offset: &mut usize) -> (usize, String) {
    let first_byte = data[*offset];
    let original_offset = *offset;
    *offset += 1;

    let (value, len) = match first_byte {
        0..=0xfc => (first_byte as usize, 1),
        0xfd => {
            let value = u16::from_le_bytes([data[*offset], data[*offset + 1]]) as usize;
            *offset += 2;
            (value, 3)
        }
        0xfe => {
            let value = u32::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]) as usize;
            *offset += 4;
            (value, 5)
        }
        _ => {
            let value = u64::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3], 
                                          data[*offset + 4], data[*offset + 5], data[*offset + 6], data[*offset + 7]]) as usize;
            *offset += 8;
            (value, 9)
        }
    };
    let raw = hex::encode(&data[original_offset..original_offset + len]);
    (value, raw)
}

pub fn script_to_address(script: &[u8]) -> Option<String> {
    if script.is_empty() {
        return None;
    }

    if script.len() == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 
        && script[23] == 0x88 && script[24] == 0xac {
        return Some(hash160_to_address(&script[3..23], 0x00));
    }

    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return Some(hash160_to_address(&script[2..22], 0x05));
    }
    None
}

fn hash160_to_address(hash: &[u8], version: u8) -> String {
    let mut address = vec![version];
    address.extend_from_slice(hash);

    let mut hasher = Sha256::new();
    hasher.update(&address);
    let temp = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(temp);
    let checksum = &hasher.finalize()[0..4];

    address.extend_from_slice(checksum);
    bs58::encode(address).into_string()

}

pub fn parse_tx_from_hash(hex_str: String) -> Result<Transaction, String> {
    let data = hex::decode(&hex_str).map_err(|e| e.to_string())?;

    let mut offset = 0;
    offset += 4; 

    let (input_count, _) = parse_varint(&data, &mut offset);
    let mut inputs = Vec::with_capacity(input_count);

    for _ in 0..input_count {
        let raw_txid = hex::encode(&data[offset..offset + 32]);
        let txid = raw_txid.clone();
        offset += 32;

        let vout = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        let (script_len, _) = parse_varint(&data, &mut offset);
        let raw_script = hex::encode(&data[offset..offset + script_len]);
        let script = raw_script.clone();
        offset += script_len;

        let sequence = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        offset += 4;

        inputs.push(Input {
            txid,
            vout,
            script,
            sequence,
        });
    }

    let (output_count, _) = parse_varint(&data, &mut offset);
    let mut outputs = Vec::with_capacity(output_count);

    for _ in 0..output_count {
        let value = u64::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                                      data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        offset += 8;
        let (script_len, _) = parse_varint(&data, &mut offset);
        let script_data = &data[offset..offset + script_len];
        let raw_script = hex::encode(script_data);
        let script = raw_script.clone();
        let address = script_to_address(script_data);
        offset += script_len;
        outputs.push(Output {
            value,
            script,
            address,
        });
    }

    let lock_time = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);

    Ok(Transaction {
        inputs,
        outputs,
        lock_time,
    })
}

#[derive(CandidType, Deserialize, Clone)]
pub struct TxOutputInfo {
   pub address: String,
   pub amount: u64,
   pub script_hex: String,
   pub op_return_data: String,
}

pub fn parse_bitcoin_transaction(tx_hex: &str) -> Result<Vec<TxOutputInfo>, Box<dyn std::error::Error>> {
   let tx_bytes = hex::decode(tx_hex)?;
   let tx: bitcoin::Transaction = deserialize(&tx_bytes)?;

   let outputs_info: Vec<TxOutputInfo> = tx.output.iter().map(|output| {
       let address = match Address::from_script(&output.script_pubkey, bitcoin::Network::Bitcoin) {
           Ok(addr) => addr.to_string(),
           Err(_) => "N/A".to_string(),
       };

       let op_return_data = if output.script_pubkey.is_op_return() {
           let data_bytes = &output.script_pubkey.as_bytes()[2..];
           String::from_utf8_lossy(data_bytes).to_string()
       } else {
           "N/A".to_string()
       };

       TxOutputInfo {
           address,
           amount: output.value.to_sat(),
           script_hex: hex::encode(output.script_pubkey.as_bytes()),
           op_return_data,
       }
   }).collect();

   Ok(outputs_info)
}
