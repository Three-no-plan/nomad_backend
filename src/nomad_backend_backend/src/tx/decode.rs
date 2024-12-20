use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use sha2::{Sha256, Digest};
use bs58;

#[derive(CandidType, Deserialize, Clone)]
pub struct Transaction {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    lock_time: u32,
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
    value: u64,
    script: String,
    address: Option<String>,
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

#[ic_cdk::update]
pub async fn parse_tx_from_hash(hex_str: String) -> Result<Transaction, String> {
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