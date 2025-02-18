use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
use bitcoin::consensus::encode::serialize;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Sequence, Txid, Witness};
use serde_json::json;
use std::str::FromStr;
use bitcoin::Address;
use bitcoin::Network;

pub fn build_deploy_brc20_tx(
    network: Network
) -> String {

    // 1. 创建 BRC-20 铭文 JSON 数据
    let inscription = json!({
        "p": "brc-20",
        "op": "deploy",
        "tick": "rust",
        "max": "21000000",
        "lim": "1000"
    });

    // 2. 将铭文 JSON 转换为字符串
    let inscription_data = inscription.to_string();

    // 3. 构造比特币交易
    let from_address = "tb1p6eelr5m8eulhkqpavze4yr6mrn6ss2fsmqxur82ffzqenkh44v4s39qm46";
    let to_address = "tb1p6eelr5m8eulhkqpavze4yr6mrn6ss2fsmqxur82ffzqenkh44v4s39qm46";  // 通常为 P2TR 地址
    let utxo_txid = "dd3e51b58793c28ec1c33078655e0911c43bf2d970e8aa380a2b955414337ae8";  // 你拥有的 UTXO
    let vout = 0; // 选择对应的输出索引

    let from_addr = Address::from_str(from_address).unwrap().require_network(network).unwrap();
    let to_addr = Address::from_str(to_address).unwrap().require_network(network).unwrap();

    let mut txin = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: Txid::from_str(&utxo_txid).unwrap(),
            vout,
        },
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new()
    };
    txin.witness.push(inscription_data.as_bytes());
    let txout = TxOut {
        value: Amount::from_sat(546),  // 最小比特币金额，防止 dust limit
        script_pubkey: to_addr.script_pubkey(),
    };

    let transaction = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    // 4. 序列化交易
    let raw_tx = serialize(&transaction);
    let raw_tx_hex = hex::encode(raw_tx);

    raw_tx_hex
}
