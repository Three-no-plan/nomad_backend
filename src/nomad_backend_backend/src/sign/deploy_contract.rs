


// 定义代币类型
#[derive(CandidType, Clone, Debug, PartialEq)]
pub enum TokenType {
    BRC20,
    RUNES,
}

#[derive(CandidType, Clone, Debug)]
pub struct deployRecord {
    pub token_name: String,
    pub token_type: TokenType,
    pub deploy_hash: String,
    pub timestamp: u64,
}

pub fn deploy_token(token_name: String, token_type: TokenType, withdrawal_hash: String) -> Result<deployRecord, String> {
    if token_name.is_empty() || withdrawal_hash.is_empty() {
        return Err("Token name and hash cannot be empty".to_string());
    }
// 假如类型是符文，添加对utxo的校验
    let record = deployRecord {
        token_name,
        token_type,
        deploy_hash,
        timestamp: ic_cdk::api::time(),
    };

    let id = WITHDRAWAL_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        let id = storage.len();
        storage.insert(id, record.clone());
        id
    });

    Ok(record)
}
