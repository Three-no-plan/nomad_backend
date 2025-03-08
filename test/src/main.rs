mod deploy;
mod mint;
mod refund;
mod utils;
mod ido_did;
mod brc20;

use bitcoin::Network;
use utils::build_agent;
use ido_did::{DeployBrc20Args, MintBrc20Args};

pub const IDO_CANISTER_STR: &str = "6lgb3-2iaaa-aaaan-qzu3a-cai";
const IDENTITY_STR: &str = "./identity.pem";
pub const BTC_NETWORK: Network = Network::Testnet4;

#[tokio::main]
async fn main() {
    // brc20 ----------------------------------------------------------------
    println!("Deploy brc20 TX_HEX: {}", brc20::build_deploy_brc20_tx(bitcoin::Network::Testnet4));

    // Canister ------------------------------------------------------------------------------------
    let agent = build_agent(IDENTITY_STR);
    // test_init
    deploy::test_init(agent.clone()).await;

    // test_deploy_brc20_token
    // tx中的tx::decode::parse_tx_from_hash 解码交易会报错
    deploy::test_deploy_brc20_token(agent.clone(), DeployBrc20Args {
        token_amount: 100,
        ido_target_btc_vol: 100_000_000,
        deploy_tx_hash: "d6510635992ffe2f3a460425390bf80a00c29f165673124b5c33a0b3d5535218".to_string(),
        token_name: "ORDI".to_string(),
    }).await;

    // test_mint_brc20_token
    mint::test_mint_brc20_token(agent.clone(), MintBrc20Args {
        mint_psbt_tx_hex: "d6510635992ffe2f3a460425390bf80a00c29f165673124b5c33a0b3d5535218".to_string(),
        contract_id: "ORDI#0".to_string(),
        user_address: "tb1plqtlfuzvg0sse2x5tk50jzdk5kt3n3tt3g3pfehsdra0c74wmhssu8wfz0".to_string(),
        token_name: "ORDI".to_string()
    }).await;
}