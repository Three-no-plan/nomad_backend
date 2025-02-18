use ic_agent::Agent;
use candid::{Principal, Encode, Decode};
use crate::ido_did::{MintBrc20Args, MintBrc20Result};
use crate::IDO_CANISTER_STR;

pub async fn test_mint_brc20_token(
    agent: Agent,
    args: MintBrc20Args
) {
    let canister = Principal::from_text(IDO_CANISTER_STR).unwrap();

    let mint_res_blob = agent.update(
        &canister, "mint_brc20_token"
    )
    .with_arg(Encode!(&args).unwrap())
    .call_and_wait()
    .await.unwrap(); 

    let mint_res = Decode!(&mint_res_blob, MintBrc20Result).unwrap();

    match mint_res {
        MintBrc20Result::Ok(sig_hex) => println!("test_mint_brc20_token sig_hex: {}", sig_hex),
        MintBrc20Result::Err(err) => panic!("test_mint_brc20_token err : {}", err)
    }
}