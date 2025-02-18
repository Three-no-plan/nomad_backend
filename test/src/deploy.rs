use ic_agent::Agent;
use candid::{Principal, Encode, Decode};
use crate::IDO_CANISTER_STR;
use crate::ido_did::{DeployBrc20Args, DeployBrc20Result};

// #[test]
// fn test_init() {
//     let pic = PocketIc::new();

//     let canister = pic.create_canister();
//     pic.add_cycles(canister, (4_u64 * 10_u64.pow(12)) as u128);
    
//     let wasm_bytes = include_bytes!("../../target/wasm32-unknown-unknown/release/nomad_backend_backend.wasm").to_vec();
//     pic.install_canister(canister, wasm_bytes, vec![], None);

//     let init_res = pocket_ic::update_candid::<((), ), ((), )>(
//         &pic,
//         canister, 
//         "init", 
//         ((), )
//     ).unwrap().0;

// }

pub async fn test_init(
    agent: Agent,
) {
    let canister = Principal::from_text(IDO_CANISTER_STR).unwrap();

    let init_res = agent.update(
        &canister, "init"
    )
    .with_arg(Encode!().unwrap())
    .call_and_wait()
    .await.unwrap();
}

pub async fn test_deploy_brc20_token(
    agent: Agent,
    args: DeployBrc20Args
) {
    let canister = Principal::from_text(IDO_CANISTER_STR).unwrap();

    let deploy_res_blob = agent.update(
        &canister, "deploy_brc20_token"
    )
    .with_arg(Encode!(&args).unwrap())
    .call_and_wait()
    .await.unwrap(); 

    let deploy_res = Decode!(&deploy_res_blob, DeployBrc20Result).unwrap();

    match deploy_res {
        DeployBrc20Result::Ok => {},
        DeployBrc20Result::Err(err) => panic!("test_deploy_brc20_token err : {}", err)
    }
}