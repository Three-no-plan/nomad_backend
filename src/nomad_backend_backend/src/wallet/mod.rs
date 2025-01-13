use ic_cdk::api::management_canister::{ecdsa, schnorr};
use ecdsa::{EcdsaPublicKeyArgument, EcdsaKeyId, SignWithEcdsaArgument};
use schnorr::{SchnorrPublicKeyArgument, SchnorrKeyId, SignWithSchnorrArgument};
use bitcoin::{
    Address, Network, KnownHrp, ScriptBuf,
    taproot::{TaprootSpendInfo, TaprootBuilder},
    secp256k1::{Secp256k1, PublicKey},
    key::XOnlyPublicKey
};

pub async fn get_ecdsa_public_key(key_id: EcdsaKeyId, derivation_path: Vec<Vec<u8>>) -> Vec<u8> {
    let call_res = ecdsa::ecdsa_public_key(EcdsaPublicKeyArgument { 
        canister_id: None, 
        derivation_path: derivation_path, 
        key_id: key_id 
    }).await.unwrap().0;

    call_res.public_key
}

pub async fn get_ecdsa_signature(key_id: EcdsaKeyId, derivation_path: Vec<Vec<u8>>, message_hash: Vec<u8>) -> Vec<u8> {
    let call_res = ecdsa::sign_with_ecdsa(SignWithEcdsaArgument {
        message_hash: message_hash,
        derivation_path: derivation_path,
        key_id: key_id
    }).await.unwrap().0;

    call_res.signature
}

// Converts a SEC1 ECDSA signature to the DER format.
pub fn sec1_to_der(sec1_signature: Vec<u8>) -> Vec<u8> {
    let r: Vec<u8> = if sec1_signature[0] & 0x80 != 0 {
        // r is negative. Prepend a zero byte.
        let mut tmp = vec![0x00];
        tmp.extend(sec1_signature[..32].to_vec());
        tmp
    } else {
        // r is positive.
        sec1_signature[..32].to_vec()
    };

    let s: Vec<u8> = if sec1_signature[32] & 0x80 != 0 {
        // s is negative. Prepend a zero byte.
        let mut tmp = vec![0x00];
        tmp.extend(sec1_signature[32..].to_vec());
        tmp
    } else {
        // s is positive.
        sec1_signature[32..].to_vec()
    };

    // Convert signature to DER.
    vec![
        vec![0x30, 4 + r.len() as u8 + s.len() as u8, 0x02, r.len() as u8],
        r,
        vec![0x02, s.len() as u8],
        s,
    ]
    .into_iter()
    .flatten()
    .collect()
}

pub async fn get_schnorr_public_key(key_id: SchnorrKeyId, derivation_path: Vec<Vec<u8>>) -> Vec<u8> {
    let call_res = schnorr::schnorr_public_key(SchnorrPublicKeyArgument {
        canister_id: None,
        derivation_path: derivation_path,
        key_id: key_id
    }).await.unwrap().0;

    call_res.public_key
}

pub async fn get_schnorr_signature(key_id: SchnorrKeyId, derivation_path: Vec<Vec<u8>>, message: Vec<u8>) -> Vec<u8> {
    let call_res = schnorr::sign_with_schnorr(SignWithSchnorrArgument {
        message: message,
        derivation_path: derivation_path,
        key_id: key_id
    }).await.unwrap().0;

    call_res.signature
}

pub fn public_key_to_p2tr_script_spend_address(
    bitcoin_network: Network,
    public_key: &[u8],
) -> Address {
    let taproot_spend_info = p2tr_scipt_spend_info(public_key);
    Address::p2tr_tweaked(taproot_spend_info.output_key(), transform_network_to_knownhrp(bitcoin_network))
}

pub fn transform_network_to_knownhrp(network: Network) -> KnownHrp {
    match network {
        Network::Bitcoin => KnownHrp::Mainnet,
        Network::Testnet => KnownHrp::Testnets,
        Network::Testnet4 => KnownHrp::Testnets,
        Network::Signet => KnownHrp::Testnets,
        Network::Regtest => KnownHrp::Regtest,
        _ => panic!("Unsupported network"),
    }
}

fn p2tr_scipt_spend_info(public_key: &[u8]) -> TaprootSpendInfo {
    let spend_script = p2tr_script(public_key);
    let secp256k1_engine = Secp256k1::new();
    // This is the key used in the *tweaked* key path spending. Currently, this
    // use case is not supported on the IC. But, once the IC supports this use
    // case, the addresses constructed in this way will be able to use same key
    // in both script and *tweaked* key path spending.
    let internal_public_key = XOnlyPublicKey::from(PublicKey::from_slice(&public_key).unwrap());

    TaprootBuilder::new()
        .add_leaf(0, spend_script.clone())
        .expect("adding leaf should work")
        .finalize(&secp256k1_engine, internal_public_key)
        .expect("finalizing taproot builder should work")
}

/// Computes a simple P2TR script that allows the `public_key` and no other keys
/// to be used for spending.
fn p2tr_script(public_key: &[u8]) -> ScriptBuf {
    let x_only_public_key = XOnlyPublicKey::from(PublicKey::from_slice(public_key).unwrap());
    bitcoin::blockdata::script::Builder::new()
        .push_x_only_key(&x_only_public_key)
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
        .into_script()
}