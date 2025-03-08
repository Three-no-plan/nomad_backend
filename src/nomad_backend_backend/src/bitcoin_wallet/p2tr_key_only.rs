use bitcoin::absolute::LockTime;
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, TxIn, TxOut, Witness};
use bitcoin::{key::Secp256k1, secp256k1::PublicKey, Address, Transaction, taproot::TaprootSpendInfo};
use ic_cdk::api::management_canister::bitcoin::BitcoinNetwork;
use ic_cdk::api::management_canister::schnorr::{SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgument, SignWithSchnorrArgument};
use std::str::FromStr;

/// Returns the P2TR key-only address of this canister at the given derivation
/// path.
///
/// Quoting the `bitcoin` crate's rustdoc:
///
/// *Note*: As per BIP341
///
/// When the Merkle root is [`None`], the output key commits to an unspendable script path
/// instead of having no script path. This is achieved by computing the output key point as
/// `Q = P + int(hashTapTweak(bytes(P)))G`. See also [`TaprootSpendInfo::tap_tweak`].
pub async fn get_address(
    network: BitcoinNetwork,
    key_name: String,
    derivation_path: Vec<Vec<u8>>,
) -> Address {
    let public_key = ic_cdk::api::management_canister::schnorr::schnorr_public_key(SchnorrPublicKeyArgument {
        canister_id: None,
        derivation_path: derivation_path,
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340secp256k1,
            name: key_name
        }
    }).await.unwrap().0.public_key;
    let x_only_pubkey =
        bitcoin::key::XOnlyPublicKey::from(PublicKey::from_slice(&public_key).unwrap());
    let secp256k1_engine = Secp256k1::new();
    Address::p2tr(
        &secp256k1_engine,
        x_only_pubkey,
        None,
        super::common::transform_network(network),
    )
}

// pub async fn sign_tx(
//     network: BitcoinNetwork,
//     derivation_path: Vec<Vec<u8>>,
//     key_name: String,
//     tx_fee: u64,
//     dst_address: String,
//     out_points: Vec<OutPoint>,
//     tx_outs: Vec<TxOut>,
//     prevouts_value: u64,
// ) -> Transaction {
//     // Fetch our public key, P2TR key-only address, and UTXOs.
//     let own_public_key = ic_cdk::api::management_canister::schnorr::schnorr_public_key(SchnorrPublicKeyArgument {
//         canister_id: None,
//         derivation_path: derivation_path,
//         key_id: SchnorrKeyId {
//             algorithm: SchnorrAlgorithm::Bip340secp256k1,
//             name: key_name
//         }
//     }).await.unwrap().0.public_key;
//     let x_only_pubkey =
//         bitcoin::key::XOnlyPublicKey::from(PublicKey::from_slice(&own_public_key).unwrap());

//     let secp256k1_engine = Secp256k1::new();
//     let taproot_spend_info =
//         TaprootSpendInfo::new_key_spend(&secp256k1_engine, x_only_pubkey, None);

//     let own_address = Address::p2tr_tweaked(
//         taproot_spend_info.output_key(),
//         super::common::transform_network(network),
//     );

//     let dst_address = Address::from_str(&dst_address)
//         .unwrap()
//         .require_network(super::common::transform_network(network))
//         .expect("should be valid address for the network");

//     let transaction = Transaction {
//         version: Version::TWO,
//         lock_time: LockTime::ZERO,
//         input: {
//             let mut inputs = Vec::new();
//             for outpoint in out_points {
//                 inputs.push(TxIn {
//                     previous_output: outpoint,
//                     script_sig: ScriptBuf::default(),
//                     sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
//                     witness: Witness::default()
//                 });
//             }
//             inputs
//         },
//         output: tx_outs
//     };
//     let prevouts = [TxOut {
//         value: Amount::from_sat(prevouts_value),
//         script_pubkey: own_address.script_pubkey()
//     }];

//     for i in 0..transaction.input.len() {
//         let mut sighasher = SighashCache::new(&mut transaction);

//         let signing_data = sighasher.taproot_key_spend_signature_hash(
//             i,
//             &bitcoin::sighash::Prevouts::All(&prevouts),
//             TapSighashType::Default,
//         )
//         .expect("Failed to encode signing data")
//         .as_byte_array()
//         .to_vec();
    
//         let raw_signature = ic_cdk::api::management_canister::schnorr::sign_with_schnorr(SignWithSchnorrArgument {
//             message: signing_data,
//             derivation_path: derivation_path,
//             key_id: SchnorrKeyId {
//                 algorithm: SchnorrAlgorithm::Bip340secp256k1,
//                 name: key_name
//             }
//         }).await.unwrap().0.signature;
    
//         // Update the witness stack.
//         let witness = sighasher.witness_mut(i).unwrap();
//         let signature = bitcoin::taproot::Signature {
//             signature: Signature::from_slice(&raw_signature).expect("failed to parse signature"),
//             sighash_type: TapSighashType::Default,
//         };
//         witness.push(&signature.to_vec());
//     };

//     transaction
// }