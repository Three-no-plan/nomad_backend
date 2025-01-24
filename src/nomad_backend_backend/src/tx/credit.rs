use bitcoin::secp256k1::{
    Secp256k1, Message, PublicKey, Error,
    ecdsa::{RecoverableSignature, RecoveryId}
};

pub fn get_credit_code(message_digest: &[u8], sig: &[u8], recovery_id: i32) -> String {
    let user_public_key = recover_public_key_from_signature(message_digest, sig, recovery_id).unwrap();
    generate_credit_code()
}

fn recover_public_key_from_signature(message_digest: &[u8], sig: &[u8], recovery_id: i32) -> Result<PublicKey, Error> {
    let secp = Secp256k1::new();
    let recovery_id = RecoveryId::from_i32(recovery_id).unwrap();
    let msg = Message::from_digest_slice(message_digest).unwrap();
    let recoverable_sig = RecoverableSignature::from_compact(&sig, recovery_id).unwrap();
    secp.recover_ecdsa(&msg, &recoverable_sig)
}


fn generate_credit_code() -> String {
    "".to_string()
}