use bitcoin::{
    absolute::LockTime,
    psbt,
    ScriptBuf,
    transaction::Version,
    Address,
    AddressType,
    Amount,
    CompressedPublicKey,
    Network,
    PublicKey,
    Script,
    Sequence,
    Transaction,
    TxIn,
    TxOut,
    Witness,
    OutPoint,
    Txid,
};
use bitcoin::psbt::Psbt;  

use std::str::FromStr;
use super::types::InputUtxo;
use bitcoin::psbt::PsbtSighashType;
use super::types::InputSignatureType;


struct PsbtBuilderIn {
    prevout: InputUtxo,
    owner_address: Address,
    owner_pub_key: Option<PublicKey>,
    sighash_type: Option<PsbtSighashType>, 
}

pub struct PsbtBuilder {
    network: Network,
    inputs: Vec<PsbtBuilderIn>,
    outputs: Vec<TxOut>,
}

impl PsbtBuilder {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }
    pub fn add_input(
        &mut self,
        utxo: InputUtxo,
        owner_address: &str,
        owner_pub_key: Option<&[u8]>,
        signature_type: Option<InputSignatureType>,
        // sighash_type: Option<PsbtSighashType>, 
        // sighash_type: Option<TapSighashType>, // 使用 TapSighashType

    ) -> Result<(), String> {
        let owner_address = Address::from_str(owner_address)
            .map_err(|e| e.to_string())?
            .require_network(self.network)
            .map_err(|e| e.to_string())?;

        let owner_pub_key = owner_pub_key
            .map(|pk| PublicKey::from_slice(pk))
            .transpose()
            .map_err(|_| "invalid public key".to_string())?;
        let psbt_sighash_type = signature_type.map(|st| st.to_psbt_sighash_type());


        self.inputs.push(PsbtBuilderIn {
            prevout: utxo,
            owner_address,
            owner_pub_key,
            sighash_type: psbt_sighash_type,
        });

        Ok(())
    }
    pub fn add_output(&mut self, address: &str, amount: u64, op_return: Option<Vec<u8>>) -> Result<(), String> {
        if let Some(data) = op_return {
            if data.len() > 80 {
                return Err("OP_RETURN data too long (more than 80 bytes)".to_string());
            }
            
            let script = ScriptBuf::from_bytes(data);

            
            self.outputs.push(TxOut {
                script_pubkey: script,
                value: Amount::from_sat(0),
            });
            
            return Ok(());
        }
        let address = Address::from_str(address)
            .map_err(|e| e.to_string())?
            .require_network(self.network)
            .map_err(|e| e.to_string())?;

        let amount = Amount::from_sat(amount);

        self.outputs.push(TxOut {
            script_pubkey: address.script_pubkey(),
            value: amount,
        });

        Ok(())
    }


    pub fn build(&self) -> Result<psbt::Psbt, String> {
        let mut psbt_inputs = Vec::with_capacity(self.inputs.len());
        let mut tx_inputs = Vec::with_capacity(self.inputs.len());

        for input in &self.inputs {
            tx_inputs.push(TxIn {
                previous_output: (&input.prevout).into(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            });

            let redeem_script = match (input.owner_address.address_type(), input.owner_pub_key) {
                (Some(AddressType::P2sh), Some(pub_key)) => {
                    if let Ok(pub_key) = CompressedPublicKey::try_from(pub_key) {
                        let addr = Address::p2wpkh(&pub_key, self.network);
                        Some(addr.script_pubkey())
                    } else {
                        None
                    }
                }
                _ => None,
            };

            psbt_inputs.push(psbt::Input {
                witness_utxo: Some(TxOut {
                    value: input.prevout.value,
                    script_pubkey: input.owner_address.script_pubkey(),
                }),
                redeem_script,
                sighash_type: input.sighash_type, 

                ..Default::default()
            });
        }

        let tx_outputs = self.outputs.clone();
        let psbt_outputs = vec![Default::default(); tx_outputs.len()];

        let unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        Ok(psbt::Psbt {
            version: 0,
            inputs: psbt_inputs,
            outputs: psbt_outputs,
            unsigned_tx,
            proprietary: Default::default(),
            unknown: Default::default(),
            xpub: Default::default(),
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        let psbt = self.build()?;
        Ok(psbt.serialize())
    }

    pub fn estimate_vbytes(&self) -> Result<u64, String> {
        const PAYLOAD_SIZE: usize = 50;

        let psbt = self.build()?;
        let mut unsigned_tx = psbt
            .extract_tx()
            .map_err(|ex| format!("failed to extract tx: {}", ex))?;

        for (tx_in, psbt_in) in unsigned_tx.input.iter_mut().zip(&self.inputs) {
            if let Some(addr_type) = psbt_in.owner_address.address_type() {
                match addr_type {
                    AddressType::P2sh => {
                        tx_in.witness = Witness::from_slice(&[[0; PAYLOAD_SIZE]]);
                        tx_in.script_sig = Script::from_bytes(&[0; PAYLOAD_SIZE]).into();
                    }
                    AddressType::P2wsh => {
                        tx_in.witness = Witness::from_slice(&[[0; PAYLOAD_SIZE]]);
                    }
                    _ => {
                        tx_in.script_sig = Script::from_bytes(&[0; PAYLOAD_SIZE]).into();
                    }
                }
            }
        }
        Ok(unsigned_tx.weight().to_vbytes_ceil())
    }
}
