use bitcoin::Network;
use ic_cdk::api::management_canister::bitcoin::BitcoinNetwork;

pub fn transform_network(network: BitcoinNetwork) -> Network {
    match network {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Regtest => Network::Regtest,
    }
}