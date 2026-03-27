//! Aptos blockchain provider for x402 payments.
//!
//! This module implements the x402 facilitator interface for Aptos blockchain.
//! Aptos uses the Move programming language and has different transaction
//! semantics compared to EVM chains.
//!
//! # Configuration
//!
//! Configure via environment variables:
//! - `APTOS_RPC_URL` or `APTOS_TESTNET_RPC_URL`: Aptos node endpoint
//! - `APTOS_PRIVATE_KEY` or `APTOS_TESTNET_PRIVATE_KEY`: Facilitator signing key
//!
//! # Status
//!
//! This is a placeholder implementation. Full Aptos support requires:
//! - Aptos SDK integration
//! - Move module for x402 payments
//! - USDC token integration on Aptos

use std::sync::Arc;

use crate::facilitator::Facilitator;
use crate::network::Network;
use crate::tokens::TokenManager;
use crate::types::{
    MixedAddress, Scheme, SettleRequest, SettleResponse, SupportedPaymentKind,
    SupportedPaymentKindsResponse, VerifyRequest, VerifyResponse, X402Version,
};

use super::FacilitatorLocalError;

/// Aptos provider configuration.
#[derive(Debug, Clone)]
pub struct AptosConfig {
    /// The Aptos network (mainnet or testnet).
    pub network: Network,
    /// RPC endpoint URL.
    pub rpc_url: String,
    /// Facilitator account address (hex-encoded).
    pub account_address: String,
}

/// Provider for Aptos blockchain interactions.
///
/// Handles x402 payment verification and settlement on Aptos.
pub struct AptosProvider {
    config: AptosConfig,
    #[allow(unused)]
    token_manager: Option<Arc<TokenManager>>,
}

impl AptosProvider {
    /// Creates a new Aptos provider with the given configuration.
    pub fn new(config: AptosConfig, token_manager: Option<Arc<TokenManager>>) -> Self {
        Self {
            config,
            token_manager,
        }
    }

    /// Attempts to create an Aptos provider from environment variables.
    ///
    /// Returns `Ok(None)` if the required environment variables are not set,
    /// indicating this network should be skipped.
    pub async fn from_env(
        network: Network,
        token_manager: Option<&Arc<TokenManager>>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let (rpc_env, key_env) = match network {
            Network::Aptos => ("APTOS_RPC_URL", "APTOS_PRIVATE_KEY"),
            Network::AptosTestnet => ("APTOS_TESTNET_RPC_URL", "APTOS_TESTNET_PRIVATE_KEY"),
            _ => return Ok(None),
        };

        // Check if RPC URL is configured
        let rpc_url = match std::env::var(rpc_env) {
            Ok(url) => url,
            Err(_) => {
                tracing::debug!(
                    network = %network,
                    env_var = %rpc_env,
                    "Aptos RPC URL not configured, skipping network"
                );
                return Ok(None);
            }
        };

        // Check if private key is configured
        let account_address = match std::env::var(key_env) {
            Ok(key) => {
                // In a full implementation, we'd derive the address from the key
                // For now, just use a placeholder
                format!("0x{}", &key[..64.min(key.len())])
            }
            Err(_) => {
                tracing::debug!(
                    network = %network,
                    env_var = %key_env,
                    "Aptos private key not configured, skipping network"
                );
                return Ok(None);
            }
        };

        let config = AptosConfig {
            network,
            rpc_url,
            account_address,
        };

        Ok(Some(Self::new(config, token_manager.cloned())))
    }

    /// Returns the network this provider is configured for.
    pub fn network(&self) -> Network {
        self.config.network
    }

    /// Returns the facilitator's signer address.
    pub fn signer_address(&self) -> MixedAddress {
        MixedAddress::Offchain(self.config.account_address.clone())
    }
}

impl Facilitator for AptosProvider {
    type Error = FacilitatorLocalError;

    async fn verify(&self, _request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        // Aptos verification is not yet implemented
        // Return an error indicating the network is not yet supported
        Err(FacilitatorLocalError::UnsupportedNetwork(None))
    }

    async fn settle(&self, _request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        // Aptos settlement is not yet implemented
        Err(FacilitatorLocalError::UnsupportedNetwork(None))
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        // Return supported payment kinds for Aptos
        // Even though verify/settle are not implemented, we advertise support
        // so clients know the network will be supported
        let network = self.config.network;
        Ok(SupportedPaymentKindsResponse {
            kinds: vec![
                SupportedPaymentKind {
                    x402_version: X402Version::V1,
                    scheme: Scheme::Exact,
                    network: network.to_string(),
                    extra: None,
                },
                SupportedPaymentKind {
                    x402_version: X402Version::V2,
                    scheme: Scheme::Exact,
                    network: network.to_chain_id().to_string(),
                    extra: None,
                },
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Scheme, X402Version};

    #[test]
    fn test_aptos_config() {
        let config = AptosConfig {
            network: Network::Aptos,
            rpc_url: "https://fullnode.mainnet.aptoslabs.com/v1".to_string(),
            account_address: "0x1".to_string(),
        };

        assert_eq!(config.network, Network::Aptos);
    }

    #[test]
    fn test_signer_address() {
        let config = AptosConfig {
            network: Network::Aptos,
            rpc_url: "https://example.com".to_string(),
            account_address: "0x123abc".to_string(),
        };

        let provider = AptosProvider::new(config, None);
        match provider.signer_address() {
            MixedAddress::Offchain(addr) => assert_eq!(addr, "0x123abc"),
            _ => panic!("expected Offchain address"),
        }
    }

    #[tokio::test]
    async fn test_supported_returns_v1_and_v2() {
        let config = AptosConfig {
            network: Network::Aptos,
            rpc_url: "https://example.com".to_string(),
            account_address: "0x1".to_string(),
        };
        let provider = AptosProvider::new(config, None);
        let response = provider.supported().await.unwrap();

        assert_eq!(response.kinds.len(), 2);

        // V1 entry uses network name
        let v1 = &response.kinds[0];
        assert_eq!(v1.x402_version, X402Version::V1);
        assert_eq!(v1.scheme, Scheme::Exact);
        assert_eq!(v1.network, "aptos");

        // V2 entry uses CAIP-2 chain ID
        let v2 = &response.kinds[1];
        assert_eq!(v2.x402_version, X402Version::V2);
        assert_eq!(v2.scheme, Scheme::Exact);
        assert_eq!(v2.network, "aptos:mainnet");
    }

    #[tokio::test]
    async fn test_supported_testnet_returns_v1_and_v2() {
        let config = AptosConfig {
            network: Network::AptosTestnet,
            rpc_url: "https://example.com".to_string(),
            account_address: "0x1".to_string(),
        };
        let provider = AptosProvider::new(config, None);
        let response = provider.supported().await.unwrap();

        assert_eq!(response.kinds.len(), 2);

        let v1 = &response.kinds[0];
        assert_eq!(v1.x402_version, X402Version::V1);
        assert_eq!(v1.network, "aptos-testnet");

        let v2 = &response.kinds[1];
        assert_eq!(v2.x402_version, X402Version::V2);
        assert_eq!(v2.network, "aptos:testnet");
    }

    #[tokio::test]
    async fn test_supported_json_format() {
        let config = AptosConfig {
            network: Network::Aptos,
            rpc_url: "https://example.com".to_string(),
            account_address: "0x1".to_string(),
        };
        let provider = AptosProvider::new(config, None);
        let response = provider.supported().await.unwrap();

        let json = serde_json::to_value(&response).unwrap();
        let kinds = json["kinds"].as_array().unwrap();

        // V1 entry: x402Version serializes as 1, network is plain name
        assert_eq!(kinds[0]["x402Version"], 1);
        assert_eq!(kinds[0]["network"], "aptos");
        assert_eq!(kinds[0]["scheme"], "exact");

        // V2 entry: x402Version serializes as 2, network is CAIP-2
        assert_eq!(kinds[1]["x402Version"], 2);
        assert_eq!(kinds[1]["network"], "aptos:mainnet");
        assert_eq!(kinds[1]["scheme"], "exact");
    }
}
