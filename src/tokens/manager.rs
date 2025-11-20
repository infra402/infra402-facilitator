//! Token manager with configuration loading and resolution

use alloy::primitives::Address;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::config::{ContractType, TokenConfig, TokenDefinition, TokenSettings};

/// Token manager for resolving token addresses and definitions
#[derive(Debug, Clone)]
pub struct TokenManager {
    /// Path to tokens.toml configuration file
    config_path: String,
    /// Hot-reloadable state
    state: Arc<RwLock<TokenState>>,
}

/// Internal state for token management
#[derive(Debug, Clone)]
struct TokenState {
    /// Global settings from tokens.toml
    settings: TokenSettings,
    /// Cached address → token_name mappings per network
    /// network_name → (address → token_name)
    address_cache: HashMap<String, HashMap<Address, String>>,
}

impl TokenManager {
    /// Create a new TokenManager and load configuration from file
    pub fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config = TokenConfig::from_file(config_path)?;

        let mut address_cache = HashMap::new();

        // Build reverse lookup cache (address → token_name) for each network
        // Custom tokens are already merged into config.tokens.networks by TokenConfig::from_file
        for (network_name, network_tokens) in &config.tokens.networks {
            let mut network_cache = HashMap::new();

            for (token_name, address_str) in &network_tokens.tokens {
                if let Ok(addr) = Address::from_str(address_str) {
                    network_cache.insert(addr, token_name.clone());
                } else {
                    tracing::warn!(
                        address = address_str,
                        token = token_name,
                        network = network_name,
                        "Invalid address format in token configuration"
                    );
                }
            }

            address_cache.insert(network_name.clone(), network_cache);
        }

        let state = TokenState {
            settings: config.tokens,
            address_cache,
        };

        tracing::info!(
            path = config_path,
            definitions = state.settings.definitions.len(),
            networks = state.settings.networks.len(),
            "Initialized TokenManager"
        );

        Ok(Self {
            config_path: config_path.to_string(),
            state: Arc::new(RwLock::new(state)),
        })
    }


    /// Get token name from address for a specific network
    ///
    /// Returns the token identifier (e.g., "usdc", "xbnb") if found
    pub async fn get_token_name(
        &self,
        address: Address,
        network: &str,
    ) -> Option<String> {
        let state = self.state.read().await;

        state
            .address_cache
            .get(network)
            .and_then(|cache| cache.get(&address))
            .cloned()
    }

    /// Get token definition by name
    pub async fn get_token_definition(&self, token_name: &str) -> Option<TokenDefinition> {
        let state = self.state.read().await;
        state.settings.definitions.get(token_name).cloned()
    }

    /// Get resolved token address for a network
    pub async fn get_token_address(
        &self,
        token_name: &str,
        network: &str,
    ) -> Option<Address> {
        let state = self.state.read().await;

        let network_tokens = state.settings.networks.get(network)?;

        // Custom tokens are already merged into network_tokens.tokens by TokenConfig
        if let Some(address_str) = network_tokens.tokens.get(token_name) {
            return Address::from_str(address_str).ok();
        }

        None
    }

    /// Get contract type for a token
    pub async fn get_contract_type(&self, token_name: &str) -> Option<ContractType> {
        let state = self.state.read().await;
        state
            .settings
            .definitions
            .get(token_name)
            .map(|def| def.contract_type.clone())
    }

    /// Reload configuration from disk
    pub async fn reload(&self) -> Result<(), String> {
        let config = TokenConfig::from_file(&self.config_path).map_err(|e| e.to_string())?;

        let mut address_cache = HashMap::new();

        // Rebuild reverse lookup cache
        // Custom tokens are already merged into config.tokens.networks by TokenConfig::from_file
        for (network_name, network_tokens) in &config.tokens.networks {
            let mut network_cache = HashMap::new();

            for (token_name, address_str) in &network_tokens.tokens {
                if let Ok(addr) = Address::from_str(address_str) {
                    network_cache.insert(addr, token_name.clone());
                } else {
                    tracing::warn!(
                        address = address_str,
                        token = token_name,
                        network = network_name,
                        "Invalid address format in token configuration during reload"
                    );
                }
            }

            address_cache.insert(network_name.clone(), network_cache);
        }

        let new_state = TokenState {
            settings: config.tokens,
            address_cache,
        };

        let mut state = self.state.write().await;
        *state = new_state.clone();

        tracing::info!(
            definitions = new_state.settings.definitions.len(),
            networks = new_state.settings.networks.len(),
            "Reloaded TokenManager configuration"
        );

        Ok(())
    }

    /// Check if a token exists for a network
    pub async fn has_token(&self, token_name: &str, network: &str) -> bool {
        self.get_token_address(token_name, network).await.is_some()
    }

    /// Get all token names for a network
    pub async fn get_network_tokens(&self, network: &str) -> Vec<String> {
        let state = self.state.read().await;

        state
            .settings
            .networks
            .get(network)
            .map(|network_tokens| {
                let mut tokens: Vec<String> = network_tokens
                    .tokens
                    .keys()
                    .cloned()
                    .collect();
                tokens.sort();
                tokens
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_manager_creation() {
        // Create a minimal test config
        let toml = r#"
[tokens]

[tokens.definitions.usdc]
symbol = "USDC"
name = "USD Coin"
decimals = 6
eip712_name = "USD Coin"
eip712_version = "2"
contract_type = "usdc"

[tokens.networks.base-sepolia]
usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
"#;

        let temp_path = "/tmp/test_tokens.toml";
        std::fs::write(temp_path, toml).unwrap();

        let manager = TokenManager::new(temp_path).unwrap();

        // Test token lookup
        let token_def = manager.get_token_definition("usdc").await;
        assert!(token_def.is_some());
        assert_eq!(token_def.unwrap().symbol, "USDC");

        // Test address lookup
        let address = manager.get_token_address("usdc", "base-sepolia").await;
        assert!(address.is_some());

        // Test name lookup from address
        let addr = Address::from_str("0x036CbD53842c5426634e7929541eC2318f3dCF7e").unwrap();
        let name = manager.get_token_name(addr, "base-sepolia").await;
        assert_eq!(name, Some("usdc".to_string()));

        // Cleanup
        std::fs::remove_file(temp_path).ok();
    }

}
