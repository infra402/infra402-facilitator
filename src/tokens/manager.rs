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
        for (network_name, network_tokens) in &config.tokens.networks {
            let mut network_cache = HashMap::new();
            let mut prod_addresses = std::collections::HashSet::new();

            // Process production tokens
            for (token_name, address_str) in &network_tokens.tokens {
                if let Some(addr) = Self::resolve_address(address_str) {
                    prod_addresses.insert(addr);
                    network_cache.insert(addr, token_name.clone());
                }
            }

            // Process custom tokens with conflict detection
            for (token_name, address_str) in &network_tokens.custom {
                if let Some(addr) = Self::resolve_address(address_str) {
                    // Validate that custom token doesn't conflict with production address
                    if prod_addresses.contains(&addr) {
                        // Find which production token uses this address for better error message
                        let prod_token = network_cache.get(&addr).unwrap();
                        return Err(format!(
                            "Custom token '{}' at address {} conflicts with production token '{}' on network '{}'",
                            token_name, addr, prod_token, network_name
                        ).into());
                    }
                    network_cache.insert(addr, token_name.clone());
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

    /// Resolve address string with optional env var substitution
    ///
    /// Supports format: "${ENV_VAR_NAME}" or direct address
    fn resolve_address(address_str: &str) -> Option<Address> {
        let resolved = if address_str.starts_with("${") && address_str.ends_with("}") {
            let env_var_name = &address_str[2..address_str.len() - 1];
            match std::env::var(env_var_name) {
                Ok(val) => val,
                Err(_) => {
                    tracing::debug!(
                        env_var = env_var_name,
                        "Environment variable not found for token address"
                    );
                    return None;
                }
            }
        } else {
            address_str.to_string()
        };

        Address::from_str(&resolved).ok()
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
    ///
    /// Handles environment variable substitution
    pub async fn get_token_address(
        &self,
        token_name: &str,
        network: &str,
    ) -> Option<Address> {
        let state = self.state.read().await;

        let network_tokens = state.settings.networks.get(network)?;

        // Check production tokens first
        if let Some(address_str) = network_tokens.tokens.get(token_name) {
            return Self::resolve_address(address_str);
        }

        // Check custom tokens
        if let Some(address_str) = network_tokens.custom.get(token_name) {
            return Self::resolve_address(address_str);
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
        for (network_name, network_tokens) in &config.tokens.networks {
            let mut network_cache = HashMap::new();
            let mut prod_addresses = std::collections::HashSet::new();

            for (token_name, address_str) in &network_tokens.tokens {
                if let Some(addr) = Self::resolve_address(address_str) {
                    prod_addresses.insert(addr);
                    network_cache.insert(addr, token_name.clone());
                }
            }

            // Process custom tokens with conflict detection
            for (token_name, address_str) in &network_tokens.custom {
                if let Some(addr) = Self::resolve_address(address_str) {
                    // Validate that custom token doesn't conflict with production address
                    if prod_addresses.contains(&addr) {
                        let prod_token = network_cache.get(&addr).unwrap();
                        return Err(format!(
                            "Custom token '{}' at address {} conflicts with production token '{}' on network '{}'",
                            token_name, addr, prod_token, network_name
                        ));
                    }
                    network_cache.insert(addr, token_name.clone());
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
                    .chain(network_tokens.custom.keys())
                    .cloned()
                    .collect();
                tokens.sort();
                tokens.dedup();
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

    #[tokio::test]
    async fn test_custom_token_address_conflict() {
        // Create a config where custom token conflicts with production token
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

[tokens.networks.base-sepolia.custom]
my_custom_token = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
"#;

        let temp_path = "/tmp/test_tokens_conflict.toml";
        std::fs::write(temp_path, toml).unwrap();

        // Should fail to create TokenManager due to address conflict
        let result = TokenManager::new(temp_path);
        assert!(result.is_err());

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Custom token 'my_custom_token'"));
        assert!(error_msg.contains("conflicts with production token 'usdc'"));
        assert!(error_msg.to_lowercase().contains("0x036c"));  // Check address is in error (case-insensitive)

        // Cleanup
        std::fs::remove_file(temp_path).ok();
    }

    #[tokio::test]
    async fn test_custom_token_no_conflict() {
        // Create a config where custom token uses different address
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

[tokens.networks.base-sepolia.custom]
my_custom_token = "0x1111111111111111111111111111111111111111"
"#;

        let temp_path = "/tmp/test_tokens_no_conflict.toml";
        std::fs::write(temp_path, toml).unwrap();

        // Should succeed - custom token uses different address
        let manager = TokenManager::new(temp_path).unwrap();

        // Verify both tokens are accessible
        let usdc_addr = manager.get_token_address("usdc", "base-sepolia").await;
        assert_eq!(
            usdc_addr,
            Some(Address::from_str("0x036CbD53842c5426634e7929541eC2318f3dCF7e").unwrap())
        );

        let custom_addr = manager.get_token_address("my_custom_token", "base-sepolia").await;
        assert_eq!(
            custom_addr,
            Some(Address::from_str("0x1111111111111111111111111111111111111111").unwrap())
        );

        // Cleanup
        std::fs::remove_file(temp_path).ok();
    }
}
