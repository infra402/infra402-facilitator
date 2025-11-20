//! Token configuration structures
//!
//! Defines the configuration format for tokens.toml

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Contract type determines which ABI to use
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ContractType {
    Usdc,  // Uses USDC ABI variant
    Xbnb,  // Uses XBNB ABI variant
}

/// Token definition shared across networks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDefinition {
    /// Token symbol (e.g., "USDC", "XBNB")
    pub symbol: String,

    /// Human-readable token name
    pub name: String,

    /// Number of decimals (6 for USDC, 18 for XBNB)
    pub decimals: u8,

    /// EIP-712 domain name for typed data signing
    pub eip712_name: String,

    /// EIP-712 domain version
    pub eip712_version: String,

    /// Contract type determines which ABI variant to use
    pub contract_type: ContractType,
}

/// Network-specific token deployments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTokens {
    /// Production token deployments
    /// Map of token_name → address (direct addresses only, no env vars)
    #[serde(flatten)]
    pub tokens: HashMap<String, String>,
}

/// Complete token configuration loaded from tokens.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    #[serde(default)]
    pub tokens: TokenSettings,
}

/// Top-level token settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSettings {
    /// Optional path to custom tokens file (e.g., "tokens-custom.toml")
    /// Set to null to disable custom tokens. Supports relative or absolute paths.
    /// Custom tokens will be merged with production tokens at load time.
    #[serde(default)]
    pub custom_tokens_file: Option<String>,

    /// Global token definitions shared across networks
    #[serde(default)]
    pub definitions: HashMap<String, TokenDefinition>,

    /// Per-network token deployments
    #[serde(default)]
    pub networks: HashMap<String, NetworkTokens>,
}

impl Default for TokenSettings {
    fn default() -> Self {
        Self {
            custom_tokens_file: None,
            definitions: HashMap::new(),
            networks: HashMap::new(),
        }
    }
}

/// Custom token configuration loaded from separate file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomTokenConfig {
    #[serde(default)]
    pub tokens: CustomTokenSettings,
}

/// Custom token settings (subset of TokenSettings)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomTokenSettings {
    /// Custom token definitions
    #[serde(default)]
    pub definitions: HashMap<String, TokenDefinition>,

    /// Custom per-network token deployments
    #[serde(default)]
    pub networks: HashMap<String, NetworkTokens>,
}

impl TokenConfig {
    /// Load token configuration from TOML file with optional custom tokens
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: TokenConfig = toml::from_str(&content)?;

        // Load and merge custom tokens if configured
        if let Some(ref custom_file) = config.tokens.custom_tokens_file {
            let custom_path = Self::resolve_path(path, custom_file);

            match Self::load_custom_tokens(&custom_path) {
                Ok(custom_config) => {
                    Self::merge_custom_tokens(&mut config.tokens, custom_config)?;
                    tracing::info!(
                        custom_file = custom_path,
                        "Loaded and merged custom tokens"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        custom_file = custom_path,
                        error = %e,
                        "Failed to load custom tokens file (continuing without custom tokens)"
                    );
                }
            }
        } else {
            tracing::debug!("Custom tokens disabled (custom_tokens_file not configured)");
        }

        tracing::info!(
            path = path,
            definitions_count = config.tokens.definitions.len(),
            networks_count = config.tokens.networks.len(),
            "Loaded token configuration"
        );

        Ok(config)
    }

    /// Resolve custom token file path (relative to tokens.toml or absolute)
    fn resolve_path(base_config_path: &str, custom_file: &str) -> String {
        let custom_path = std::path::Path::new(custom_file);

        if custom_path.is_absolute() {
            custom_file.to_string()
        } else {
            // Relative to tokens.toml directory
            if let Some(parent) = std::path::Path::new(base_config_path).parent() {
                parent.join(custom_file).to_string_lossy().to_string()
            } else {
                custom_file.to_string()
            }
        }
    }

    /// Load custom tokens from separate file
    fn load_custom_tokens(path: &str) -> Result<CustomTokenConfig, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: CustomTokenConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Merge custom tokens into main configuration with address conflict validation
    fn merge_custom_tokens(
        main: &mut TokenSettings,
        custom: CustomTokenConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use alloy::primitives::Address;
        use std::str::FromStr;

        // Build set of all production token addresses for conflict detection
        let mut prod_addresses: HashMap<String, HashMap<Address, String>> = HashMap::new();

        for (network_name, network_tokens) in &main.networks {
            let mut network_addrs = HashMap::new();
            for (token_name, address_str) in &network_tokens.tokens {
                if let Ok(addr) = Address::from_str(address_str) {
                    network_addrs.insert(addr, token_name.clone());
                }
            }
            prod_addresses.insert(network_name.clone(), network_addrs);
        }

        // Merge custom token definitions
        for (name, def) in custom.tokens.definitions {
            if main.definitions.contains_key(&name) {
                tracing::warn!(
                    token = name,
                    "Custom token definition overriding production definition"
                );
            }
            main.definitions.insert(name, def);
        }

        // Merge custom network tokens with conflict detection
        for (network_name, custom_network) in custom.tokens.networks {
            let network_tokens = main.networks.entry(network_name.clone()).or_insert_with(|| NetworkTokens {
                tokens: HashMap::new(),
            });

            for (token_name, address_str) in custom_network.tokens {
                // Validate address format
                let addr = Address::from_str(&address_str).map_err(|e| {
                    format!("Invalid address '{}' for custom token '{}': {}", address_str, token_name, e)
                })?;

                // Check for address conflict with production tokens
                if let Some(prod_addrs) = prod_addresses.get(&network_name) {
                    if let Some(prod_token) = prod_addrs.get(&addr) {
                        return Err(format!(
                            "Custom token '{}' at address {} conflicts with production token '{}' on network '{}'",
                            token_name, addr, prod_token, network_name
                        ).into());
                    }
                }

                // Warn if overriding existing custom token
                if network_tokens.tokens.contains_key(&token_name) {
                    tracing::warn!(
                        token = token_name,
                        network = network_name,
                        "Custom token overriding existing token deployment"
                    );
                }

                network_tokens.tokens.insert(token_name, address_str);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_config_parsing() {
        let toml = r#"
[tokens]

[tokens.definitions.usdc]
symbol = "USDC"
name = "USD Coin"
decimals = 6
eip712_name = "USD Coin"
eip712_version = "2"
contract_type = "usdc"

[tokens.definitions.xbnb]
symbol = "XBNB"
name = "x402 BNB"
decimals = 18
eip712_name = "x402 BNB"
eip712_version = "1"
contract_type = "xbnb"

[tokens.networks.base-sepolia]
usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
"#;

        let config: TokenConfig = toml::from_str(toml).unwrap();

        // Check definitions
        assert_eq!(config.tokens.definitions.len(), 2);

        let usdc = config.tokens.definitions.get("usdc").unwrap();
        assert_eq!(usdc.symbol, "USDC");
        assert_eq!(usdc.decimals, 6);
        assert_eq!(usdc.contract_type, ContractType::Usdc);

        let xbnb = config.tokens.definitions.get("xbnb").unwrap();
        assert_eq!(xbnb.symbol, "XBNB");
        assert_eq!(xbnb.decimals, 18);
        assert_eq!(xbnb.contract_type, ContractType::Xbnb);

        // Check network deployments
        assert_eq!(config.tokens.networks.len(), 1);

        let base_sepolia = config.tokens.networks.get("base-sepolia").unwrap();
        assert_eq!(
            base_sepolia.tokens.get("usdc").unwrap(),
            "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
        );
    }

    #[test]
    fn test_custom_tokens_disabled() {
        // Test config without custom_tokens_file field
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

        let temp_path = "/tmp/test_tokens_no_custom.toml";
        std::fs::write(temp_path, toml).unwrap();

        let config = TokenConfig::from_file(temp_path).unwrap();

        // Should load successfully without custom tokens
        assert_eq!(config.tokens.definitions.len(), 1);
        assert_eq!(config.tokens.networks.len(), 1);
        assert_eq!(config.tokens.custom_tokens_file, None);

        std::fs::remove_file(temp_path).ok();
    }

    #[test]
    fn test_custom_tokens_file_not_found() {
        // Test config pointing to non-existent custom file (should warn but not fail)
        let toml = r#"
[tokens]
custom_tokens_file = "non_existent.toml"

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

        let temp_path = "/tmp/test_tokens_missing_custom.toml";
        std::fs::write(temp_path, toml).unwrap();

        // Should load successfully and warn about missing custom file
        let config = TokenConfig::from_file(temp_path).unwrap();
        assert_eq!(config.tokens.definitions.len(), 1);

        std::fs::remove_file(temp_path).ok();
    }

    #[test]
    fn test_custom_tokens_merge_success() {
        // Create main config
        let main_toml = r#"
[tokens]
custom_tokens_file = "test_custom.toml"

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

        // Create custom config
        let custom_toml = r#"
[tokens]

[tokens.definitions.test_usdc]
symbol = "TestUSDC"
name = "Test USD Coin"
decimals = 6
eip712_name = "Test USD Coin"
eip712_version = "2"
contract_type = "usdc"

[tokens.networks.base-sepolia]
test_usdc = "0x1111111111111111111111111111111111111111"
"#;

        let main_path = "/tmp/test_tokens_main.toml";
        let custom_path = "/tmp/test_custom.toml";

        std::fs::write(main_path, main_toml).unwrap();
        std::fs::write(custom_path, custom_toml).unwrap();

        let config = TokenConfig::from_file(main_path).unwrap();

        // Should have both production and custom tokens
        assert_eq!(config.tokens.definitions.len(), 2);
        assert!(config.tokens.definitions.contains_key("usdc"));
        assert!(config.tokens.definitions.contains_key("test_usdc"));

        let base_sepolia = config.tokens.networks.get("base-sepolia").unwrap();
        assert_eq!(base_sepolia.tokens.len(), 2);
        assert_eq!(
            base_sepolia.tokens.get("usdc").unwrap(),
            "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
        );
        assert_eq!(
            base_sepolia.tokens.get("test_usdc").unwrap(),
            "0x1111111111111111111111111111111111111111"
        );

        std::fs::remove_file(main_path).ok();
        std::fs::remove_file(custom_path).ok();
    }

    #[test]
    fn test_custom_tokens_address_conflict() {
        // Create main config
        let main_toml = r#"
[tokens]
custom_tokens_file = "test_custom_conflict.toml"

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

        // Create custom config with conflicting address
        let custom_toml = r#"
[tokens]

[tokens.definitions.test_usdc]
symbol = "TestUSDC"
name = "Test USD Coin"
decimals = 6
eip712_name = "Test USD Coin"
eip712_version = "2"
contract_type = "usdc"

[tokens.networks.base-sepolia]
test_usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
"#;

        let main_path = "/tmp/test_tokens_conflict_main.toml";
        let custom_path = "/tmp/test_custom_conflict.toml";

        std::fs::write(main_path, main_toml).unwrap();
        std::fs::write(custom_path, custom_toml).unwrap();

        // Should fail with address conflict error
        let result = TokenConfig::from_file(main_path);
        assert!(result.is_err());

        let error = result.unwrap_err().to_string();
        assert!(error.contains("Custom token 'test_usdc'"));
        assert!(error.contains("conflicts with production token 'usdc'"));

        std::fs::remove_file(main_path).ok();
        std::fs::remove_file(custom_path).ok();
    }

    #[test]
    fn test_path_resolution_relative() {
        // Test that relative paths are resolved relative to main config
        let main_toml = r#"
[tokens]
custom_tokens_file = "custom/tokens-custom.toml"

[tokens.definitions.usdc]
symbol = "USDC"
name = "USD Coin"
decimals = 6
eip712_name = "USD Coin"
eip712_version = "2"
contract_type = "usdc"
"#;

        let main_path = "/tmp/tokens_test_dir/tokens.toml";
        std::fs::create_dir_all("/tmp/tokens_test_dir/custom").ok();
        std::fs::write(main_path, main_toml).unwrap();

        let custom_toml = r#"
[tokens]

[tokens.definitions.test]
symbol = "TEST"
name = "Test Token"
decimals = 6
eip712_name = "Test"
eip712_version = "1"
contract_type = "usdc"
"#;

        std::fs::write("/tmp/tokens_test_dir/custom/tokens-custom.toml", custom_toml).unwrap();

        // Should resolve relative path correctly
        let config = TokenConfig::from_file(main_path).unwrap();
        assert_eq!(config.tokens.definitions.len(), 2);

        std::fs::remove_dir_all("/tmp/tokens_test_dir").ok();
    }
}
