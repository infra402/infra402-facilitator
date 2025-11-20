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
    /// Map of token_name → address
    /// Addresses can be hardcoded or use env var substitution: "${ENV_VAR}"
    #[serde(flatten)]
    pub tokens: HashMap<String, String>,

    /// Custom/additional token deployments (optional)
    /// Use to add new tokens via environment variables
    /// IMPORTANT: Must use addresses not already in production tokens
    /// Config loading will fail if custom token conflicts with production address
    #[serde(default)]
    pub custom: HashMap<String, String>,
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
            definitions: HashMap::new(),
            networks: HashMap::new(),
        }
    }
}

impl TokenConfig {
    /// Load token configuration from TOML file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: TokenConfig = toml::from_str(&content)?;

        tracing::info!(
            path = path,
            definitions_count = config.tokens.definitions.len(),
            networks_count = config.tokens.networks.len(),
            "Loaded token configuration"
        );

        Ok(config)
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

[tokens.networks.base-sepolia.custom]
test_usdc = "${TEST_USDC}"
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
        assert_eq!(
            base_sepolia.custom.get("test_usdc").unwrap(),
            "${TEST_USDC}"
        );
    }
}
