//! Hook configuration structures and parsing
//!
//! This module defines the configuration format for post-settlement hooks
//! that can be executed atomically with transfers via Multicall3.

use alloy::primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Hook definition with contract address, calldata, and gas limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookDefinition {
    /// Whether this hook is currently enabled
    pub enabled: bool,
    /// Target contract address for the hook call
    pub contract: Address,
    /// Pre-configured calldata for the hook call
    #[serde(with = "hex")]
    pub calldata: Bytes,
    /// Gas limit for this hook (0 = unlimited)
    #[serde(default)]
    pub gas_limit: u64,
    /// Human-readable description of what this hook does
    #[serde(default)]
    pub description: String,
}

/// Complete hook configuration loaded from hooks.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// Global hook settings
    #[serde(default)]
    pub hooks: HookSettings,
}

/// Global hook settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookSettings {
    /// Whether hooks are enabled globally
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether hook failures should be allowed (default: false = hooks must succeed)
    #[serde(default)]
    pub allow_hook_failure: bool,
    /// Mapping of destination addresses to hook names
    #[serde(default)]
    pub mappings: HashMap<Address, Vec<String>>,
    /// Hook definitions by name
    #[serde(default)]
    pub definitions: HashMap<String, HookDefinition>,
}

impl Default for HookSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_hook_failure: false,
            mappings: HashMap::new(),
            definitions: HashMap::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Hex serialization module for Bytes
mod hex {
    use alloy::primitives::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", alloy::hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        alloy::hex::decode(s)
            .map(Bytes::from)
            .map_err(serde::de::Error::custom)
    }
}

impl HookConfig {
    /// Load hook configuration from TOML file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: HookConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save hook configuration to TOML file
    pub fn to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_config_parsing() {
        let toml = r#"
[hooks]
enabled = true
allow_hook_failure = false

[hooks.mappings]
"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb" = ["test_hook"]

[hooks.definitions.test_hook]
enabled = true
contract = "0x1234567890123456789012345678901234567890"
calldata = "0xabcdef"
gas_limit = 300000
description = "Test hook"
"#;

        let config: HookConfig = toml::from_str(toml).unwrap();
        assert!(config.hooks.enabled);
        assert!(!config.hooks.allow_hook_failure);
        assert_eq!(config.hooks.mappings.len(), 1);
        assert_eq!(config.hooks.definitions.len(), 1);
    }
}
