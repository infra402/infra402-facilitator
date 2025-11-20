//! Hook configuration structures and parsing
//!
//! This module defines the configuration format for post-settlement hooks
//! that can be executed atomically with transfers via Multicall3.
//!
//! Supports both legacy static calldata and new parameterized hooks.

use alloy::dyn_abi::{DynSolType, DynSolValue};
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use crate::chain::evm::SettlementMetadata;
use super::context::RuntimeContext;
use super::errors::{HookError, HookResult};

/// Source of a parameter value
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "source_type", content = "field", rename_all = "lowercase")]
pub enum ParameterSource {
    /// Value from EIP-3009 payment
    Payment(PaymentField),
    /// Value from runtime context
    Runtime(RuntimeField),
    /// Static configured value
    Static(String),
    /// Custom configuration value
    Config(String),
}

/// Fields available from EIP-3009 payment metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PaymentField {
    /// Payer address (from)
    From,
    /// Recipient address (to)
    To,
    /// Transfer amount
    Value,
    /// Valid after timestamp
    ValidAfter,
    /// Valid before timestamp
    ValidBefore,
    /// Unique nonce
    Nonce,
    /// Token contract address
    ContractAddress,
    /// Signature v component
    SignatureV,
    /// Signature r component
    SignatureR,
    /// Signature s component
    SignatureS,
}

/// Fields available from runtime context
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeField {
    /// Block timestamp (block.timestamp)
    Timestamp,
    /// Block number (block.number)
    BlockNumber,
    /// Facilitator address (msg.sender)
    Sender,
    /// Settlement index in batch
    BatchIndex,
    /// Total batch size
    BatchSize,
}

/// Parameter definition for a single function argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDefinition {
    /// Solidity type (address, uint256, bytes32, etc.)
    #[serde(rename = "type")]
    pub sol_type: String,
    /// Where to get the value from
    pub source: ParameterSource,
}

/// Hook definition shared across networks
///
/// Defines the function signature, parameters, and execution settings.
/// Contract addresses are specified per-network in NetworkHookConfig.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookDefinition {
    /// Whether this hook is currently enabled globally
    pub enabled: bool,

    /// Function signature for ABI encoding (e.g., "notifySettlement(address,address,uint256)")
    pub function_signature: String,

    /// Ordered parameter definitions matching function signature
    #[serde(default)]
    pub parameters: Vec<ParameterDefinition>,

    /// Custom configuration values (key-value pairs for Config parameter source)
    #[serde(default)]
    pub config_values: HashMap<String, String>,

    /// Gas limit for this hook (0 = unlimited)
    #[serde(default)]
    pub gas_limit: u64,

    /// Human-readable description of what this hook does
    #[serde(default)]
    pub description: String,
}

impl HookDefinition {
    /// Encode calldata with runtime parameter resolution
    pub fn encode_calldata(
        &self,
        metadata: &SettlementMetadata,
        runtime: &RuntimeContext,
    ) -> HookResult<Bytes> {
        let function_sig = &self.function_signature;

        // Parse function signature to get selector and input types
        let (function_name, input_types) = Self::parse_function_signature(function_sig)?;

        // Validate parameter count matches
        if self.parameters.len() != input_types.len() {
            return Err(HookError::ParameterCountMismatch {
                function: function_sig.clone(),
                expected: input_types.len(),
                actual: self.parameters.len(),
            });
        }

        // Build DynSolValue for each parameter
        let mut values = Vec::new();
        for (i, param) in self.parameters.iter().enumerate() {
            let sol_type = DynSolType::parse(&param.sol_type)
                .map_err(|e| HookError::InvalidSolidityType(
                    param.sol_type.clone(),
                    e.to_string()
                ))?;

            // Verify type matches function signature
            if param.sol_type != input_types[i] {
                return Err(HookError::TypeMismatch {
                    param: format!("parameter {}", i),
                    expected: input_types[i].clone(),
                    actual: param.sol_type.clone(),
                });
            }

            let value = self.resolve_parameter_value(&param.source, &sol_type, metadata, runtime)?;
            values.push(value);
        }

        // Encode with function selector
        let encoded = Self::encode_with_selector(function_name, &values)?;

        Ok(Bytes::from(encoded))
    }

    /// Parse function signature into name and input types
    fn parse_function_signature(sig: &str) -> HookResult<(String, Vec<String>)> {
        // Format: "functionName(type1,type2,type3)"
        let parts: Vec<&str> = sig.splitn(2, '(').collect();
        if parts.len() != 2 {
            return Err(HookError::InvalidFunctionSignature(
                sig.to_string(),
                "Missing '(' in signature".to_string()
            ));
        }

        let function_name = parts[0].to_string();
        let params_str = parts[1].trim_end_matches(')');

        let input_types = if params_str.is_empty() {
            Vec::new()
        } else {
            params_str.split(',').map(|s| s.trim().to_string()).collect()
        };

        Ok((function_name, input_types))
    }

    /// Encode function call with selector
    fn encode_with_selector(function_name: String, values: &[DynSolValue]) -> HookResult<Vec<u8>> {
        // Build full signature for selector calculation
        let type_strs: Vec<String> = values.iter().map(|v| {
            match v {
                DynSolValue::Address(_) => "address".to_string(),
                DynSolValue::Uint(_, bits) => format!("uint{}", bits),
                DynSolValue::Int(_, bits) => format!("int{}", bits),
                DynSolValue::Bool(_) => "bool".to_string(),
                DynSolValue::FixedBytes(_, size) => format!("bytes{}", size),
                DynSolValue::Bytes(_) => "bytes".to_string(),
                DynSolValue::String(_) => "string".to_string(),
                _ => "unknown".to_string(),
            }
        }).collect();

        let full_signature = format!("{}({})", function_name, type_strs.join(","));

        // Calculate selector (first 4 bytes of keccak256 hash)
        let selector = alloy::primitives::keccak256(full_signature.as_bytes());
        let selector_bytes = &selector[0..4];

        // Encode parameters using ABI encoding
        // Create a tuple of all parameter values and encode it
        let tuple_value = DynSolValue::Tuple(values.to_vec());
        let encoded_params = tuple_value.abi_encode_params();


        // Combine selector + encoded params
        let mut result = Vec::with_capacity(4 + encoded_params.len());
        result.extend_from_slice(selector_bytes);
        result.extend_from_slice(&encoded_params);

        Ok(result)
    }

    /// Resolve a parameter value from its source
    fn resolve_parameter_value(
        &self,
        source: &ParameterSource,
        sol_type: &DynSolType,
        metadata: &SettlementMetadata,
        runtime: &RuntimeContext,
    ) -> HookResult<DynSolValue> {
        match source {
            ParameterSource::Payment(field) => {
                Self::extract_payment_field(field, metadata, sol_type)
            }
            ParameterSource::Runtime(field) => {
                Self::extract_runtime_field(field, runtime, sol_type)
            }
            ParameterSource::Static(val) => {
                Self::parse_static_value(val, sol_type)
            }
            ParameterSource::Config(key) => {
                let val = self.config_values.get(key)
                    .ok_or_else(|| HookError::InvalidParameterSource(
                        key.clone(),
                        "Config key not found in config_values".to_string()
                    ))?;
                Self::parse_static_value(val, sol_type)
            }
        }
    }

    /// Extract value from payment metadata
    fn extract_payment_field(
        field: &PaymentField,
        metadata: &SettlementMetadata,
        _sol_type: &DynSolType,
    ) -> HookResult<DynSolValue> {
        match field {
            PaymentField::From => Ok(DynSolValue::Address(metadata.from)),
            PaymentField::To => Ok(DynSolValue::Address(metadata.to)),
            PaymentField::Value => Ok(DynSolValue::Uint(metadata.value, 256)),
            PaymentField::ValidAfter => Ok(DynSolValue::Uint(metadata.valid_after, 256)),
            PaymentField::ValidBefore => Ok(DynSolValue::Uint(metadata.valid_before, 256)),
            PaymentField::Nonce => Ok(DynSolValue::FixedBytes(
                metadata.nonce,
                32
            )),
            PaymentField::ContractAddress => Ok(DynSolValue::Address(metadata.contract_address)),
            PaymentField::SignatureV => {
                // Extract v from signature if available (byte 64 of 65-byte signature)
                let v = if let Some(sig_bytes) = metadata.signature.get(64) {
                    U256::from(*sig_bytes)
                } else {
                    U256::ZERO
                };
                Ok(DynSolValue::Uint(v, 8))
            }
            PaymentField::SignatureR => {
                // Extract r (first 32 bytes of signature)
                let r = if metadata.signature.len() >= 32 {
                    FixedBytes::from_slice(&metadata.signature[0..32])
                } else {
                    FixedBytes::ZERO
                };
                Ok(DynSolValue::FixedBytes(r, 32))
            }
            PaymentField::SignatureS => {
                // Extract s (bytes 32-64 of signature)
                let s = if metadata.signature.len() >= 64 {
                    FixedBytes::from_slice(&metadata.signature[32..64])
                } else {
                    FixedBytes::ZERO
                };
                Ok(DynSolValue::FixedBytes(s, 32))
            }
        }
    }

    /// Extract value from runtime context
    fn extract_runtime_field(
        field: &RuntimeField,
        runtime: &RuntimeContext,
        _sol_type: &DynSolType,
    ) -> HookResult<DynSolValue> {
        match field {
            RuntimeField::Timestamp => Ok(DynSolValue::Uint(runtime.timestamp, 256)),
            RuntimeField::BlockNumber => Ok(DynSolValue::Uint(runtime.block_number, 256)),
            RuntimeField::Sender => Ok(DynSolValue::Address(runtime.sender)),
            RuntimeField::BatchIndex => {
                let idx = runtime.batch_index.unwrap_or(0);
                Ok(DynSolValue::Uint(U256::from(idx), 256))
            }
            RuntimeField::BatchSize => {
                let size = runtime.batch_size.unwrap_or(0);
                Ok(DynSolValue::Uint(U256::from(size), 256))
            }
        }
    }

    /// Parse a static string value to appropriate Solidity type
    fn parse_static_value(
        val: &str,
        sol_type: &DynSolType,
    ) -> HookResult<DynSolValue> {
        match sol_type {
            DynSolType::Address => {
                let addr = Address::from_str(val)
                    .map_err(|e| HookError::StaticValueParseFailed(
                        val.to_string(),
                        "address".to_string(),
                        e.to_string()
                    ))?;
                Ok(DynSolValue::Address(addr))
            }
            DynSolType::Uint(bits) => {
                let uint = if val.starts_with("0x") {
                    U256::from_str_radix(val.trim_start_matches("0x"), 16)
                } else {
                    U256::from_str_radix(val, 10)
                }.map_err(|e| HookError::StaticValueParseFailed(
                    val.to_string(),
                    format!("uint{}", bits),
                    e.to_string()
                ))?;
                Ok(DynSolValue::Uint(uint, *bits))
            }
            DynSolType::Int(bits) => {
                // Parse as U256 first, then convert to I256
                let abs_val = if val.starts_with("0x") {
                    U256::from_str_radix(val.trim_start_matches("0x"), 16)
                } else if val.starts_with("-") {
                    U256::from_str_radix(val.trim_start_matches("-"), 10)
                } else {
                    U256::from_str_radix(val, 10)
                }.map_err(|e| HookError::StaticValueParseFailed(
                    val.to_string(),
                    format!("int{}", bits),
                    e.to_string()
                ))?;

                let is_negative = val.starts_with("-");
                let int = if is_negative {
                    alloy::primitives::I256::unchecked_from(abs_val).wrapping_neg()
                } else {
                    alloy::primitives::I256::unchecked_from(abs_val)
                };

                Ok(DynSolValue::Int(int, *bits))
            }
            DynSolType::Bool => {
                let b = val.parse::<bool>()
                    .map_err(|e| HookError::StaticValueParseFailed(
                        val.to_string(),
                        "bool".to_string(),
                        e.to_string()
                    ))?;
                Ok(DynSolValue::Bool(b))
            }
            DynSolType::FixedBytes(size) => {
                let hex_str = val.strip_prefix("0x").unwrap_or(val);
                let bytes = alloy::hex::decode(hex_str)
                    .map_err(|e| HookError::StaticValueParseFailed(
                        val.to_string(),
                        format!("bytes{}", size),
                        e.to_string()
                    ))?;
                if bytes.len() != *size {
                    return Err(HookError::StaticValueParseFailed(
                        val.to_string(),
                        format!("bytes{}", size),
                        format!("Expected {} bytes, got {}", size, bytes.len())
                    ));
                }
                Ok(DynSolValue::FixedBytes(FixedBytes::from_slice(&bytes), *size))
            }
            DynSolType::Bytes => {
                let hex_str = val.strip_prefix("0x").unwrap_or(val);
                let bytes = alloy::hex::decode(hex_str)
                    .map_err(|e| HookError::StaticValueParseFailed(
                        val.to_string(),
                        "bytes".to_string(),
                        e.to_string()
                    ))?;
                Ok(DynSolValue::Bytes(bytes.into()))
            }
            DynSolType::String => {
                Ok(DynSolValue::String(val.to_string()))
            }
            _ => Err(HookError::InvalidSolidityType(
                format!("{:?}", sol_type),
                "Unsupported type for static value parsing".to_string()
            ))
        }
    }

    /// Validate hook configuration
    pub fn validate(&self) -> HookResult<()> {
        // Validate function signature
        let (_, input_types) = Self::parse_function_signature(&self.function_signature)?;

        if self.parameters.len() != input_types.len() {
            return Err(HookError::ParameterCountMismatch {
                function: self.function_signature.clone(),
                expected: input_types.len(),
                actual: self.parameters.len(),
            });
        }

        // Validate each parameter type
        for (i, param) in self.parameters.iter().enumerate() {
            DynSolType::parse(&param.sol_type)
                .map_err(|e| HookError::InvalidSolidityType(
                    param.sol_type.clone(),
                    e.to_string()
                ))?;

            if param.sol_type != input_types[i] {
                return Err(HookError::TypeMismatch {
                    param: format!("parameter {}", i),
                    expected: input_types[i].clone(),
                    actual: param.sol_type.clone(),
                });
            }
        }

        Ok(())
    }
}

/// Per-network hook configuration
///
/// Specifies which hooks are active for a specific network,
/// destination address mappings, and contract addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHookConfig {
    /// Override enabled for this network
    /// - Some(true): Force hooks enabled for this network
    /// - Some(false): Force hooks disabled for this network
    /// - None: Use global enabled setting
    pub enabled: Option<bool>,

    /// Destination address → hook names mapping for this network
    #[serde(default)]
    pub mappings: HashMap<Address, Vec<String>>,

    /// Hook name → contract address mapping for this network
    /// Supports environment variable substitution: "${ENV_VAR_NAME}"
    #[serde(default)]
    pub contracts: HashMap<String, String>,
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

    /// Hook definitions shared across all networks
    #[serde(default)]
    pub definitions: HashMap<String, HookDefinition>,

    /// Per-network configuration overrides
    #[serde(default)]
    pub networks: HashMap<String, NetworkHookConfig>,

    /// DEPRECATED: Global mappings (use per-network mappings instead)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub mappings: HashMap<Address, Vec<String>>,
}

impl Default for HookSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_hook_failure: false,
            definitions: HashMap::new(),
            networks: HashMap::new(),
            mappings: HashMap::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

impl HookSettings {
    /// Check if hooks are enabled for a specific network
    ///
    /// Resolution order:
    /// 1. If network has explicit `enabled = true/false`, use that
    /// 2. Otherwise, fall back to global `enabled` setting
    pub fn is_enabled_for_network(&self, network_name: &str) -> bool {
        self.networks
            .get(network_name)
            .and_then(|n| n.enabled)
            .unwrap_or(self.enabled)
    }

    /// Resolve contract address for a hook on a specific network
    ///
    /// Supports environment variable substitution: "${ENV_VAR_NAME}"
    /// Returns None if hook not configured for this network.
    pub fn resolve_contract_address(&self, hook_name: &str, network_name: &str) -> Option<Address> {
        let network_config = self.networks.get(network_name)?;
        let address_str = network_config.contracts.get(hook_name)?;

        // Substitute environment variable if present
        let resolved = Self::substitute_env_var(address_str);

        // Parse address
        Address::from_str(&resolved).ok()
    }

    /// Substitute environment variable in string
    ///
    /// Format: "${ENV_VAR_NAME}" → value from std::env::var
    fn substitute_env_var(s: &str) -> String {
        if s.starts_with("${") && s.ends_with("}") {
            let env_var_name = &s[2..s.len()-1];
            std::env::var(env_var_name).unwrap_or_else(|_| {
                tracing::warn!(
                    env_var = env_var_name,
                    "Environment variable not found, using empty address"
                );
                String::new()
            })
        } else {
            s.to_string()
        }
    }

    /// Get destination mappings for a specific network
    ///
    /// Falls back to deprecated global mappings if network not configured.
    pub fn get_network_mappings(&self, network_name: &str) -> &HashMap<Address, Vec<String>> {
        self.networks
            .get(network_name)
            .map(|n| &n.mappings)
            .filter(|m| !m.is_empty())
            .unwrap_or(&self.mappings)
    }
}

impl HookConfig {
    /// Load hook configuration from TOML file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: HookConfig = toml::from_str(&content)?;

        // Validate all hook definitions
        for (name, hook) in &config.hooks.definitions {
            hook.validate().map_err(|e| format!("Hook '{}' validation failed: {}", name, e))?;
        }

        Ok(config)
    }

    /// Save hook configuration to TOML file (test utility)
    #[cfg(test)]
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
    fn test_parameterized_hook_config_parsing() {
        let toml = r#"
[hooks]
enabled = true

[hooks.mappings]
"0x5555555555555555555555555555555555555555" = ["notify_hook"]

[hooks.definitions.notify_hook]
enabled = true
contract = "0x1234567890123456789012345678901234567890"
function_signature = "notifySettlement(address,address,uint256)"
gas_limit = 200000
description = "Notify settlement with dynamic params"

[[hooks.definitions.notify_hook.parameters]]
type = "address"
source = { source_type = "payment", field = "from" }

[[hooks.definitions.notify_hook.parameters]]
type = "address"
source = { source_type = "payment", field = "to" }

[[hooks.definitions.notify_hook.parameters]]
type = "uint256"
source = { source_type = "payment", field = "value" }
"#;

        let config: HookConfig = toml::from_str(toml).unwrap();
        assert!(config.hooks.enabled);

        let hook = config.hooks.definitions.get("notify_hook").unwrap();
        assert_eq!(&hook.function_signature, "notifySettlement(address,address,uint256)");
        assert_eq!(hook.parameters.len(), 3);
    }

    #[test]
    fn test_parse_function_signature() {
        let (name, types) = HookDefinition::parse_function_signature(
            "notifySettlement(address,address,uint256)"
        ).unwrap();

        assert_eq!(name, "notifySettlement");
        assert_eq!(types, vec!["address", "address", "uint256"]);
    }

    #[test]
    fn test_parse_function_signature_no_params() {
        let (name, types) = HookDefinition::parse_function_signature("trigger()").unwrap();

        assert_eq!(name, "trigger");
        assert!(types.is_empty());
    }
}
