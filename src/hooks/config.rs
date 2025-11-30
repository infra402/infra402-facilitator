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

/// Token filter configuration for hooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum TokenFilter {
    /// Wildcard: Accept any token
    Any(String),  // "*"
    /// Specific token names from tokens.toml
    Specific(Vec<String>),
}

impl TokenFilter {
    /// Check if a token name passes this filter
    pub fn matches(&self, token_name: &str) -> bool {
        match self {
            TokenFilter::Any(s) if s == "*" => true,
            TokenFilter::Specific(tokens) => tokens.contains(&token_name.to_string()),
            _ => false,
        }
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
    /// Supports environment variable substitution: "${ENV_VAR_NAME}"
    #[serde(default)]
    pub mappings: HashMap<String, Vec<String>>,

    /// Hook name → (destination → contract address) mapping for this network
    /// Supports environment variable substitution: "${ENV_VAR_NAME}"
    #[serde(default)]
    pub contracts: HashMap<String, HashMap<String, String>>,

    /// Token filters: Restrict hooks to specific payment tokens
    /// Maps hook_name → token filter (wildcard "*" or list of token names)
    /// If a hook is not listed, it accepts all tokens (same as "*")
    /// Token names must match those defined in tokens.toml
    #[serde(default)]
    pub token_filters: HashMap<String, TokenFilter>,
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

    /// Optional path to custom hooks file (e.g., "hooks-custom.toml")
    /// Set to null to disable custom hooks. Supports relative or absolute paths.
    /// Custom hooks will be merged with production hooks at load time.
    #[serde(default)]
    pub custom_hooks_file: Option<String>,

    /// Hook definitions shared across all networks
    #[serde(default)]
    pub definitions: HashMap<String, HookDefinition>,

    /// Per-network configuration overrides
    #[serde(default)]
    pub networks: HashMap<String, NetworkHookConfig>,

    /// DEPRECATED: Global mappings (use per-network mappings instead)
    /// Supports environment variable substitution: "${ENV_VAR_NAME}"
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub mappings: HashMap<String, Vec<String>>,
}

impl Default for HookSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_hook_failure: false,
            custom_hooks_file: None,
            definitions: HashMap::new(),
            networks: HashMap::new(),
            mappings: HashMap::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Custom hook configuration loaded from separate file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomHookConfig {
    #[serde(default)]
    pub hooks: CustomHookSettings,
}

/// Custom hook settings (subset of HookSettings)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomHookSettings {
    /// Custom hook definitions
    #[serde(default)]
    pub definitions: HashMap<String, HookDefinition>,

    /// Custom per-network hook configurations
    #[serde(default)]
    pub networks: HashMap<String, NetworkHookConfig>,
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

    /// Resolve contract address for a hook on a specific network and destination
    ///
    /// Supports environment variable substitution: "${ENV_VAR_NAME}"
    /// Returns None if hook not configured for this network/destination.
    pub fn resolve_contract_address(
        &self,
        hook_name: &str,
        network_name: &str,
        destination: &Address,
    ) -> Option<Address> {
        let network_config = self.networks.get(network_name)?;
        let dest_map = network_config.contracts.get(hook_name)?;

        // Case-insensitive lookup for destination address
        let dest_str = format!("{:?}", destination);
        let dest_lower = dest_str.to_lowercase();

        for (key, addr) in dest_map {
            if key.to_lowercase() == dest_lower {
                let resolved = Self::substitute_env_var(addr);
                return Address::from_str(&resolved).ok();
            }
        }

        None
    }

    /// Resolve a mapping address string to Address
    ///
    /// Supports environment variable substitution: "${ENV_VAR_NAME}"
    /// Returns None if address string cannot be parsed.
    pub fn resolve_mapping_address(address_str: &str) -> Option<Address> {
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
    /// Mapping keys support environment variable substitution: "${ENV_VAR_NAME}"
    pub fn get_network_mappings(&self, network_name: &str) -> &HashMap<String, Vec<String>> {
        self.networks
            .get(network_name)
            .map(|n| &n.mappings)
            .filter(|m| !m.is_empty())
            .unwrap_or(&self.mappings)
    }
}

impl HookConfig {
    /// Load hook configuration from TOML file with optional custom hooks
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: HookConfig = toml::from_str(&content)?;

        // Load and merge custom hooks if configured
        if let Some(ref custom_file) = config.hooks.custom_hooks_file {
            let custom_path = Self::resolve_path(path, custom_file);

            match Self::load_custom_hooks(&custom_path) {
                Ok(custom_config) => {
                    Self::merge_custom_hooks(&mut config.hooks, custom_config)?;
                    tracing::info!(
                        custom_file = custom_path,
                        "Loaded and merged custom hooks"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        custom_file = custom_path,
                        error = %e,
                        "Failed to load custom hooks file (continuing without custom hooks)"
                    );
                }
            }
        } else {
            tracing::debug!("Custom hooks disabled (custom_hooks_file not configured)");
        }

        // Validate all hook definitions (including merged custom hooks)
        for (name, hook) in &config.hooks.definitions {
            hook.validate().map_err(|e| format!("Hook '{}' validation failed: {}", name, e))?;
        }

        tracing::info!(
            path = path,
            definitions_count = config.hooks.definitions.len(),
            networks_count = config.hooks.networks.len(),
            "Loaded hook configuration"
        );

        Ok(config)
    }

    /// Resolve custom hook file path (relative to hooks.toml or absolute)
    fn resolve_path(base_config_path: &str, custom_file: &str) -> String {
        let custom_path = std::path::Path::new(custom_file);

        if custom_path.is_absolute() {
            custom_file.to_string()
        } else {
            // Relative to hooks.toml directory
            if let Some(parent) = std::path::Path::new(base_config_path).parent() {
                parent.join(custom_file).to_string_lossy().to_string()
            } else {
                custom_file.to_string()
            }
        }
    }

    /// Load custom hooks from separate file
    fn load_custom_hooks(path: &str) -> Result<CustomHookConfig, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: CustomHookConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Merge custom hooks into main configuration
    fn merge_custom_hooks(
        main: &mut HookSettings,
        custom: CustomHookConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Merge custom hook definitions
        for (name, def) in custom.hooks.definitions {
            if main.definitions.contains_key(&name) {
                tracing::warn!(
                    hook = name,
                    "Custom hook definition overriding production definition"
                );
            }
            main.definitions.insert(name, def);
        }

        // Merge custom network configurations
        for (network_name, custom_network) in custom.hooks.networks {
            let network_config = main.networks.entry(network_name.clone()).or_insert_with(|| NetworkHookConfig {
                enabled: None,
                mappings: HashMap::new(),
                contracts: HashMap::new(),
                token_filters: HashMap::new(),
            });

            // Merge mappings
            for (dest_addr, hook_names) in custom_network.mappings {
                if network_config.mappings.contains_key(&dest_addr) {
                    tracing::warn!(
                        destination = dest_addr,
                        network = network_name,
                        "Custom hook mapping overriding existing mapping"
                    );
                }
                network_config.mappings.insert(dest_addr, hook_names);
            }

            // Merge contract addresses (destination-scoped)
            for (hook_name, dest_contracts) in custom_network.contracts {
                let hook_contracts = network_config.contracts.entry(hook_name.clone()).or_default();
                for (dest_addr, contract_addr) in dest_contracts {
                    if hook_contracts.contains_key(&dest_addr) {
                        tracing::warn!(
                            hook = hook_name,
                            destination = dest_addr,
                            network = network_name,
                            "Custom contract address overriding existing address"
                        );
                    }
                    hook_contracts.insert(dest_addr, contract_addr);
                }
            }

            // Merge token filters
            for (hook_name, token_filter) in custom_network.token_filters {
                if network_config.token_filters.contains_key(&hook_name) {
                    tracing::warn!(
                        hook = hook_name,
                        network = network_name,
                        "Custom token filter overriding existing filter"
                    );
                }
                network_config.token_filters.insert(hook_name, token_filter);
            }

            // Override network enabled flag if custom config specifies it
            if let Some(custom_enabled) = custom_network.enabled {
                if network_config.enabled.is_some() {
                    tracing::warn!(
                        network = network_name,
                        "Custom network enabled flag overriding existing flag"
                    );
                }
                network_config.enabled = Some(custom_enabled);
            }
        }

        Ok(())
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
"${NOTIFY_RECIPIENT}" = ["notify_hook"]

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

    #[test]
    fn test_custom_hooks_file_missing() {
        // Test that missing custom hooks file only warns, doesn't error
        let toml = r#"
[hooks]
enabled = true
allow_hook_failure = false
custom_hooks_file = "nonexistent-hooks-custom.toml"

[hooks.definitions.test_hook]
enabled = true
function_signature = "test()"
description = "Test hook"
"#;

        let temp_path = "/tmp/test_hooks_missing_custom_file.toml";
        std::fs::write(temp_path, toml).unwrap();

        // Should load successfully despite missing custom file
        let result = HookConfig::from_file(temp_path);
        assert!(result.is_ok(), "Should succeed even when custom hooks file is missing");

        let config = result.unwrap();
        assert!(config.hooks.enabled);
        assert_eq!(config.hooks.definitions.len(), 1);
        assert!(config.hooks.definitions.contains_key("test_hook"));

        std::fs::remove_file(temp_path).ok();
    }

    #[test]
    fn test_custom_hooks_disabled() {
        // Test that custom_hooks_file = None works correctly
        let toml = r#"
[hooks]
enabled = true

[hooks.definitions.prod_hook]
enabled = true
function_signature = "prod()"
description = "Production hook"
"#;

        let temp_path = "/tmp/test_hooks_no_custom.toml";
        std::fs::write(temp_path, toml).unwrap();

        let config = HookConfig::from_file(temp_path).unwrap();
        assert!(config.hooks.enabled);
        assert_eq!(config.hooks.custom_hooks_file, None);
        assert_eq!(config.hooks.definitions.len(), 1);

        std::fs::remove_file(temp_path).ok();
    }
}
