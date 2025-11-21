//! Hook manager with hot-reload capability
//!
//! Manages post-settlement hooks with thread-safe hot-reloading via Arc<RwLock>.
//! Supports both legacy static calldata and new parameterized hooks.

use alloy::primitives::{Address, Bytes};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::chain::evm::SettlementMetadata;
use crate::tokens::TokenManager;
use super::config::{HookConfig, HookDefinition};
use super::context::RuntimeContext;
use super::errors::HookError;

/// Runtime hook call specification
#[derive(Debug, Clone)]
pub struct HookCall {
    /// Target contract address
    pub target: Address,
    /// Pre-configured or dynamically encoded calldata
    pub calldata: Bytes,
    /// Gas limit (0 = unlimited)
    pub gas_limit: u64,
    /// Whether this call can fail without reverting batch
    pub allow_failure: bool,
}

/// Internal state for hot-reloadable hook management
///
/// Wraps HookSettings for thread-safe hot-reload capability
type HookState = super::config::HookSettings;

/// Thread-safe hook manager with hot-reload capability
#[derive(Debug, Clone)]
pub struct HookManager {
    /// Path to hooks.toml configuration file
    config_path: String,
    /// Hot-reloadable state
    state: Arc<RwLock<HookState>>,
    /// Token manager for resolving token names from addresses
    token_manager: Option<TokenManager>,
}

impl HookManager {
    /// Create a new HookManager and load configuration from file
    pub fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config = HookConfig::from_file(config_path)?;

        let state = config.hooks;

        tracing::info!(
            path = config_path,
            hooks_count = state.definitions.len(),
            networks_count = state.networks.len(),
            "Initialized HookManager"
        );

        Ok(Self {
            config_path: config_path.to_string(),
            state: Arc::new(RwLock::new(state)),
            token_manager: None,
        })
    }

    /// Create a new HookManager with token filtering support
    pub fn new_with_tokens(
        config_path: &str,
        token_manager: TokenManager,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = HookConfig::from_file(config_path)?;

        let state = config.hooks;

        tracing::info!(
            path = config_path,
            hooks_count = state.definitions.len(),
            networks_count = state.networks.len(),
            "Initialized HookManager with token filtering"
        );

        Ok(Self {
            config_path: config_path.to_string(),
            state: Arc::new(RwLock::new(state)),
            token_manager: Some(token_manager),
        })
    }

    /// Reload configuration from disk without restarting server
    pub async fn reload(&self) -> Result<(), String> {
        let config = HookConfig::from_file(&self.config_path).map_err(|e| e.to_string())?;

        let new_state = config.hooks;

        let mut state = self.state.write().await;
        *state = new_state.clone();

        tracing::info!(
            hooks_count = new_state.definitions.len(),
            networks_count = new_state.networks.len(),
            "Reloaded HookManager configuration"
        );

        Ok(())
    }

    /// Get hooks for a specific destination with runtime parameter resolution
    ///
    /// Returns all enabled hooks mapped to this destination with dynamically encoded calldata.
    /// Filters hooks based on token_filters configuration if TokenManager is available.
    ///
    /// # Arguments
    /// * `destination` - Recipient address to check for hooks
    /// * `token_address` - Payment token contract address for filtering
    /// * `network` - Network name (e.g., "base_sepolia", "base")
    /// * `metadata` - Settlement metadata for parameter resolution
    /// * `runtime` - Runtime context for parameter resolution
    pub async fn get_hooks_for_destination_with_context(
        &self,
        destination: Address,
        token_address: Address,
        network: &str,
        metadata: &SettlementMetadata,
        runtime: &RuntimeContext,
    ) -> Result<Vec<HookCall>, HookError> {
        let state = self.state.read().await;

        // Check if hooks are enabled for this network
        if !state.is_enabled_for_network(network) {
            return Ok(Vec::new());
        }

        // Get network-specific mappings
        let mappings = state.get_network_mappings(network);

        // Resolve mapping addresses and find hooks for destination
        // Mapping keys support env var substitution: "${ENV_VAR_NAME}"
        let mut hook_names: Option<&Vec<String>> = None;
        for (address_str, names) in mappings.iter() {
            if let Some(resolved_addr) = super::config::HookSettings::resolve_mapping_address(address_str) {
                if resolved_addr == destination {
                    hook_names = Some(names);
                    break;
                }
            } else {
                tracing::warn!(
                    address_str = address_str,
                    network = network,
                    "Failed to resolve mapping address (invalid or missing env var)"
                );
            }
        }

        let hook_names = match hook_names {
            Some(names) => names,
            None => return Ok(Vec::new()),
        };

        // Resolve token name from address for filtering (if TokenManager available)
        let token_name: Option<String> = if let Some(ref token_mgr) = self.token_manager {
            token_mgr.get_token_name(token_address, network).await
        } else {
            None
        };

        // Get network-specific config for token filters
        let network_config = state.networks.get(network);

        // Resolve each hook name to its definition and encode calldata
        let mut hooks = Vec::new();
        for name in hook_names {
            if let Some(def) = state.definitions.get(name) {
                if !def.enabled {
                    tracing::debug!(hook = name, network = network, "Skipping disabled hook");
                    continue;
                }

                // Check token filter if token filtering is configured
                if let (Some(token_name_val), Some(network_cfg)) = (token_name.as_ref(), network_config) {
                    if let Some(filter) = network_cfg.token_filters.get(name) {
                        if !filter.matches(token_name_val) {
                            tracing::debug!(
                                hook = name,
                                token = token_name_val,
                                network = network,
                                "Skipping hook due to token filter"
                            );
                            continue;
                        }
                    }
                    // If no filter specified for this hook, allow all tokens (default behavior)
                } else if token_name.is_none() && self.token_manager.is_some() {
                    // TokenManager is available but token not recognized - log warning
                    tracing::warn!(
                        token_address = %token_address,
                        network = network,
                        hook = name,
                        "Token address not recognized in tokens.toml, allowing hook"
                    );
                }

                // Resolve contract address for this network
                let contract_address = match state.resolve_contract_address(name, network) {
                    Some(addr) => addr,
                    None => {
                        tracing::warn!(
                            hook = name,
                            network = network,
                            "Hook contract address not configured for network, skipping"
                        );
                        continue;
                    }
                };

                // Encode calldata with parameter resolution
                match def.encode_calldata(metadata, runtime) {
                    Ok(calldata) => {
                        let calldata_len = calldata.len();

                        hooks.push(HookCall {
                            target: contract_address,
                            calldata,
                            gas_limit: def.gas_limit,
                            allow_failure: state.allow_hook_failure,
                        });

                        tracing::debug!(
                            hook = name,
                            network = network,
                            destination = %destination,
                            contract = %contract_address,
                            calldata_len,
                            "Encoded hook calldata"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            hook = name,
                            network = network,
                            destination = %destination,
                            error = %e,
                            "Failed to encode hook calldata"
                        );
                        return Err(e);
                    }
                }
            } else {
                tracing::warn!(
                    hook = name,
                    network = network,
                    destination = %destination,
                    "Hook referenced in mapping but not found in definitions"
                );
            }
        }

        if !hooks.is_empty() {
            tracing::info!(
                destination = %destination,
                network = network,
                hooks_count = hooks.len(),
                "Retrieved hooks for destination with parameter resolution"
            );
        }

        Ok(hooks)
    }

    /// Enable a specific hook by name
    pub async fn enable_hook(&self, name: &str) -> Result<(), String> {
        let mut state = self.state.write().await;

        match state.definitions.get_mut(name) {
            Some(def) => {
                def.enabled = true;
                tracing::info!(hook = name, "Enabled hook");
                Ok(())
            }
            None => Err(format!("Hook '{}' not found", name)),
        }
    }

    /// Disable a specific hook by name
    pub async fn disable_hook(&self, name: &str) -> Result<(), String> {
        let mut state = self.state.write().await;

        match state.definitions.get_mut(name) {
            Some(def) => {
                def.enabled = false;
                tracing::info!(hook = name, "Disabled hook");
                Ok(())
            }
            None => Err(format!("Hook '{}' not found", name)),
        }
    }

    /// Get all hook definitions (for admin API)
    pub async fn get_all_hooks(&self) -> HashMap<String, HookDefinition> {
        let state = self.state.read().await;
        state.definitions.clone()
    }

    /// Get all destination mappings (for admin API)
    /// Mapping keys support environment variable substitution: "${ENV_VAR_NAME}"
    pub async fn get_all_mappings(&self) -> HashMap<String, Vec<String>> {
        let state = self.state.read().await;
        state.mappings.clone()
    }

    /// Check if hooks are globally enabled
    pub async fn is_enabled(&self) -> bool {
        let state = self.state.read().await;
        state.enabled
    }

    /// Get a specific hook definition by name (for debugging)
    pub async fn get_hook(&self, name: &str) -> Option<HookDefinition> {
        let state = self.state.read().await;
        state.definitions.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, U256};

    #[tokio::test]
    async fn test_hook_manager_no_hooks() {
        use super::super::config::*;
        use crate::chain::evm::SettlementMetadata;

        // Create temporary config with no mappings
        let config = HookConfig {
            hooks: HookSettings {
                enabled: true,
                allow_hook_failure: false,
                custom_hooks_file: None,
                definitions: HashMap::new(),
                networks: HashMap::new(),
                mappings: HashMap::new(),
            },
        };

        let temp_path = "/tmp/test_hooks_empty.toml";
        config.to_file(temp_path).unwrap();

        let manager = HookManager::new(temp_path).unwrap();

        // Create test metadata and runtime context
        let metadata = SettlementMetadata {
            from: address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            to: address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            value: U256::from(1000000),
            valid_after: U256::ZERO,
            valid_before: U256::MAX,
            nonce: alloy::primitives::FixedBytes::ZERO,
            signature: alloy::primitives::Bytes::new(),
            contract_address: address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
            sig_kind: "eoa".to_string(),
        };

        let runtime = RuntimeContext::new(
            U256::from(1234567890),
            U256::from(100),
            address!("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
        );

        let hooks = manager
            .get_hooks_for_destination_with_context(
                address!("0x2222222222222222222222222222222222222222"),
                address!("0x0000000000000000000000000000000000000000"),  // Dummy token address
                "base_sepolia",
                &metadata,
                &runtime,
            )
            .await
            .unwrap();

        assert_eq!(hooks.len(), 0);
    }

    #[tokio::test]
    async fn test_hook_manager_with_context() {
        use super::super::config::*;
        use crate::chain::evm::SettlementMetadata;

        // Create a parameterized hook
        let mut definitions = HashMap::new();
        let mut parameters = Vec::new();
        parameters.push(ParameterDefinition {
            sol_type: "address".to_string(),
            source: ParameterSource::Payment(PaymentField::From),
        });
        parameters.push(ParameterDefinition {
            sol_type: "address".to_string(),
            source: ParameterSource::Payment(PaymentField::To),
        });
        parameters.push(ParameterDefinition {
            sol_type: "uint256".to_string(),
            source: ParameterSource::Payment(PaymentField::Value),
        });

        definitions.insert(
            "test_hook".to_string(),
            HookDefinition {
                enabled: true,
                function_signature: "notifySettlement(address,address,uint256)".to_string(),
                parameters,
                config_values: HashMap::new(),
                gas_limit: 100000,
                description: "Test hook".to_string(),
            },
        );

        // Create network-specific configuration for base_sepolia
        let mut network_mappings = HashMap::new();
        network_mappings.insert(
            "0x3333333333333333333333333333333333333333".to_string(),
            vec!["test_hook".to_string()],
        );

        let mut network_contracts = HashMap::new();
        network_contracts.insert(
            "test_hook".to_string(),
            "0x1234567890123456789012345678901234567890".to_string(),
        );

        let mut networks = HashMap::new();
        networks.insert(
            "base_sepolia".to_string(),
            NetworkHookConfig {
                enabled: Some(true),
                mappings: network_mappings,
                contracts: network_contracts,
                token_filters: HashMap::new(),
            },
        );

        let config = HookConfig {
            hooks: HookSettings {
                enabled: true,
                allow_hook_failure: false,
                custom_hooks_file: None,
                definitions,
                networks,
                mappings: HashMap::new(),
            },
        };

        let temp_path = "/tmp/test_hooks_parameterized.toml";
        config.to_file(temp_path).unwrap();

        let manager = HookManager::new(temp_path).unwrap();

        // Create test metadata and runtime context
        let metadata = SettlementMetadata {
            from: address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            to: address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            value: U256::from(1000000),
            valid_after: U256::ZERO,
            valid_before: U256::MAX,
            nonce: alloy::primitives::FixedBytes::ZERO,
            signature: Bytes::new(),  // Empty signature for testing
            contract_address: address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
            sig_kind: "eoa".to_string(),
        };

        let runtime = RuntimeContext::new(
            U256::from(1234567890),
            U256::from(100),
            address!("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
        );

        let hooks = manager
            .get_hooks_for_destination_with_context(
                address!("0x3333333333333333333333333333333333333333"),
                address!("0x0000000000000000000000000000000000000000"),  // Dummy token address
                "base_sepolia",
                &metadata,
                &runtime,
            )
            .await
            .unwrap();

        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].target, address!("0x1234567890123456789012345678901234567890"));
        assert!(hooks[0].calldata.len() > 4); // Should have selector + encoded params
    }
}
