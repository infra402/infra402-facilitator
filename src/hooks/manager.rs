//! Hook manager with hot-reload capability
//!
//! Manages post-settlement hooks with thread-safe hot-reloading via Arc<RwLock>.
//! Supports both legacy static calldata and new parameterized hooks.

use alloy::primitives::{Address, Bytes};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::chain::evm::SettlementMetadata;
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
#[derive(Debug, Clone)]
struct HookState {
    /// Global enabled flag
    enabled: bool,
    /// Global allow_hook_failure setting
    allow_hook_failure: bool,
    /// Destination address → hook names mapping
    mappings: HashMap<Address, Vec<String>>,
    /// Hook name → definition mapping
    definitions: HashMap<String, HookDefinition>,
}

/// Thread-safe hook manager with hot-reload capability
#[derive(Debug, Clone)]
pub struct HookManager {
    /// Path to hooks.toml configuration file
    config_path: String,
    /// Hot-reloadable state
    state: Arc<RwLock<HookState>>,
}

impl HookManager {
    /// Create a new HookManager and load configuration from file
    pub fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config = HookConfig::from_file(config_path)?;

        let state = HookState {
            enabled: config.hooks.enabled,
            allow_hook_failure: config.hooks.allow_hook_failure,
            mappings: config.hooks.mappings,
            definitions: config.hooks.definitions,
        };

        tracing::info!(
            path = config_path,
            hooks_count = state.definitions.len(),
            mappings_count = state.mappings.len(),
            "Initialized HookManager"
        );

        Ok(Self {
            config_path: config_path.to_string(),
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Reload configuration from disk without restarting server
    pub async fn reload(&self) -> Result<(), String> {
        let config = HookConfig::from_file(&self.config_path).map_err(|e| e.to_string())?;

        let new_state = HookState {
            enabled: config.hooks.enabled,
            allow_hook_failure: config.hooks.allow_hook_failure,
            mappings: config.hooks.mappings,
            definitions: config.hooks.definitions,
        };

        let mut state = self.state.write().await;
        *state = new_state.clone();

        tracing::info!(
            hooks_count = new_state.definitions.len(),
            mappings_count = new_state.mappings.len(),
            "Reloaded HookManager configuration"
        );

        Ok(())
    }

    /// Get hooks for a specific destination address (LEGACY - uses static calldata)
    ///
    /// Returns all enabled hooks mapped to this destination, or empty vec if none.
    /// This method is kept for backward compatibility and uses static calldata.
    pub async fn get_hooks_for_destination(&self, destination: Address) -> Vec<HookCall> {
        let state = self.state.read().await;

        // If hooks disabled globally, return empty
        if !state.enabled {
            return Vec::new();
        }

        // Look up hooks mapped to this destination
        let hook_names = match state.mappings.get(&destination) {
            Some(names) => names,
            None => return Vec::new(),
        };

        // Resolve each hook name to its definition
        let mut hooks = Vec::new();
        for name in hook_names {
            if let Some(def) = state.definitions.get(name) {
                // Only include if hook is enabled
                if def.enabled {
                    // Legacy mode: require static calldata
                    if let Some(calldata) = &def.calldata {
                        hooks.push(HookCall {
                            target: def.contract,
                            calldata: calldata.clone(),
                            gas_limit: def.gas_limit,
                            allow_failure: state.allow_hook_failure,
                        });
                    } else {
                        tracing::warn!(
                            hook = name,
                            "Hook has no static calldata, skipping in legacy mode. \
                             Use get_hooks_for_destination_with_context for parameterized hooks."
                        );
                    }
                } else {
                    tracing::debug!(hook = name, "Skipping disabled hook");
                }
            } else {
                tracing::warn!(
                    hook = name,
                    destination = %destination,
                    "Hook referenced in mapping but not found in definitions"
                );
            }
        }

        if !hooks.is_empty() {
            tracing::debug!(
                destination = %destination,
                hooks_count = hooks.len(),
                "Retrieved hooks for destination (legacy mode)"
            );
        }

        hooks
    }

    /// Get hooks for a specific destination with runtime parameter resolution
    ///
    /// Returns all enabled hooks mapped to this destination with dynamically encoded calldata.
    /// Supports both legacy static calldata and new parameterized hooks.
    pub async fn get_hooks_for_destination_with_context(
        &self,
        destination: Address,
        metadata: &SettlementMetadata,
        runtime: &RuntimeContext,
    ) -> Result<Vec<HookCall>, HookError> {
        let state = self.state.read().await;

        // If hooks disabled globally, return empty
        if !state.enabled {
            return Ok(Vec::new());
        }

        // Look up hooks mapped to this destination
        let hook_names = match state.mappings.get(&destination) {
            Some(names) => names,
            None => return Ok(Vec::new()),
        };

        // Resolve each hook name to its definition and encode calldata
        let mut hooks = Vec::new();
        for name in hook_names {
            if let Some(def) = state.definitions.get(name) {
                if !def.enabled {
                    tracing::debug!(hook = name, "Skipping disabled hook");
                    continue;
                }

                // Encode calldata with parameter resolution
                match def.encode_calldata(metadata, runtime) {
                    Ok(calldata) => {
                        let calldata_len = calldata.len();

                        hooks.push(HookCall {
                            target: def.contract,
                            calldata,
                            gas_limit: def.gas_limit,
                            allow_failure: state.allow_hook_failure,
                        });

                        tracing::debug!(
                            hook = name,
                            destination = %destination,
                            calldata_len,
                            "Encoded hook calldata"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            hook = name,
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
                    destination = %destination,
                    "Hook referenced in mapping but not found in definitions"
                );
            }
        }

        if !hooks.is_empty() {
            tracing::info!(
                destination = %destination,
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
    pub async fn get_all_mappings(&self) -> HashMap<Address, Vec<String>> {
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
    use crate::hooks::config::{ParameterDefinition, ParameterSource, PaymentField};

    #[tokio::test]
    async fn test_hook_manager_no_hooks() {
        use super::super::config::*;

        // Create temporary config with no mappings
        let config = HookConfig {
            hooks: HookSettings {
                enabled: true,
                allow_hook_failure: false,
                mappings: HashMap::new(),
                definitions: HashMap::new(),
            },
        };

        let temp_path = "/tmp/test_hooks_empty.toml";
        config.to_file(temp_path).unwrap();

        let manager = HookManager::new(temp_path).unwrap();
        let hooks = manager
            .get_hooks_for_destination(address!("0x2222222222222222222222222222222222222222"))
            .await;

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
                contract: address!("0x1234567890123456789012345678901234567890"),
                calldata: None,
                function_signature: Some("notifySettlement(address,address,uint256)".to_string()),
                parameters,
                config_values: HashMap::new(),
                gas_limit: 100000,
                description: "Test hook".to_string(),
            },
        );

        let mut mappings = HashMap::new();
        mappings.insert(
            address!("0x3333333333333333333333333333333333333333"),
            vec!["test_hook".to_string()],
        );

        let config = HookConfig {
            hooks: HookSettings {
                enabled: true,
                allow_hook_failure: false,
                mappings,
                definitions,
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
