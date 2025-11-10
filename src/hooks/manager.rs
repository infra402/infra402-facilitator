//! Hook manager with hot-reload capability
//!
//! Manages post-settlement hooks with thread-safe hot-reloading via Arc<RwLock>.

use alloy::primitives::{Address, Bytes};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::config::{HookConfig, HookDefinition};

/// Runtime hook call specification
#[derive(Debug, Clone)]
pub struct HookCall {
    /// Target contract address
    pub target: Address,
    /// Pre-configured calldata
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

    /// Get hooks for a specific destination address
    ///
    /// Returns all enabled hooks mapped to this destination, or empty vec if none.
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
                    hooks.push(HookCall {
                        target: def.contract,
                        calldata: def.calldata.clone(),
                        gas_limit: def.gas_limit,
                        allow_failure: state.allow_hook_failure,
                    });
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
                "Retrieved hooks for destination"
            );
        }

        hooks
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[tokio::test]
    async fn test_hook_manager_no_hooks() {
        // Create temporary config with no mappings
        let config = HookConfig {
            hooks: super::super::config::HookSettings {
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
            .get_hooks_for_destination(address!("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"))
            .await;

        assert_eq!(hooks.len(), 0);
    }
}
