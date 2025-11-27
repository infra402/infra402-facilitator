//! Configuration file parsing for x402 facilitator security settings.
//!
//! This module handles loading and parsing the `config.toml` file for security-related
//! settings such as rate limiting, CORS, IP filtering, and request size limits.
//!
//! Configuration is optional and defaults to permissive settings for backwards compatibility.

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Complete facilitator configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FacilitatorConfig {
    pub rate_limiting: RateLimitingConfig,
    pub cors: CorsConfig,
    pub ip_filtering: IpFilteringConfig,
    pub request: RequestConfig,
    pub security: SecurityConfig,
    pub transaction: TransactionConfig,
    pub batch_settlement: BatchSettlementConfig,
}

impl Default for FacilitatorConfig {
    fn default() -> Self {
        Self {
            rate_limiting: RateLimitingConfig::default(),
            cors: CorsConfig::default(),
            ip_filtering: IpFilteringConfig::default(),
            request: RequestConfig::default(),
            security: SecurityConfig::default(),
            transaction: TransactionConfig::default(),
            batch_settlement: BatchSettlementConfig::default(),
        }
    }
}

impl FacilitatorConfig {
    /// Load configuration from a TOML file.
    ///
    /// If the file doesn't exist, returns the default configuration.
    /// If the file exists but is malformed, returns an error.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, config::ConfigError> {
        let path = path.as_ref();

        if !path.exists() {
            tracing::info!("Config file not found at {:?}, using defaults", path);
            return Ok(Self::default());
        }

        config::Config::builder()
            .add_source(config::File::from(path))
            .build()?
            .try_deserialize()
    }

    /// Load configuration from environment variable CONFIG_FILE or default path.
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let config_path = std::env::var("CONFIG_FILE").unwrap_or_else(|_| "config.toml".to_string());
        Self::from_file(config_path)
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimitingConfig {
    /// Enable rate limiting globally.
    pub enabled: bool,
    /// Global rate limit (requests per second per IP).
    pub requests_per_second: u32,
    /// Duration in seconds to ban an IP after threshold violations.
    pub ban_duration_seconds: u64,
    /// Number of rate limit violations before triggering a ban.
    pub ban_threshold: u32,
    /// Per-endpoint rate limit overrides.
    #[serde(default)]
    pub endpoints: HashMap<String, u32>,
    /// IPs exempt from rate limiting (e.g., localhost, trusted services).
    #[serde(with = "ip_list_serde")]
    pub whitelisted_ips: Vec<IpNetwork>,
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 10,
            ban_duration_seconds: 300, // 5 minutes
            ban_threshold: 5,
            endpoints: HashMap::new(),
            whitelisted_ips: default_local_whitelist(),
        }
    }
}

/// Default whitelist includes local IP ranges for development/testing.
fn default_local_whitelist() -> Vec<IpNetwork> {
    use std::str::FromStr;
    vec![
        IpNetwork::from_str("127.0.0.0/8").unwrap(),   // IPv4 localhost
        IpNetwork::from_str("::1/128").unwrap(),        // IPv6 localhost
        IpNetwork::from_str("::ffff:127.0.0.0/104").unwrap(), // IPv4-mapped IPv6 localhost
    ]
}

/// CORS configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CorsConfig {
    /// List of allowed origins. Empty list means allow all (*).
    pub allowed_origins: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec![],
        }
    }
}

/// IP filtering configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct IpFilteringConfig {
    /// List of allowed IPs/CIDRs. Empty = allow all.
    #[serde(with = "ip_list_serde")]
    pub allowed_ips: Vec<IpNetwork>,
    /// List of blocked IPs/CIDRs.
    #[serde(with = "ip_list_serde")]
    pub blocked_ips: Vec<IpNetwork>,
}

impl Default for IpFilteringConfig {
    fn default() -> Self {
        Self {
            allowed_ips: vec![],
            blocked_ips: vec![],
        }
    }
}

/// Request validation configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RequestConfig {
    /// Maximum request body size in bytes (default 1MB).
    pub max_body_size_bytes: usize,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            max_body_size_bytes: 1_048_576, // 1MB
        }
    }
}

/// Security-related configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Require API key for /health endpoint.
    pub health_endpoint_requires_auth: bool,
    /// Log security-related events (rate limits, auth failures, etc).
    pub log_security_events: bool,
    /// Cleanup interval for abuse detector and rate limiter (in seconds).
    /// Default: 300 seconds (5 minutes).
    pub cleanup_interval_seconds: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            health_endpoint_requires_auth: false,
            log_security_events: true,
            cleanup_interval_seconds: 300, // 5 minutes
        }
    }
}

/// Chain-specific configuration for transaction timeouts and block times.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainConfig {
    /// Average block time for this chain in seconds.
    pub block_time_seconds: u64,
    /// Number of blocks to wait when polling for transaction receipt.
    /// Receipt timeout = block_time_seconds * receipt_timeout_blocks.
    pub receipt_timeout_blocks: u64,
    /// Timeout for individual RPC requests in seconds.
    pub rpc_request_timeout_seconds: u64,
    /// Gas buffer multiplier override for this chain.
    /// If not set, uses the global transaction.gas_buffer.
    #[serde(default)]
    pub gas_buffer: Option<f64>,
}

impl ChainConfig {
    /// Get the total receipt timeout duration.
    pub fn receipt_timeout(&self) -> Duration {
        Duration::from_secs(self.block_time_seconds * self.receipt_timeout_blocks)
    }

    /// Get the RPC request timeout duration.
    pub fn rpc_timeout(&self) -> Duration {
        Duration::from_secs(self.rpc_request_timeout_seconds)
    }
}

/// Transaction-related configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TransactionConfig {
    /// Default RPC request timeout in seconds.
    /// This is used as a fallback when chain-specific configuration is not provided.
    /// Default: 30 seconds.
    pub default_rpc_timeout_seconds: u64,

    /// HTTP connection establishment timeout in seconds.
    /// Default: 10 seconds.
    pub connection_timeout_seconds: u64,

    /// Maximum idle connections per host in the connection pool.
    /// Default: 100 connections.
    pub pool_max_idle_per_host: usize,

    /// How long to keep idle connections alive in seconds.
    /// Default: 90 seconds.
    pub pool_idle_timeout_seconds: u64,

    /// Per-chain configuration overrides.
    /// Key is the network name (e.g., "bsc", "ethereum", "base").
    /// Each chain should specify its block_time_seconds, receipt_timeout_blocks, and rpc_request_timeout_seconds.
    /// If a chain is not configured, sensible defaults will be used (120s receipt timeout, 30s RPC timeout).
    #[serde(default)]
    pub chains: HashMap<String, ChainConfig>,

    /// Gas buffer multiplier applied to estimated gas (e.g., 1.2 = 20% buffer).
    /// Default: 1.0 (no buffer, for backwards compatibility)
    #[serde(default = "default_gas_buffer")]
    pub gas_buffer: f64,
}

fn default_gas_buffer() -> f64 {
    1.0
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            default_rpc_timeout_seconds: 30, // 30 seconds
            connection_timeout_seconds: 10, // 10 seconds
            pool_max_idle_per_host: 100, // 100 connections
            pool_idle_timeout_seconds: 90, // 90 seconds
            chains: HashMap::new(),
            gas_buffer: default_gas_buffer(),
        }
    }
}

impl TransactionConfig {
    /// Get the effective gas buffer for a specific network.
    /// Returns the chain-specific override if set, otherwise the global default.
    pub fn gas_buffer_for_network(&self, network: &str) -> f64 {
        self.chains
            .get(network)
            .and_then(|c| c.gas_buffer)
            .unwrap_or(self.gas_buffer)
    }
}

/// Batch settlement configuration for high-throughput scenarios.
///
/// Enables bundling multiple settlement transactions into single Multicall3 transactions
/// to improve throughput and reduce gas costs.
///
/// Supports per-network configuration overrides to tune batching parameters independently
/// for each blockchain network (e.g., different batch sizes for Base vs BSC).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BatchSettlementConfig {
    /// Enable batch settlement processing globally.
    /// Default: false (opt-in for backward compatibility)
    pub enabled: bool,

    /// Maximum number of settlements per batch (global default).
    /// Limited by block gas limit (~30M gas / ~55k per transfer = ~545 theoretical max).
    /// Default: 150 (conservative for safety)
    pub max_batch_size: usize,

    /// Maximum time to wait before flushing batch in milliseconds (global default).
    /// Default: 500ms (balance between latency and throughput)
    pub max_wait_ms: u64,

    /// Minimum batch size for immediate flush (global default).
    /// If queue reaches this size, flush immediately without waiting.
    /// Default: 10 (avoid waiting for small batches)
    pub min_batch_size: usize,

    /// Allow partial failures in batch - Multicall3 allowFailure flag (global default).
    /// - true: Individual transfers can fail without reverting entire batch
    /// - false: Any failure reverts entire batch (safer default)
    /// Default: false
    pub allow_partial_failure: bool,

    /// Allow hook failures in batch when hooks are present (global default).
    /// - true: Hook calls can fail without reverting entire batch
    /// - false: Any hook failure reverts entire batch
    /// When hooks are attached to a settlement, this overrides allow_partial_failure.
    /// Default: false
    pub allow_hook_failure: bool,

    /// Per-network configuration overrides.
    /// Key is the network name (e.g., "base", "bsc", "avalanche").
    /// Each network can override any subset of the global defaults.
    #[serde(default)]
    pub networks: HashMap<String, NetworkBatchConfig>,
}

impl Default for BatchSettlementConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Opt-in for safety
            max_batch_size: 150,
            max_wait_ms: 500,
            min_batch_size: 10,
            allow_partial_failure: false,
            allow_hook_failure: false,
            networks: HashMap::new(),
        }
    }
}

impl BatchSettlementConfig {
    /// Check if batch settlement is enabled for a specific network.
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

    /// Check if batch settlement is enabled globally or for any network.
    ///
    /// Returns true if:
    /// - Global `enabled = true`, OR
    /// - Any network has explicit `enabled = true`
    ///
    /// This is used to determine if the batch queue manager should be created.
    pub fn is_enabled_anywhere(&self) -> bool {
        self.enabled || self.networks.values().any(|n| n.enabled == Some(true))
    }

    /// Get the effective configuration for a specific network.
    ///
    /// Returns a resolved configuration that applies network-specific overrides
    /// on top of global defaults.
    pub fn for_network(&self, network_name: &str) -> ResolvedBatchConfig {
        let network_override = self.networks.get(network_name);

        ResolvedBatchConfig {
            max_batch_size: network_override
                .and_then(|n| n.max_batch_size)
                .unwrap_or(self.max_batch_size),
            max_wait_ms: network_override
                .and_then(|n| n.max_wait_ms)
                .unwrap_or(self.max_wait_ms),
            min_batch_size: network_override
                .and_then(|n| n.min_batch_size)
                .unwrap_or(self.min_batch_size),
            allow_partial_failure: network_override
                .and_then(|n| n.allow_partial_failure)
                .unwrap_or(self.allow_partial_failure),
        }
    }
}

/// Per-network batch settlement configuration overrides.
///
/// All fields are optional - only specified fields override global defaults.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkBatchConfig {
    /// Override enabled for this network.
    /// - Some(true): Force batch settlement enabled for this network
    /// - Some(false): Force batch settlement disabled for this network
    /// - None: Use global enabled setting
    pub enabled: Option<bool>,

    /// Override max_batch_size for this network.
    pub max_batch_size: Option<usize>,

    /// Override max_wait_ms for this network.
    pub max_wait_ms: Option<u64>,

    /// Override min_batch_size for this network.
    pub min_batch_size: Option<usize>,

    /// Override allow_partial_failure for this network.
    pub allow_partial_failure: Option<bool>,
}

/// Resolved batch configuration for a specific network.
///
/// Contains the final effective values after applying network-specific overrides.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedBatchConfig {
    pub max_batch_size: usize,
    pub max_wait_ms: u64,
    pub min_batch_size: usize,
    pub allow_partial_failure: bool,
}

/// Custom serde module for IP network lists.
mod ip_list_serde {
    use ipnetwork::IpNetwork;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(ips: &Vec<IpNetwork>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let strings: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        serializer.collect_seq(strings)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<IpNetwork>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| IpNetwork::from_str(&s).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FacilitatorConfig::default();
        assert!(config.rate_limiting.enabled);
        assert_eq!(config.rate_limiting.requests_per_second, 10);
        assert_eq!(config.request.max_body_size_bytes, 1_048_576);
    }

    #[test]
    fn test_parse_ip_networks() {
        let config_str = r#"
[ip_filtering]
allowed_ips = ["192.168.1.0/24", "10.0.0.1"]
blocked_ips = ["192.0.2.0/24"]
"#;

        let config: FacilitatorConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.ip_filtering.allowed_ips.len(), 2);
        assert_eq!(config.ip_filtering.blocked_ips.len(), 1);
    }

    #[test]
    fn test_batch_settlement_default() {
        let config = BatchSettlementConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_batch_size, 150);
        assert_eq!(config.max_wait_ms, 500);
        assert_eq!(config.min_batch_size, 10);
        assert!(!config.allow_partial_failure);
        assert!(config.networks.is_empty());
    }

    #[test]
    fn test_batch_settlement_global_config() {
        let config_str = r#"
[batch_settlement]
enabled = true
max_batch_size = 200
max_wait_ms = 1000
min_batch_size = 20
allow_partial_failure = true
"#;

        let config: FacilitatorConfig = toml::from_str(config_str).unwrap();
        assert!(config.batch_settlement.enabled);
        assert_eq!(config.batch_settlement.max_batch_size, 200);
        assert_eq!(config.batch_settlement.max_wait_ms, 1000);
        assert_eq!(config.batch_settlement.min_batch_size, 20);
        assert!(config.batch_settlement.allow_partial_failure);
    }

    #[test]
    fn test_batch_settlement_per_network_config() {
        let config_str = r#"
[batch_settlement]
enabled = true
max_batch_size = 150
max_wait_ms = 500
min_batch_size = 10
allow_partial_failure = false

[batch_settlement.networks.bsc]
max_batch_size = 200
allow_partial_failure = true

[batch_settlement.networks.base]
max_wait_ms = 250
min_batch_size = 5
"#;

        let config: FacilitatorConfig = toml::from_str(config_str).unwrap();

        // Test global defaults
        let global = config.batch_settlement.for_network("unknown-network");
        assert_eq!(global.max_batch_size, 150);
        assert_eq!(global.max_wait_ms, 500);
        assert_eq!(global.min_batch_size, 10);
        assert!(!global.allow_partial_failure);

        // Test BSC overrides (partial)
        let bsc = config.batch_settlement.for_network("bsc");
        assert_eq!(bsc.max_batch_size, 200); // overridden
        assert_eq!(bsc.max_wait_ms, 500); // global default
        assert_eq!(bsc.min_batch_size, 10); // global default
        assert!(bsc.allow_partial_failure); // overridden

        // Test Base overrides (different subset)
        let base = config.batch_settlement.for_network("base");
        assert_eq!(base.max_batch_size, 150); // global default
        assert_eq!(base.max_wait_ms, 250); // overridden
        assert_eq!(base.min_batch_size, 5); // overridden
        assert!(!base.allow_partial_failure); // global default
    }

    #[test]
    fn test_batch_settlement_network_complete_override() {
        let config_str = r#"
[batch_settlement]
enabled = true
max_batch_size = 100
max_wait_ms = 300
min_batch_size = 5
allow_partial_failure = false

[batch_settlement.networks.avalanche]
max_batch_size = 300
max_wait_ms = 2000
min_batch_size = 50
allow_partial_failure = true
"#;

        let config: FacilitatorConfig = toml::from_str(config_str).unwrap();

        let avalanche = config.batch_settlement.for_network("avalanche");
        assert_eq!(avalanche.max_batch_size, 300);
        assert_eq!(avalanche.max_wait_ms, 2000);
        assert_eq!(avalanche.min_batch_size, 50);
        assert!(avalanche.allow_partial_failure);
    }

    #[test]
    fn test_batch_settlement_per_network_enabled_override() {
        let config_str = r#"
[batch_settlement]
enabled = false

[batch_settlement.networks.bsc-testnet]
enabled = true
max_batch_size = 100
"#;

        let config: FacilitatorConfig = toml::from_str(config_str).unwrap();

        // Global is disabled
        assert!(!config.batch_settlement.enabled);

        // BSC testnet should be enabled despite global being disabled
        assert!(config.batch_settlement.is_enabled_for_network("bsc-testnet"));

        // Other networks should fall back to global (disabled)
        assert!(!config.batch_settlement.is_enabled_for_network("base"));
        assert!(!config.batch_settlement.is_enabled_for_network("avalanche"));

        // Should return true because at least one network has batching enabled
        assert!(config.batch_settlement.is_enabled_anywhere());
    }

    #[test]
    fn test_batch_settlement_per_network_disabled_override() {
        let config_str = r#"
[batch_settlement]
enabled = true

[batch_settlement.networks.base]
enabled = false
"#;

        let config: FacilitatorConfig = toml::from_str(config_str).unwrap();

        // Global is enabled
        assert!(config.batch_settlement.enabled);

        // Base should be disabled despite global being enabled
        assert!(!config.batch_settlement.is_enabled_for_network("base"));

        // Other networks should fall back to global (enabled)
        assert!(config.batch_settlement.is_enabled_for_network("bsc"));
        assert!(config.batch_settlement.is_enabled_for_network("avalanche"));

        // Should return true because global is enabled
        assert!(config.batch_settlement.is_enabled_anywhere());
    }

    #[test]
    fn test_batch_settlement_is_enabled_anywhere() {
        // Test 1: Global disabled, no network overrides
        let config1_str = r#"
[batch_settlement]
enabled = false
"#;
        let config1: FacilitatorConfig = toml::from_str(config1_str).unwrap();
        assert!(!config1.batch_settlement.is_enabled_anywhere());

        // Test 2: Global enabled
        let config2_str = r#"
[batch_settlement]
enabled = true
"#;
        let config2: FacilitatorConfig = toml::from_str(config2_str).unwrap();
        assert!(config2.batch_settlement.is_enabled_anywhere());

        // Test 3: Global disabled, but one network enabled
        let config3_str = r#"
[batch_settlement]
enabled = false

[batch_settlement.networks.bsc]
enabled = true
"#;
        let config3: FacilitatorConfig = toml::from_str(config3_str).unwrap();
        assert!(config3.batch_settlement.is_enabled_anywhere());

        // Test 4: Global disabled, network explicitly disabled
        let config4_str = r#"
[batch_settlement]
enabled = false

[batch_settlement.networks.bsc]
enabled = false
"#;
        let config4: FacilitatorConfig = toml::from_str(config4_str).unwrap();
        assert!(!config4.batch_settlement.is_enabled_anywhere());
    }
}
