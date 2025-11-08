//! Ethereum provider cache and initialization logic.
//!
//! This module defines a cache of configured Ethereum JSON-RPC providers with signing capabilities.
//! Providers are constructed dynamically from environment variables, including private key credentials.
//!
//! This enables interaction with multiple Ethereum-compatible networks using Alloy's `ProviderBuilder`.
//!
//! Supported signer type: `private-key`.
//!
//! Environment variables used:
//! - `SIGNER_TYPE` — currently only `"private-key"` is supported,
//! - `EVM_PRIVATE_KEY` — comma-separated list of private keys used to sign transactions,
//! - `RPC_URL_BASE`, `RPC_URL_BASE_SEPOLIA` — RPC endpoints per network
//!
//! Example usage:
//! ```ignore
//! let provider_cache = ProviderCache::from_env().await?;
//! let provider = provider_cache.by_network(Network::Base)?;
//! ```

use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::Address;
use tokio::sync::RwLock;

use crate::chain::FromEnvByNetworkBuild;
use crate::chain::NetworkProvider;
use crate::network::Network;

/// Cached EIP-712 domain information for a token contract.
#[derive(Clone, Debug)]
pub struct Eip712DomainCache {
    /// The EIP-712 version string
    pub version: String,
    /// When this cache entry was created
    pub cached_at: Instant,
}

impl Eip712DomainCache {
    /// Cache TTL: 1 hour (versions rarely change)
    const TTL: Duration = Duration::from_secs(3600);

    /// Creates a new cache entry with the current timestamp
    pub fn new(version: String) -> Self {
        Self {
            version,
            cached_at: Instant::now(),
        }
    }

    /// Returns true if this cache entry has expired
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > Self::TTL
    }
}

/// A cache of pre-initialized [`EthereumProvider`] instances keyed by network.
///
/// This struct is responsible for lazily connecting to all configured RPC URLs
/// and wrapping them with appropriate signing and filler middleware.
///
/// Use [`ProviderCache::from_env`] to load credentials and connect using environment variables.
pub struct ProviderCache {
    providers: HashMap<Network, Arc<NetworkProvider>>,
    /// Cache of EIP-712 domain information by (network, token_address)
    eip712_domain_cache: Arc<RwLock<HashMap<(Network, Address), Eip712DomainCache>>>,
}

/// A generic cache of pre-initialized Ethereum provider instances [`ProviderMap::Value`] keyed by network.
///
/// This allows querying configured providers by network, and checking whether the network
/// supports EIP-1559 fee mechanics.
pub trait ProviderMap {
    type Value;

    /// Returns the Ethereum provider for the specified network, if configured.
    fn by_network<N: Borrow<Network>>(&self, network: N) -> Option<&Self::Value>;

    /// An iterator visiting all values in arbitrary order.
    fn values(&self) -> impl Iterator<Item = &Self::Value> + Send;
}

impl<'a> IntoIterator for &'a ProviderCache {
    type Item = (&'a Network, &'a Arc<NetworkProvider>);
    type IntoIter = std::collections::hash_map::Iter<'a, Network, Arc<NetworkProvider>>;

    fn into_iter(self) -> Self::IntoIter {
        self.providers.iter()
    }
}

impl ProviderCache {
    /// Constructs a new [`ProviderCache`] from environment variables.
    ///
    /// Expects the following to be set:
    /// - `SIGNER_TYPE` — currently only `"private-key"` is supported
    /// - `EVM_PRIVATE_KEY` — comma-separated list of private keys used to sign transactions
    /// - `RPC_URL_BASE`, `RPC_URL_BASE_SEPOLIA` — RPC endpoints per network
    ///
    /// Fails if required env vars are missing or if the provider cannot connect.
    pub async fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let mut providers = HashMap::new();
        for network in Network::variants() {
            let network_provider = NetworkProvider::from_env(*network).await?;
            if let Some(network_provider) = network_provider {
                providers.insert(*network, Arc::new(network_provider));
            }
        }
        Ok(Self {
            providers,
            eip712_domain_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Gets a cached EIP-712 version for a token contract, if available and not expired.
    pub async fn get_eip712_version(
        &self,
        network: Network,
        token_address: Address,
    ) -> Option<String> {
        let cache = self.eip712_domain_cache.read().await;
        cache.get(&(network, token_address)).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.version.clone())
            }
        })
    }

    /// Caches an EIP-712 version for a token contract.
    pub async fn set_eip712_version(
        &self,
        network: Network,
        token_address: Address,
        version: String,
    ) {
        let mut cache = self.eip712_domain_cache.write().await;
        cache.insert((network, token_address), Eip712DomainCache::new(version));
    }
}

impl ProviderMap for ProviderCache {
    type Value = Arc<NetworkProvider>;

    fn by_network<N: Borrow<Network>>(&self, network: N) -> Option<&Arc<NetworkProvider>> {
        self.providers.get(network.borrow())
    }

    fn values(&self) -> impl Iterator<Item = &Self::Value> {
        self.providers.values()
    }
}
