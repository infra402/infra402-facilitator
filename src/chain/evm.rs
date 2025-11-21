//! x402 EVM flow: verification (off-chain) and settlement (on-chain).
//!
//! - **Verify**: simulate signature validity and transfer atomically in a single `eth_call`.
//!   For 6492 signatures, we call the universal validator which may *prepare* (deploy) the
//!   counterfactual wallet inside the same simulation.
//! - **Settle**: if the signer wallet is not yet deployed, we deploy it (via the 6492
//!   factory+calldata) and then call ERC-3009 `transferWithAuthorization` in a real tx.
//!
//! Assumptions:
//! - Target tokens implement ERC-3009 and support ERC-1271 for contract signers.
//! - The validator contract exists at [`VALIDATOR_ADDRESS`] on supported chains.
//!
//! Invariants:
//! - Settlement is atomic: deploy (if needed) + transfer happen in a single user flow.
//! - Verification does not persist state.

use alloy::contract::SolCallBuilder;
use alloy::dyn_abi::SolType;
use alloy::network::{
    Ethereum as AlloyEthereum, EthereumWallet, NetworkWallet, TransactionBuilder,
};
use alloy::primitives::{Address, Bytes, FixedBytes, U256, address};
use alloy::providers::ProviderBuilder;
use alloy::providers::bindings::IMulticall3;
use alloy::providers::fillers::NonceManager;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy::providers::{
    Identity, MULTICALL3_ADDRESS, MulticallItem, Provider, RootProvider, WalletProvider,
};
use alloy::rpc::client::RpcClient;
use alloy::rpc::types::{BlockId, BlockNumberOrTag, TransactionReceipt, TransactionRequest};
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct, eip712_domain};
use alloy::{hex, sol};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{Instrument, instrument};
use tracing_core::Level;

use crate::chain::{FacilitatorLocalError, FromEnvByNetworkBuild, NetworkProviderOps};
use crate::facilitator::Facilitator;
use crate::from_env;
use crate::hooks::{HookCall, HookManager, RuntimeContext};
use crate::network::{Network, USDCDeployment};
use crate::timestamp::UnixTimestamp;
use crate::types::{
    EvmAddress, EvmSignature, ExactPaymentPayload, FacilitatorErrorReason, HexEncodedNonce,
    MixedAddress, PaymentPayload, PaymentRequirements, Scheme, SettleRequest, SettleResponse,
    SupportedPaymentKind, SupportedPaymentKindsResponse, TokenAmount, TransactionHash,
    TransferWithAuthorization, VerifyRequest, VerifyResponse, X402Version,
};

sol!(
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc)]
    USDC,
    "abi/USDC.json"
);

sol!(
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc)]
    XBNB,
    "abi/XBNB.json"
);

sol!(
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc)]
    ERC20TokenWith3009,
    "abi/ERC20TokenWith3009.json"
);

sol! {
    #[allow(missing_docs)]
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc)]
    Validator6492,
    "abi/Validator6492.json"
}

/// Signature verifier for EIP-6492, EIP-1271, EOA, universally deployed on the supported EVM chains
/// If absent on a target chain, verification will fail; you should deploy the validator there.
const VALIDATOR_ADDRESS: alloy::primitives::Address =
    address!("0xdAcD51A54883eb67D95FAEb2BBfdC4a9a6BD2a3B");

// Task-local storage for pre-selected facilitator address during settlement.
// This allows settle_with_lock() to pass the locked address to send_transaction().
tokio::task_local! {
    pub static PRESELECTED_FACILITATOR: Address;
}

/// ABI signature variant for ERC-3009 transferWithAuthorization.
///
/// Different token implementations use different signature parameter formats:
/// - BytesSignature: signature passed as single bytes parameter (e.g., USDC)
/// - SplitSignature: signature passed as (v, r, s) components (e.g., XBNB, ERC20TokenWith3009)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiVariant {
    /// Signature as bytes: transferWithAuthorization(..., bytes signature)
    BytesSignature,
    /// Signature as components: transferWithAuthorization(..., uint8 v, bytes32 r, bytes32 s)
    SplitSignature,
}

/// Unified enum for ERC-3009 compatible token contracts (USDC, XBNB, and ERC20TokenWith3009).
///
/// All variants implement the ERC-3009 `transferWithAuthorization` interface.
/// This enum allows the code to work with any token type while maintaining type safety.
pub enum Erc3009Contract<P> {
    Usdc(USDC::USDCInstance<P>),
    Xbnb(XBNB::XBNBInstance<P>),
    ERC20TokenWith3009(ERC20TokenWith3009::ERC20TokenWith3009Instance<P>),
}

/// Combined filler type for gas, blob gas, nonce, and chain ID.
type InnerFiller = JoinFill<
    GasFiller,
    JoinFill<BlobGasFiller, JoinFill<NonceFiller<PendingNonceManager>, ChainIdFiller>>,
>;

/// The fully composed Ethereum provider type used in this project.
///
/// Combines multiple filler layers for gas, nonce, chain ID, blob gas, and wallet signing,
/// and wraps a [`RootProvider`] for actual JSON-RPC communication.
pub type InnerProvider = FillProvider<
    JoinFill<JoinFill<Identity, InnerFiller>, WalletFiller<EthereumWallet>>,
    RootProvider,
>;

/// Chain descriptor used by the EVM provider.
///
/// Wraps a `Network` enum and the concrete `chain_id` used for EIP-155 and EIP-712.
#[derive(Clone, Copy, Debug)]
pub struct EvmChain {
    /// x402 network name (Base, Avalanche, etc.).
    pub network: Network,
    /// Numeric chain id used in transactions and EIP-712 domains.
    pub chain_id: u64,
}

impl EvmChain {
    /// Construct a chain descriptor from a network and chain id.
    pub fn new(network: Network, chain_id: u64) -> Self {
        Self { network, chain_id }
    }

    /// Returns the x402 network.
    pub fn network(&self) -> Network {
        self.network
    }
}

impl TryFrom<Network> for EvmChain {
    type Error = FacilitatorLocalError;

    /// Map a `Network` to its canonical `chain_id`.
    ///
    /// # Errors
    /// Returns [`FacilitatorLocalError::UnsupportedNetwork`] for non-EVM networks (e.g. Solana).
    fn try_from(value: Network) -> Result<Self, Self::Error> {
        match value {
            Network::BaseSepolia => Ok(EvmChain::new(value, 84532)),
            Network::Base => Ok(EvmChain::new(value, 8453)),
            Network::XdcMainnet => Ok(EvmChain::new(value, 50)),
            Network::AvalancheFuji => Ok(EvmChain::new(value, 43113)),
            Network::Avalanche => Ok(EvmChain::new(value, 43114)),
            Network::Solana => Err(FacilitatorLocalError::UnsupportedNetwork(None)),
            Network::SolanaDevnet => Err(FacilitatorLocalError::UnsupportedNetwork(None)),
            Network::PolygonAmoy => Ok(EvmChain::new(value, 80002)),
            Network::Polygon => Ok(EvmChain::new(value, 137)),
            Network::Sei => Ok(EvmChain::new(value, 1329)),
            Network::SeiTestnet => Ok(EvmChain::new(value, 1328)),
            Network::BscTestnet => Ok(EvmChain::new(value, 97)),
            Network::Bsc => Ok(EvmChain::new(value, 56)),
        }
    }
}

/// A fully specified ERC-3009 authorization payload for EVM settlement.
pub struct ExactEvmPayment {
    /// Target chain for settlement.
    #[allow(dead_code)] // Just in case.
    pub chain: EvmChain,
    /// Authorized sender (`from`) — EOA or smart wallet.
    pub from: EvmAddress,
    /// Authorized recipient (`to`).
    pub to: EvmAddress,
    /// Transfer amount (token units).
    pub value: TokenAmount,
    /// Not valid before this timestamp (inclusive).
    pub valid_after: UnixTimestamp,
    /// Not valid at/after this timestamp (exclusive).
    pub valid_before: UnixTimestamp,
    /// Unique 32-byte nonce (prevents replay).
    pub nonce: HexEncodedNonce,
    /// Raw signature bytes (EIP-1271 or EIP-6492-wrapped).
    pub signature: EvmSignature,
}

/// EVM implementation of the x402 facilitator.
///
/// Holds a composed Alloy ethereum provider [`InnerProvider`],
/// an `eip1559` toggle for gas pricing strategy, and the `EvmChain` context.
#[derive(Debug)]
pub struct EvmProvider {
    /// Composed Alloy provider with all fillers.
    inner: InnerProvider,
    /// Whether network supports EIP-1559 gas pricing.
    eip1559: bool,
    /// Chain descriptor (network + chain ID).
    chain: EvmChain,
    /// Available signer addresses for round-robin selection.
    signer_addresses: Arc<Vec<Address>>,
    /// Current position in round-robin signer rotation.
    signer_cursor: Arc<AtomicUsize>,
    /// Per-address settlement locks to ensure FIFO ordering and prevent nonce race conditions.
    /// Each facilitator address has its own mutex to serialize settlements.
    settlement_locks: Arc<DashMap<Address, Arc<Mutex<()>>>>,
    /// Nonce manager for resetting nonces on transaction failures.
    nonce_manager: PendingNonceManager,
    /// EIP-712 version cache shared across all providers
    eip712_version_cache: Arc<tokio::sync::RwLock<std::collections::HashMap<Address, (String, std::time::Instant)>>>,
}

impl EvmProvider {
    /// Build an [`EvmProvider`] from a pre-composed Alloy ethereum provider [`InnerProvider`].
    pub async fn try_new(
        wallet: EthereumWallet,
        rpc_url: &str,
        eip1559: bool,
        network: Network,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let chain = EvmChain::try_from(network)?;
        let signer_addresses: Vec<Address> =
            NetworkWallet::<AlloyEthereum>::signer_addresses(&wallet).collect();
        if signer_addresses.is_empty() {
            return Err("wallet must contain at least one signer".into());
        }
        let signer_addresses = Arc::new(signer_addresses);
        let signer_cursor = Arc::new(AtomicUsize::new(0));

        // Configure RPC client with custom HTTP timeouts to prevent indefinite hangs
        let config = crate::config::FacilitatorConfig::from_env().ok();
        let network_str = network.to_string();
        let rpc_timeout = config
            .as_ref()
            .and_then(|c| c.transaction.chains.get(&network_str))
            .map(|chain_config| chain_config.rpc_timeout())
            .or_else(|| {
                config
                    .as_ref()
                    .map(|c| Duration::from_secs(c.transaction.default_rpc_timeout_seconds))
            })
            .unwrap_or(Duration::from_secs(30));

        tracing::debug!(
            network=%network,
            rpc_timeout_secs=rpc_timeout.as_secs(),
            "Configuring RPC client with timeout"
        );

        // Parse RPC URL for HTTP client configuration
        let url = rpc_url
            .parse::<url::Url>()
            .map_err(|e| {
                let error_str = format!("{:?}", e);
                if error_str.contains("failed to lookup address") {
                    tracing::error!("DNS lookup failed for {rpc_url}: {e:?}");
                    FacilitatorLocalError::RpcProviderError(
                        format!("DNS resolution failed for {rpc_url}")
                    )
                } else {
                    tracing::error!("Invalid RPC URL {rpc_url}: {e:?}");
                    FacilitatorLocalError::RpcProviderError(
                        format!("Invalid RPC URL: {rpc_url}")
                    )
                }
            })?;

        // Get connection pool configuration from config or use defaults
        let connection_timeout_secs = config
            .as_ref()
            .map(|c| c.transaction.connection_timeout_seconds)
            .unwrap_or(10);
        let pool_max_idle = config
            .as_ref()
            .map(|c| c.transaction.pool_max_idle_per_host)
            .unwrap_or(100);
        let pool_idle_timeout_secs = config
            .as_ref()
            .map(|c| c.transaction.pool_idle_timeout_seconds)
            .unwrap_or(90);

        tracing::debug!(
            connection_timeout_secs,
            pool_max_idle,
            pool_idle_timeout_secs,
            "Configuring HTTP connection pool"
        );

        // Build custom HTTP client with configured timeouts
        let http_client = alloy::transports::http::reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(connection_timeout_secs))
            .timeout(rpc_timeout)
            .pool_idle_timeout(Duration::from_secs(pool_idle_timeout_secs))
            .pool_max_idle_per_host(pool_max_idle)
            .build()
            .map_err(|e| {
                let error_str = format!("{:?}", e);
                if error_str.contains("Too many open files") || error_str.contains("EMFILE") {
                    tracing::error!(
                        "File descriptor limit reached (pool_max_idle_per_host={}): {e:?}",
                        pool_max_idle
                    );
                    FacilitatorLocalError::ResourceExhaustion(
                        "File descriptor limit reached".to_string()
                    )
                } else {
                    tracing::error!("HTTP client build failed: {e:?}");
                    FacilitatorLocalError::RpcProviderError(
                        format!("HTTP client initialization failed: {e}")
                    )
                }
            })?;

        // Create RPC client with custom HTTP client
        let client = RpcClient::builder()
            .http_with_client(http_client, url);

        // Create nonce manager explicitly so we can store a reference for error handling
        let nonce_manager = PendingNonceManager::default();

        // Build the filler stack: Gas -> BlobGas -> Nonce -> ChainId
        // This mirrors the InnerFiller type but with our custom nonce manager
        let filler = JoinFill::new(
            GasFiller,
            JoinFill::new(
                BlobGasFiller,
                JoinFill::new(NonceFiller::new(nonce_manager.clone()), ChainIdFiller::default()),
            ),
        );

        let inner = ProviderBuilder::default()
            .filler(filler)
            .wallet(wallet)
            .connect_client(client);

        tracing::info!(network=%network, rpc=rpc_url, signers=?signer_addresses, "Initialized provider");

        Ok(Self {
            inner,
            eip1559,
            chain,
            signer_addresses,
            signer_cursor,
            settlement_locks: Arc::new(DashMap::new()),
            nonce_manager,
            eip712_version_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Round-robin selection of next signer from wallet.
    pub fn next_signer_address(&self) -> Address {
        debug_assert!(!self.signer_addresses.is_empty());
        if self.signer_addresses.len() == 1 {
            self.signer_addresses[0]
        } else {
            let next =
                self.signer_cursor.fetch_add(1, Ordering::Relaxed) % self.signer_addresses.len();
            self.signer_addresses[next]
        }
    }

    /// Get the settlement lock Arc for a specific facilitator address.
    /// Caller must lock it to ensure sequential processing.
    pub fn get_settlement_lock(&self, address: Address) -> Arc<Mutex<()>> {
        let entry = self
            .settlement_locks
            .entry(address)
            .or_insert_with(|| Arc::new(Mutex::new(())));
        Arc::clone(entry.value())
    }

    /// Settle with proper locking to prevent nonce race conditions.
    ///
    /// This method wraps the trait's settle() implementation with per-address
    /// settlement serialization to ensure FIFO nonce ordering. The lock is
    /// acquired BEFORE validation to ensure proper ordering based on arrival
    /// time, not validation completion time.
    ///
    /// Note: This does NOT prevent duplicate ERC-3009 signatures - that is the
    /// smart contract's responsibility. The facilitator only ensures correct
    /// blockchain-level nonce ordering.
    pub async fn settle_with_lock(&self, request: &SettleRequest) -> Result<SettleResponse, FacilitatorLocalError> {
        // Step 1: Select facilitator address early to acquire settlement lock BEFORE validation
        // This ensures FIFO ordering - earlier requests lock first regardless of validation timing
        let facilitator_address = self.next_signer_address();
        tracing::info!(
            %facilitator_address,
            "processing settlement request"
        );

        // Step 2: Acquire settlement lock to serialize transactions from this facilitator address
        // This prevents nonce race conditions by ensuring sequential processing per address
        let settlement_lock = self.get_settlement_lock(facilitator_address);
        tracing::debug!(%facilitator_address, "acquiring settlement lock");
        let _settlement_guard = settlement_lock.lock().await;
        tracing::debug!(%facilitator_address, "settlement lock acquired");

        // Step 3: Call the trait's settle method with pre-selected facilitator address
        // Use task-local storage to pass the address to send_transaction()
        PRESELECTED_FACILITATOR.scope(facilitator_address, Facilitator::settle(self, request)).await
    }
}

/// Trait for sending meta-transactions with custom target and calldata.
pub trait MetaEvmProvider {
    /// Error type for operations.
    type Error;
    /// Underlying provider type.
    type Inner: Provider;

    /// Returns reference to underlying provider.
    fn inner(&self) -> &Self::Inner;
    /// Returns reference to chain descriptor.
    fn chain(&self) -> &EvmChain;
    /// Returns reference to EIP-712 version cache.
    fn eip712_cache(&self) -> &Arc<tokio::sync::RwLock<std::collections::HashMap<Address, (String, std::time::Instant)>>>;

    /// Sends a meta-transaction to the network.
    fn send_transaction(
        &self,
        tx: MetaTransaction,
    ) -> impl Future<Output = Result<TransactionReceipt, Self::Error>> + Send;
}

/// Meta-transaction parameters: target address, calldata, and required confirmations.
pub struct MetaTransaction {
    /// Target contract address.
    pub to: Address,
    /// Transaction calldata (encoded function call).
    pub calldata: Bytes,
    /// Number of block confirmations to wait for.
    pub confirmations: u64,
    /// Optional sender address. If None, uses round-robin selection via next_signer_address().
    /// Should be set when the address has been pre-selected for locking purposes.
    pub from: Option<Address>,
}

impl MetaEvmProvider for EvmProvider {
    type Error = FacilitatorLocalError;
    type Inner = InnerProvider;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    fn chain(&self) -> &EvmChain {
        &self.chain
    }

    fn eip712_cache(&self) -> &Arc<tokio::sync::RwLock<std::collections::HashMap<Address, (String, std::time::Instant)>>> {
        &self.eip712_version_cache
    }

    /// Send a meta-transaction with provided `to`, `calldata`, and automatically selected signer.
    ///
    /// This method constructs a transaction from the provided [`MetaTransaction`], automatically
    /// selects the next available signer using round-robin selection, and handles gas pricing
    /// based on whether the network supports EIP-1559.
    ///
    /// If the transaction fails at any point (during submission or receipt fetching), the nonce
    /// for the sending address is reset to force a fresh query on the next transaction. This
    /// ensures correctness even when transactions partially succeed (e.g., submitted but receipt
    /// fetch times out).
    ///
    /// # Gas Pricing Strategy
    ///
    /// - **EIP-1559 networks**: Uses automatic gas pricing via the provider's fillers.
    /// - **Legacy networks**: Fetches the current gas price using `get_gas_price()` and sets it explicitly.
    ///
    /// # Timeout Configuration
    ///
    /// Receipt fetching is subject to a configurable timeout:
    /// - Default: 30 seconds
    /// - Override via `TX_RECEIPT_TIMEOUT_SECS` environment variable
    /// - If the timeout expires, the nonce is reset and an error is returned
    ///
    /// # Parameters
    ///
    /// - `tx`: A [`MetaTransaction`] containing the target address and calldata.
    ///
    /// # Returns
    ///
    /// A [`TransactionReceipt`] once the transaction has been mined and confirmed.
    ///
    /// # Errors
    ///
    /// Returns [`FacilitatorLocalError::ContractCall`] if:
    /// - Gas price fetching fails (on legacy networks)
    /// - Transaction sending fails
    /// - Receipt retrieval fails or times out
    async fn send_transaction(
        &self,
        tx: MetaTransaction,
    ) -> Result<TransactionReceipt, Self::Error> {
        // Use pre-selected address if provided, otherwise check task-local, otherwise use round-robin
        let from_address = tx.from.or_else(|| {
            PRESELECTED_FACILITATOR.try_with(|addr| *addr).ok()
        }).unwrap_or_else(|| self.next_signer_address());

        let mut txr = TransactionRequest::default()
            .with_to(tx.to)
            .with_from(from_address)
            .with_input(tx.calldata);
        if !self.eip1559 {
            let provider = &self.inner;
            let gas: u128 = provider
                .get_gas_price()
                .instrument(tracing::info_span!("get_gas_price"))
                .await
                .map_err(|e| FacilitatorLocalError::ContractCall(format!("{e:?}")))?;
            txr.set_gas_price(gas);
        }

        // Read receipt timeout from chain-specific config, fall back to env var, or use default of 120 seconds
        let config = crate::config::FacilitatorConfig::from_env().ok();
        let network_str = self.chain.network.to_string();
        let receipt_timeout = config
            .as_ref()
            .and_then(|c| c.transaction.chains.get(&network_str))
            .map(|chain_config| chain_config.receipt_timeout())
            .or_else(|| {
                // Fallback to env var for backwards compatibility with upstream examples
                std::env::var("TX_RECEIPT_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .map(Duration::from_secs)
            })
            .unwrap_or(Duration::from_secs(120));

        tracing::debug!(
            network=%self.chain.network,
            receipt_timeout_secs=receipt_timeout.as_secs(),
            "Using receipt timeout for transaction"
        );

        // Send transaction with error handling for nonce reset
        let pending_tx = match self.inner.send_transaction(txr).await {
            Ok(pending) => pending,
            Err(e) => {
                let error_str = format!("{e:?}");
                // Detect nonce collision errors
                if error_str.contains("nonce too low") || error_str.contains("nonce too high") {
                    tracing::error!(
                        from = %from_address,
                        error = %error_str,
                        "❌ NONCE COLLISION DETECTED - transaction rejected due to nonce mismatch"
                    );
                } else if error_str.contains("replacement transaction underpriced") {
                    tracing::warn!(
                        from = %from_address,
                        error = %error_str,
                        "transaction replacement attempted with insufficient gas price"
                    );
                }
                // Transaction submission failed - reset nonce to force requery
                self.nonce_manager.reset_nonce(from_address).await;
                return Err(FacilitatorLocalError::ContractCall(error_str));
            }
        };

        // Get receipt with timeout - use with_timeout for better error handling
        let watcher = pending_tx
            .with_required_confirmations(tx.confirmations)
            .with_timeout(Some(receipt_timeout));

        match watcher.get_receipt().await {
            Ok(receipt) => Ok(receipt),
            Err(e) => {
                // Receipt fetch failed (timeout or other error) - reset nonce to force requery
                self.nonce_manager.reset_nonce(from_address).await;
                Err(FacilitatorLocalError::ContractCall(format!("{e:?}")))
            }
        }
    }
}

impl NetworkProviderOps for EvmProvider {
    /// Address of the default signer used by this provider (for tx sending).
    fn signer_address(&self) -> MixedAddress {
        self.inner.default_signer_address().into()
    }

    /// x402 network handled by this provider.
    fn network(&self) -> Network {
        self.chain.network
    }
}

impl FromEnvByNetworkBuild for EvmProvider {
    async fn from_env(network: Network) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let env_var = from_env::rpc_env_name_from_network(network);
        let rpc_url = match std::env::var(env_var).ok() {
            Some(rpc_url) => rpc_url,
            None => {
                tracing::warn!(network=%network, "no RPC URL configured, skipping");
                return Ok(None);
            }
        };
        let wallet = from_env::SignerType::from_env()?.make_evm_wallet()?;
        let is_eip1559 = match network {
            Network::BaseSepolia => true,
            Network::Base => true,
            Network::XdcMainnet => false,
            Network::AvalancheFuji => true,
            Network::Avalanche => true,
            Network::Solana => false,
            Network::SolanaDevnet => false,
            Network::PolygonAmoy => true,
            Network::Polygon => true,
            Network::Sei => true,
            Network::SeiTestnet => true,
            Network::BscTestnet => false,
            Network::Bsc => false,
        };
        let provider = EvmProvider::try_new(wallet, &rpc_url, is_eip1559, network).await?;
        Ok(Some(provider))
    }
}

impl<P> Facilitator for P
where
    P: MetaEvmProvider + Sync,
    FacilitatorLocalError: From<P::Error>,
{
    type Error = FacilitatorLocalError;

    /// Verify x402 payment intent by simulating signature validity and ERC-3009 transfer.
    ///
    /// For EIP-6492 signatures, perform a multicall: first the validator’s
    /// `isValidSigWithSideEffects` (which *may* deploy the counterfactual wallet in sim),
    /// then the token’s `transferWithAuthorization`. Both run within a single `eth_call`
    /// so the state is shared during simulation.
    ///
    /// # Errors
    /// - [`FacilitatorLocalError::NetworkMismatch`], [`FacilitatorLocalError::SchemeMismatch`], [`FacilitatorLocalError::ReceiverMismatch`] if inputs are inconsistent.
    /// - [`FacilitatorLocalError::InvalidTiming`] if outside `validAfter/validBefore`.
    /// - [`FacilitatorLocalError::InsufficientFunds`] / `FacilitatorLocalError::InsufficientValue` on balance/value checks.
    /// - [`FacilitatorLocalError::ContractCall`] if on-chain calls revert.
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;

        // Perform payment validation WITHOUT balance check (we'll batch it with signature validation)
        let (contract, payment, eip712_domain) =
            assert_valid_payment(self.inner(), self.chain(), payload, requirements, Some(self.eip712_cache()), true).await?;

        let signed_message = SignedMessage::extract(&payment, &eip712_domain)?;
        let payer = signed_message.address;
        let hash = signed_message.hash;
        let max_amount_required = requirements.max_amount_required.0;

        match signed_message.signature {
            StructuredSignature::EIP6492 {
                factory: _,
                factory_calldata: _,
                inner,
                original,
            } => {
                // Prepare the call to validate EIP-6492 signature
                let validator6492 = Validator6492::new(VALIDATOR_ADDRESS, self.inner());
                let is_valid_signature_call =
                    validator6492.isValidSigWithSideEffects(payer, hash, original);
                // Prepare the call to simulate transfer the funds
                let transfer_call = transferWithAuthorization_0(&contract, &payment, inner).await?;
                // Execute ALL three calls in a single Multicall3 transaction: balance + signature + transfer
                match (&contract, transfer_call.tx) {
                    (Erc3009Contract::Usdc(usdc_contract), TransferWithAuthorizationCallBuilder::Usdc(tx)) => {
                        let balance_call = usdc_contract.balanceOf(payment.from.0);
                        let (balance_result, is_valid_signature_result, transfer_result) = call_with_fallback(
                            self
                                .inner()
                                .multicall()
                                .add(balance_call.clone())
                                .add(is_valid_signature_call.clone())
                                .add(tx.clone())
                                .aggregate3()
                                .instrument(tracing::info_span!("batched_verify_usdc",
                                        from = %transfer_call.from,
                                        to = %transfer_call.to,
                                        value = %transfer_call.value,
                                        valid_after = %transfer_call.valid_after,
                                        valid_before = %transfer_call.valid_before,
                                        nonce = %transfer_call.nonce,
                                        signature = %transfer_call.signature,
                                        token_contract = %transfer_call.contract_address,
                                        otel.kind = "client",
                                )),
                            self
                                .inner()
                                .multicall()
                                .add(balance_call)
                                .add(is_valid_signature_call)
                                .add(tx)
                                .block(BlockId::Number(BlockNumberOrTag::Latest))
                                .aggregate3()
                                .instrument(tracing::info_span!("batched_verify_usdc",
                                        from = %transfer_call.from,
                                        to = %transfer_call.to,
                                        value = %transfer_call.value,
                                        valid_after = %transfer_call.valid_after,
                                        valid_before = %transfer_call.valid_before,
                                        nonce = %transfer_call.nonce,
                                        signature = %transfer_call.signature,
                                        token_contract = %transfer_call.contract_address,
                                        otel.kind = "client",
                                )),
                        )
                        .await
                        .map_err(|e| categorize_transport_error(e, "batched verification multicall"))?;
                        // Check balance result
                        let balance = balance_result.map_err(|e| categorize_transport_error(e, "balance query"))?;
                        if balance < max_amount_required {
                            return Err(FacilitatorLocalError::InsufficientFunds(payer.into()));
                        }
                        // Check signature validation result
                        let is_valid_signature_result = is_valid_signature_result
                            .map_err(|e| categorize_transport_error(e, "signature validation result"))?;
                        if !is_valid_signature_result {
                            return Err(FacilitatorLocalError::InvalidSignature(
                                payer.into(),
                                "Incorrect signature".to_string(),
                            ));
                        }
                        // Check transfer simulation result
                        transfer_result.map_err(|e| categorize_transport_error(e, "transfer simulation"))?;
                    }
                    (Erc3009Contract::Xbnb(xbnb_contract), TransferWithAuthorizationCallBuilder::Xbnb(tx)) => {
                        let balance_call = xbnb_contract.balanceOf(payment.from.0);
                        let (balance_result, is_valid_signature_result, transfer_result) = call_with_fallback(
                            self
                                .inner()
                                .multicall()
                                .add(balance_call.clone())
                                .add(is_valid_signature_call.clone())
                                .add(tx.clone())
                                .aggregate3()
                                .instrument(tracing::info_span!("batched_verify_xbnb",
                                        from = %transfer_call.from,
                                        to = %transfer_call.to,
                                        value = %transfer_call.value,
                                        valid_after = %transfer_call.valid_after,
                                        valid_before = %transfer_call.valid_before,
                                        nonce = %transfer_call.nonce,
                                        signature = %transfer_call.signature,
                                        token_contract = %transfer_call.contract_address,
                                        otel.kind = "client",
                                )),
                            self
                                .inner()
                                .multicall()
                                .add(balance_call)
                                .add(is_valid_signature_call)
                                .add(tx)
                                .block(BlockId::Number(BlockNumberOrTag::Latest))
                                .aggregate3()
                                .instrument(tracing::info_span!("batched_verify_xbnb",
                                        from = %transfer_call.from,
                                        to = %transfer_call.to,
                                        value = %transfer_call.value,
                                        valid_after = %transfer_call.valid_after,
                                        valid_before = %transfer_call.valid_before,
                                        nonce = %transfer_call.nonce,
                                        signature = %transfer_call.signature,
                                        token_contract = %transfer_call.contract_address,
                                        otel.kind = "client",
                                )),
                        )
                        .await
                        .map_err(|e| categorize_transport_error(e, "batched verification multicall"))?;
                        // Check balance result
                        let balance = balance_result.map_err(|e| categorize_transport_error(e, "balance query"))?;
                        if balance < max_amount_required {
                            return Err(FacilitatorLocalError::InsufficientFunds(payer.into()));
                        }
                        // Check signature validation result
                        let is_valid_signature_result = is_valid_signature_result
                            .map_err(|e| categorize_transport_error(e, "signature validation result"))?;
                        if !is_valid_signature_result {
                            return Err(FacilitatorLocalError::InvalidSignature(
                                payer.into(),
                                "Incorrect signature".to_string(),
                            ));
                        }
                        // Check transfer simulation result
                        transfer_result.map_err(|e| categorize_transport_error(e, "transfer simulation"))?;
                    }
                    _ => {
                        return Err(FacilitatorLocalError::ContractCall(
                            "Mismatched token contract and transfer call builder".to_string()
                        ));
                    }
                }
                // Drop contract to release provider clone after multicall completes
                drop(contract);
            }
            StructuredSignature::EIP1271(signature) => {
                // It is EOA or EIP-1271 signature, which we can pass to the transfer simulation
                let transfer_call =
                    transferWithAuthorization_0(&contract, &payment, signature).await?;
                // Batch balance check + transfer simulation in a single Multicall3
                match (&contract, transfer_call.tx) {
                    (Erc3009Contract::Usdc(usdc_contract), TransferWithAuthorizationCallBuilder::Usdc(tx)) => {
                        let balance_call = usdc_contract.balanceOf(payment.from.0);
                        let (balance_result, transfer_result) = call_with_fallback(
                            self
                                .inner()
                                .multicall()
                                .add(balance_call.clone())
                                .add(tx.clone())
                                .aggregate3()
                                .instrument(tracing::info_span!("batched_verify_eip1271_usdc",
                                        from = %transfer_call.from,
                                        to = %transfer_call.to,
                                        value = %transfer_call.value,
                                        valid_after = %transfer_call.valid_after,
                                        valid_before = %transfer_call.valid_before,
                                        nonce = %transfer_call.nonce,
                                        signature = %transfer_call.signature,
                                        token_contract = %transfer_call.contract_address,
                                        otel.kind = "client",
                                )),
                            self
                                .inner()
                                .multicall()
                                .add(balance_call)
                                .add(tx)
                                .block(BlockId::Number(BlockNumberOrTag::Latest))
                                .aggregate3()
                                .instrument(tracing::info_span!("batched_verify_eip1271_usdc",
                                        from = %transfer_call.from,
                                        to = %transfer_call.to,
                                        value = %transfer_call.value,
                                        valid_after = %transfer_call.valid_after,
                                        valid_before = %transfer_call.valid_before,
                                        nonce = %transfer_call.nonce,
                                        signature = %transfer_call.signature,
                                        token_contract = %transfer_call.contract_address,
                                        otel.kind = "client",
                                )),
                        )
                        .await
                        .map_err(|e| categorize_transport_error(e, "batched verification multicall"))?;
                        // Check balance result
                        let balance = balance_result.map_err(|e| categorize_transport_error(e, "balance query"))?;
                        if balance < max_amount_required {
                            return Err(FacilitatorLocalError::InsufficientFunds(payer.into()));
                        }
                        // Check transfer simulation result
                        transfer_result.map_err(|e| categorize_transport_error(e, "transfer simulation"))?;
                    }
                    (Erc3009Contract::Xbnb(xbnb_contract), TransferWithAuthorizationCallBuilder::Xbnb(tx)) => {
                        let balance_call = xbnb_contract.balanceOf(payment.from.0);
                        let (balance_result, transfer_result) = call_with_fallback(
                            self
                                .inner()
                                .multicall()
                                .add(balance_call.clone())
                                .add(tx.clone())
                                .aggregate3()
                                .instrument(tracing::info_span!("batched_verify_eip1271_xbnb",
                                        from = %transfer_call.from,
                                        to = %transfer_call.to,
                                        value = %transfer_call.value,
                                        valid_after = %transfer_call.valid_after,
                                        valid_before = %transfer_call.valid_before,
                                        nonce = %transfer_call.nonce,
                                        signature = %transfer_call.signature,
                                        token_contract = %transfer_call.contract_address,
                                        otel.kind = "client",
                                )),
                            self
                                .inner()
                                .multicall()
                                .add(balance_call)
                                .add(tx)
                                .block(BlockId::Number(BlockNumberOrTag::Latest))
                                .aggregate3()
                                .instrument(tracing::info_span!("batched_verify_eip1271_xbnb",
                                        from = %transfer_call.from,
                                        to = %transfer_call.to,
                                        value = %transfer_call.value,
                                        valid_after = %transfer_call.valid_after,
                                        valid_before = %transfer_call.valid_before,
                                        nonce = %transfer_call.nonce,
                                        signature = %transfer_call.signature,
                                        token_contract = %transfer_call.contract_address,
                                        otel.kind = "client",
                                )),
                        )
                        .await
                        .map_err(|e| categorize_transport_error(e, "batched verification multicall"))?;
                        // Check balance result
                        let balance = balance_result.map_err(|e| categorize_transport_error(e, "balance query"))?;
                        if balance < max_amount_required {
                            return Err(FacilitatorLocalError::InsufficientFunds(payer.into()));
                        }
                        // Check transfer simulation result
                        transfer_result.map_err(|e| categorize_transport_error(e, "transfer simulation"))?;
                    }
                    _ => {
                        return Err(FacilitatorLocalError::ContractCall(
                            "Mismatched token contract and transfer call builder".to_string()
                        ));
                    }
                }
                // Drop contract to release provider clone after call completes
                drop(contract);
            }
        }

        Ok(VerifyResponse::valid(payer.into()))
    }

    /// Settle a verified payment on-chain.
    ///
    /// If the signer is counterfactual (EIP-6492) and the wallet is not yet deployed,
    /// this submits **one** transaction to Multicall3 (`aggregate3`) that:
    /// 1) calls the 6492 factory with the provided calldata (best-effort prepare),
    /// 2) calls `transferWithAuthorization` with the **inner** signature.
    ///
    /// This makes deploy + transfer atomic and avoids read-your-write issues.
    ///
    /// If the wallet is already deployed (or the signature is plain EIP-1271/EOA),
    /// we submit a single `transferWithAuthorization` transaction.
    ///
    /// # Returns
    /// A [`SettleResponse`] containing success flag and transaction hash.
    ///
    /// # Errors
    /// Propagates [`FacilitatorLocalError::ContractCall`] on deployment or transfer failures
    /// and all prior validation errors.
    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;
        let (contract, payment, eip712_domain) =
            assert_valid_payment(self.inner(), self.chain(), payload, requirements, Some(self.eip712_cache()), false).await?;

        let signed_message = SignedMessage::extract(&payment, &eip712_domain)?;
        let payer = signed_message.address;
        let transaction_receipt_fut = match signed_message.signature {
            StructuredSignature::EIP6492 {
                factory,
                factory_calldata,
                inner,
                original: _,
            } => {
                let is_contract_deployed = is_contract_deployed(self.inner(), &payer).await?;
                let transfer_call = transferWithAuthorization_0(&contract, &payment, inner).await?;

                // Extract all necessary data before dropping contract
                let tx_target = transfer_call.tx.target();
                let tx_calldata = transfer_call.tx.calldata().clone();
                let span_from = transfer_call.from;
                let span_to = transfer_call.to;
                let span_value = transfer_call.value;
                let span_valid_after = transfer_call.valid_after;
                let span_valid_before = transfer_call.valid_before;
                let span_nonce = transfer_call.nonce;
                let span_signature = transfer_call.signature.clone();
                let span_contract_address = transfer_call.contract_address;

                // Drop transfer_call and contract to release provider clone
                drop(transfer_call);
                drop(contract);

                if is_contract_deployed {
                    // transferWithAuthorization with inner signature
                    self.send_transaction(MetaTransaction {
                        to: tx_target,
                        calldata: tx_calldata,
                        confirmations: 1,
                        from: None,
                    })
                    .instrument(
                        tracing::info_span!("call_transferWithAuthorization_0",
                            from = %span_from,
                            to = %span_to,
                            value = %span_value,
                            valid_after = %span_valid_after,
                            valid_before = %span_valid_before,
                            nonce = %span_nonce,
                            signature = %span_signature,
                            token_contract = %span_contract_address,
                            sig_kind="EIP6492.deployed",
                            otel.kind = "client",
                        ),
                    )
                } else {
                    // deploy the smart wallet, and transferWithAuthorization with inner signature
                    let deployment_call = IMulticall3::Call3 {
                        allowFailure: true,
                        target: factory,
                        callData: factory_calldata,
                    };
                    let transfer_with_authorization_call = IMulticall3::Call3 {
                        allowFailure: false,
                        target: tx_target,
                        callData: tx_calldata,
                    };
                    let aggregate_call = IMulticall3::aggregate3Call {
                        calls: vec![deployment_call, transfer_with_authorization_call],
                    };
                    self.send_transaction(MetaTransaction {
                        to: MULTICALL3_ADDRESS,
                        calldata: aggregate_call.abi_encode().into(),
                        confirmations: 1,
                        from: None,
                    })
                    .instrument(
                        tracing::info_span!("call_transferWithAuthorization_0",
                            from = %span_from,
                            to = %span_to,
                            value = %span_value,
                            valid_after = %span_valid_after,
                            valid_before = %span_valid_before,
                            nonce = %span_nonce,
                            signature = %span_signature,
                            token_contract = %span_contract_address,
                            sig_kind="EIP6492.counterfactual",
                            otel.kind = "client",
                        ),
                    )
                }
            }
            StructuredSignature::EIP1271(eip1271_signature) => {
                let transfer_call =
                    transferWithAuthorization_0(&contract, &payment, eip1271_signature).await?;

                // Extract all necessary data before dropping contract
                let tx_target = transfer_call.tx.target();
                let tx_calldata = transfer_call.tx.calldata().clone();
                let span_from = transfer_call.from;
                let span_to = transfer_call.to;
                let span_value = transfer_call.value;
                let span_valid_after = transfer_call.valid_after;
                let span_valid_before = transfer_call.valid_before;
                let span_nonce = transfer_call.nonce;
                let span_signature = transfer_call.signature.clone();
                let span_contract_address = transfer_call.contract_address;

                // Drop transfer_call and contract to release provider clone
                drop(transfer_call);
                drop(contract);

                // transferWithAuthorization with eip1271 signature
                self.send_transaction(MetaTransaction {
                    to: tx_target,
                    calldata: tx_calldata,
                    confirmations: 1,
                    from: None,
                })
                .instrument(
                    tracing::info_span!("call_transferWithAuthorization_0",
                        from = %span_from,
                        to = %span_to,
                        value = %span_value,
                        valid_after = %span_valid_after,
                        valid_before = %span_valid_before,
                        nonce = %span_nonce,
                        signature = %span_signature,
                        token_contract = %span_contract_address,
                        sig_kind="EIP1271",
                        otel.kind = "client",
                    ),
                )
            }
        };

        let receipt = transaction_receipt_fut.await?;

        let success = receipt.status();
        if success {
            tracing::event!(Level::INFO,
                status = "ok",
                tx = %receipt.transaction_hash,
                "transferWithAuthorization_0 succeeded"
            );

            Ok(SettleResponse {
                success: true,
                error_reason: None,
                payer: payment.from.into(),
                transaction: Some(TransactionHash::Evm(receipt.transaction_hash.0)),
                network: payload.network,
            })
        } else {
            tracing::event!(
                Level::WARN,
                status = "failed",
                tx = %receipt.transaction_hash,
                "transferWithAuthorization_0 failed"
            );

            Ok(SettleResponse {
                success: false,
                error_reason: Some(FacilitatorErrorReason::InvalidScheme),
                payer: payment.from.into(),
                transaction: Some(TransactionHash::Evm(receipt.transaction_hash.0)),
                network: payload.network,
            })
        }
    }

    /// Report payment kinds supported by this provider on its current network.
    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        let kinds = vec![SupportedPaymentKind {
            network: self.chain().network().to_string(),
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            extra: None,
        }];
        Ok(SupportedPaymentKindsResponse { kinds })
    }
}

/// Validated settlement data prepared for batching via Multicall3.
///
/// Contains all the information needed to include this settlement in a Multicall3 aggregate3 call.
pub struct ValidatedSettlement {
    /// Target contract address for the transfer
    pub target: Address,
    /// Encoded calldata for transferWithAuthorization
    pub calldata: Bytes,
    /// Payer address (from field)
    pub payer: MixedAddress,
    /// Network for this settlement
    pub network: Network,
    /// Optional EIP-6492 deployment data (if wallet not yet deployed)
    pub deployment: Option<DeploymentData>,
    /// Post-settlement hooks to execute atomically (via Multicall3)
    pub hooks: Vec<HookCall>,
    /// Tracing metadata
    pub metadata: SettlementMetadata,
}

/// EIP-6492 deployment data for counterfactual wallets.
pub struct DeploymentData {
    pub factory: Address,
    pub factory_calldata: Bytes,
}

/// Metadata for settlement tracing and logging.
pub struct SettlementMetadata {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub valid_after: U256,
    pub valid_before: U256,
    pub nonce: FixedBytes<32>,
    pub signature: Bytes,
    pub contract_address: Address,
    pub sig_kind: String,
}

impl EvmProvider {
    /// Validates a settlement request and prepares it for batching.
    ///
    /// This method performs all validation checks (signature, balance, timing, etc.)
    /// and returns a `ValidatedSettlement` that can be included in a Multicall3 batch.
    ///
    /// For EIP-6492 counterfactual wallets, includes deployment data if wallet not yet deployed.
    pub async fn validate_and_prepare_settlement(
        &self,
        request: &SettleRequest,
        hook_manager: Option<&Arc<HookManager>>,
    ) -> Result<ValidatedSettlement, FacilitatorLocalError> {
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;

        // Validate payment and extract contract, payment data, and EIP-712 domain
        let (contract, payment, eip712_domain) =
            assert_valid_payment(self.inner(), self.chain(), payload, requirements, Some(self.eip712_cache()), false).await?;

        let signed_message = SignedMessage::extract(&payment, &eip712_domain)?;
        let payer = signed_message.address;

        // Build transfer call and handle EIP-6492 deployment if needed
        match signed_message.signature {
            StructuredSignature::EIP6492 {
                factory,
                factory_calldata,
                inner,
                original: _,
            } => {
                let is_contract_deployed = is_contract_deployed(self.inner(), &payer).await?;
                let transfer_call = transferWithAuthorization_0(&contract, &payment, inner).await?;

                // Extract all necessary data before dropping contract
                let target = transfer_call.tx.target();
                let calldata = transfer_call.tx.calldata().clone();
                let from = transfer_call.from;
                let to = transfer_call.to;
                let value = transfer_call.value;
                let valid_after = transfer_call.valid_after;
                let valid_before = transfer_call.valid_before;
                let nonce = transfer_call.nonce;
                let signature = transfer_call.signature.clone();
                let contract_address = transfer_call.contract_address;
                let deployment = if !is_contract_deployed {
                    Some(DeploymentData {
                        factory,
                        factory_calldata,
                    })
                } else {
                    None
                };

                // Build metadata before hook lookup
                let metadata = SettlementMetadata {
                    from,
                    to,
                    value,
                    valid_after,
                    valid_before,
                    nonce,
                    signature,
                    contract_address,
                    sig_kind: if is_contract_deployed {
                        "EIP6492.deployed".to_string()
                    } else {
                        "EIP6492.counterfactual".to_string()
                    },
                };

                // Lookup hooks for destination address with parameterized resolution
                let hooks = if let Some(hook_mgr) = hook_manager {
                    // Create runtime context for parameter resolution
                    // Use first signer address as placeholder (actual sender determined at settlement time)
                    let sender = self.signer_addresses.first().copied().unwrap_or(Address::ZERO);
                    let network = &self.chain().network().to_string();

                    match RuntimeContext::from_provider(self.inner(), sender).await {
                        Ok(runtime) => {
                            match hook_mgr.get_hooks_for_destination_with_context(to, contract_address, network, &metadata, &runtime).await {
                                Ok(hooks) => hooks,
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        network = network,
                                        destination = %to,
                                        token = %contract_address,
                                        "Hook parameter resolution failed, skipping hooks"
                                    );
                                    Vec::new()
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                network = network,
                                "Failed to fetch runtime context for hooks, skipping hooks"
                            );
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                };

                // Drop transfer_call and contract to release provider clone
                drop(transfer_call);
                drop(contract);

                Ok(ValidatedSettlement {
                    target,
                    calldata,
                    payer: payment.from.into(),
                    network: self.chain().network(),
                    deployment,
                    hooks,
                    metadata,
                })
            }
            StructuredSignature::EIP1271(eip1271_signature) => {
                let transfer_call =
                    transferWithAuthorization_0(&contract, &payment, eip1271_signature).await?;

                // Extract all necessary data before dropping contract
                let target = transfer_call.tx.target();
                let calldata = transfer_call.tx.calldata().clone();
                let from = transfer_call.from;
                let to = transfer_call.to;
                let value = transfer_call.value;
                let valid_after = transfer_call.valid_after;
                let valid_before = transfer_call.valid_before;
                let nonce = transfer_call.nonce;
                let signature = transfer_call.signature.clone();
                let contract_address = transfer_call.contract_address;

                // Build metadata before hook lookup
                let metadata = SettlementMetadata {
                    from,
                    to,
                    value,
                    valid_after,
                    valid_before,
                    nonce,
                    signature,
                    contract_address,
                    sig_kind: "EIP1271".to_string(),
                };

                // Lookup hooks for destination address with parameterized resolution
                let hooks = if let Some(hook_mgr) = hook_manager {
                    // Create runtime context for parameter resolution
                    // Use first signer address as placeholder (actual sender determined at settlement time)
                    let sender = self.signer_addresses.first().copied().unwrap_or(Address::ZERO);
                    let network = &self.chain().network().to_string();

                    match RuntimeContext::from_provider(self.inner(), sender).await {
                        Ok(runtime) => {
                            match hook_mgr.get_hooks_for_destination_with_context(to, contract_address, network, &metadata, &runtime).await {
                                Ok(hooks) => hooks,
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        network = network,
                                        destination = %to,
                                        token = %contract_address,
                                        "Hook parameter resolution failed, skipping hooks"
                                    );
                                    Vec::new()
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                network = network,
                                "Failed to fetch runtime context for hooks, skipping hooks"
                            );
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                };

                // Drop transfer_call and contract to release provider clone
                drop(transfer_call);
                drop(contract);

                Ok(ValidatedSettlement {
                    target,
                    calldata,
                    payer: payment.from.into(),
                    network: self.chain().network(),
                    deployment: None,
                    hooks,
                    metadata,
                })
            }
        }
    }

    /// Settles a batch of validated settlements via Multicall3.
    ///
    /// This method takes pre-validated settlements and combines them into a single
    /// Multicall3 aggregate3 transaction. The `allow_partial_failure` parameter controls
    /// whether individual transfer failures should revert the entire batch.
    ///
    /// Returns a vector of SettleResponse objects corresponding to each input settlement.
    pub async fn settle_batch(
        &self,
        settlements: Vec<ValidatedSettlement>,
        allow_partial_failure: bool,
    ) -> Result<Vec<SettleResponse>, FacilitatorLocalError> {
        if settlements.is_empty() {
            return Ok(Vec::new());
        }

        // Build Multicall3 Call3 structs
        let mut calls = Vec::new();
        let mut deployment_indices = Vec::new(); // Track which calls are deployments

        // Determine allow_failure based on whether hooks are present
        let has_hooks = settlements.iter().any(|s| !s.hooks.is_empty());
        let hook_allow_failure = if has_hooks {
            // If any settlement has hooks, use allow_hook_failure setting
            // This will be passed from config
            allow_partial_failure // TODO: Use allow_hook_failure from config
        } else {
            allow_partial_failure
        };

        for (_idx, settlement) in settlements.iter().enumerate() {
            // Add deployment call if needed (EIP-6492 counterfactual wallet)
            if let Some(deployment) = &settlement.deployment {
                deployment_indices.push(calls.len());
                calls.push(IMulticall3::Call3 {
                    allowFailure: true, // Deployment may already be done
                    target: deployment.factory,
                    callData: deployment.factory_calldata.clone(),
                });
            }

            // Add transfer call
            calls.push(IMulticall3::Call3 {
                allowFailure: hook_allow_failure,
                target: settlement.target,
                callData: settlement.calldata.clone(),
            });

            // Add hook calls for this settlement
            for hook in &settlement.hooks {
                calls.push(IMulticall3::Call3 {
                    allowFailure: hook.allow_failure,
                    target: hook.target,
                    callData: hook.calldata.clone(),
                });
            }
        }

        // Build and send Multicall3 aggregate3 transaction
        let aggregate_call = IMulticall3::aggregate3Call { calls };
        let receipt = self
            .send_transaction(MetaTransaction {
                to: MULTICALL3_ADDRESS,
                calldata: aggregate_call.abi_encode().into(),
                confirmations: 1,
                from: None,
            })
            .instrument(
                tracing::info_span!("batch_settle_multicall3",
                    batch_size = settlements.len(),
                    allow_partial_failure = allow_partial_failure,
                    otel.kind = "client",
                ),
            )
            .await?;

        // Parse results from Multicall3 aggregate3 return data
        let results = self.parse_aggregate3_results(&receipt, &deployment_indices, &settlements)?;

        // Build SettleResponse for each settlement
        let mut responses = Vec::with_capacity(settlements.len());
        for (settlement, result) in settlements.iter().zip(results.iter()) {
            let response = if result.success {
                SettleResponse {
                    success: true,
                    error_reason: None,
                    payer: settlement.payer.clone(),
                    transaction: Some(TransactionHash::Evm(receipt.transaction_hash.0)),
                    network: settlement.network,
                }
            } else {
                SettleResponse {
                    success: false,
                    error_reason: Some(FacilitatorErrorReason::FreeForm(
                        "Transfer failed in batch".to_string(),
                    )),
                    payer: settlement.payer.clone(),
                    transaction: Some(TransactionHash::Evm(receipt.transaction_hash.0)),
                    network: settlement.network,
                }
            };
            responses.push(response);
        }

        Ok(responses)
    }

    /// Parse aggregate3 results from transaction receipt.
    ///
    /// Filters out deployment calls (tracked by deployment_indices) and returns only
    /// the transfer call results.
    ///
    /// This method checks for ERC-20 Transfer events in the transaction logs to determine
    /// which settlements succeeded. Each successful transfer emits a Transfer(from, to, value) event.
    ///
    /// Matches Transfer events to individual settlements based on from/to/value, enabling
    /// accurate per-settlement success tracking when allow_partial_failure is true.
    fn parse_aggregate3_results(
        &self,
        receipt: &alloy::rpc::types::TransactionReceipt,
        _deployment_indices: &[usize],
        settlements: &[ValidatedSettlement],
    ) -> Result<Vec<Aggregate3Result>, FacilitatorLocalError> {
        // If the transaction failed entirely, all transfers failed
        if !receipt.status() {
            return Ok(vec![
                Aggregate3Result {
                    success: false,
                    return_data: Bytes::new(),
                };
                settlements.len()
            ]);
        }

        // Parse Transfer events from logs
        // Transfer(address indexed from, address indexed to, uint256 value)
        // Event signature: keccak256("Transfer(address,address,uint256)")
        let transfer_event_signature = alloy::primitives::b256!(
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );

        let mut transfer_events = Vec::new();
        for log in &receipt.inner.as_receipt().unwrap().logs {
            // Check if this is a Transfer event
            if log.topics().len() >= 3 && log.topics()[0] == transfer_event_signature {
                // Extract from and to addresses from indexed topics
                let from = Address::from_word(log.topics()[1]);
                let to = Address::from_word(log.topics()[2]);

                // Extract value from log data (uint256)
                let value = if log.data().data.len() >= 32 {
                    U256::from_be_slice(&log.data().data[..32])
                } else {
                    U256::ZERO
                };

                transfer_events.push((from, to, value));
            }
        }

        tracing::debug!(
            transfer_count = transfer_events.len(),
            expected_count = settlements.len(),
            "parsed Transfer events from batch settlement receipt"
        );

        // Match each settlement to a Transfer event
        let mut results = Vec::with_capacity(settlements.len());
        for settlement in settlements {
            // Look for a matching Transfer event (from, to, value)
            let found = transfer_events.iter().any(|(from, to, value)| {
                *from == settlement.metadata.from
                    && *to == settlement.metadata.to
                    && *value == settlement.metadata.value
            });

            if found {
                tracing::trace!(
                    from = %settlement.metadata.from,
                    to = %settlement.metadata.to,
                    value = %settlement.metadata.value,
                    "matched settlement to Transfer event"
                );
                results.push(Aggregate3Result {
                    success: true,
                    return_data: Bytes::new(),
                });
            } else {
                tracing::warn!(
                    from = %settlement.metadata.from,
                    to = %settlement.metadata.to,
                    value = %settlement.metadata.value,
                    "no matching Transfer event found for settlement"
                );
                results.push(Aggregate3Result {
                    success: false,
                    return_data: Bytes::new(),
                });
            }
        }

        let success_count = results.iter().filter(|r| r.success).count();
        tracing::info!(
            success_count,
            total_count = settlements.len(),
            "batch settlement results parsed"
        );

        Ok(results)
    }
}

/// Result from a single call in Multicall3.aggregate3
#[derive(Clone)]
struct Aggregate3Result {
    success: bool,
    #[allow(dead_code)]
    return_data: Bytes,
}

/// Unified enum for ERC-3009 `transferWithAuthorization` call builders.
///
/// Wraps either a USDC or XBNB call builder for the `transferWithAuthorization` function.
/// Note: USDC has multiple overloads (_0), while XBNB and ERC20TokenWith3009 have only one (no suffix).
pub enum TransferWithAuthorizationCallBuilder<P> {
    Usdc(SolCallBuilder<P, USDC::transferWithAuthorization_0Call>),
    Xbnb(SolCallBuilder<P, XBNB::transferWithAuthorizationCall>),
    ERC20TokenWith3009(SolCallBuilder<P, ERC20TokenWith3009::transferWithAuthorizationCall>),
}

impl<P> TransferWithAuthorizationCallBuilder<P>
where
    P: Provider,
{
    /// Get the target address (contract address) of the call.
    pub fn target(&self) -> Address {
        match self {
            TransferWithAuthorizationCallBuilder::Usdc(tx) => tx.target(),
            TransferWithAuthorizationCallBuilder::Xbnb(tx) => tx.target(),
            TransferWithAuthorizationCallBuilder::ERC20TokenWith3009(tx) => tx.target(),
        }
    }

    /// Get the calldata for this transaction.
    pub fn calldata(&self) -> Bytes {
        match self {
            TransferWithAuthorizationCallBuilder::Usdc(tx) => tx.calldata().clone(),
            TransferWithAuthorizationCallBuilder::Xbnb(tx) => tx.calldata().clone(),
            TransferWithAuthorizationCallBuilder::ERC20TokenWith3009(tx) => tx.calldata().clone(),
        }
    }
}

/// A prepared call to `transferWithAuthorization` (ERC-3009) including all derived fields.
///
/// This struct wraps the assembled call builder, making it reusable across verification
/// (`.call()`) and settlement (`.send()`) flows, along with context useful for tracing/logging.
///
/// This is created by [`EvmProvider::transferWithAuthorization_0`].
pub struct TransferWithAuthorization0Call<P> {
    /// The prepared call builder that can be `.call()`ed or `.send()`ed.
    pub tx: TransferWithAuthorizationCallBuilder<P>,
    /// The sender (`from`) address for the authorization.
    pub from: alloy::primitives::Address,
    /// The recipient (`to`) address for the authorization.
    pub to: alloy::primitives::Address,
    /// The amount to transfer (value).
    pub value: U256,
    /// Start of the validity window (inclusive).
    pub valid_after: U256,
    /// End of the validity window (exclusive).
    pub valid_before: U256,
    /// 32-byte authorization nonce (prevents replay).
    pub nonce: FixedBytes<32>,
    /// EIP-712 signature for the transfer authorization.
    pub signature: Bytes,
    /// Address of the token contract used for this transfer.
    pub contract_address: alloy::primitives::Address,
}

/// Checks if a contract error is caused by the RPC not supporting the "pending" block tag.
///
/// Some networks (like BSC) don't support the "pending" block tag and return an error
/// with code -32603 and message "Unsupported pending tag".
fn is_unsupported_pending_error<E: std::fmt::Debug>(error: &E) -> bool {
    let error_str = format!("{:?}", error);
    let has_error = error_str.contains("Unsupported pending") || error_str.contains("unsupported pending");
    if has_error {
        tracing::warn!("Detected unsupported pending block tag error: {}", error_str);
    }
    has_error
}

/// Helper function to call a contract method with automatic fallback to "latest" block tag
/// if the RPC doesn't support "pending".
///
/// Takes async blocks that produce the call results.
async fn call_with_fallback<T, E>(
    try_call: impl std::future::Future<Output = Result<T, E>>,
    retry_call: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, E>
where
    E: std::fmt::Debug,
{
    match try_call.await {
        Ok(result) => {
            tracing::trace!("Contract call succeeded on first attempt");
            Ok(result)
        }
        Err(e) if is_unsupported_pending_error(&e) => {
            tracing::warn!("Pending block tag not supported, retrying with latest block");
            match retry_call.await {
                Ok(result) => {
                    tracing::info!("Contract call succeeded after fallback to latest block");
                    Ok(result)
                }
                Err(retry_err) => {
                    tracing::error!("Contract call failed even after fallback: {:?}", retry_err);
                    Err(retry_err)
                }
            }
        }
        Err(e) => {
            tracing::debug!("Contract call failed with non-pending error: {:?}", e);
            Err(e)
        }
    }
}

/// Validates that the current time is within the `validAfter` and `validBefore` bounds.
///
/// Adds a 6-second grace buffer when checking expiration to account for latency.
///
/// # Errors
/// Returns [`FacilitatorLocalError::InvalidTiming`] if the authorization is not yet active or already expired.
/// Returns [`FacilitatorLocalError::ClockError`] if the system clock cannot be read.
#[instrument(skip_all)]
fn assert_time(
    payer: MixedAddress,
    valid_after: UnixTimestamp,
    valid_before: UnixTimestamp,
) -> Result<(), FacilitatorLocalError> {
    let now = UnixTimestamp::try_now().map_err(FacilitatorLocalError::ClockError)?;
    if valid_before < now + 6 {
        return Err(FacilitatorLocalError::InvalidTiming(
            payer,
            format!("Expired: now {} > valid_before {}", now + 6, valid_before),
        ));
    }
    if valid_after > now {
        return Err(FacilitatorLocalError::InvalidTiming(
            payer,
            format!("Not active yet: valid_after {valid_after} > now {now}",),
        ));
    }
    Ok(())
}

/// Checks if the payer has enough on-chain token balance to meet the `maxAmountRequired`.
///
/// Performs an `ERC20.balanceOf()` call using the token contract instance.
///
/// # Errors
/// Returns [`FacilitatorLocalError::InsufficientFunds`] if the balance is too low.
/// Returns [`FacilitatorLocalError::ContractCall`] if the balance query fails.
#[instrument(skip_all, fields(
    sender = %sender,
    max_required = %max_amount_required
))]
async fn assert_enough_balance<P: Provider>(
    token_contract: &Erc3009Contract<P>,
    sender: &EvmAddress,
    max_amount_required: U256,
) -> Result<(), FacilitatorLocalError> {
    let balance = match token_contract {
        Erc3009Contract::Usdc(usdc_contract) => {
            call_with_fallback(
                usdc_contract
                    .balanceOf(sender.0)
                    .call()
                    .into_future()
                    .instrument(tracing::info_span!(
                        "fetch_token_balance",
                        token_contract = %usdc_contract.address(),
                        sender = %sender,
                        otel.kind = "client"
                    )),
                usdc_contract
                    .balanceOf(sender.0)
                    .call()
                    .block(BlockId::Number(BlockNumberOrTag::Latest))
                    .into_future()
                    .instrument(tracing::info_span!(
                        "fetch_token_balance",
                        token_contract = %usdc_contract.address(),
                        sender = %sender,
                        otel.kind = "client"
                    )),
            )
            .await
            .map_err(|e| categorize_transport_error(e, "balance query"))?
        }
        Erc3009Contract::Xbnb(xbnb_contract) => {
            call_with_fallback(
                xbnb_contract
                    .balanceOf(sender.0)
                    .call()
                    .into_future()
                    .instrument(tracing::info_span!(
                        "fetch_token_balance",
                        token_contract = %xbnb_contract.address(),
                        sender = %sender,
                        otel.kind = "client"
                    )),
                xbnb_contract
                    .balanceOf(sender.0)
                    .call()
                    .block(BlockId::Number(BlockNumberOrTag::Latest))
                    .into_future()
                    .instrument(tracing::info_span!(
                        "fetch_token_balance",
                        token_contract = %xbnb_contract.address(),
                        sender = %sender,
                        otel.kind = "client"
                    )),
            )
            .await
            .map_err(|e| categorize_transport_error(e, "balance query"))?
        }
        Erc3009Contract::ERC20TokenWith3009(erc20_contract) => {
            call_with_fallback(
                erc20_contract
                    .balanceOf(sender.0)
                    .call()
                    .into_future()
                    .instrument(tracing::info_span!(
                        "fetch_token_balance",
                        token_contract = %erc20_contract.address(),
                        sender = %sender,
                        otel.kind = "client"
                    )),
                erc20_contract
                    .balanceOf(sender.0)
                    .call()
                    .block(BlockId::Number(BlockNumberOrTag::Latest))
                    .into_future()
                    .instrument(tracing::info_span!(
                        "fetch_token_balance",
                        token_contract = %erc20_contract.address(),
                        sender = %sender,
                        otel.kind = "client"
                    )),
            )
            .await
            .map_err(|e| categorize_transport_error(e, "balance query"))?
        }
    };

    if balance < max_amount_required {
        Err(FacilitatorLocalError::InsufficientFunds((*sender).into()))
    } else {
        Ok(())
    }
}

/// Verifies that the declared `value` in the payload is sufficient for the required amount.
///
/// This is a static check (not on-chain) that compares two numbers.
///
/// # Errors
/// Return [`FacilitatorLocalError::InsufficientValue`] if the payload's value is less than required.
#[instrument(skip_all, fields(
    sent = %sent,
    max_amount_required = %max_amount_required
))]
fn assert_enough_value(
    payer: &EvmAddress,
    sent: &U256,
    max_amount_required: &U256,
) -> Result<(), FacilitatorLocalError> {
    if sent < max_amount_required {
        Err(FacilitatorLocalError::InsufficientValue((*payer).into()))
    } else {
        Ok(())
    }
}

/// Check whether contract code is present at `address`.
///
/// Uses `eth_getCode` against this provider. This is useful after a counterfactual
/// deployment to confirm visibility on the sending RPC before submitting a
/// follow-up transaction.
///
/// # Errors
/// Return [`FacilitatorLocalError::ContractCall`] if the RPC call fails.
async fn is_contract_deployed<P: Provider>(
    provider: P,
    address: &Address,
) -> Result<bool, FacilitatorLocalError> {
    let bytes = match provider
        .get_code_at(*address)
        .into_future()
        .instrument(tracing::info_span!("get_code_at",
            address = %address,
            otel.kind = "client",
        ))
        .await
    {
        Ok(code) => code,
        Err(e) if is_unsupported_pending_error(&e) => {
            tracing::debug!(%address, "pending block tag not supported for get_code_at, retrying with latest");
            provider
                .get_code_at(*address)
                .block_id(BlockId::Number(BlockNumberOrTag::Latest))
                .into_future()
                .instrument(tracing::info_span!("get_code_at",
                    address = %address,
                    otel.kind = "client",
                ))
                .await
                .map_err(|e| categorize_transport_error(e, "get_code_at"))?
        }
        Err(e) => return Err(categorize_transport_error(e, "get_code_at")),
    };
    Ok(!bytes.is_empty())
}

/// Constructs the correct EIP-712 domain for signature verification.
///
/// Resolves the `name` and `version` based on:
/// - Static metadata from [`USDCDeployment`] (if available),
/// - Or by calling `version()` on the token contract if not matched statically.
#[instrument(skip_all, fields(
    network = %payload.network,
    asset = %asset_address
))]
async fn assert_domain<P: Provider>(
    chain: &EvmChain,
    token_contract: &Erc3009Contract<P>,
    payload: &PaymentPayload,
    asset_address: &Address,
    requirements: &PaymentRequirements,
    version_cache: Option<&Arc<tokio::sync::RwLock<std::collections::HashMap<Address, (String, std::time::Instant)>>>>,
) -> Result<Eip712Domain, FacilitatorLocalError> {
    let usdc = USDCDeployment::by_network(payload.network);
    let name = requirements
        .extra
        .as_ref()
        .and_then(|e| e.get("name")?.as_str().map(str::to_string))
        .or_else(|| usdc.eip712.clone().map(|e| e.name))
        .ok_or(FacilitatorLocalError::UnsupportedNetwork(None))?;
    let chain_id = chain.chain_id;
    let version = requirements
        .extra
        .as_ref()
        .and_then(|extra| extra.get("version"))
        .and_then(|version| version.as_str().map(|s| s.to_string()));
    let version = if let Some(extra_version) = version {
        Some(extra_version)
    } else if usdc.address() == (*asset_address).into() {
        usdc.eip712.clone().map(|e| e.version)
    } else {
        None
    };
    let version = if let Some(version) = version {
        version
    } else {
        // Check cache first if available
        if let Some(cache) = version_cache {
            if let Some(cached_version) = cache.read().await.get(asset_address).and_then(|(v, cached_at)| {
                const CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour
                if cached_at.elapsed() > CACHE_TTL {
                    None
                } else {
                    Some(v.clone())
                }
            }) {
                tracing::debug!(token = %asset_address, version = %cached_version, "using cached EIP-712 version");
                cached_version
            } else {
                // Cache miss or expired - fetch from RPC
                let fetched_version = match token_contract {
                    Erc3009Contract::Usdc(usdc_contract) => {
                        call_with_fallback(
                            usdc_contract
                                .version()
                                .call()
                                .into_future()
                                .instrument(tracing::info_span!(
                                    "fetch_eip712_version",
                                    otel.kind = "client",
                                )),
                            usdc_contract
                                .version()
                                .call()
                                .block(BlockId::Number(BlockNumberOrTag::Latest))
                                .into_future()
                                .instrument(tracing::info_span!(
                                    "fetch_eip712_version",
                                    otel.kind = "client",
                                )),
                        )
                        .await
                        .map_err(|e| categorize_transport_error(e, "fetch EIP-712 version"))?
                    }
                    Erc3009Contract::Xbnb(xbnb_contract) => {
                        let domain = call_with_fallback(
                            xbnb_contract
                                .eip712Domain()
                                .call()
                                .into_future()
                                .instrument(tracing::info_span!(
                                    "fetch_eip712_domain",
                                    otel.kind = "client",
                                )),
                            xbnb_contract
                                .eip712Domain()
                                .call()
                                .block(BlockId::Number(BlockNumberOrTag::Latest))
                                .into_future()
                                .instrument(tracing::info_span!(
                                    "fetch_eip712_domain",
                                    otel.kind = "client",
                                )),
                        )
                        .await
                        .map_err(|e| categorize_transport_error(e, "fetch EIP-712 domain"))?;
                        domain.version // version field from the eip712Domain response
                    }
                    Erc3009Contract::ERC20TokenWith3009(erc20_contract) => {
                        let domain = call_with_fallback(
                            erc20_contract
                                .eip712Domain()
                                .call()
                                .into_future()
                                .instrument(tracing::info_span!(
                                    "fetch_eip712_domain",
                                    otel.kind = "client",
                                )),
                            erc20_contract
                                .eip712Domain()
                                .call()
                                .block(BlockId::Number(BlockNumberOrTag::Latest))
                                .into_future()
                                .instrument(tracing::info_span!(
                                    "fetch_eip712_domain",
                                    otel.kind = "client",
                                )),
                        )
                        .await
                        .map_err(|e| categorize_transport_error(e, "fetch EIP-712 domain"))?;
                        domain.version // version field from the eip712Domain response
                    }
                };
                // Store in cache for future requests
                cache.write().await.insert(*asset_address, (fetched_version.clone(), std::time::Instant::now()));
                tracing::debug!(token = %asset_address, version = %fetched_version, "cached EIP-712 version");
                fetched_version
            }
        } else {
            // No cache provided - fetch directly (legacy behavior)
            match token_contract {
                Erc3009Contract::Usdc(usdc_contract) => {
                    call_with_fallback(
                        usdc_contract
                            .version()
                            .call()
                            .into_future()
                            .instrument(tracing::info_span!(
                                "fetch_eip712_version",
                                otel.kind = "client",
                            )),
                        usdc_contract
                            .version()
                            .call()
                            .block(BlockId::Number(BlockNumberOrTag::Latest))
                            .into_future()
                            .instrument(tracing::info_span!(
                                "fetch_eip712_version",
                                otel.kind = "client",
                            )),
                    )
                    .await
                    .map_err(|e| categorize_transport_error(e, "fetch EIP-712 version"))?
                }
                Erc3009Contract::Xbnb(xbnb_contract) => {
                    let domain = call_with_fallback(
                        xbnb_contract
                            .eip712Domain()
                            .call()
                            .into_future()
                            .instrument(tracing::info_span!(
                                "fetch_eip712_domain",
                                otel.kind = "client",
                            )),
                        xbnb_contract
                            .eip712Domain()
                            .call()
                            .block(BlockId::Number(BlockNumberOrTag::Latest))
                            .into_future()
                            .instrument(tracing::info_span!(
                                "fetch_eip712_domain",
                                otel.kind = "client",
                            )),
                    )
                    .await
                    .map_err(|e| categorize_transport_error(e, "fetch EIP-712 domain"))?;
                    domain.version // version field from the eip712Domain response
                }
                Erc3009Contract::ERC20TokenWith3009(erc20_contract) => {
                    let domain = call_with_fallback(
                        erc20_contract
                            .eip712Domain()
                            .call()
                            .into_future()
                            .instrument(tracing::info_span!(
                                "fetch_eip712_domain",
                                otel.kind = "client",
                            )),
                        erc20_contract
                            .eip712Domain()
                            .call()
                            .block(BlockId::Number(BlockNumberOrTag::Latest))
                            .into_future()
                            .instrument(tracing::info_span!(
                                "fetch_eip712_domain",
                                otel.kind = "client",
                            )),
                    )
                    .await
                    .map_err(|e| categorize_transport_error(e, "fetch EIP-712 domain"))?;
                    domain.version // version field from the eip712Domain response
                }
            }
        }
    };
    let domain = eip712_domain! {
        name: name,
        version: version,
        chain_id: chain_id,
        verifying_contract: *asset_address,
    };
    Ok(domain)
}

/// Helper function to determine which ERC-3009 contract variant to use based on abi_file.
///
/// Maps abi_file paths to the correct contract instance. This function will be used
/// once TokenManager is integrated into the call chain to enable token-based selection.
///
/// # Arguments
/// * `abi_file` - Path to the ABI file (e.g., "abi/USDC.json", "abi/XBNB.json", "abi/ERC20TokenWith3009.json")
/// * `asset_address` - The token contract address
/// * `provider` - The Ethereum provider
///
/// # Returns
/// The appropriate `Erc3009Contract` variant for the given ABI file
fn determine_contract_from_abi_file<P: Provider + Clone>(
    abi_file: &str,
    asset_address: Address,
    provider: P,
) -> Result<Erc3009Contract<P>, FacilitatorLocalError> {
    match abi_file {
        "abi/USDC.json" | "abi/usdc.json" => {
            Ok(Erc3009Contract::Usdc(USDC::new(asset_address, provider)))
        }
        "abi/XBNB.json" | "abi/xbnb.json" => {
            Ok(Erc3009Contract::Xbnb(XBNB::new(asset_address, provider)))
        }
        "abi/ERC20TokenWith3009.json" | "abi/erc20tokenwith3009.json" => {
            Ok(Erc3009Contract::ERC20TokenWith3009(ERC20TokenWith3009::new(asset_address, provider)))
        }
        _ => Err(FacilitatorLocalError::ContractCall(
            format!("Unknown ABI file: {}. Supported ABIs: abi/USDC.json, abi/XBNB.json, abi/ERC20TokenWith3009.json", abi_file)
        )),
    }
}

/// Runs all preconditions needed for a successful payment:
/// - Valid scheme, network, and receiver.
/// - Valid time window (validAfter/validBefore).
/// - Correct EIP-712 domain construction.
/// - Sufficient on-chain balance.
/// - Sufficient value in payload.
#[instrument(skip_all)]
async fn assert_valid_payment<P: Provider + Clone>(
    provider: P,
    chain: &EvmChain,
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
    version_cache: Option<&Arc<tokio::sync::RwLock<std::collections::HashMap<Address, (String, std::time::Instant)>>>>,
    skip_balance_check: bool,
) -> Result<(Erc3009Contract<P>, ExactEvmPayment, Eip712Domain), FacilitatorLocalError> {
    let payment_payload = match &payload.payload {
        ExactPaymentPayload::Evm(payload) => payload,
        ExactPaymentPayload::Solana(_) => {
            return Err(FacilitatorLocalError::UnsupportedNetwork(None));
        }
    };
    let payer = payment_payload.authorization.from;
    if payload.network != chain.network {
        return Err(FacilitatorLocalError::NetworkMismatch(
            Some(payer.into()),
            chain.network,
            payload.network,
        ));
    }
    if requirements.network != chain.network {
        return Err(FacilitatorLocalError::NetworkMismatch(
            Some(payer.into()),
            chain.network,
            requirements.network,
        ));
    }
    if payload.scheme != requirements.scheme {
        return Err(FacilitatorLocalError::SchemeMismatch(
            Some(payer.into()),
            requirements.scheme,
            payload.scheme,
        ));
    }
    let payload_to: EvmAddress = payment_payload.authorization.to;
    let requirements_to: EvmAddress = requirements
        .pay_to
        .clone()
        .try_into()
        .map_err(|_| FacilitatorLocalError::InvalidAddress(
            "Invalid Ethereum address format".to_string()
        ))?;
    if payload_to != requirements_to {
        return Err(FacilitatorLocalError::ReceiverMismatch(
            payer.into(),
            payload_to.to_string(),
            requirements_to.to_string(),
        ));
    }
    let valid_after = payment_payload.authorization.valid_after;
    let valid_before = payment_payload.authorization.valid_before;
    assert_time(payer.into(), valid_after, valid_before)?;
    let asset_address = requirements
        .asset
        .clone()
        .try_into()
        .map_err(|_| FacilitatorLocalError::InvalidAddress(
            "Invalid Ethereum address format".to_string()
        ))?;

    // TODO: Integrate TokenManager to determine contract type based on asset_address
    // The full flow should be: asset_address → TokenManager.get_token_name() →
    // TokenManager.get_abi_file() → determine_contract_from_abi_file()
    // For now, use network-based fallback until TokenManager is wired into the call chain
    let contract = match chain.network {
        Network::BscTestnet | Network::Bsc => {
            Erc3009Contract::Xbnb(XBNB::new(asset_address, provider.clone()))
        }
        _ => {
            Erc3009Contract::Usdc(USDC::new(asset_address, provider.clone()))
        }
    };

    let domain = assert_domain(chain, &contract, payload, &asset_address, requirements, version_cache).await?;

    let amount_required = requirements.max_amount_required.0;
    if !skip_balance_check {
        assert_enough_balance(
            &contract,
            &payment_payload.authorization.from,
            amount_required,
        )
        .await?;
    }
    let value: U256 = payment_payload.authorization.value.into();
    assert_enough_value(&payer, &value, &amount_required)?;

    let payment = ExactEvmPayment {
        chain: *chain,
        from: payment_payload.authorization.from,
        to: payment_payload.authorization.to,
        value: payment_payload.authorization.value,
        valid_after: payment_payload.authorization.valid_after,
        valid_before: payment_payload.authorization.valid_before,
        nonce: payment_payload.authorization.nonce,
        signature: payment_payload.signature.clone(),
    };

    Ok((contract, payment, domain))
}

/// Constructs a full `transferWithAuthorization` call for a verified payment payload.
///
/// This function prepares the transaction builder with gas pricing adapted to the network's
/// capabilities (EIP-1559 or legacy) and packages it together with signature metadata
/// into a [`TransferWithAuthorization0Call`] structure.
///
/// This function does not perform any validation — it assumes inputs are already checked.
#[allow(non_snake_case)]
async fn transferWithAuthorization_0<'a, P: Provider>(
    contract: &'a Erc3009Contract<P>,
    payment: &ExactEvmPayment,
    signature: Bytes,
) -> Result<TransferWithAuthorization0Call<&'a P>, FacilitatorLocalError> {
    let from: Address = payment.from.into();
    let to: Address = payment.to.into();
    let value: U256 = payment.value.into();
    let valid_after: U256 = payment.valid_after.into();
    let valid_before: U256 = payment.valid_before.into();
    let nonce = FixedBytes(payment.nonce.0);

    // Call transferWithAuthorization on the appropriate contract type
    // Note: USDC has overloads (_0 suffix), XBNB has only one (no suffix)
    let (tx, contract_address) = match contract {
        Erc3009Contract::Usdc(usdc_contract) => {
            let tx = usdc_contract.transferWithAuthorization_0(
                from,
                to,
                value,
                valid_after,
                valid_before,
                nonce,
                signature.clone(),
            );
            (TransferWithAuthorizationCallBuilder::Usdc(tx), *usdc_contract.address())
        }
        Erc3009Contract::Xbnb(xbnb_contract) => {
            // XBNB uses separate v, r, s parameters instead of a single Bytes signature
            // Signature format: 65 bytes (r: 32 bytes, s: 32 bytes, v: 1 byte)
            if signature.len() != 65 {
                return Err(FacilitatorLocalError::InvalidSignature(
                    payment.from.into(),
                    format!("Invalid signature length: expected 65, got {}", signature.len()),
                ));
            }
            let v = signature[64];
            let r = FixedBytes::<32>::from_slice(&signature[0..32]);
            let s = FixedBytes::<32>::from_slice(&signature[32..64]);

            let tx = xbnb_contract.transferWithAuthorization(
                from,
                to,
                value,
                valid_after,
                valid_before,
                nonce,
                v,
                r,
                s,
            );
            (TransferWithAuthorizationCallBuilder::Xbnb(tx), *xbnb_contract.address())
        }
        Erc3009Contract::ERC20TokenWith3009(erc20_contract) => {
            // ERC20TokenWith3009 uses separate v, r, s parameters like XBNB
            // Signature format: 65 bytes (r: 32 bytes, s: 32 bytes, v: 1 byte)
            if signature.len() != 65 {
                return Err(FacilitatorLocalError::InvalidSignature(
                    payment.from.into(),
                    format!("Invalid signature length: expected 65, got {}", signature.len()),
                ));
            }
            let v = signature[64];
            let r = FixedBytes::<32>::from_slice(&signature[0..32]);
            let s = FixedBytes::<32>::from_slice(&signature[32..64]);

            let tx = erc20_contract.transferWithAuthorization(
                from,
                to,
                value,
                valid_after,
                valid_before,
                nonce,
                v,
                r,
                s,
            );
            (TransferWithAuthorizationCallBuilder::ERC20TokenWith3009(tx), *erc20_contract.address())
        }
    };

    Ok(TransferWithAuthorization0Call {
        tx,
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
        signature,
        contract_address,
    })
}

/// A structured representation of an Ethereum signature.
///
/// This enum normalizes two supported cases:
///
/// - **EIP-6492 wrapped signatures**: used for counterfactual contract wallets.
///   They include deployment metadata (factory + calldata) plus the inner
///   signature that the wallet contract will validate after deployment.
/// - **EIP-1271 signatures**: plain contract (or EOA-style) signatures.
#[derive(Debug, Clone)]
enum StructuredSignature {
    /// An EIP-6492 wrapped signature.
    EIP6492 {
        /// Factory contract that can deploy the wallet deterministically
        factory: alloy::primitives::Address,
        /// Calldata to invoke on the factory (often a CREATE2 deployment).
        factory_calldata: Bytes,
        /// Inner signature for the wallet itself, probably EIP-1271.
        inner: Bytes,
        /// Full original bytes including the 6492 wrapper and magic bytes suffix.
        original: Bytes,
    },
    /// A plain EIP-1271 or EOA signature (no 6492 wrappers).
    EIP1271(Bytes),
}

/// Canonical data required to verify a signature.
#[derive(Debug, Clone)]
struct SignedMessage {
    /// Expected signer (an EOA or contract wallet).
    address: alloy::primitives::Address,
    /// 32-byte digest that was signed (typically an EIP-712 hash).
    hash: FixedBytes<32>,
    /// Structured signature, either EIP-6492 or EIP-1271.
    signature: StructuredSignature,
}

impl SignedMessage {
    /// Construct a [`SignedMessage`] from an [`ExactEvmPayment`] and its
    /// corresponding [`Eip712Domain`].
    ///
    /// This helper ties together:
    /// - The **payment intent** (an ERC-3009 `TransferWithAuthorization` struct),
    /// - The **EIP-712 domain** used for signing,
    /// - And the raw signature bytes attached to the payment.
    ///
    /// Steps performed:
    /// 1. Build an in-memory [`TransferWithAuthorization`] struct from the
    ///    `ExactEvmPayment` fields (`from`, `to`, `value`, validity window, `nonce`).
    /// 2. Compute the **EIP-712 struct hash** for that transfer under the given
    ///    `domain`. This becomes the `hash` field of the signed message.
    /// 3. Parse the raw signature bytes into a [`StructuredSignature`], which
    ///    distinguishes between:
    ///    - EIP-1271 (plain signature), and
    ///    - EIP-6492 (counterfactual signature wrapper).
    /// 4. Assemble all parts into a [`SignedMessage`] and return it.
    ///
    /// # Errors
    ///
    /// Returns [`FacilitatorLocalError`] if:
    /// - The raw signature cannot be decoded as either EIP-1271 or EIP-6492.
    pub fn extract(
        payment: &ExactEvmPayment,
        domain: &Eip712Domain,
    ) -> Result<Self, FacilitatorLocalError> {
        let transfer_with_authorization = TransferWithAuthorization {
            from: payment.from.0,
            to: payment.to.0,
            value: payment.value.into(),
            validAfter: payment.valid_after.into(),
            validBefore: payment.valid_before.into(),
            nonce: FixedBytes(payment.nonce.0),
        };
        let eip712_hash = transfer_with_authorization.eip712_signing_hash(domain);
        let expected_address = payment.from;
        let structured_signature: StructuredSignature = payment.signature.clone().try_into()?;
        let signed_message = Self {
            address: expected_address.into(),
            hash: eip712_hash,
            signature: structured_signature,
        };
        Ok(signed_message)
    }
}

/// The fixed 32-byte magic suffix defined by [EIP-6492](https://eips.ethereum.org/EIPS/eip-6492).
///
/// Any signature ending with this constant is treated as a 6492-wrapped
/// signature; the preceding bytes are ABI-decoded as `(address factory, bytes factoryCalldata, bytes innerSig)`.
const EIP6492_MAGIC_SUFFIX: [u8; 32] =
    hex!("6492649264926492649264926492649264926492649264926492649264926492");

sol! {
    /// Solidity-compatible struct for decoding the prefix of an EIP-6492 signature.
    ///
    /// Matches the tuple `(address factory, bytes factoryCalldata, bytes innerSig)`.
    #[derive(Debug)]
    struct Sig6492 {
        address factory;
        bytes   factoryCalldata;
        bytes   innerSig;
    }
}

impl TryFrom<EvmSignature> for StructuredSignature {
    type Error = FacilitatorLocalError;
    /// Convert from an `EvmSignature` wrapper to a structured signature.
    ///
    /// This delegates to the `TryFrom<Vec<u8>>` implementation.
    fn try_from(signature: EvmSignature) -> Result<Self, Self::Error> {
        signature.0.try_into()
    }
}

impl TryFrom<Vec<u8>> for StructuredSignature {
    type Error = FacilitatorLocalError;

    /// Parse raw signature bytes into a `StructuredSignature`.
    ///
    /// Rules:
    /// - If the last 32 bytes equal [`EIP6492_MAGIC_SUFFIX`], the prefix is
    ///   decoded as a [`Sig6492`] struct and returned as
    ///   [`StructuredSignature::EIP6492`].
    /// - Otherwise, the bytes are returned as [`StructuredSignature::EIP1271`].
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let is_eip6492 = bytes.len() >= 32 && bytes[bytes.len() - 32..] == EIP6492_MAGIC_SUFFIX;
        let signature = if is_eip6492 {
            let body = &bytes[..bytes.len() - 32];
            let sig6492 = Sig6492::abi_decode_params(body).map_err(|e| {
                FacilitatorLocalError::ContractCall(format!(
                    "Failed to decode EIP6492 signature: {e}"
                ))
            })?;
            StructuredSignature::EIP6492 {
                factory: sig6492.factory,
                factory_calldata: sig6492.factoryCalldata,
                inner: sig6492.innerSig,
                original: bytes.into(),
            }
        } else {
            StructuredSignature::EIP1271(bytes.into())
        };
        Ok(signature)
    }
}

/// A nonce manager that caches nonces locally and checks pending transactions on initialization.
///
/// This implementation attempts to improve upon Alloy's `CachedNonceManager` by using `.pending()` when
/// fetching the initial nonce, which includes pending transactions in the mempool. This prevents
/// "nonce too low" errors when the application restarts while transactions are still pending.
///
/// # How it works
///
/// - **First call for an address**: Attempts to fetch the nonce using `.pending()`, which includes
///   transactions in the mempool, not just confirmed transactions. If the RPC provider doesn't
///   support the `pending` block tag (e.g., BSC), gracefully falls back to `.latest()`.
/// - **Subsequent calls**: Increments the cached nonce locally without querying the RPC.
/// - **Per-address tracking**: Each address has its own cached nonce, allowing concurrent
///   transaction submission from multiple addresses.
///
/// # RPC Compatibility
///
/// Some RPC providers (notably BSC) do not support the `pending` block tag. For these providers,
/// the fallback to `.latest()` means there is a small risk of "nonce too low" errors if the
/// application restarts while transactions are still pending in the mempool.
///
/// # Thread Safety
///
/// The nonce cache is shared across all clones using `Arc<DashMap>`, ensuring that concurrent
/// requests see consistent nonce values. Each address's nonce is protected by its own `Mutex`
/// to prevent race conditions during allocation.
/// ```
#[derive(Clone, Debug, Default)]
pub struct PendingNonceManager {
    /// Cache of nonces per address. Each address has its own mutex-protected nonce value.
    nonces: Arc<DashMap<alloy::primitives::Address, Arc<Mutex<u64>>>>,
}

#[async_trait]
impl NonceManager for PendingNonceManager {
    async fn get_next_nonce<P, N>(
        &self,
        provider: &P,
        address: alloy::primitives::Address,
    ) -> alloy::transports::TransportResult<u64>
    where
        P: Provider<N>,
        N: alloy::network::Network,
    {
        // Use `u64::MAX` as a sentinel value to indicate that the nonce has not been fetched yet.
        const NONE: u64 = u64::MAX;

        // Locks dashmap internally for a short duration to clone the `Arc`.
        // We also don't want to hold the dashmap lock through the await point below.
        let nonce = {
            let rm = self
                .nonces
                .entry(address)
                .or_insert_with(|| Arc::new(Mutex::new(NONE)));
            Arc::clone(rm.value())
        };

        let mut nonce = nonce.lock().await;
        let new_nonce = if *nonce == NONE {
            // Initialize the nonce if we haven't seen this account before.
            tracing::info!(%address, "initializing nonce for new address");
            match provider.get_transaction_count(address).pending().await {
                Ok(pending_nonce) => {
                    tracing::info!(
                        %address,
                        nonce = pending_nonce,
                        block_tag = "pending",
                        "nonce fetched successfully"
                    );
                    pending_nonce
                }
                Err(e) => {
                    tracing::warn!(
                        %address,
                        error = ?e,
                        "pending block tag not supported by RPC, falling back to latest"
                    );
                    let latest_nonce = provider.get_transaction_count(address).latest().await?;
                    tracing::warn!(
                        %address,
                        nonce = latest_nonce,
                        block_tag = "latest",
                        "nonce fetched from latest block - may miss in-flight transactions"
                    );
                    latest_nonce
                }
            }
        } else {
            let prev_nonce = *nonce;
            let next_nonce = prev_nonce + 1;
            tracing::info!(
                %address,
                prev_nonce,
                next_nonce,
                "allocating next nonce"
            );
            next_nonce
        };
        *nonce = new_nonce;
        tracing::debug!(%address, allocated_nonce = new_nonce, "nonce allocated and stored");
        Ok(new_nonce)
    }
}

/// Categorize transport/RPC errors for appropriate HTTP status mapping.
///
/// Distinguishes between:
/// - Network/connection errors (DNS, TCP, timeouts) -> RpcProviderError (503)
/// - Resource exhaustion (file descriptors, pool) -> ResourceExhaustion (503)
/// - Contract execution errors -> ContractCall (502)
fn categorize_transport_error(e: impl std::fmt::Debug, context: &str) -> FacilitatorLocalError {
    let err_str = format!("{:?}", e);

    if err_str.contains("Connection refused") ||
       err_str.contains("Connection reset") ||
       err_str.contains("No route to host") ||
       err_str.contains("timeout") ||
       err_str.contains("Timeout") ||
       err_str.contains("dns error") {
        tracing::error!("{context}: RPC connection error: {err_str}");
        FacilitatorLocalError::RpcProviderError(
            format!("{context}: Connection error")
        )
    } else if err_str.contains("Too many open files") || err_str.contains("EMFILE") {
        tracing::error!("{context}: File descriptor exhaustion: {err_str}");
        FacilitatorLocalError::ResourceExhaustion(
            "Connection pool exhausted".to_string()
        )
    } else {
        tracing::error!("{context}: Contract call failed: {err_str}");
        FacilitatorLocalError::ContractCall(
            format!("{context}: Call failed")
        )
    }
}

impl PendingNonceManager {
    /// Resets the cached nonce for a given address, forcing a fresh query on next use.
    ///
    /// This should be called when a transaction fails, as we cannot be certain of the
    /// actual on-chain state (the transaction may or may not have reached the mempool).
    /// By resetting to the sentinel value, the next call to `get_next_nonce` will query
    /// the RPC provider using `.pending()`, which includes mempool transactions.
    pub async fn reset_nonce(&self, address: Address) {
        if let Some(nonce_lock) = self.nonces.get(&address) {
            let mut nonce = nonce_lock.lock().await;
            *nonce = u64::MAX; // NONE sentinel - will trigger fresh query
            tracing::debug!(%address, "reset nonce cache, will requery on next use");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[tokio::test]
    async fn test_reset_nonce_clears_cache() {
        let manager = PendingNonceManager::default();
        let test_address = address!("0000000000000000000000000000000000000001");

        // Manually set a nonce in the cache (simulating it was fetched)
        {
            let nonce_lock = manager
                .nonces
                .entry(test_address)
                .or_insert_with(|| Arc::new(Mutex::new(0)));
            let mut nonce = nonce_lock.lock().await;
            *nonce = 42;
        }

        // Verify nonce is cached
        {
            let nonce_lock = manager.nonces.get(&test_address).unwrap();
            let nonce = nonce_lock.lock().await;
            assert_eq!(*nonce, 42);
        }

        // Reset the nonce
        manager.reset_nonce(test_address).await;

        // Verify nonce is reset to sentinel value (u64::MAX)
        {
            let nonce_lock = manager.nonces.get(&test_address).unwrap();
            let nonce = nonce_lock.lock().await;
            assert_eq!(*nonce, u64::MAX);
        }
    }

    #[tokio::test]
    async fn test_reset_nonce_after_allocation_sequence() {
        let manager = PendingNonceManager::default();
        let test_address = address!("0000000000000000000000000000000000000002");

        // Simulate nonce allocations
        {
            let nonce_lock = manager
                .nonces
                .entry(test_address)
                .or_insert_with(|| Arc::new(Mutex::new(0)));
            let mut nonce = nonce_lock.lock().await;
            *nonce = 50; // First allocation
            *nonce = 51; // Second allocation
            *nonce = 52; // Third allocation
        }

        // Simulate a transaction failure - reset nonce
        manager.reset_nonce(test_address).await;

        // Verify nonce is back to sentinel for requery
        {
            let nonce_lock = manager.nonces.get(&test_address).unwrap();
            let nonce = nonce_lock.lock().await;
            assert_eq!(*nonce, u64::MAX);
        }
    }

    #[tokio::test]
    async fn test_reset_nonce_on_nonexistent_address() {
        let manager = PendingNonceManager::default();
        let test_address = address!("0000000000000000000000000000000000000099");

        // Reset should not panic on address that hasn't been used
        manager.reset_nonce(test_address).await;

        // Verify nonce map still doesn't have this address
        assert!(!manager.nonces.contains_key(&test_address));
    }

    #[tokio::test]
    async fn test_multiple_addresses_independent_nonces() {
        let manager = PendingNonceManager::default();
        let address1 = address!("0000000000000000000000000000000000000001");
        let address2 = address!("0000000000000000000000000000000000000002");

        // Set nonces for both addresses
        {
            let nonce_lock1 = manager
                .nonces
                .entry(address1)
                .or_insert_with(|| Arc::new(Mutex::new(0)));
            *nonce_lock1.lock().await = 10;

            let nonce_lock2 = manager
                .nonces
                .entry(address2)
                .or_insert_with(|| Arc::new(Mutex::new(0)));
            *nonce_lock2.lock().await = 20;
        }

        // Reset address1
        manager.reset_nonce(address1).await;

        // address1 should be reset, address2 should be unchanged
        {
            let nonce_lock1 = manager.nonces.get(&address1).unwrap();
            assert_eq!(*nonce_lock1.lock().await, u64::MAX);

            let nonce_lock2 = manager.nonces.get(&address2).unwrap();
            assert_eq!(*nonce_lock2.lock().await, 20);
        }
    }

    #[tokio::test]
    async fn test_concurrent_reset_and_access() {
        let manager = Arc::new(PendingNonceManager::default());
        let test_address = address!("0000000000000000000000000000000000000003");

        // Set initial nonce
        {
            let nonce_lock = manager
                .nonces
                .entry(test_address)
                .or_insert_with(|| Arc::new(Mutex::new(0)));
            *nonce_lock.lock().await = 100;
        }

        // Spawn concurrent tasks
        let manager1 = Arc::clone(&manager);
        let handle1 = tokio::spawn(async move {
            manager1.reset_nonce(test_address).await;
        });

        let manager2 = Arc::clone(&manager);
        let handle2 = tokio::spawn(async move {
            manager2.reset_nonce(test_address).await;
        });

        // Wait for both to complete
        handle1.await.unwrap();
        handle2.await.unwrap();

        // Verify nonce is reset (both resets should work fine)
        {
            let nonce_lock = manager.nonces.get(&test_address).unwrap();
            assert_eq!(*nonce_lock.lock().await, u64::MAX);
        }
    }
}
