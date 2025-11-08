use anyhow::{Context, Result};
use clap::Parser;
use std::env;

/// X402 Stress Testing Tool
#[derive(Parser, Debug, Clone)]
#[command(name = "x402-stress-test")]
#[command(about = "Stress test the x402 facilitator /verify and /settle endpoints")]
pub struct CliArgs {
    /// Requests per second to send (0 = unlimited)
    #[arg(long, default_value = "10")]
    pub requests_per_second: u32,

    /// Total duration to run in seconds (conflicts with --total-requests)
    #[arg(long, conflicts_with = "total_requests")]
    pub duration_seconds: Option<u64>,

    /// Total number of requests to send (conflicts with --duration-seconds)
    #[arg(long, conflicts_with = "duration_seconds")]
    pub total_requests: Option<u64>,

    /// Only test /verify endpoint (no settlements)
    #[arg(long, conflicts_with = "settle_only")]
    pub verify_only: bool,

    /// Only test /settle endpoint (no verification-only calls)
    #[arg(long, conflicts_with = "verify_only")]
    pub settle_only: bool,

    /// Number of concurrent worker threads
    #[arg(long, default_value = "10")]
    pub workers: usize,

    /// Print stats every N seconds
    #[arg(long, default_value = "1")]
    pub stats_interval_seconds: u64,
}

impl CliArgs {
    pub fn validate(&self) -> Result<()> {
        if self.duration_seconds.is_none() && self.total_requests.is_none() {
            anyhow::bail!("Must specify either --duration-seconds or --total-requests");
        }
        Ok(())
    }
}

/// Configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct EnvConfig {
    /// Facilitator base URL (e.g., http://localhost:3000)
    pub facilitator_url: String,

    /// Optional API key for Bearer authentication
    pub facilitator_api_key: Option<String>,

    /// EVM private key (hex string)
    pub evm_private_key: String,

    /// Network to use (e.g., base-sepolia)
    /// Stored as string to support all facilitator networks including BSC
    pub network: String,

    /// Recipient address for payments
    pub pay_to: String,

    /// Amount in smallest unit (e.g., 1000000 = $1 USDC)
    pub amount: String,

    /// Token contract address
    pub asset: String,

    /// Token name for EIP-712 domain (e.g., "USD Coin")
    pub token_name: String,

    /// Token version for EIP-712 domain (e.g., "2")
    pub token_version: String,

    /// Max timeout in seconds for payment validity
    pub max_timeout_seconds: u64,
}

impl EnvConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            facilitator_url: env::var("FACILITATOR_URL")
                .context("FACILITATOR_URL not set")?,

            facilitator_api_key: env::var("FACILITATOR_API_KEY").ok(),

            evm_private_key: env::var("EVM_PRIVATE_KEY")
                .context("EVM_PRIVATE_KEY not set")?,

            network: env::var("NETWORK")
                .context("NETWORK not set - must be one of: base-sepolia, base, xdc, avalanche-fuji, avalanche, solana, solana-devnet, polygon-amoy, polygon, sei, sei-testnet, bsc-testnet, bsc")?,

            pay_to: env::var("PAY_TO")
                .context("PAY_TO not set")?,

            amount: env::var("AMOUNT")
                .context("AMOUNT not set")?,

            asset: env::var("ASSET")
                .context("ASSET not set")?,

            token_name: env::var("TOKEN_NAME")
                .context("TOKEN_NAME not set")?,

            token_version: env::var("TOKEN_VERSION")
                .context("TOKEN_VERSION not set")?,

            max_timeout_seconds: env::var("MAX_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .context("Invalid MAX_TIMEOUT_SECONDS")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub cli: CliArgs,
    pub env: EnvConfig,
}

impl Config {
    pub fn load() -> Result<Self> {
        dotenvy::dotenv().ok();

        let cli = CliArgs::parse();
        cli.validate()?;

        let env = EnvConfig::from_env()?;

        Ok(Self { cli, env })
    }
}
