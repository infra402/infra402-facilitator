use crate::client::FacilitatorClient;
use crate::config::Config;
use crate::stats::{RequestOutcome, RequestRecord, RequestType, Stats};
use alloy::primitives::U256;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use chrono::Utc;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use x402_reqwest::chains::evm::EvmSenderWallet;
use x402_reqwest::chains::SenderWallet;
use x402_reqwest::X402PaymentsError;
use x402_rs::types::{EvmAddress, MixedAddress, PaymentPayload, PaymentRequirements, Scheme, TokenAmount, VerifyResponse};

pub struct StressTest {
    config: Config,
    client: FacilitatorClient,
    sender_wallet: EvmSenderWallet,
    stats: Stats,
}

impl StressTest {
    pub fn new(config: Config) -> Result<Self> {
        // Parse private key and create sender wallet
        let signer: PrivateKeySigner = config
            .env
            .evm_private_key
            .parse()
            .context("Failed to parse EVM_PRIVATE_KEY")?;

        let sender_wallet = EvmSenderWallet::new(signer);

        // Create HTTP client
        let client = FacilitatorClient::new(
            config.env.facilitator_url.clone(),
            config.env.facilitator_api_key.clone(),
        );

        let stats = Stats::new();

        Ok(Self {
            config,
            client,
            sender_wallet,
            stats,
        })
    }

    /// Run the stress test
    pub async fn run(&self) -> Result<()> {
        println!("Starting X402 Stress Test");
        println!("Facilitator: {}", self.config.env.facilitator_url);
        println!("Network: {}", self.config.env.network);
        println!("Workers: {}", self.config.cli.workers);
        println!("RPS Limit: {}", self.config.cli.requests_per_second);

        let verify_ratio = self.config.cli.get_verify_ratio();
        println!(
            "Test Mix: {:.0}% verify, {:.0}% settle",
            verify_ratio * 100.0,
            (1.0 - verify_ratio) * 100.0
        );

        if let Some(duration) = self.config.cli.duration_seconds {
            println!("Duration: {}s", duration);
        } else if let Some(total) = self.config.cli.total_requests {
            println!("Total Requests: {}", total);
        }

        println!("\nPress Ctrl+C to stop early\n");

        // Shared state
        let stop_flag = Arc::new(AtomicBool::new(false));
        let request_counter = Arc::new(AtomicU64::new(0));

        // Setup Ctrl+C handler
        let stop_flag_clone = stop_flag.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            println!("\n\nStopping... (press Ctrl+C again to force quit)");
            stop_flag_clone.store(true, Ordering::Relaxed);
        });

        // Spawn stats printer
        let stats_clone = self.stats.clone();
        let stop_flag_clone = stop_flag.clone();
        let stats_interval = self.config.cli.stats_interval_seconds;
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(stats_interval)).await;
                if stop_flag_clone.load(Ordering::Relaxed) {
                    break;
                }
                stats_clone.snapshot().print(false);
            }
        });

        // Spawn worker tasks
        let mut handles = vec![];

        for worker_id in 0..self.config.cli.workers {
            let config = self.config.clone();
            let client = self.client.clone();
            let sender_wallet = self.sender_wallet.clone();
            let stats = self.stats.clone();
            let stop_flag = stop_flag.clone();
            let request_counter = request_counter.clone();

            let handle = tokio::spawn(async move {
                worker_loop(
                    worker_id,
                    config,
                    client,
                    sender_wallet,
                    stats,
                    stop_flag,
                    request_counter,
                )
                .await;
            });

            handles.push(handle);
        }

        // Setup duration-based stop if configured
        if let Some(duration_secs) = self.config.cli.duration_seconds {
            let stop_flag = stop_flag.clone();
            tokio::spawn(async move {
                sleep(Duration::from_secs(duration_secs)).await;
                stop_flag.store(true, Ordering::Relaxed);
            });
        }

        // Wait for all workers to complete
        for handle in handles {
            handle.await.ok();
        }

        // Print final statistics
        println!("\n");
        self.stats.snapshot().print(true);

        Ok(())
    }
}

async fn worker_loop(
    worker_id: usize,
    config: Config,
    client: FacilitatorClient,
    sender_wallet: EvmSenderWallet,
    stats: Stats,
    stop_flag: Arc<AtomicBool>,
    request_counter: Arc<AtomicU64>,
) {
    let verify_ratio = config.cli.get_verify_ratio();
    let total_requests = config.cli.total_requests;
    let requests_per_second = config.cli.requests_per_second;

    // Calculate delay between requests for rate limiting
    let delay_between_requests = if requests_per_second > 0 {
        let total_rps = requests_per_second as f64;
        let per_worker_rps = total_rps / config.cli.workers as f64;
        Duration::from_secs_f64(1.0 / per_worker_rps)
    } else {
        Duration::from_millis(0)
    };

    loop {
        // Check stop conditions
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        if let Some(total) = total_requests {
            let current = request_counter.load(Ordering::Relaxed);
            if current >= total {
                break;
            }
        }

        // Increment request counter
        let request_num = request_counter.fetch_add(1, Ordering::Relaxed);

        // Check again after incrementing
        if let Some(total) = total_requests {
            if request_num >= total {
                break;
            }
        }

        // Determine if this should be a verify or settle request
        let is_verify = (request_num as f64 / 1000.0).fract() < verify_ratio as f64;

        // Execute request
        let start = Instant::now();
        let outcome = execute_request(&config, &client, &sender_wallet, is_verify).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        // Record result
        let request_type = if is_verify {
            RequestType::Verify
        } else {
            RequestType::Settle
        };

        stats.record(RequestRecord {
            request_type,
            outcome,
            latency_ms,
            timestamp: Utc::now(),
        });

        // Rate limiting: sleep between requests
        if delay_between_requests > Duration::from_millis(0) {
            sleep(delay_between_requests).await;
        }
    }
}

async fn execute_request(
    config: &Config,
    client: &FacilitatorClient,
    sender_wallet: &EvmSenderWallet,
    is_verify: bool,
) -> RequestOutcome {
    // Create payment requirements
    let payment_requirements = PaymentRequirements {
        scheme: Scheme::Exact,
        network: config.env.network,
        max_amount_required: TokenAmount(
            U256::from_str(&config.env.amount).expect("Invalid AMOUNT format")
        ),
        resource: "http://stress-test".parse().expect("Invalid URL"),
        description: "X402 stress test".to_string(),
        mime_type: "application/json".to_string(),
        output_schema: None,
        pay_to: MixedAddress::Evm(
            EvmAddress::from_str(&config.env.pay_to).expect("Invalid PAY_TO address")
        ),
        max_timeout_seconds: config.env.max_timeout_seconds,
        asset: MixedAddress::Evm(
            EvmAddress::from_str(&config.env.asset).expect("Invalid ASSET address")
        ),
        extra: Some({
            let mut map = serde_json::Map::new();
            map.insert(
                "name".to_string(),
                serde_json::Value::String(config.env.token_name.clone()),
            );
            map.insert(
                "version".to_string(),
                serde_json::Value::String(config.env.token_version.clone()),
            );
            serde_json::Value::Object(map)
        }),
    };

    // Generate signed payment payload
    let payment_payload = match sender_wallet.payment_payload(payment_requirements.clone()).await
    {
        Ok(payload) => payload,
        Err(e) => {
            return RequestOutcome::HttpError {
                error: format!("Failed to generate payment payload: {}", e),
            };
        }
    };

    // Execute request
    if is_verify {
        match client
            .verify(payment_payload, payment_requirements)
            .await
        {
            Ok(response) => match response {
                VerifyResponse::Valid { .. } => RequestOutcome::VerifyValid,
                VerifyResponse::Invalid { reason, .. } => RequestOutcome::VerifyInvalid {
                    reason: format!("{:?}", reason),
                },
            },
            Err(e) => RequestOutcome::HttpError {
                error: format!("{}", e),
            },
        }
    } else {
        match client
            .settle(payment_payload, payment_requirements)
            .await
        {
            Ok(response) => {
                if response.success {
                    RequestOutcome::SettleSuccess
                } else {
                    RequestOutcome::SettleFailure {
                        reason: response
                            .error_reason
                            .map(|r| format!("{:?}", r))
                            .unwrap_or_else(|| "unknown".to_string()),
                    }
                }
            }
            Err(e) => RequestOutcome::HttpError {
                error: format!("{}", e),
            },
        }
    }
}
