use crate::client::FacilitatorClient;
use crate::config::Config;
use crate::stats::{RequestOutcome, RequestRecord, RequestType, Stats};
use alloy::primitives::U256;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use chrono::Utc;
use infra402_facilitator::proto::v2::{
    ExactSchemePayload, PaymentPayload as PaymentPayloadV2,
    PaymentRequirements as PaymentRequirementsV2, ResourceInfo, X402Version2,
};
use infra402_facilitator::types::{PaymentRequirements, Scheme, VerifyResponse};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use x402_reqwest::chains::evm::EvmSenderWallet;
use x402_reqwest::chains::SenderWallet;

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

        let test_mode = if self.config.cli.verify_only {
            "verify only"
        } else if self.config.cli.settle_only {
            "settle only"
        } else {
            "verify + settle pairs"
        };
        println!("Test Mode: {}", test_mode);
        println!("Protocol Version: v{}", self.config.cli.protocol_version);

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
    _worker_id: usize,
    config: Config,
    client: FacilitatorClient,
    sender_wallet: EvmSenderWallet,
    stats: Stats,
    stop_flag: Arc<AtomicBool>,
    request_counter: Arc<AtomicU64>,
) {
    let total_requests = config.cli.total_requests;
    let requests_per_second = config.cli.requests_per_second;
    let verify_only = config.cli.verify_only;
    let settle_only = config.cli.settle_only;

    // Calculate delay between requests for rate limiting
    // Note: In default mode (verify+settle pairs), RPS applies to pairs, not individual API calls
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

        // Execute request(s) based on mode
        if verify_only {
            // Only send verify
            execute_and_record(&config, &client, &sender_wallet, &stats, true).await;
        } else if settle_only {
            // Only send settle
            execute_and_record(&config, &client, &sender_wallet, &stats, false).await;
        } else {
            // Default: send both verify AND settle
            execute_and_record(&config, &client, &sender_wallet, &stats, true).await;
            execute_and_record(&config, &client, &sender_wallet, &stats, false).await;
        }

        // Rate limiting: sleep between requests
        if delay_between_requests > Duration::from_millis(0) {
            sleep(delay_between_requests).await;
        }
    }
}

async fn execute_and_record(
    config: &Config,
    client: &FacilitatorClient,
    sender_wallet: &EvmSenderWallet,
    stats: &Stats,
    is_verify: bool,
) {
    let start = Instant::now();
    let outcome = execute_request(config, client, sender_wallet, is_verify).await;
    let latency_ms = start.elapsed().as_millis() as u64;

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
}

async fn execute_request(
    config: &Config,
    client: &FacilitatorClient,
    sender_wallet: &EvmSenderWallet,
    is_verify: bool,
) -> RequestOutcome {
    // Create payment requirements using facilitator types (supports BSC networks)
    let network: infra402_facilitator::network::Network = serde_json::from_value(
        serde_json::Value::String(config.env.network.clone())
    ).expect("Invalid network value");

    let payment_requirements = PaymentRequirements {
        scheme: Scheme::Exact,
        network,
        max_amount_required: infra402_facilitator::types::TokenAmount(
            U256::from_str(&config.env.amount).expect("Invalid AMOUNT format")
        ),
        resource: "http://stress-test".parse().expect("Invalid URL"),
        description: "X402 stress test".to_string(),
        mime_type: "application/json".to_string(),
        output_schema: None,
        pay_to: infra402_facilitator::types::MixedAddress::Evm(
            infra402_facilitator::types::EvmAddress::from_str(&config.env.pay_to).expect("Invalid PAY_TO address")
        ),
        max_timeout_seconds: config.env.max_timeout_seconds,
        asset: infra402_facilitator::types::MixedAddress::Evm(
            infra402_facilitator::types::EvmAddress::from_str(&config.env.asset).expect("Invalid ASSET address")
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

    // Generate signed payment payload (x402-reqwest now uses facilitator types!)
    let payment_payload = match sender_wallet.payment_payload(payment_requirements.clone()).await
    {
        Ok(payload) => payload,
        Err(e) => {
            return RequestOutcome::HttpError {
                error: format!("Failed to generate payment payload: {}", e),
            };
        }
    };

    // Branch on protocol version
    if config.cli.protocol_version == 2 {
        execute_request_v2(client, payment_payload, payment_requirements, is_verify).await
    } else {
        execute_request_v1(client, payment_payload, payment_requirements, is_verify).await
    }
}

async fn execute_request_v1(
    client: &FacilitatorClient,
    payment_payload: infra402_facilitator::types::PaymentPayload,
    payment_requirements: PaymentRequirements,
    is_verify: bool,
) -> RequestOutcome {
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

async fn execute_request_v2(
    client: &FacilitatorClient,
    payment_payload: infra402_facilitator::types::PaymentPayload,
    payment_requirements: PaymentRequirements,
    is_verify: bool,
) -> RequestOutcome {
    // Convert v1 types to v2 types
    let chain_id = payment_requirements.network.to_chain_id();

    let resource = ResourceInfo {
        url: payment_requirements.resource.clone(),
        description: payment_requirements.description.clone(),
        mime_type: payment_requirements.mime_type.clone(),
        output_schema: payment_requirements.output_schema.clone(),
        content_length: None,
        preview_url: None,
    };

    let payment_requirements_v2 = PaymentRequirementsV2 {
        scheme: payment_requirements.scheme,
        chain_id: chain_id.clone(),
        max_amount_required: payment_requirements.max_amount_required,
        resource,
        pay_to: payment_requirements.pay_to.clone(),
        max_timeout_seconds: payment_requirements.max_timeout_seconds,
        asset: payment_requirements.asset.clone(),
        payload: ExactSchemePayload::default(),
        extra: payment_requirements.extra.clone(),
    };

    let payment_payload_v2 = PaymentPayloadV2 {
        x402_version: X402Version2,
        scheme: payment_payload.scheme,
        chain_id,
        payload: payment_payload.payload,
    };

    if is_verify {
        match client
            .verify_v2(payment_payload_v2, payment_requirements_v2)
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
            .settle_v2(payment_payload_v2, payment_requirements_v2)
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
