//! Batch processor for settlement transactions.
//!
//! This module handles processing batches of settlement requests using Multicall3
//! to bundle multiple transferWithAuthorization calls into single transactions.

use crate::chain::{evm::EvmProvider, FacilitatorLocalError, NetworkProvider};
use crate::types::{SettleRequest, SettleResponse};
use alloy::primitives::Address;
use tokio::sync::oneshot;

/// Batch processor for settlement transactions.
pub struct BatchProcessor;

impl BatchProcessor {
    /// Process a batch of settlement requests for a specific (facilitator, network) pair.
    ///
    /// This method:
    /// 1. Validates all settlement requests
    /// 2. For EVM networks: bundles them into a Multicall3 aggregate3 transaction
    /// 3. For Solana networks: processes them individually (no batching)
    /// 4. Returns results to requesters via oneshot channels
    ///
    /// The facilitator_addr must match the queue this batch came from, ensuring
    /// the settlement lock is acquired for the correct facilitator address.
    pub async fn process_batch(
        network_provider: &NetworkProvider,
        facilitator_addr: Address,
        requests: Vec<(SettleRequest, oneshot::Sender<Result<SettleResponse, FacilitatorLocalError>>)>,
        allow_partial_failure: bool,
    ) -> Result<(), FacilitatorLocalError> {
        if requests.is_empty() {
            return Ok(());
        }

        let batch_size = requests.len();
        tracing::info!(
            %facilitator_addr,
            batch_size,
            "processing batch for facilitator"
        );

        // Match on network provider type
        match network_provider {
            NetworkProvider::Evm(evm_provider) => {
                Self::process_evm_batch(evm_provider, facilitator_addr, requests, allow_partial_failure).await
            }
            NetworkProvider::Solana(_solana_provider) => {
                // Solana batching not implemented yet - process individually
                tracing::info!(
                    batch_size,
                    "Solana batching not implemented - processing settlements individually"
                );
                Self::process_individually_fallback(network_provider, requests).await
            }
        }
    }

    /// Process an EVM batch using Multicall3.
    ///
    /// This method acquires the facilitator's settlement lock, validates all requests,
    /// and sends a single Multicall3 transaction containing all transfers.
    async fn process_evm_batch(
        evm_provider: &EvmProvider,
        facilitator_addr: Address,
        requests: Vec<(SettleRequest, oneshot::Sender<Result<SettleResponse, FacilitatorLocalError>>)>,
        allow_partial_failure: bool,
    ) -> Result<(), FacilitatorLocalError> {
        // Acquire settlement lock for this facilitator address
        // This ensures sequential processing and prevents nonce race conditions
        let settlement_lock = evm_provider.get_settlement_lock(facilitator_addr);
        tracing::debug!(%facilitator_addr, "acquiring settlement lock for batch");
        let _settlement_guard = settlement_lock.lock().await;
        tracing::debug!(%facilitator_addr, "settlement lock acquired for batch");

        // Validate all settlements and prepare them for batching
        let mut validated_settlements = Vec::with_capacity(requests.len());
        let mut response_channels = Vec::with_capacity(requests.len());

        for (request, response_tx) in requests {
            match evm_provider.validate_and_prepare_settlement(&request, None).await {
                Ok(validated) => {
                    validated_settlements.push(validated);
                    response_channels.push(response_tx);
                }
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "settlement validation failed - sending error to requester"
                    );
                    // Send error back to requester
                    let _ = response_tx.send(Err(e));
                    // Continue processing other requests
                }
            }
        }

        if validated_settlements.is_empty() {
            tracing::warn!("all settlements in batch failed validation");
            return Ok(());
        }

        tracing::info!(
            validated_count = validated_settlements.len(),
            "validated settlements - splitting into Call3-aware sub-batches"
        );

        // Split validated settlements into sub-batches based on max Call3 count
        // Each settlement needs 1 Call3 for the transfer + N Call3s for hooks
        // max_batch_size in config represents max total Call3 structs, not settlement count
        const MAX_CALL3_PER_BATCH: usize = 150; // TODO: Make this configurable

        let mut sub_batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_batch_channels = Vec::new();
        let mut current_call3_count = 0;

        for (settlement, channel) in validated_settlements.into_iter().zip(response_channels.into_iter()) {
            let calls_needed = 1 + settlement.hooks.len(); // 1 for transfer + N for hooks

            // If adding this settlement would exceed limit, flush current batch
            if current_call3_count + calls_needed > MAX_CALL3_PER_BATCH && !current_batch.is_empty() {
                sub_batches.push((current_batch, current_batch_channels));
                current_batch = Vec::new();
                current_batch_channels = Vec::new();
                current_call3_count = 0;
            }

            current_batch.push(settlement);
            current_batch_channels.push(channel);
            current_call3_count += calls_needed;
        }

        // Add final batch if non-empty
        if !current_batch.is_empty() {
            sub_batches.push((current_batch, current_batch_channels));
        }

        tracing::info!(
            sub_batch_count = sub_batches.len(),
            "split into {} sub-batches based on Call3 limits",
            sub_batches.len()
        );

        // Process each sub-batch sequentially
        use crate::chain::evm::PRESELECTED_FACILITATOR;
        for (batch_settlements, batch_channels) in sub_batches {
            tracing::info!(
                batch_size = batch_settlements.len(),
                total_call3s = batch_settlements.iter().map(|s| 1 + s.hooks.len()).sum::<usize>(),
                "processing sub-batch"
            );

            let batch_result = PRESELECTED_FACILITATOR
                .scope(
                    facilitator_addr,
                    evm_provider.settle_batch(batch_settlements, allow_partial_failure),
                )
                .await;

            match batch_result {
                Ok(responses) => {
                    // Send each response back to its requester
                    for (response, response_tx) in responses.into_iter().zip(batch_channels.into_iter()) {
                        let _ = response_tx.send(Ok(response));
                    }
                }
                Err(e) => {
                    tracing::error!(error = ?e, "sub-batch settlement failed");
                    // Send error to all requesters in this sub-batch
                    for response_tx in batch_channels {
                        let batch_error = FacilitatorLocalError::ContractCall(
                            "Batch settlement failed".to_string()
                        );
                        let _ = response_tx.send(Err(batch_error));
                    }
                    return Err(e);
                }
            }
        }

        tracing::info!("all sub-batches completed successfully");
        Ok(())
    }

    /// Fallback: process settlements individually (used for Solana or when batching fails).
    async fn process_individually_fallback(
        network_provider: &NetworkProvider,
        requests: Vec<(SettleRequest, oneshot::Sender<Result<SettleResponse, FacilitatorLocalError>>)>,
    ) -> Result<(), FacilitatorLocalError> {
        for (request, response_tx) in requests {
            // Use the existing settle method from NetworkProvider's Facilitator trait
            use crate::facilitator::Facilitator;
            let result = network_provider.settle(&request).await;
            let _ = response_tx.send(result);
        }
        Ok(())
    }
}
