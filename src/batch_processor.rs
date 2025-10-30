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
            match evm_provider.validate_and_prepare_settlement(&request).await {
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
            "validated settlements - sending Multicall3 batch"
        );

        // Use PRESELECTED_FACILITATOR task-local to ensure correct signer
        use crate::chain::evm::PRESELECTED_FACILITATOR;
        let batch_result = PRESELECTED_FACILITATOR
            .scope(
                facilitator_addr,
                evm_provider.settle_batch(validated_settlements, allow_partial_failure),
            )
            .await;

        match batch_result {
            Ok(responses) => {
                // Send each response back to its requester
                for (response, response_tx) in responses.into_iter().zip(response_channels.into_iter()) {
                    let _ = response_tx.send(Ok(response));
                }
                tracing::info!("batch settlement completed successfully");
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = ?e, "batch settlement failed");
                // Send generic batch failure error to all remaining requesters
                // (can't clone the original error)
                for response_tx in response_channels {
                    let batch_error = FacilitatorLocalError::ContractCall(
                        "Batch settlement failed".to_string()
                    );
                    let _ = response_tx.send(Err(batch_error));
                }
                Err(e)
            }
        }
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
