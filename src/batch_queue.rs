//! Batch queue manager for settlement requests.
//!
//! This module provides a manager that maintains separate queues per (facilitator_address, network) pair.
//! Each queue collects settlement requests and processes them in batches using Multicall3.

use crate::chain::FacilitatorLocalError;
use crate::config::BatchSettlementConfig;
use crate::network::Network;
use crate::types::{SettleRequest, SettleResponse};
use alloy::primitives::Address;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex, oneshot};
use tokio::time::{Duration, interval};

/// Manager for per-(facilitator, network) batch queues.
///
/// Maintains separate queues for each (facilitator_address, network) combination to enable:
/// - Parallel batch processing across different facilitators and networks
/// - Clean integration with per-facilitator settlement locks
/// - Optimal batching without cross-network contamination
pub struct BatchQueueManager {
    /// Map of queues keyed by (facilitator_address, network)
    queues: Arc<DashMap<(Address, Network), Arc<BatchQueue>>>,
    /// Configuration for batch settlement
    config: BatchSettlementConfig,
}

impl BatchQueueManager {
    /// Creates a new BatchQueueManager with the given configuration.
    pub fn new(config: BatchSettlementConfig) -> Self {
        Self {
            queues: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Enqueues a settlement request to the appropriate queue.
    ///
    /// The queue is selected based on the (facilitator_address, network) pair.
    /// If no queue exists for this pair, one is created. A background processor task
    /// is spawned if one is not already running for this queue.
    ///
    /// The caller must ensure the network is supported before calling this method.
    pub async fn enqueue(
        &self,
        facilitator_addr: Address,
        network: Network,
        network_provider: &Arc<crate::chain::NetworkProvider>,
        request: SettleRequest,
    ) -> oneshot::Receiver<Result<SettleResponse, FacilitatorLocalError>> {
        // Capture key for cleanup after process_loop exits
        let key = (facilitator_addr, network);

        // Get or create queue for this (facilitator, network) pair
        let queue = self
            .queues
            .entry(key)
            .or_insert_with(|| {
                // Resolve per-network configuration
                let network_config = self.config.for_network(&network.to_string());

                tracing::debug!(
                    %facilitator_addr,
                    %network,
                    max_batch_size = network_config.max_batch_size,
                    max_wait_ms = network_config.max_wait_ms,
                    min_batch_size = network_config.min_batch_size,
                    allow_partial_failure = network_config.allow_partial_failure,
                    "creating new batch queue for facilitator+network pair"
                );

                Arc::new(BatchQueue::new(
                    network_config.max_batch_size,
                    network_config.max_wait_ms,
                    network_config.min_batch_size,
                    facilitator_addr,
                    network,
                ))
            })
            .clone();

        // Enqueue the request first
        let rx = queue.enqueue(request).await;

        // Check if we need to spawn a background processing task
        // Use compare_exchange to atomically check and set the flag
        if queue.task_running.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ).is_ok() {
            // We successfully set the flag from false to true, so we spawn the task
            let queue_for_loop = Arc::clone(&queue);
            let queue_for_cleanup = Arc::clone(&queue);
            let provider_clone = Arc::clone(network_provider);
            let queues_map = Arc::clone(&self.queues);
            let network_config = self.config.for_network(&network.to_string());
            let allow_partial_failure = network_config.allow_partial_failure;

            tracing::info!(
                %facilitator_addr,
                %network,
                "spawning background batch processor task"
            );

            tokio::spawn(async move {
                queue_for_loop.process_loop(provider_clone, allow_partial_failure).await;

                // Clear the task_running flag
                queue_for_cleanup.task_running.store(false, Ordering::SeqCst);

                // CLEANUP: Remove from DashMap when task exits to release provider Arc
                queues_map.remove(&key);
                tracing::info!(
                    facilitator = %key.0,
                    network = %key.1,
                    "removed queue entry from DashMap after process_loop exit"
                );
            });
        }

        rx
    }

    /// Returns statistics about active queues.
    pub fn stats(&self) -> BatchQueueStats {
        BatchQueueStats {
            active_queues: self.queues.len(),
        }
    }
}

/// Statistics about batch queue manager.
pub struct BatchQueueStats {
    pub active_queues: usize,
}

/// Single batch queue for a specific (facilitator_address, network) pair.
///
/// Collects settlement requests and periodically flushes them as Multicall3 batches.
pub struct BatchQueue {
    /// Pending settlement requests with their response channels
    pending: Arc<Mutex<Vec<(SettleRequest, oneshot::Sender<Result<SettleResponse, FacilitatorLocalError>>)>>>,
    /// Maximum number of settlements per batch
    max_batch_size: usize,
    /// Maximum time to wait before flushing batch (milliseconds)
    max_wait_ms: u64,
    /// Minimum batch size for immediate flush
    min_batch_size: usize,
    /// Facilitator address for this queue
    facilitator_addr: Address,
    /// Network for this queue
    network: Network,
    /// Flag indicating whether a background processing task is currently running
    task_running: Arc<AtomicBool>,
}

impl BatchQueue {
    /// Creates a new BatchQueue for a specific (facilitator, network) pair.
    pub fn new(
        max_batch_size: usize,
        max_wait_ms: u64,
        min_batch_size: usize,
        facilitator_addr: Address,
        network: Network,
    ) -> Self {
        Self {
            pending: Arc::new(Mutex::new(Vec::new())),
            max_batch_size,
            max_wait_ms,
            min_batch_size,
            facilitator_addr,
            network,
            task_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Enqueues a settlement request and returns a channel to receive the result.
    pub async fn enqueue(
        &self,
        request: SettleRequest,
    ) -> oneshot::Receiver<Result<SettleResponse, FacilitatorLocalError>> {
        let (tx, rx) = oneshot::channel();

        let mut pending = self.pending.lock().await;
        pending.push((request, tx));

        tracing::debug!(
            facilitator = %self.facilitator_addr,
            network = %self.network,
            queue_size = pending.len(),
            "enqueued settlement request"
        );

        rx
    }

    /// Run the batch processing loop for this queue.
    ///
    /// Waits for max_wait_ms, then flushes any pending requests and exits.
    /// This ensures the provider Arc is only held during active batch processing.
    /// A new task will be spawned by the next enqueue() call if needed.
    pub async fn process_loop(
        self: Arc<Self>,
        network_provider: Arc<crate::chain::NetworkProvider>,
        allow_partial_failure: bool,
    ) {
        tracing::debug!(
            facilitator = %self.facilitator_addr,
            network = %self.network,
            max_batch_size = self.max_batch_size,
            max_wait_ms = self.max_wait_ms,
            min_batch_size = self.min_batch_size,
            "batch processor task started"
        );

        // Wait for max_wait_ms to allow requests to accumulate
        let mut ticker = interval(Duration::from_millis(self.max_wait_ms));
        ticker.tick().await; // First tick completes immediately
        ticker.tick().await; // Second tick waits for max_wait_ms

        // Flush whatever we have accumulated
        if let Err(e) = self.flush_batch(&network_provider, allow_partial_failure).await {
            tracing::error!(
                facilitator = %self.facilitator_addr,
                network = %self.network,
                error = ?e,
                "failed to flush batch"
            );
        }

        tracing::debug!(
            facilitator = %self.facilitator_addr,
            network = %self.network,
            "batch processor task exiting - provider Arc will be dropped"
        );
    }

    /// Flush the current batch of pending requests.
    async fn flush_batch(
        &self,
        network_provider: &crate::chain::NetworkProvider,
        allow_partial_failure: bool,
    ) -> Result<(), FacilitatorLocalError> {
        // Take up to max_batch_size requests from the queue
        let batch = {
            let mut pending = self.pending.lock().await;
            if pending.is_empty() {
                return Ok(());
            }

            let batch_size = std::cmp::min(pending.len(), self.max_batch_size);
            pending.drain(..batch_size).collect::<Vec<_>>()
        };

        if batch.is_empty() {
            return Ok(());
        }

        tracing::info!(
            facilitator = %self.facilitator_addr,
            network = %self.network,
            batch_size = batch.len(),
            "flushing batch"
        );

        // Process batch using batch_processor
        crate::batch_processor::BatchProcessor::process_batch(
            network_provider,
            self.facilitator_addr,
            batch,
            allow_partial_failure,
        )
        .await
    }
}
