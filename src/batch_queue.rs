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
use std::time::Instant;
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
    /// If no queue exists for this pair, one is created and a background processor is spawned.
    ///
    /// The caller must ensure the network is supported before calling this method.
    pub async fn enqueue(
        &self,
        facilitator_addr: Address,
        network: Network,
        network_provider: &Arc<crate::chain::NetworkProvider>,
        request: SettleRequest,
    ) -> oneshot::Receiver<Result<SettleResponse, FacilitatorLocalError>> {
        // Clone the provider Arc for use in the closure
        let provider_arc_clone = Arc::clone(network_provider);

        // Capture key and queues map for cleanup after process_loop exits
        let key = (facilitator_addr, network);
        let queues_map_clone = Arc::clone(&self.queues);

        // Get or create queue for this (facilitator, network) pair
        let queue = self
            .queues
            .entry(key)
            .or_insert_with(|| {
                // Resolve per-network configuration
                let network_config = self.config.for_network(&network.to_string());

                tracing::info!(
                    %facilitator_addr,
                    %network,
                    max_batch_size = network_config.max_batch_size,
                    max_wait_ms = network_config.max_wait_ms,
                    min_batch_size = network_config.min_batch_size,
                    allow_partial_failure = network_config.allow_partial_failure,
                    "creating new batch queue for facilitator+network pair"
                );

                let queue = Arc::new(BatchQueue::new(
                    network_config.max_batch_size,
                    network_config.max_wait_ms,
                    network_config.min_batch_size,
                    facilitator_addr,
                    network,
                ));

                // Clone the provider Arc and queues map for the background task
                // This ensures only the specific network's provider is held by the background task
                let queue_clone = Arc::clone(&queue);
                let provider_clone = Arc::clone(&provider_arc_clone);
                let queues_map = Arc::clone(&queues_map_clone);
                let allow_partial_failure = network_config.allow_partial_failure;

                tokio::spawn(async move {
                    queue_clone.process_loop(provider_clone, allow_partial_failure).await;

                    // CLEANUP: Remove from DashMap when task exits to release provider Arc
                    queues_map.remove(&key);
                    tracing::info!(
                        facilitator = %key.0,
                        network = %key.1,
                        "removed queue entry from DashMap after process_loop exit"
                    );
                });

                queue
            })
            .clone();

        // Enqueue request
        queue.enqueue(request).await
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
    /// Periodically flushes batches when either max_wait_ms elapses or max_batch_size is reached.
    /// Exits after 30 seconds of inactivity to allow provider references to be dropped.
    pub async fn process_loop(
        self: Arc<Self>,
        network_provider: Arc<crate::chain::NetworkProvider>,
        allow_partial_failure: bool,
    ) {
        const IDLE_TIMEOUT_SECS: u64 = 30;

        let mut ticker = interval(Duration::from_millis(self.max_wait_ms));
        let mut last_batch_time = Instant::now();

        tracing::info!(
            facilitator = %self.facilitator_addr,
            network = %self.network,
            max_batch_size = self.max_batch_size,
            max_wait_ms = self.max_wait_ms,
            min_batch_size = self.min_batch_size,
            idle_timeout_secs = IDLE_TIMEOUT_SECS,
            "batch processor started for queue"
        );

        loop {
            ticker.tick().await;

            // Check if queue is empty
            let is_empty = self.pending.lock().await.is_empty();

            // Exit if idle timeout exceeded
            if is_empty && last_batch_time.elapsed().as_secs() >= IDLE_TIMEOUT_SECS {
                tracing::info!(
                    facilitator = %self.facilitator_addr,
                    network = %self.network,
                    idle_seconds = last_batch_time.elapsed().as_secs(),
                    "batch processor exiting due to idle timeout"
                );
                break;
            }

            if let Err(e) = self.flush_batch(&network_provider, allow_partial_failure).await {
                tracing::error!(
                    facilitator = %self.facilitator_addr,
                    network = %self.network,
                    error = ?e,
                    "failed to flush batch"
                );
            } else if !is_empty {
                // Reset idle timer when we process a non-empty batch
                last_batch_time = Instant::now();
            }
        }

        tracing::info!(
            facilitator = %self.facilitator_addr,
            network = %self.network,
            "batch processor stopped"
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
