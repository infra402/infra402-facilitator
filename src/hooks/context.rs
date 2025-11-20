//! Runtime context for hook parameter resolution
//!
//! Provides dynamic values available at settlement time (block.timestamp, block.number, etc.)

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;

/// Runtime context available during hook execution
#[derive(Debug, Clone)]
pub struct RuntimeContext {
    /// Current block timestamp (block.timestamp)
    pub timestamp: U256,
    /// Current block number (block.number)
    pub block_number: U256,
    /// Facilitator address (msg.sender in hook calls)
    pub sender: Address,
    /// Settlement batch index (position in current batch)
    pub batch_index: Option<usize>,
    /// Total settlements in current batch
    pub batch_size: Option<usize>,
}

impl RuntimeContext {
    /// Create a new runtime context with the given values
    pub fn new(
        timestamp: U256,
        block_number: U256,
        sender: Address,
    ) -> Self {
        Self {
            timestamp,
            block_number,
            sender,
            batch_index: None,
            batch_size: None,
        }
    }

    /// Create a runtime context by fetching current block info from provider
    pub async fn from_provider<P>(
        provider: &P,
        sender: Address,
    ) -> Result<Self, String>
    where
        P: Provider,
    {
        // Fetch latest block to get timestamp and number
        let block = provider
            .get_block_by_number(alloy::rpc::types::BlockNumberOrTag::Latest)
            .await
            .map_err(|e| format!("Failed to fetch block: {}", e))?
            .ok_or("Block not found")?;

        let timestamp = U256::from(block.header.timestamp);
        let block_number = U256::from(block.header.number);

        Ok(Self::new(timestamp, block_number, sender))
    }

    /// Set batch context information
    pub fn with_batch_info(mut self, index: usize, size: usize) -> Self {
        self.batch_index = Some(index);
        self.batch_size = Some(size);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_runtime_context_creation() {
        let ctx = RuntimeContext::new(
            U256::from(1234567890),
            U256::from(100),
            address!("0x1111111111111111111111111111111111111111"),
        );

        assert_eq!(ctx.timestamp, U256::from(1234567890));
        assert_eq!(ctx.block_number, U256::from(100));
        assert_eq!(ctx.batch_index, None);
        assert_eq!(ctx.batch_size, None);
    }

    #[test]
    fn test_runtime_context_with_batch_info() {
        let ctx = RuntimeContext::new(
            U256::from(1234567890),
            U256::from(100),
            address!("0x1111111111111111111111111111111111111111"),
        ).with_batch_info(5, 10);

        assert_eq!(ctx.batch_index, Some(5));
        assert_eq!(ctx.batch_size, Some(10));
    }
}
