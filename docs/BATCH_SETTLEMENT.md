# Per-Network Batch Settlement Configuration

This document explains how to configure batch settlement parameters independently for each blockchain network.

## Overview

The facilitator supports per-network configuration for batch settlement, allowing you to tune batching parameters based on each network's characteristics:
- Block times (faster networks can flush more frequently)
- Gas costs (expensive networks benefit from larger batches)
- Traffic patterns (high-volume networks need different tuning)
- Risk tolerance (production vs testnet settings)

## Configuration Structure

Batch settlement configuration has two levels:
1. **Global defaults** - Applied to all networks
2. **Per-network overrides** - Override specific parameters for individual networks

### Global Configuration

```toml
[batch_settlement]
enabled = true                    # Enable batching globally
max_batch_size = 150             # Default max settlements per batch
max_wait_ms = 500                # Default max wait time (milliseconds)
min_batch_size = 10              # Default min size for immediate flush
allow_partial_failure = false    # Default failure mode (strict)
```

### Per-Network Overrides

```toml
[batch_settlement.networks.<network-name>]
max_batch_size = <value>         # Optional: override max batch size
max_wait_ms = <value>            # Optional: override max wait time
min_batch_size = <value>         # Optional: override min batch size
allow_partial_failure = <value>  # Optional: override failure mode
```

**Network names**: `base`, `base-sepolia`, `bsc`, `bsc-testnet`, `avalanche`, `avalanche-fuji`, `polygon`, `polygon-amoy`, `sei`, `sei-testnet`, `xdc`, `solana`, `solana-devnet`

## Example Configurations

### Example 1: Optimize for Different Networks

```toml
[batch_settlement]
enabled = true
max_batch_size = 150
max_wait_ms = 500
min_batch_size = 10
allow_partial_failure = false

# BSC: High throughput with larger batches
[batch_settlement.networks.bsc]
max_batch_size = 200
max_wait_ms = 1000
allow_partial_failure = true

# Base: Low latency for better UX
[batch_settlement.networks.base]
max_batch_size = 50
max_wait_ms = 250
min_batch_size = 5

# Avalanche: Aggressive batching for high throughput
[batch_settlement.networks.avalanche]
max_batch_size = 300
max_wait_ms = 2000
allow_partial_failure = true
```

### Example 2: Production vs Testnet

```toml
[batch_settlement]
enabled = true
max_batch_size = 150
max_wait_ms = 500
min_batch_size = 10
allow_partial_failure = false  # Strict for production

# Testnets: Faster flushing, permissive failure mode
[batch_settlement.networks.base-sepolia]
max_wait_ms = 250
allow_partial_failure = true

[batch_settlement.networks.bsc-testnet]
max_wait_ms = 250
allow_partial_failure = true

[batch_settlement.networks.avalanche-fuji]
max_wait_ms = 250
allow_partial_failure = true
```

### Example 3: Override Only What You Need

Each network can override any subset of parameters. Unspecified parameters use global defaults:

```toml
[batch_settlement]
enabled = true
max_batch_size = 150
max_wait_ms = 500
min_batch_size = 10
allow_partial_failure = false

# Only override batch size for BSC
[batch_settlement.networks.bsc]
max_batch_size = 200

# Only override wait time for Base
[batch_settlement.networks.base]
max_wait_ms = 250
```

## Parameter Guidelines

### max_batch_size
- **Range**: 1-545 (theoretical max based on gas limit)
- **Recommended**: 50-200 for safety
- **Consider**:
  - Gas limits (~30M / ~55k per transfer)
  - Network congestion
  - Risk tolerance

### max_wait_ms
- **Range**: 100-5000 milliseconds
- **Recommended**: 250-1000ms
- **Trade-offs**:
  - Lower = better latency, fewer batches
  - Higher = better throughput, more batching efficiency

### min_batch_size
- **Range**: 1-100
- **Recommended**: 5-20
- **Purpose**: Avoid waiting when enough settlements are ready

### allow_partial_failure
- **Values**: `true` or `false`
- **Default**: `false` (safer)
- **When true**: Individual transfers can fail without reverting entire batch
- **When false**: Any failure reverts all transfers (safer but less throughput)

## How It Works

1. **Queue Creation**: When the first settlement arrives for a (facilitator, network) pair, a queue is created using that network's resolved configuration
2. **Resolution**: The system looks up the network name (e.g., "bsc") and applies any overrides on top of global defaults
3. **Logging**: The resolved configuration is logged when each queue is created:
   ```
   INFO creating new batch queue for facilitator+network pair
     facilitator_addr=0x1234...
     network=bsc
     max_batch_size=200
     max_wait_ms=1000
     min_batch_size=10
     allow_partial_failure=true
   ```

## Monitoring

Check batch queue statistics via the admin endpoint:

```bash
curl -H "X-Admin-Key: your-admin-key" http://localhost:8080/admin/stats
```

Response includes:
```json
{
  "abuse_detection": {
    "total_ips_tracked": 42,
    "suspicious_ips": 0
  },
  "batch_settlement": {
    "active_queues": 3
  }
}
```

## Implementation Details

- **File**: `src/config.rs` - Configuration structures and resolution logic
- **File**: `src/batch_queue.rs` - Queue creation with per-network config
- **Resolution Method**: `BatchSettlementConfig::for_network(network_name)` returns `ResolvedBatchConfig`
- **Logging**: Network-specific settings logged at queue creation time

## Testing

Run the configuration tests:
```bash
cargo test config::tests
```

Tests verify:
- Global defaults
- Per-network overrides
- Partial overrides (mixing global and network-specific)
- Complete overrides (all parameters)

## Best Practices

1. **Start Conservative**: Use global defaults and only override when needed
2. **Monitor Throughput**: Check queue statistics to see if batching is working
3. **Test on Testnets**: Experiment with aggressive settings on testnets first
4. **Consider Block Times**: Faster networks (Base: 2s) can use shorter wait times than slower networks (Ethereum: 12s)
5. **Balance Latency vs Throughput**: Lower wait times = better UX, higher wait times = more efficient batching
6. **Use Partial Failure Carefully**: Only enable on networks/scenarios where you can tolerate individual failures

## Migration from Global Config

If you have existing global configuration:
```toml
[batch_settlement]
enabled = true
max_batch_size = 150
```

It continues to work exactly as before. Networks without overrides use these global defaults.

To add network-specific tuning, simply add network sections:
```toml
[batch_settlement]
enabled = true
max_batch_size = 150

# Add overrides without changing existing behavior for other networks
[batch_settlement.networks.bsc]
max_batch_size = 200
```
