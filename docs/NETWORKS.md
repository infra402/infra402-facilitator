# Supported Networks

Complete guide to configuring blockchain network support in the facilitator.

## Overview

The facilitator supports multiple EVM-compatible and Solana networks. Networks are enabled by configuring their RPC endpoints via environment variables. Only networks with configured RPC URLs will be available.

## Quick Reference

| Network                | Environment Variable       | Chain ID | Status |
|:-----------------------|:---------------------------|:---------|:------:|
| Base Sepolia Testnet   | `RPC_URL_BASE_SEPOLIA`     | 84532    | ✅      |
| Base Mainnet           | `RPC_URL_BASE`             | 8453     | ✅      |
| BSC Testnet            | `RPC_URL_BSC_TESTNET`      | 97       | ✅      |
| BSC Mainnet            | `RPC_URL_BSC`              | 56       | ✅      |
| Solana Devnet          | `RPC_URL_SOLANA_DEVNET`    | -        | ✅      |
| Solana Mainnet         | `RPC_URL_SOLANA`           | -        | ✅      |
| Avalanche Fuji Testnet | `RPC_URL_AVALANCHE_FUJI`   | 43113    | ✅      |
| Avalanche C-Chain      | `RPC_URL_AVALANCHE`        | 43114    | ✅      |
| Polygon Amoy Testnet   | `RPC_URL_POLYGON_AMOY`     | 80002    | ✅      |
| Polygon Mainnet        | `RPC_URL_POLYGON`          | 137      | ✅      |
| Sei Testnet            | `RPC_URL_SEI_TESTNET`      | 1328     | ✅      |
| Sei Mainnet            | `RPC_URL_SEI`              | 1329     | ✅      |
| XDC Mainnet            | `RPC_URL_XDC`              | 50       | ✅      |

## Configuration

### Basic Setup

Add RPC URLs to your `.env` file:

```bash
# Base networks
RPC_URL_BASE=https://mainnet.base.org
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org

# BSC networks
RPC_URL_BSC=https://bsc-dataseed.binance.org
RPC_URL_BSC_TESTNET=https://data-seed-prebsc-1-s1.binance.org:8545

# Solana networks
RPC_URL_SOLANA=https://api.mainnet-beta.solana.com
RPC_URL_SOLANA_DEVNET=https://api.devnet.solana.com

# Avalanche networks
RPC_URL_AVALANCHE=https://api.avax.network/ext/bc/C/rpc
RPC_URL_AVALANCHE_FUJI=https://api.avax-test.network/ext/bc/C/rpc

# Polygon networks
RPC_URL_POLYGON=https://polygon-rpc.com
RPC_URL_POLYGON_AMOY=https://rpc-amoy.polygon.technology

# Sei networks
RPC_URL_SEI=https://evm-rpc.sei-apis.com
RPC_URL_SEI_TESTNET=https://evm-rpc-testnet.sei-apis.com

# XDC network
RPC_URL_XDC=https://rpc.xdcnetwork.com
```

### RPC Provider Options

#### Public RPC Endpoints (Free)

**Pros:**
- No cost
- No registration required
- Quick setup

**Cons:**
- Rate limits
- Shared infrastructure
- No SLA
- Potential downtime

**Example Public Endpoints:**

```bash
# Base
RPC_URL_BASE=https://mainnet.base.org

# BSC
RPC_URL_BSC=https://bsc-dataseed.binance.org

# Polygon
RPC_URL_POLYGON=https://polygon-rpc.com
```

#### Dedicated RPC Providers (Recommended for Production)

**Providers:**
- [Alchemy](https://www.alchemy.com/)
- [Infura](https://www.infura.io/)
- [QuickNode](https://www.quicknode.com/)
- [Ankr](https://www.ankr.com/)
- [GetBlock](https://getblock.io/)

**Pros:**
- Higher rate limits
- Better reliability
- SLA guarantees
- Analytics and monitoring
- Dedicated support

**Cons:**
- Cost (free tiers available)
- Requires account registration

**Example with Alchemy:**

```bash
# Get API key from https://dashboard.alchemy.com/
RPC_URL_BASE=https://base-mainnet.g.alchemy.com/v2/YOUR_API_KEY
RPC_URL_POLYGON=https://polygon-mainnet.g.alchemy.com/v2/YOUR_API_KEY
```

**Example with Infura:**

```bash
# Get API key from https://infura.io/
RPC_URL_BASE=https://base-mainnet.infura.io/v3/YOUR_PROJECT_ID
```

### Verifying Network Configuration

Check which networks are available:

```bash
curl http://localhost:8080/supported
```

Response:
```json
{
  "kinds": [
    {
      "version": "1.0",
      "scheme": "ERC-3009-TransferWithAuthorization",
      "network": "base"
    },
    {
      "version": "1.0",
      "scheme": "ERC-3009-TransferWithAuthorization",
      "network": "bsc"
    }
  ]
}
```

Check startup logs for network initialization:

```
INFO Initialized provider network=base signers=["0xAddress1", "0xAddress2"]
INFO Initialized provider network=bsc signers=["0xAddress3"]
```

## Network-Specific Configuration

### Transaction Timeouts

Configure per-network timeouts in `config.toml`:

```toml
[transaction.chains.bsc]
block_time_seconds = 3
receipt_timeout_blocks = 20        # 60s total
rpc_request_timeout_seconds = 15

[transaction.chains.base]
block_time_seconds = 2
receipt_timeout_blocks = 30        # 60s total
rpc_request_timeout_seconds = 20
```

See [Configuration Guide](CONFIGURATION.md#transaction-configuration) for details.

### Batch Settlement

Configure per-network batch settlement in `config.toml`:

```toml
[batch_settlement.networks.bsc]
max_batch_size = 200
max_wait_ms = 1000

[batch_settlement.networks.base]
max_batch_size = 50
max_wait_ms = 250
```

See [Batch Settlement Guide](BATCH_SETTLEMENT.md) for details.

## Private Keys

### EVM Networks

Configure EVM private keys via `EVM_PRIVATE_KEY`:

```bash
# Single wallet
EVM_PRIVATE_KEY=0xYourPrivateKeyHere

# Multiple wallets for high throughput
EVM_PRIVATE_KEY=0xKey1,0xKey2,0xKey3
```

All EVM networks share the same wallet(s). See [Performance Guide](PERFORMANCE.md) for multi-wallet configuration.

### Solana Networks

Configure Solana private keys via `SOLANA_PRIVATE_KEY`:

```bash
SOLANA_PRIVATE_KEY=YourBase58EncodedPrivateKey
```

Solana networks use separate keys from EVM networks.

## Network Characteristics

### Base (Mainnet)
- **Block Time**: ~2 seconds
- **Gas Token**: ETH
- **Contract Standard**: ERC-3009 USDC
- **Recommended for**: Low latency, high throughput

### BSC (Binance Smart Chain)
- **Block Time**: ~3 seconds
- **Gas Token**: BNB
- **Contract Standard**: ERC-3009 compatible tokens
- **Recommended for**: Low gas costs, high volume

### Solana
- **Block Time**: ~400ms
- **Gas Token**: SOL
- **Contract Standard**: Solana Program Library
- **Recommended for**: Ultra-low latency
- **Note**: Batch settlement not yet supported (processed individually)

### Avalanche C-Chain
- **Block Time**: ~2 seconds
- **Gas Token**: AVAX
- **Contract Standard**: ERC-3009 compatible tokens
- **Recommended for**: Fast finality

### Polygon
- **Block Time**: ~2 seconds
- **Gas Token**: MATIC
- **Contract Standard**: ERC-3009 USDC
- **Recommended for**: Low gas costs

### Sei
- **Block Time**: ~400ms
- **Gas Token**: SEI
- **Contract Standard**: ERC-3009 compatible tokens
- **Recommended for**: High performance

### XDC
- **Block Time**: ~2 seconds
- **Gas Token**: XDC
- **Contract Standard**: ERC-3009 compatible tokens
- **Recommended for**: Enterprise use cases

## Testing Networks

Always test on testnets before deploying to mainnet:

```bash
# Testnets for development
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
RPC_URL_BSC_TESTNET=https://data-seed-prebsc-1-s1.binance.org:8545
RPC_URL_SOLANA_DEVNET=https://api.devnet.solana.com
RPC_URL_AVALANCHE_FUJI=https://api.avax-test.network/ext/bc/C/rpc
RPC_URL_POLYGON_AMOY=https://rpc-amoy.polygon.technology
RPC_URL_SEI_TESTNET=https://evm-rpc-testnet.sei-apis.com
```

## Gas Funding

Facilitator wallets need native tokens for gas fees:

| Network          | Gas Token | Typical Gas Cost per Settlement |
|:-----------------|:----------|:--------------------------------|
| Base             | ETH       | ~$0.01-0.05                     |
| BSC              | BNB       | ~$0.10-0.50                     |
| Solana           | SOL       | ~$0.00001                       |
| Avalanche        | AVAX      | ~$0.01-0.10                     |
| Polygon          | MATIC     | ~$0.001-0.01                    |
| Sei              | SEI       | ~$0.001-0.01                    |
| XDC              | XDC       | ~$0.0001                        |

**Batch settlement** can reduce gas costs by ~75% (see [Batch Settlement Guide](BATCH_SETTLEMENT.md)).

### Funding Wallets

For each network, fund all facilitator wallet addresses with gas tokens:

```bash
# Example: Fund Base wallets with ETH
cast send 0xFacilitatorAddress1 --value 0.1ether --rpc-url $RPC_URL_BASE
cast send 0xFacilitatorAddress2 --value 0.1ether --rpc-url $RPC_URL_BASE
```

## Monitoring

### Check RPC Health

```bash
# EVM networks
curl -X POST $RPC_URL_BASE \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Solana
curl -X POST $RPC_URL_SOLANA \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getHealth","id":1}'
```

### Check Wallet Balances

```bash
# EVM networks
cast balance 0xYourWalletAddress --rpc-url $RPC_URL_BASE --ether

# Solana
solana balance YOUR_PUBLIC_KEY --url $RPC_URL_SOLANA
```

## Troubleshooting

### Network not appearing in /supported

**Cause**: RPC URL not configured or connection failed

**Solution**:
1. Verify environment variable is set: `echo $RPC_URL_BASE`
2. Test RPC connectivity (see Monitoring section above)
3. Check startup logs for errors

### "Unsupported network" error

**Cause**: Client requested a network that's not configured

**Solution**: Add the network's RPC URL to your `.env` file and restart

### RPC rate limit errors

**Cause**: Exceeded public RPC rate limits

**Solution**:
- Use dedicated RPC provider (Alchemy, Infura, etc.)
- Configure multiple RPC URLs with load balancing (future feature)
- Reduce traffic or enable batch settlement

### Transaction timeouts

**Cause**: Network congestion or RPC issues

**Solution**:
- Increase timeouts in `config.toml` (see Transaction Configuration section)
- Use more reliable RPC provider
- Check network status pages

## Further Reading

- [Configuration Guide](CONFIGURATION.md) - Transaction and timeout configuration
- [Performance Guide](PERFORMANCE.md) - Multi-wallet configuration for scaling
- [Batch Settlement Guide](BATCH_SETTLEMENT.md) - Per-network batch configuration
- [Quick Start Guide](QUICK_START.md) - Basic setup instructions
