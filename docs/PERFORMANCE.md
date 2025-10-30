# Performance & Scaling Guide

Guide to scaling the facilitator for high-throughput workloads using multi-wallet configuration and batch settlement.

## Overview

The facilitator supports two primary scaling strategies:
1. **Multi-Wallet Configuration**: Multiple facilitator wallets enable concurrent transaction submission
2. **Batch Settlement**: Bundle multiple settlements into single transactions (see [Batch Settlement Guide](BATCH_SETTLEMENT.md))

## Multi-Wallet Configuration

### How It Works

- The facilitator pays gas fees for all settlement transactions
- Each wallet can process one settlement at a time (per-address nonce management)
- Multiple wallets enable parallel processing using round-robin selection
- **Scaling formula**: N wallets = N concurrent settlements

### Configuration

Provide **comma-separated private keys** in the `EVM_PRIVATE_KEY` environment variable:

```bash
# Single wallet (baseline) - ~5 settlements/second
EVM_PRIVATE_KEY=0xabc123...

# 5 wallets - ~25 settlements/second
EVM_PRIVATE_KEY=0xkey1,0xkey2,0xkey3,0xkey4,0xkey5

# 20 wallets - ~100 settlements/second
EVM_PRIVATE_KEY=0xkey1,0xkey2,...,0xkey20
```

### Performance Benchmarks

| Wallets | Concurrent Streams | Approx Throughput | Use Case                   |
|---------|-------------------|-------------------|----------------------------|
| 1       | 1                 | ~5 TPS            | Low traffic (< 10/hour)    |
| 5       | 5                 | ~25 TPS           | Medium (10-100/hour)       |
| 10      | 10                | ~50 TPS           | High (100-500/hour)        |
| 20      | 20                | ~100 TPS          | Very high (500-1000/hour)  |
| 50+     | 50+               | ~250+ TPS         | Enterprise (1000+/hour)    |

**Actual throughput depends on:**
- RPC node performance and rate limits
- Network congestion and block times
- Transaction complexity (EIP-6492 deployments are slower)
- Batch settlement configuration

### Verification

Check startup logs to confirm multiple wallets loaded:

```bash
RUST_LOG=info cargo run
```

Look for:
```
INFO Initialized provider network=bsc signers=["0xWallet1", "0xWallet2", "0xWallet3", ...]
```

The `signers` array should list all your wallet addresses.

## Wallet Management

### Generating Wallets

Generate secure random private keys:

```python
from eth_account import Account
import secrets

num_wallets = 10
keys = []
addresses = []

for i in range(num_wallets):
    private_key = "0x" + secrets.token_hex(32)
    account = Account.from_key(private_key)
    keys.append(private_key)
    addresses.append(account.address)
    print(f"Wallet {i+1}: {account.address}")

# Output for .env file
print("\nEVM_PRIVATE_KEY=" + ",".join(keys))

# Save addresses for funding
with open("wallet_addresses.txt", "w") as f:
    for addr in addresses:
        f.write(addr + "\n")
```

### Gas Funding

Each wallet needs native tokens for gas fees.

**Example: Fund BSC wallets**

```bash
# Fund all wallets with BNB
for address in $(cat wallet_addresses.txt); do
    cast send $address --value 0.1ether --rpc-url $RPC_URL_BSC
done
```

**Monitoring balances:**

```bash
# Check all wallet balances
for address in $(cat wallet_addresses.txt); do
    balance=$(cast balance $address --rpc-url $RPC_URL_BSC --ether)
    echo "$address: $balance BNB"
done
```

### Balance Monitoring (Production)

Set up automated alerts when balances drop below threshold:

```bash
#!/bin/bash
MIN_BALANCE="0.05"  # Minimum BNB balance
WALLETS="0xWallet1 0xWallet2 0xWallet3"

for wallet in $WALLETS; do
    balance=$(cast balance $wallet --rpc-url $RPC_URL_BSC --ether)
    if (( $(echo "$balance < $MIN_BALANCE" | bc -l) )); then
        echo "⚠️ LOW BALANCE: $wallet has only $balance BNB"
        # Send alert (PagerDuty, Slack, email, etc.)
    fi
done
```

## Key Management

### Development

- Store keys in `.env` file (add to `.gitignore`)
- Use separate keys per environment
- Use testnets for development

```bash
# .env (local development)
EVM_PRIVATE_KEY=0xDevKey1,0xDevKey2,0xDevKey3
```

### Production

#### Secret Management Services

**AWS Secrets Manager:**

```bash
# Store keys
aws secretsmanager create-secret \
    --name facilitator/evm-private-keys \
    --secret-string "key1,key2,key3"

# Retrieve at startup
export EVM_PRIVATE_KEY=$(aws secretsmanager get-secret-value \
    --secret-id facilitator/evm-private-keys \
    --query SecretString --output text)
```

**HashiCorp Vault:**

```bash
# Store keys
vault kv put secret/facilitator evm_private_key="key1,key2,key3"

# Retrieve at startup
export EVM_PRIVATE_KEY=$(vault kv get -field=evm_private_key secret/facilitator)
```

**Google Secret Manager:**

```bash
# Store keys
echo -n "key1,key2,key3" | gcloud secrets create facilitator-evm-keys --data-file=-

# Retrieve at startup
export EVM_PRIVATE_KEY=$(gcloud secrets versions access latest --secret=facilitator-evm-keys)
```

#### Best Practices

- ✅ Use secret management services (not environment variables in production)
- ✅ Rotate keys periodically
- ✅ Use separate keys per blockchain network
- ✅ Use separate keys per environment (dev/staging/prod)
- ✅ Consider hardware security modules (HSMs) for highest security
- ✅ Implement key rotation automation
- ✅ Audit key access logs

**⚠️ Security Note**: More wallets = larger attack surface. Secure key storage is critical.

## Scaling Strategy by Traffic Level

### Low Traffic (< 10 settlements/hour)

**Configuration:**
- 1-3 wallets
- Public RPC endpoints acceptable
- Manual funding and monitoring

**Setup:**
```bash
EVM_PRIVATE_KEY=0xKey1,0xKey2,0xKey3
RPC_URL_BSC=https://bsc-dataseed.binance.org
```

**Complexity**: Minimal

### Medium Traffic (10-100 settlements/hour)

**Configuration:**
- 5-10 wallets
- Consider dedicated RPC provider
- Scripted balance checks

**Setup:**
```bash
EVM_PRIVATE_KEY=0xKey1,0xKey2,...,0xKey10
RPC_URL_BSC=https://bsc-mainnet.g.alchemy.com/v2/YOUR_API_KEY
```

**Monitoring script** (cron job):
```bash
# Check balances every hour
0 * * * * /path/to/check_balances.sh
```

**Complexity**: Moderate

### High Traffic (100-1000 settlements/hour)

**Configuration:**
- 20-50 wallets
- Dedicated RPC provider with high tier
- Automated funding + monitoring + alerts
- Consider batch settlement

**Setup:**
```bash
EVM_PRIVATE_KEY=0xKey1,...,0xKey50
RPC_URL_BSC=https://dedicated-node.provider.com

# Enable batch settlement
```

**In `config.toml`:**
```toml
[batch_settlement]
enabled = true
max_batch_size = 150
max_wait_ms = 500
```

**Monitoring**: PagerDuty/Slack alerts for low balances

**Complexity**: High

### Enterprise Scale (1000+ settlements/hour)

**Configuration:**
- 50-100+ wallets
- Dedicated RPC infrastructure or run own nodes
- Full automation, HSMs, key rotation
- Batch settlement enabled
- Per-network tuning

**Setup:**
```bash
# Use secret manager
EVM_PRIVATE_KEY=$(aws secretsmanager get-secret-value ...)
RPC_URL_BSC=https://your-dedicated-node.com
```

**In `config.toml`:**
```toml
[batch_settlement]
enabled = true
max_batch_size = 150
max_wait_ms = 500

[batch_settlement.networks.bsc]
max_batch_size = 300
max_wait_ms = 2000
allow_partial_failure = true
```

**Infrastructure:**
- Kubernetes deployment with auto-scaling
- Load balancing across multiple facilitator instances
- Database for transaction tracking
- Full observability stack (see [Observability Guide](OBSERVABILITY.md))

**Complexity**: Very high

## Batch Settlement

Batch settlement can provide **100-150x throughput improvement** and **~75% gas cost reduction** by bundling multiple settlements into single Multicall3 transactions.

See [Batch Settlement Guide](BATCH_SETTLEMENT.md) for complete configuration.

### Quick Enable

```toml
[batch_settlement]
enabled = true
max_batch_size = 150       # Max settlements per batch
max_wait_ms = 500          # Flush every 500ms
min_batch_size = 10        # Immediate flush if queue reaches 10
allow_partial_failure = false
```

### Per-Network Tuning

```toml
# BSC: Large batches for high throughput
[batch_settlement.networks.bsc]
max_batch_size = 200
max_wait_ms = 1000

# Base: Smaller batches for lower latency
[batch_settlement.networks.base]
max_batch_size = 50
max_wait_ms = 250
```

## RPC Provider Selection

### Public RPC

**When to use:**
- Development and testing
- Low traffic (<10/hour)
- Prototyping

**Limitations:**
- Rate limits
- No SLA
- Shared infrastructure

### Dedicated RPC (Recommended)

**Providers:**
- [Alchemy](https://www.alchemy.com/)
- [Infura](https://www.infura.io/)
- [QuickNode](https://www.quicknode.com/)
- [Ankr](https://www.ankr.com/)

**When to use:**
- Production deployments
- Medium+ traffic
- Need reliability and SLA

**Benefits:**
- Higher rate limits
- Better performance
- Analytics and monitoring
- Support

### Self-Hosted Nodes

**When to use:**
- Enterprise scale
- Complete control needed
- Cost optimization at very high scale

**Considerations:**
- Infrastructure management
- High initial setup cost
- Ongoing maintenance
- Requires expertise

## Monitoring Performance

### Key Metrics

- **Throughput**: Settlements per second/minute/hour
- **Latency**: Time from request to settlement completion
- **Success Rate**: Percentage of successful settlements
- **Queue Depth**: Pending settlements (if using batch settlement)
- **Wallet Balances**: Gas token balances across all wallets

### Admin Stats Endpoint

```bash
curl -H "X-Admin-Key: your-key" http://localhost:8080/admin/stats
```

Response:
```json
{
  "abuse_detection": {
    "total_ips_tracked": 42,
    "suspicious_ips": 3
  },
  "batch_settlement": {
    "active_queues": 5
  }
}
```

### OpenTelemetry

Configure OpenTelemetry for detailed metrics:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443
OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=YOUR_API_KEY
```

See [Observability Guide](OBSERVABILITY.md) for details.

## Troubleshooting Performance

### Low Throughput

**Symptoms**: Actual throughput lower than expected

**Possible Causes**:
1. RPC rate limits
2. Network congestion
3. Not enough wallets
4. Batch settlement disabled

**Solutions**:
- Upgrade to dedicated RPC provider
- Add more wallets
- Enable batch settlement
- Check RPC provider metrics

### Nonce Errors

**Symptoms**: "nonce too low" or "replacement transaction underpriced"

**Cause**: Concurrent transactions from same wallet (should not happen with proper nonce management)

**Solution**: File a bug report - this indicates a nonce management issue

### High Latency

**Symptoms**: Slow settlement times

**Possible Causes**:
1. Network congestion
2. Slow RPC provider
3. Large batch wait times

**Solutions**:
- Use faster RPC provider
- Reduce `max_wait_ms` in batch settlement config
- Check network status

### Wallet Running Out of Gas

**Symptoms**: "insufficient funds for gas"

**Solution**:
- Set up automated balance monitoring
- Configure alerts for low balances
- Implement automated refunding

## Cost Optimization

### Gas Cost Comparison

| Strategy                | Gas Cost per Settlement | Throughput | Total Cost (1000 settlements) |
|------------------------|-------------------------|------------|------------------------------|
| Individual settlements | $0.50                   | ~5 TPS     | $500                         |
| Batch (10)             | $0.12                   | ~50 TPS    | $120                         |
| Batch (100)            | $0.05                   | ~500 TPS   | $50                          |

*Example costs on BSC mainnet*

### Recommendations

- **Low Volume (<100/day)**: Individual settlements, minimal wallets
- **Medium Volume (100-1000/day)**: Enable batching, 5-10 wallets
- **High Volume (1000+/day)**: Aggressive batching, 20+ wallets, per-network tuning

## Further Reading

- [Batch Settlement Guide](BATCH_SETTLEMENT.md) - Detailed batch configuration
- [Networks Guide](NETWORKS.md) - Network-specific characteristics
- [Configuration Guide](CONFIGURATION.md) - Per-network transaction timeouts
- [Observability Guide](OBSERVABILITY.md) - Monitoring and metrics
- [Deployment Guide](DEPLOYMENT.md) - Production deployment best practices
