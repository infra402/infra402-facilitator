# Quick Start Guide

Get the infra402 facilitator up and running in minutes.

## Prerequisites

- Rust 1.80+ and Cargo
- RPC endpoints for your target blockchain networks
- Private key(s) for settlement transactions

## Installation

### Option 1: Build from Source

```bash
git clone https://github.com/your-org/infra402-facilitator.git
cd infra402-facilitator
cargo build --release
```

### Option 2: Docker (Coming Soon)

```bash
docker pull ghcr.io/infra402-facilitator:latest
```

## Basic Configuration

### 1. Create Environment File

Create a `.env` file in the project root:

```bash
# Server Configuration
HOST=0.0.0.0
PORT=8080

# Blockchain RPC Endpoints
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
RPC_URL_BASE=https://mainnet.base.org
RPC_URL_BSC=https://bsc-dataseed.binance.org

# Signer Configuration
SIGNER_TYPE=private-key
EVM_PRIVATE_KEY=0xYourPrivateKeyHere

# Optional: Security
API_KEYS=your-secret-api-key-here
ADMIN_API_KEY=your-admin-key-here

# Optional: Logging
RUST_LOG=info
```

### 2. Create Configuration File

Copy the example configuration:

```bash
cp config.toml config.toml
```

Edit `config.toml` for basic security (or leave defaults):

```toml
[rate_limiting]
enabled = true
requests_per_second = 10

[cors]
allowed_origins = []  # Empty = allow all (suitable for testing)

[security]
log_security_events = true
```

### 3. Run the Facilitator

```bash
cargo run --release
```

Or if built:

```bash
./target/release/infra402-facilitator
```

## Verify It's Running

### Check Health Endpoint

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "kinds": [
    {
      "version": "1.0",
      "scheme": "ERC-3009-TransferWithAuthorization",
      "network": "base-sepolia"
    }
  ]
}
```

### Check Root Endpoint

```bash
curl http://localhost:8080/
```

You should see an HTML page listing all available endpoints.

## Test a Payment Verification

Create a test payload file `test-verify.json`:

```json
{
  "paymentPayload": {
    "version": "1.0",
    "scheme": "ERC-3009-TransferWithAuthorization",
    "network": "base-sepolia",
    "from": "0xYourWalletAddress",
    "to": "0xFacilitatorAddress",
    "value": "1000000",
    "validAfter": "0",
    "validBefore": "999999999999",
    "nonce": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "signature": "0xYourSignatureHere"
  },
  "paymentRequirements": {
    "version": "1.0",
    "scheme": "ERC-3009-TransferWithAuthorization",
    "network": "base-sepolia",
    "to": "0xFacilitatorAddress",
    "value": "1000000"
  }
}
```

Test verification:

```bash
curl -X POST http://localhost:8080/verify \
  -H "Authorization: Bearer your-api-key-here" \
  -H "Content-Type: application/json" \
  -d @test-verify.json
```

## Next Steps

- **Security Setup**: See [Configuration Guide](CONFIGURATION.md) for production security settings
- **Multi-Chain**: See [Networks Guide](NETWORKS.md) to enable additional blockchain networks
- **Scaling**: See [Performance Guide](PERFORMANCE.md) for multi-wallet setup
- **Batch Settlement**: See [Batch Settlement Guide](BATCH_SETTLEMENT.md) for high-throughput configuration
- **Deployment**: See [Deployment Guide](DEPLOYMENT.md) for production deployment

## Common Issues

### "Failed to create Ethereum providers"

**Cause**: RPC URL not configured or unreachable

**Solution**: Check your `RPC_URL_*` environment variables and ensure the endpoints are accessible:

```bash
curl -X POST $RPC_URL_BASE \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### "Invalid signature" errors

**Cause**: Signature doesn't match the payload or wrong signer

**Solution**: Ensure the payment payload signature was created correctly with EIP-712 and the signer address matches the `from` field.

### Port already in use

**Cause**: Another process is using port 8080

**Solution**: Change the `PORT` in your `.env` file:

```bash
PORT=8081
```

## Getting Help

- **API Reference**: See [API Documentation](API.md)
- **Configuration**: See [Configuration Guide](CONFIGURATION.md)
- **Security Issues**: See [Security Documentation](SECURITY.md)
- **x402 Protocol**: See [x402 Protocol Reference](X402_PROTOCOL.md)
