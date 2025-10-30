# infra402-facilitator

> Production-ready x402 payment facilitator with enterprise security, multi-chain support, and high-throughput batch settlement.

A hardened [x402 protocol](https://x402.org) facilitator built on [x402-rs](https://github.com/x402-rs/x402-rs), featuring comprehensive security middleware, abuse detection, rate limiting, and Multicall3 batch settlement for production deployments.

## Features

### Core Protocol
- ✅ **x402 Compliance**: Full protocol implementation with TypeScript/Go/Rust SDK compatibility
- ✅ **Multi-Chain**: Base, BSC, Solana, Avalanche, Polygon, Sei, XDC networks
- ✅ **Payment Verification**: Cryptographic signature validation and balance checks
- ✅ **Payment Settlement**: On-chain transaction submission and monitoring

### Security & Operations
- 🔒 **Enterprise Security**: Rate limiting, API keys, IP filtering, abuse detection
- 📊 **Observability**: OpenTelemetry tracing, structured logging, admin stats
- ⚡ **High Performance**: Multi-wallet concurrency, Multicall3 batch settlement (100-150x throughput)
- 🐳 **Cloud Native**: Docker, Kubernetes, systemd deployment options

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/infra402-facilitator.git
cd infra402-facilitator

# Build
cargo build --release
```

### Basic Configuration

Create `.env`:

```bash
# Server
HOST=0.0.0.0
PORT=8080

# RPC Endpoints
RPC_URL_BASE=https://mainnet.base.org
RPC_URL_BSC=https://bsc-dataseed.binance.org

# Signer
SIGNER_TYPE=private-key
EVM_PRIVATE_KEY=0xYourPrivateKeyHere

# Security (optional)
API_KEYS=your-api-key-here
ADMIN_API_KEY=your-admin-key-here
```

### Run

```bash
./target/release/infra402-facilitator
```

Verify it's running:
```bash
curl http://localhost:8080/health
```

**→ [Complete Quick Start Guide](docs/QUICK_START.md)**

## Documentation

### Getting Started
- **[Quick Start Guide](docs/QUICK_START.md)** - Get up and running in 5 minutes
- **[API Reference](docs/API.md)** - Complete HTTP endpoint documentation
- **[Configuration Guide](docs/CONFIGURATION.md)** - Security, rate limiting, and operational settings

### Network & Performance
- **[Networks Guide](docs/NETWORKS.md)** - Supported blockchains and RPC configuration
- **[Performance Guide](docs/PERFORMANCE.md)** - Multi-wallet scaling for high throughput
- **[Batch Settlement Guide](docs/BATCH_SETTLEMENT.md)** - 100-150x throughput with Multicall3

### Operations
- **[Observability Guide](docs/OBSERVABILITY.md)** - Logging, tracing, and monitoring
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Docker, Kubernetes, production deployment
- **[Security Documentation](docs/SECURITY.md)** - Security best practices and hardening

### Development
- **[Development Guide](docs/DEVELOPMENT.md)** - Contributing, testing, and development workflow
- **[x402 Protocol Reference](docs/X402_PROTOCOL.md)** - Protocol specification and implementation details

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   HTTP Endpoints                      │
│  GET /health  │  POST /verify  │  POST /settle       │
└────────────┬─────────────────────────────────────────┘
             │
┌────────────▼─────────────────────────────────────────┐
│              Security Middleware                      │
│  Rate Limit │ IP Filter │ API Key │ Abuse Detection  │
└────────────┬─────────────────────────────────────────┘
             │
┌────────────▼─────────────────────────────────────────┐
│             Facilitator Core                          │
│  Payment Verification │ Signature Validation          │
└────────────┬─────────────────────────────────────────┘
             │
     ┌───────┴────────┐
     │                │
┌────▼──────┐  ┌──────▼────────────────────────────────┐
│  Direct   │  │   Batch Settlement Queue Manager      │
│ Settlement│  │  • Per-(facilitator, network) queues  │
└────┬──────┘  │  • Multicall3 batching                │
     │         │  • 100-150x throughput                 │
     │         └──────┬────────────────────────────────┘
     │                │
┌────▼────────────────▼────────────────────────────────┐
│           Multi-Wallet Round-Robin                    │
│  Wallet 1 │ Wallet 2 │ ... │ Wallet N                │
└────┬────────────────┬────────────────────────────────┘
     │                │
┌────▼────────────────▼────────────────────────────────┐
│              Blockchain Networks                      │
│  Base │ BSC │ Solana │ Avalanche │ Polygon │ ...     │
└──────────────────────────────────────────────────────┘
```

## Use Cases

### Low Traffic (< 10 settlements/hour)
- Single wallet, public RPC endpoints
- Basic security configuration
- **Cost**: ~$0.50/settlement

### Medium Traffic (10-100 settlements/hour)
- 5-10 wallets, dedicated RPC provider
- Rate limiting and monitoring
- **Cost**: ~$0.50/settlement

### High Traffic (100-1000 settlements/hour)
- 20+ wallets, batch settlement enabled
- Per-network configuration tuning
- **Cost**: ~$0.12/settlement (75% savings)

### Enterprise (1000+ settlements/hour)
- 50+ wallets, aggressive batching
- Multi-region deployment, HSMs
- Full observability stack
- **Cost**: ~$0.05/settlement (90% savings)

**→ [Performance & Scaling Guide](docs/PERFORMANCE.md)**

## Key Features

### Batch Settlement

Bundle multiple settlements into single Multicall3 transactions for massive throughput improvements:

```toml
[batch_settlement]
enabled = true
max_batch_size = 150
max_wait_ms = 500

# Per-network tuning
[batch_settlement.networks.bsc]
max_batch_size = 200
max_wait_ms = 1000
```

**Benefits:**
- **100-150x throughput** increase (1 nonce instead of 150)
- **~75% gas cost reduction** (shared transaction overhead)
- **Per-network configuration** (tune for each blockchain's characteristics)

**→ [Batch Settlement Guide](docs/BATCH_SETTLEMENT.md)**

### Multi-Wallet Concurrency

Scale settlement throughput with multiple facilitator wallets:

```bash
# 5 wallets = ~25 settlements/second
EVM_PRIVATE_KEY=0xKey1,0xKey2,0xKey3,0xKey4,0xKey5

# 50 wallets = ~250 settlements/second
EVM_PRIVATE_KEY=0xKey1,...,0xKey50
```

**→ [Performance Guide](docs/PERFORMANCE.md)**

### Enterprise Security

Comprehensive security middleware for production:

```toml
[rate_limiting]
enabled = true
requests_per_second = 50
ban_threshold = 5

[ip_filtering]
allowed_ips = ["192.168.1.0/24"]
blocked_ips = ["192.0.2.0/24"]

[security]
log_security_events = true
```

**→ [Configuration Guide](docs/CONFIGURATION.md)**

## Supported Networks

| Network           | Mainnet | Testnet            | Status |
|:------------------|:--------|:-------------------|:------:|
| Base              | ✅       | ✅ Base Sepolia     | ✅      |
| BSC               | ✅       | ✅ BSC Testnet      | ✅      |
| Solana            | ✅       | ✅ Solana Devnet    | ✅      |
| Avalanche C-Chain | ✅       | ✅ Fuji Testnet     | ✅      |
| Polygon           | ✅       | ✅ Amoy Testnet     | ✅      |
| Sei               | ✅       | ✅ Sei Testnet      | ✅      |
| XDC               | ✅       | -                  | ✅      |

**→ [Networks Guide](docs/NETWORKS.md)**

## API Endpoints

### Public
- `GET /` - Service information
- `GET /health` - Health check with supported networks
- `GET /supported` - List supported payment schemes

### Payment (API key required)
- `POST /verify` - Verify payment signature and balance
- `POST /settle` - Submit payment to blockchain

### Admin (admin key required)
- `GET /admin/stats` - Security and queue statistics

**→ [API Reference](docs/API.md)**

## Monitoring

```bash
# Admin stats
curl -H "X-Admin-Key: your-key" http://localhost:8080/admin/stats
```

```json
{
  "abuse_detection": {
    "total_ips_tracked": 142,
    "suspicious_ips": 5
  },
  "batch_settlement": {
    "active_queues": 8
  }
}
```

**→ [Observability Guide](docs/OBSERVABILITY.md)**

## Deployment

### Docker

```bash
docker run -d \
  -p 8080:8080 \
  --env-file .env \
  -v ./config.toml:/app/config.toml:ro \
  infra402-facilitator:latest
```

### Kubernetes

```bash
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
```

### Systemd

```bash
sudo systemctl enable facilitator
sudo systemctl start facilitator
```

**→ [Deployment Guide](docs/DEPLOYMENT.md)**

## Environment Variables

### Required
```bash
SIGNER_TYPE=private-key
EVM_PRIVATE_KEY=0xYourPrivateKey    # Comma-separated for multiple wallets
```

### Network RPCs
```bash
RPC_URL_BASE=https://mainnet.base.org
RPC_URL_BSC=https://bsc-dataseed.binance.org
RPC_URL_SOLANA=https://api.mainnet-beta.solana.com
# ... (see Networks Guide for complete list)
```

### Security (Optional)
```bash
API_KEYS=key1,key2,key3
ADMIN_API_KEY=admin-secret
CONFIG_FILE=./config.toml
```

### Observability (Optional)
```bash
RUST_LOG=info
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443
OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=YOUR_API_KEY
```

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run locally
cargo run

# Format and lint
cargo fmt
cargo clippy
```

**→ [Development Guide](docs/DEVELOPMENT.md)**

## About x402

The [x402 protocol](https://x402.org) enables blockchain payments through HTTP using the `402 Payment Required` status code. Facilitators verify payment signatures off-chain and execute settlements on-chain, eliminating the need for server-side blockchain integration.

**→ [x402 Protocol Reference](docs/X402_PROTOCOL.md)**

## Credits

Built on [x402-rs](https://github.com/x402-rs/x402-rs) by Sergey Ukustov, extended with:
- Enterprise security features (rate limiting, abuse detection, IP filtering)
- Multi-wallet concurrency for horizontal scaling
- Multicall3 batch settlement for 100-150x throughput
- Comprehensive observability (OpenTelemetry, structured logging)
- Production deployment tooling (Docker, Kubernetes, systemd)

## Resources

- **x402 Protocol**: [x402.org](https://x402.org)
- **Coinbase x402 Docs**: [docs.cdp.coinbase.com/x402](https://docs.cdp.coinbase.com/x402/docs/overview)
- **x402-rs Repository**: [github.com/x402-rs/x402-rs](https://github.com/x402-rs/x402-rs)
- **Issues**: [GitHub Issues](https://github.com/your-org/infra402-facilitator/issues)
- **Security**: See [Security Policy](docs/SECURITY.md)

## License

[Apache-2.0](LICENSE)

---

**Need help?** Check the [documentation](docs/) or [open an issue](https://github.com/your-org/infra402-facilitator/issues).

**Security disclosure?** See [Security Policy](docs/SECURITY.md#security-disclosure).
