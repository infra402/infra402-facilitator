# infra402-facilitator

> Production-ready x402 facilitator with enterprise-grade security features, abuse detection, rate limiting, and multi-chain support.

A hardened x402 payment facilitator built on [x402-rs](https://github.com/x402-rs/x402-rs), enhanced with comprehensive security middleware for production deployments.

## Features

### Core x402 Protocol
- **Payment Verification**: Cryptographic validation of x402 payment payloads
- **Payment Settlement**: On-chain transaction submission and monitoring
- **Multi-Chain Support**: Base, BSC, Solana, Avalanche, Polygon, Sei, XDC networks
- **Protocol Compliance**: Full x402 spec implementation with SDK compatibility

### Security Features
- **Rate Limiting**: Token bucket algorithm with per-IP tracking and automatic bans
- **Abuse Detection**: Tracks invalid signatures, malformed payloads, and suspicious patterns
- **API Key Authentication**: Bearer token auth for `/verify` and `/settle` endpoints
- **Admin Authentication**: Separate admin key for monitoring and statistics endpoints
- **IP Filtering**: Allow/block lists with CIDR support
- **Request Validation**: Size limits and malformed payload detection
- **CORS Control**: Configurable origin restrictions

### Operations & Observability
- **OpenTelemetry**: Full tracing and metrics export (Honeycomb, Prometheus, Grafana)
- **Security Logging**: Detailed audit trail of rate limits, auth failures, and abuse
- **Admin Dashboard**: Real-time statistics via `/admin/stats` endpoint
- **Background Cleanup**: Automatic memory management for tracking data
- **Docker Ready**: Optimized multi-stage builds with minimal runtime dependencies

## Quick Start

### Run with Docker (TBA)

### Basic Configuration

Create a `.env` file:

```bash
# Server
HOST=0.0.0.0
PORT=8080

# Blockchain RPCs
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
RPC_URL_BASE=https://mainnet.base.org

# Signer
SIGNER_TYPE=private-key
EVM_PRIVATE_KEY=0xYourPrivateKeyHere

# Security (optional)
API_KEYS=your-secret-api-key
ADMIN_API_KEY=your-admin-key

# Observability (optional)
RUST_LOG=info
```

Create a `config.toml` (copy from `config.toml.example`):

```toml
[rate_limiting]
enabled = true
requests_per_second = 10
ban_duration_seconds = 300
ban_threshold = 5

[cors]
allowed_origins = ["https://yourdomain.com"]

[security]
log_security_events = true
cleanup_interval_seconds = 300
```

### Build Locally

```bash
cargo build --release
./target/release/infra402-facilitator
```

## API Endpoints

### Public Endpoints
- `GET /` - Service greeting
- `GET /health` - Health check
- `GET /supported` - List supported networks and payment schemes

### Payment Endpoints (API key required if `API_KEYS` set)
- `POST /verify` - Verify payment payload cryptographic signatures
- `POST /settle` - Submit verified payment to blockchain

### Admin Endpoints (admin key required)
- `GET /admin/stats` - Security statistics (tracked IPs, suspicious activity)

### Example: Verify Payment

```bash
curl -X POST https://facilitator.example.com/verify \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "paymentPayload": {...},
    "paymentRequirements": {...}
  }'
```

### Example: Admin Stats

```bash
curl https://facilitator.example.com/admin/stats \
  -H "X-Admin-Key: your-admin-key"
```

Response:
```json
{
  "total_ips_tracked": 42,
  "suspicious_ips": 3
}
```

## Security Configuration

### API Key Authentication

Protect `/verify` and `/settle` endpoints:

```bash
export API_KEYS="key1,key2,key3"
```

Clients must include:
```
Authorization: Bearer <key>
```

### Admin Authentication

Protect admin endpoints:

```bash
export ADMIN_API_KEY="your-admin-secret"
```

Clients must include:
```
X-Admin-Key: <key>
```

### Rate Limiting

Configure in `config.toml`:

```toml
[rate_limiting]
enabled = true
requests_per_second = 10          # Global limit per IP
ban_duration_seconds = 300         # 5 minute ban after violations
ban_threshold = 5                  # Violations before ban

[rate_limiting.endpoints]
verify = 5                         # Override for /verify
settle = 2                         # Override for /settle
```

**Behavior:**
- Exceeding rate limit returns `429 Too Many Requests`
- After `ban_threshold` violations, IP is temporarily banned
- Bans auto-expire after `ban_duration_seconds`

### IP Filtering

```toml
[ip_filtering]
allowed_ips = [
    "192.168.1.0/24",    # Internal network
    "10.0.0.1",          # Specific trusted IP
]

blocked_ips = [
    "192.0.2.0/24",      # Known malicious range
]
```

- Empty `allowed_ips` = allow all (default)
- Blocked IPs always rejected, regardless of allow list
- Supports IPv4, IPv6, and CIDR notation

### CORS Control

```toml
[cors]
allowed_origins = [
    "https://app.example.com",
    "https://dashboard.example.com",
]
```

Empty list = allow all origins (`*`)

### Request Limits

```toml
[request]
max_body_size_bytes = 1048576  # 1 MB
```

Prevents large payload attacks.

## Supported Networks

Configure networks via RPC environment variables:

| Network                | Environment Variable       | Status |
|:-----------------------|:---------------------------|:------:|
| Base Sepolia Testnet   | `RPC_URL_BASE_SEPOLIA`     | ✅      |
| Base Mainnet           | `RPC_URL_BASE`             | ✅      |
| BSC Testnet            | `RPC_URL_BSC_TESTNET`      | ✅      |
| BSC Mainnet            | `RPC_URL_BSC`              | ✅      |
| Solana Devnet          | `RPC_URL_SOLANA_DEVNET`    | ✅      |
| Solana Mainnet         | `RPC_URL_SOLANA`           | ✅      |
| Avalanche Fuji Testnet | `RPC_URL_AVALANCHE_FUJI`   | ✅      |
| Avalanche C-Chain      | `RPC_URL_AVALANCHE`        | ✅      |
| Polygon Amoy Testnet   | `RPC_URL_POLYGON_AMOY`     | ✅      |
| Polygon Mainnet        | `RPC_URL_POLYGON`          | ✅      |
| Sei Testnet            | `RPC_URL_SEI_TESTNET`      | ✅      |
| Sei Mainnet            | `RPC_URL_SEI`              | ✅      |
| XDC Mainnet            | `RPC_URL_XDC`              | ✅      |

Only networks with configured RPC URLs will be available.

## Observability

### OpenTelemetry Export

Configure via environment variables:

```bash
# Honeycomb example
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443
OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=YOUR_API_KEY,x-honeycomb-dataset=infra402-facilitator
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

Emits structured traces with:
- HTTP method, status, URI
- Latency measurements
- Request/response metadata
- Security events (rate limits, auth failures)

### Security Event Logging

Enable in `config.toml`:

```toml
[security]
log_security_events = true
```

Logs include:
- Rate limit violations
- Authentication failures
- IP blocks/bans
- Invalid signatures
- Suspicious activity patterns

**Filter security logs:**
```bash
RUST_LOG=info infra402-facilitator | grep -E "(banned|blocked|unauthorized|suspicious)"
```

## Deployment

### Production Checklist

- ✅ Enable API key authentication (`API_KEYS`)
- ✅ Set admin key (`ADMIN_API_KEY`)
- ✅ Restrict CORS origins in `config.toml`
- ✅ Enable rate limiting
- ✅ Deploy behind HTTPS reverse proxy (Nginx, Caddy, Cloudflare)
- ✅ Configure OpenTelemetry for monitoring
- ✅ Set up log aggregation for security events
- ✅ Test rate limiting and IP filtering before production

### Docker Compose Example

```yaml
version: '3.8'
services:
  facilitator:
    image: ghcr.io/infra402-facilitator:latest
    ports:
      - "8080:8080"
    env_file:
      - .env
    volumes:
      - ./config.toml:/app/config.toml
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Behind Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name facilitator.example.com;

    ssl_certificate /etc/ssl/certs/facilitator.crt;
    ssl_certificate_key /etc/ssl/private/facilitator.key;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

## Environment Variables

### Required
- `SIGNER_TYPE`: Signer type (currently only `private-key` supported)
- `EVM_PRIVATE_KEY`: Hex-encoded private key for EVM chains
- `SOLANA_PRIVATE_KEY`: Base58-encoded private key for Solana (if using Solana)

### Server
- `HOST`: Bind address (default: `0.0.0.0`)
- `PORT`: HTTP port (default: `8080`)

### Security (optional)
- `API_KEYS`: Comma-separated list of valid API keys
- `ADMIN_API_KEY`: Admin authentication key
- `CONFIG_FILE`: Path to config.toml (default: `./config.toml`)

### Network RPCs (configure as needed)
- `RPC_URL_BASE`, `RPC_URL_BASE_SEPOLIA`
- `RPC_URL_BSC`, `RPC_URL_BSC_TESTNET`
- `RPC_URL_SOLANA`, `RPC_URL_SOLANA_DEVNET`
- `RPC_URL_AVALANCHE`, `RPC_URL_AVALANCHE_FUJI`
- `RPC_URL_POLYGON`, `RPC_URL_POLYGON_AMOY`
- `RPC_URL_SEI`, `RPC_URL_SEI_TESTNET`
- `RPC_URL_XDC`

### Observability (optional)
- `RUST_LOG`: Log level (default: `info`)
- `OTEL_EXPORTER_OTLP_ENDPOINT`: OpenTelemetry collector endpoint
- `OTEL_EXPORTER_OTLP_HEADERS`: Headers for OTLP export
- `OTEL_EXPORTER_OTLP_PROTOCOL`: Protocol (`http/protobuf` or `grpc`)

See [`.env.example`](.env.example) for complete configuration template.

## Documentation

- [Original x402-rs README](README.x402-rs.md) - Core x402 protocol documentation
- [Security Documentation](docs/SECURITY.md) - Complete security feature reference
- [Configuration Examples](config.toml.example) - Full config reference

## About x402

The [x402 protocol](https://docs.cdp.coinbase.com/x402/docs/overview) is a standard for making blockchain payments through HTTP using the `402 Payment Required` status code.

**Flow:**
1. Client requests protected resource
2. Server responds with `402 Payment Required` and payment requirements
3. Client creates signed payment payload
4. Facilitator verifies signature and payment details
5. Facilitator settles payment on-chain
6. Server grants access to resource

**Benefits:**
- No server-side blockchain integration required
- Cryptographic payment verification
- Stateless facilitator architecture (never holds funds)
- Compatible with existing HTTP tooling

## Credits

Built on [x402-rs](https://github.com/x402-rs/x402-rs) by Sergey Ukustov.

This repository extends x402-rs with production-ready security features:
- Abuse detection middleware
- Enhanced rate limiting with token bucket algorithm
- Admin authentication and monitoring
- Background cleanup tasks
- Enhanced IP filtering
- Comprehensive security logging

For the original x402-rs implementation and protocol details, see [README.x402-rs.md](README.x402-rs.md).

## Resources

- [x402 Protocol Specification](https://x402.org)
- [x402 Overview by Coinbase](https://docs.cdp.coinbase.com/x402/docs/overview)
- [Facilitator Documentation by Coinbase](https://docs.cdp.coinbase.com/x402/docs/facilitator)
- [x402-rs Repository](https://github.com/x402-rs/x402-rs)

## Development

### Prerequisites
- Rust 1.80+
- Cargo

### Build

```bash
cargo build
```

### Run Locally

```bash
cargo run
```

### Run Tests

```bash
cargo test
```

### Build Docker Image

```bash
docker build -t infra402-facilitator .
```

## Contributing

Contributions welcome! Please open issues or pull requests for:
- Bug fixes
- Security improvements
- Documentation updates
- Feature enhancements

## License

[Apache-2.0](LICENSE)

---

**Security Disclosure:** For security vulnerabilities, please see [docs/SECURITY.md](docs/SECURITY.md#security-disclosure).
