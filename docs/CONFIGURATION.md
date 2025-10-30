# Configuration Guide

Complete reference for configuring security, rate limiting, CORS, IP filtering, and other operational settings.

## Configuration File

The facilitator reads configuration from `config.toml` in the project root directory. You can specify a custom path via the `CONFIG_FILE` environment variable:

```bash
CONFIG_FILE=/path/to/custom-config.toml infra402-facilitator
```

## Configuration Structure

```toml
[rate_limiting]
# Rate limiting settings

[cors]
# CORS settings

[ip_filtering]
# IP allow/block lists

[request]
# Request validation settings

[security]
# Security and logging settings

[transaction]
# Chain-specific transaction settings

[batch_settlement]
# Batch settlement settings
```

## Rate Limiting Configuration

### Basic Rate Limiting

```toml
[rate_limiting]
enabled = true
requests_per_second = 10          # Global limit per IP
ban_duration_seconds = 300         # 5 minutes
ban_threshold = 5                  # Violations before ban
```

### Parameters

- **`enabled`** (boolean): Enable/disable rate limiting globally
  - Default: `true`

- **`requests_per_second`** (integer): Maximum requests per second per IP address
  - Default: `10`
  - Applies to all endpoints unless overridden

- **`ban_duration_seconds`** (integer): Duration in seconds to ban an IP after exceeding `ban_threshold`
  - Default: `300` (5 minutes)

- **`ban_threshold`** (integer): Number of rate limit violations before triggering a ban
  - Default: `5`

### Per-Endpoint Overrides

Override rate limits for specific endpoints:

```toml
[rate_limiting.endpoints]
verify = 25    # 25 requests/second for /verify
settle = 25    # 25 requests/second for /settle
health = 100   # 100 requests/second for /health
```

Endpoint names should match route paths without the leading slash.

### Behavior

1. **Normal Operation**: Requests within limit are processed normally
2. **Rate Limit Exceeded**: Returns `429 Too Many Requests` with `Retry-After` header
3. **Ban Trigger**: After `ban_threshold` violations, IP is banned for `ban_duration_seconds`
4. **Ban Active**: Returns `403 Forbidden` for all requests during ban period
5. **Ban Expiry**: Ban automatically expires and IP can retry

## CORS Configuration

### Allow All Origins (Development)

```toml
[cors]
allowed_origins = []
```

Empty list allows all origins (`*`).

### Restrict Origins (Production)

```toml
[cors]
allowed_origins = [
    "https://app.example.com",
    "https://dashboard.example.com",
]
```

Only specified origins will be permitted for cross-origin requests.

### Parameters

- **`allowed_origins`** (array of strings): List of allowed origin URLs
  - Default: `[]` (allow all)
  - Format: Full URL including protocol (e.g., `https://example.com`)

## IP Filtering Configuration

### Allow/Block Lists

```toml
[ip_filtering]
allowed_ips = [
    "192.168.1.0/24",    # Internal network CIDR
    "10.0.0.1",          # Specific IP
    "2001:db8::/32",     # IPv6 CIDR
]

blocked_ips = [
    "192.0.2.0/24",      # Known malicious range
    "198.51.100.50",     # Specific blocked IP
]
```

### Parameters

- **`allowed_ips`** (array of strings): Allowed IP addresses or CIDR blocks
  - Default: `[]` (allow all)
  - If specified, **only** these IPs/ranges will be allowed
  - Supports IPv4, IPv6, and CIDR notation

- **`blocked_ips`** (array of strings): Blocked IP addresses or CIDR blocks
  - Default: `[]`
  - IPs on this list are **always** rejected, regardless of allow list
  - Supports IPv4, IPv6, and CIDR notation

### Precedence

1. **Blocked list** is checked first
2. If IP is in `blocked_ips`, request is rejected (`403 Forbidden`)
3. If `allowed_ips` is non-empty and IP is **not** in the list, request is rejected
4. Otherwise, request proceeds to next middleware

## Request Configuration

### Body Size Limits

```toml
[request]
max_body_size_bytes = 1048576  # 1 MB
```

### Parameters

- **`max_body_size_bytes`** (integer): Maximum size of HTTP request body in bytes
  - Default: `1048576` (1 MB)
  - Requests exceeding this size return `413 Payload Too Large`

## Security Configuration

### General Security Settings

```toml
[security]
health_endpoint_requires_auth = false
log_security_events = true
cleanup_interval_seconds = 300
```

### Parameters

- **`health_endpoint_requires_auth`** (boolean): Require API key for `/health` endpoint
  - Default: `false` (public access)

- **`log_security_events`** (boolean): Enable logging of security-related events
  - Default: `true`
  - Logs: rate limit violations, auth failures, blocked IPs, suspicious activity

- **`cleanup_interval_seconds`** (integer): Interval in seconds for background cleanup of tracking data
  - Default: `300` (5 minutes)
  - Cleans up: old abuse detection data, expired rate limit bans

### API Key Authentication

Configured via environment variables (not `config.toml`):

```bash
# Enable API key auth for /verify and /settle
export API_KEYS="key1,key2,key3"

# Enable admin key auth for /admin/*
export ADMIN_API_KEY="your-admin-secret"
```

**API Keys**:
- Comma-separated list
- Clients use: `Authorization: Bearer <key>`
- Applied to: `/verify`, `/settle`

**Admin Key**:
- Single secret key
- Clients use: `X-Admin-Key: <key>`
- Applied to: `/admin/*`

## Transaction Configuration

### Default Timeout

```toml
[transaction]
default_rpc_timeout_seconds = 30
```

### Per-Chain Configuration

Configure block times and timeouts for each blockchain network:

```toml
[transaction.chains.bsc]
block_time_seconds = 3
receipt_timeout_blocks = 20        # 60s total (20 * 3s)
rpc_request_timeout_seconds = 15

[transaction.chains.base]
block_time_seconds = 2
receipt_timeout_blocks = 30        # 60s total (30 * 2s)
rpc_request_timeout_seconds = 20

[transaction.chains.polygon]
block_time_seconds = 2
receipt_timeout_blocks = 30
rpc_request_timeout_seconds = 20

[transaction.chains.avalanche]
block_time_seconds = 2
receipt_timeout_blocks = 30
rpc_request_timeout_seconds = 20
```

### Parameters

- **`default_rpc_timeout_seconds`** (integer): Fallback RPC timeout when chain-specific config is missing
  - Default: `30`

#### Per-Chain Parameters

- **`block_time_seconds`** (integer): Average block time for this chain
- **`receipt_timeout_blocks`** (integer): Number of blocks to wait for transaction receipt
  - Total timeout = `block_time_seconds * receipt_timeout_blocks`
- **`rpc_request_timeout_seconds`** (integer): Timeout for individual RPC requests

### Supported Chain Names

- `bsc`, `bsc-testnet`
- `base`, `base-sepolia`
- `polygon`, `polygon-amoy`
- `avalanche`, `avalanche-fuji`
- `sei`, `sei-testnet`
- `xdc`
- `solana`, `solana-devnet`

## Batch Settlement Configuration

See [Batch Settlement Guide](BATCH_SETTLEMENT.md) for complete configuration reference.

### Quick Example

```toml
[batch_settlement]
enabled = true
max_batch_size = 150
max_wait_ms = 500
min_batch_size = 10
allow_partial_failure = false

# Per-network overrides
[batch_settlement.networks.bsc]
max_batch_size = 200
max_wait_ms = 1000
```

## Environment Variables

Some settings are configured via environment variables instead of `config.toml`.

### Server

```bash
HOST=0.0.0.0        # Bind address (default: 0.0.0.0)
PORT=8080           # HTTP port (default: 8080)
```

### Security

```bash
API_KEYS=key1,key2,key3           # API key authentication
ADMIN_API_KEY=admin-secret         # Admin authentication
CONFIG_FILE=/path/to/config.toml   # Custom config path
```

### RPC Endpoints

See [Networks Guide](NETWORKS.md) for network-specific RPC configuration.

### Observability

```bash
RUST_LOG=info                                              # Log level
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443  # OpenTelemetry endpoint
OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=API_KEY       # OTLP headers
```

## Configuration Examples

### Development (Permissive)

```toml
[rate_limiting]
enabled = false

[cors]
allowed_origins = []

[ip_filtering]
allowed_ips = []
blocked_ips = []

[security]
log_security_events = true
```

### Production (Strict)

```toml
[rate_limiting]
enabled = true
requests_per_second = 50
ban_duration_seconds = 600
ban_threshold = 5

[rate_limiting.endpoints]
verify = 25
settle = 25

[cors]
allowed_origins = [
    "https://app.example.com",
    "https://dashboard.example.com",
]

[ip_filtering]
allowed_ips = []  # Or specify trusted IPs
blocked_ips = [
    # Add known malicious IPs/ranges
]

[request]
max_body_size_bytes = 1048576

[security]
health_endpoint_requires_auth = false
log_security_events = true
cleanup_interval_seconds = 3600
```

With environment variables:

```bash
API_KEYS=prod-key-1,prod-key-2,prod-key-3
ADMIN_API_KEY=secure-admin-secret-here
RUST_LOG=info
```

## Reloading Configuration

Configuration changes require a service restart:

```bash
# Send SIGTERM for graceful shutdown
kill -TERM $(pidof infra402-facilitator)

# Restart
./infra402-facilitator
```

Or with systemd:

```bash
sudo systemctl restart infra402-facilitator
```

## Validating Configuration

Test your configuration before deploying:

```bash
# Dry-run to check for parsing errors
cargo run --release 2>&1 | grep -i "configuration"
```

Check startup logs for confirmation:

```
INFO Configuration loaded successfully
INFO Rate limiting enabled: true
INFO CORS: Allowing all origins (*)
INFO Security: log_security_events=true
```

## Further Reading

- [Security Documentation](SECURITY.md) - Security best practices and hardening
- [API Reference](API.md) - API endpoints and authentication
- [Deployment Guide](DEPLOYMENT.md) - Production deployment checklist
- [Batch Settlement Guide](BATCH_SETTLEMENT.md) - High-throughput configuration
