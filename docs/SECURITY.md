# Security Features

This document describes the security features available in the x402 facilitator and how to configure them for production deployments.

## Overview

The x402 facilitator includes comprehensive protection mechanisms to prevent abuse and secure your deployment:

1. **Rate Limiting** - Prevent abuse with per-IP request limits
2. **API Key Authentication** - Restrict access to authorized clients
3. **IP Filtering** - Allow/block specific IP addresses or ranges
4. **Request Validation** - Detect and track suspicious behavior
5. **CORS Control** - Restrict cross-origin requests
6. **Request Size Limits** - Prevent large payload attacks

All security features are **optional** and **backwards compatible** with existing deployments.

## Quick Start

### Basic Production Setup

1. **Copy the example configuration:**
   ```bash
   cp config.toml.example config.toml
   ```

2. **Set API keys (recommended for production):**
   ```bash
   export API_KEYS="your-secret-key-1,your-secret-key-2"
   ```

3. **Configure rate limiting in `config.toml`:**
   ```toml
   [rate_limiting]
   enabled = true
   requests_per_second = 10
   ban_duration_seconds = 300
   ban_threshold = 5
   ```

4. **Restrict CORS origins:**
   ```toml
   [cors]
   allowed_origins = ["https://yourdomain.com"]
   ```

## Configuration

### 1. Rate Limiting

Protects against abuse by limiting requests per IP address.

**Features:**
- Global rate limits (requests/second per IP)
- Per-endpoint overrides
- Automatic temporary bans after repeated violations
- Configurable ban duration

**Configuration (`config.toml`):**
```toml
[rate_limiting]
enabled = true
requests_per_second = 10           # Global limit
ban_duration_seconds = 300          # 5 minutes
ban_threshold = 5                   # violations before ban

[rate_limiting.endpoints]
verify = 5                          # Override for /verify
settle = 2                          # Override for /settle
```

**Behavior:**
- Exceeding rate limit returns `429 Too Many Requests`
- After `ban_threshold` violations within tracking window, IP is temporarily banned
- Bans automatically expire after `ban_duration_seconds`
- Ban status returns `429` with message "IP temporarily banned"

### 2. API Key Authentication

Requires valid API keys for protected endpoints (`/verify` and `/settle`).

**Configuration (environment variable):**
```bash
# Comma-separated list of valid API keys
export API_KEYS="key1,key2,key3"
```

**Behavior:**
- If `API_KEYS` is not set or empty: authentication **disabled** (backwards compatible)
- If `API_KEYS` is set: authentication **required** for `/verify` and `/settle`
- Public endpoints (`/`, `/supported`, `/health`) remain accessible without auth

**Client Usage:**
```bash
curl -H "Authorization: Bearer your-key-here" \
  -X POST https://facilitator.example.com/verify \
  -d '{"paymentPayload": ..., "paymentRequirements": ...}'
```

**Error Responses:**
- `401 Unauthorized` - Missing or invalid API key
- Error messages:
  - "Missing Authorization header"
  - "Invalid Authorization header format (expected 'Bearer <token>')"
  - "Invalid API key"

### 3. IP Filtering

Allow or block specific IP addresses and CIDR ranges.

**Configuration (`config.toml`):**
```toml
[ip_filtering]
# Allow list (empty = allow all)
allowed_ips = [
    "192.168.1.0/24",
    "10.0.0.1",
]

# Block list (always enforced)
blocked_ips = [
    "192.0.2.0/24",
    "198.51.100.50",
]
```

**Behavior:**
- Block list checked first (takes precedence)
- If allow list is non-empty, only listed IPs/ranges are allowed
- Returns `403 Forbidden` for blocked/disallowed IPs
- Extracts IP from `X-Forwarded-For`, `X-Real-IP`, or connection peer address

**Use Cases:**
- **Private facilitator**: Set allow list to internal network ranges
- **Block malicious IPs**: Add known bad actors to block list
- **Partner-only access**: Allow specific partner IP ranges

### 4. Request Validation & Abuse Detection

Tracks suspicious patterns like repeated invalid signatures.

**Configuration (`config.toml`):**
```toml
[security]
log_security_events = true
```

**Features:**
- Tracks invalid signature attempts per IP
- Logs warnings when thresholds exceeded
- Tracks malformed payload submissions
- Automatic cleanup of old tracking data

**Logged Events:**
- Invalid signatures exceeding threshold
- Malformed payloads
- Authentication failures
- Rate limit violations
- IP filter blocks

### 5. CORS Configuration

Control which origins can access your facilitator.

**Configuration (`config.toml`):**
```toml
[cors]
# Empty = allow all origins (*)
allowed_origins = []

# Production: specify exact origins
allowed_origins = [
    "https://app.example.com",
    "https://dashboard.example.com",
]
```

**Security Impact:**
- Empty list allows all origins (suitable for public facilitators)
- Specifying origins prevents unauthorized web applications from using your facilitator

### 6. Request Size Limits

Prevent large payload attacks.

**Configuration (`config.toml`):**
```toml
[request]
max_body_size_bytes = 1048576  # 1 MB
```

**Behavior:**
- Requests exceeding size limit are rejected with `413 Payload Too Large`
- Applied globally to all POST endpoints

## Security Best Practices

### For Production Deployments

1. ✅ **Enable API key authentication**
   ```bash
   export API_KEYS="$(openssl rand -hex 32)"
   ```

2. ✅ **Restrict CORS origins**
   ```toml
   [cors]
   allowed_origins = ["https://yourdomain.com"]
   ```

3. ✅ **Enable rate limiting**
   ```toml
   [rate_limiting]
   enabled = true
   requests_per_second = 10
   ```

4. ✅ **Use HTTPS** (deploy behind reverse proxy)
   - Nginx, Caddy, Traefik, or Cloudflare
   - Enables TLS encryption for API keys in transit

5. ✅ **Monitor security logs**
   ```bash
   RUST_LOG=info x402-rs | grep -E "(banned|blocked|unauthorized|suspicious)"
   ```

6. ✅ **Set request size limits appropriately**
   - Default 1MB is suitable for most use cases
   - Adjust based on your expected payload sizes

### For Public Facilitators

If running a public facilitator (like facilitator.x402.rs):

- Consider **keeping auth disabled** for open access
- Enable **rate limiting** to prevent abuse
- Keep **CORS open** (`allowed_origins = []`)
- Monitor logs for abuse patterns
- Consider IP blocking for repeat abusers

### For Private/Internal Facilitators

If running internally or for specific partners:

- **Enable API key authentication**
- Use **IP allow lists** for network-level restriction
- **Restrict CORS** to your applications only
- Consider stricter rate limits

## Monitoring

### Security Events Logging

When `log_security_events = true`, the facilitator logs:

```
WARN: Rate limit exceeded, ip=192.168.1.100
WARN: Request blocked: IP is temporarily banned, ip=192.168.1.100
WARN: Authentication failed: Invalid API key
WARN: Request blocked: IP not on allow list, ip=203.0.113.50
WARN: Suspicious activity: repeated invalid signatures detected, ip=192.168.1.100, count=10
```

### Recommended Log Analysis

**Filter security events:**
```bash
tail -f logs/facilitator.log | grep -E "WARN|ERROR"
```

**Count rate limit violations:**
```bash
grep "Rate limit exceeded" logs/facilitator.log | wc -l
```

**Identify banned IPs:**
```bash
grep "temporarily banned" logs/facilitator.log | grep -oP 'ip=\K[0-9.]+'  | sort | uniq -c
```

## Deployment Examples

### Docker with Security

```dockerfile
FROM ghcr.io/x402-rs/x402-facilitator:latest

# Copy configuration
COPY config.toml /app/config.toml

# Set API keys via environment
ENV API_KEYS="your-secret-keys"
ENV CONFIG_FILE=/app/config.toml

EXPOSE 8080
```

### Behind Nginx Reverse Proxy

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

        # Additional security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
    }
}
```

### With Cloudflare

Cloudflare provides additional protection layers:
- DDoS mitigation
- Bot protection
- Geographic restrictions
- Additional rate limiting

Configure your facilitator to trust Cloudflare's IP headers:
```toml
# Facilitator will automatically read X-Forwarded-For from Cloudflare
```

## Troubleshooting

### "Authentication failed" errors

**Cause:** Missing or invalid API key

**Solutions:**
- Verify `API_KEYS` environment variable is set
- Check Authorization header format: `Bearer <key>`
- Ensure API key is in the comma-separated list

### Rate limit false positives

**Cause:** Legitimate traffic exceeding limits

**Solutions:**
- Increase `requests_per_second` in config
- Add endpoint-specific overrides
- Use IP allow list for trusted clients
- Deploy multiple facilitator instances

### IP filter blocking legitimate users

**Cause:** Incorrect IP/CIDR configuration

**Solutions:**
- Review `allowed_ips` and `blocked_ips` lists
- Check IP extraction (X-Forwarded-For vs direct connection)
- Test from affected IP: `curl -v https://facilitator.example.com/health`

## Security Disclosure

If you discover a security vulnerability, please email security@x402.rs with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## Additional Resources

- [x402 Protocol Specification](https://x402.org)
- [x402-rs Repository](https://github.com/x402-rs/x402-rs)
- [Configuration Reference](../README.md#security-configuration)
