# Observability Guide

Comprehensive guide to monitoring, logging, tracing, and debugging the facilitator.

## Overview

The facilitator provides multiple observability mechanisms:
- **Structured Logging**: via `tracing` crate
- **OpenTelemetry**: Distributed tracing and metrics export
- **Admin Stats Endpoint**: Real-time statistics
- **Security Event Logging**: Audit trail for security events

## Logging

### Log Levels

Configure log verbosity via `RUST_LOG` environment variable:

```bash
# Production: Info and above
RUST_LOG=info

# Development: Debug and above
RUST_LOG=debug

# Troubleshooting: Trace everything
RUST_LOG=trace

# Module-specific logging
RUST_LOG=infra402_facilitator=debug,tower_http=info

# Silence specific modules
RUST_LOG=info,alloy=warn
```

### Log Format

Logs are output in structured format with timestamps:

```
2025-10-30T10:15:30.123Z INFO infra402_facilitator: Starting server at http://0.0.0.0:8080
2025-10-30T10:15:31.456Z INFO infra402_facilitator::chain::evm: Initialized provider network=bsc signers=["0x..."]
2025-10-30T10:15:32.789Z WARN infra402_facilitator::handlers: Verification failed error=InvalidSignature
```

### Log Categories

#### Startup Logs

```
INFO Configuration loaded successfully
INFO Initialized provider network=base signers=["0xAddr1", "0xAddr2"]
INFO Batch settlement enabled - initializing queue manager
INFO Starting server at http://0.0.0.0:8080
```

#### Request Logs

```
INFO POST /verify network=base duration=45ms status=200
INFO POST /settle network=bsc duration=3210ms status=200 tx=0xabc...
```

#### Security Logs

```
WARN Rate limit exceeded ip=192.168.1.100 endpoint=/verify
WARN IP blocked ip=10.0.0.50 reason=banned
ERROR Unauthorized access attempt ip=203.0.113.10 endpoint=/admin/stats
```

#### Error Logs

```
ERROR Settlement failed error=InsufficientFunds network=bsc payer=0x...
ERROR RPC timeout network=base duration=30s
WARN Batch settlement validation failed count=3
```

### Filtering Security Logs

Extract security events from logs:

```bash
# All security events
RUST_LOG=info cargo run | grep -E "(banned|blocked|unauthorized|suspicious|rate limit)"

# Just authentication failures
RUST_LOG=info cargo run | grep -i unauthorized

# Just rate limiting
RUST_LOG=info cargo run | grep "rate limit"
```

### Log Aggregation

#### With Docker and journald

```bash
# View logs
docker logs -f facilitator

# Follow logs with journalctl
journalctl -u infra402-facilitator -f
```

#### With Log Aggregation Services

**Datadog:**
```yaml
# docker-compose.yml
services:
  facilitator:
    logging:
      driver: "json-file"
      options:
        tag: "facilitator"
```

**Loki:**
```yaml
# promtail-config.yml
clients:
  - url: http://loki:3100/loki/api/v1/push
```

**CloudWatch:**
```bash
aws logs tail /aws/facilitator --follow
```

## OpenTelemetry

### Configuration

Enable OpenTelemetry export via environment variables:

```bash
# Honeycomb
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443
OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=YOUR_API_KEY,x-honeycomb-dataset=infra402-facilitator
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf

# Generic OTLP endpoint
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf

# Jaeger
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
```

### Honeycomb Setup

1. Sign up at [honeycomb.io](https://honeycomb.io/)
2. Create a new environment
3. Get your API key from settings
4. Configure environment:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443
OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=YOUR_API_KEY,x-honeycomb-dataset=facilitator
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
RUST_LOG=info
```

### Jaeger Setup

Run Jaeger locally:

```bash
docker run -d --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 16686:16686 \
  -p 4317:4317 \
  -p 4318:4318 \
  jaegertracing/all-in-one:latest
```

Configure facilitator:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

View traces at: http://localhost:16686

### Exported Data

#### Trace Spans

Every HTTP request creates a span with:
- **Service name**: `infra402-facilitator`
- **Operation name**: HTTP method + path (e.g., `POST /verify`)
- **Duration**: Request processing time
- **Status**: Success or error
- **Attributes**:
  - `http.method`
  - `http.route`
  - `http.status_code`
  - `http.client_ip`
  - `otel.kind` (server, client, internal)

#### Custom Spans

Settlement operations create nested spans:

```
POST /settle (3210ms)
  ├─ validate_payment (45ms)
  ├─ check_balance (120ms)
  ├─ submit_transaction (2800ms)
  │   ├─ sign_transaction (5ms)
  │   ├─ send_to_rpc (2500ms)
  │   └─ wait_for_receipt (295ms)
  └─ record_result (2ms)
```

Batch settlement operations:

```
batch_settle_multicall3 (5500ms)
  ├─ validate_batch (150ms)
  ├─ build_multicall (25ms)
  ├─ submit_batch_tx (5200ms)
  └─ parse_results (125ms)
```

### Querying Traces

#### Honeycomb Queries

**Find slow settlements:**
```
WHERE http.route = "/settle"
AND duration_ms > 5000
```

**Find errors by network:**
```
WHERE http.status_code >= 400
GROUP BY network
```

**Settlement success rate:**
```
WHERE http.route = "/settle"
CALC COUNT / ERRORS
```

#### Jaeger Queries

- Filter by service: `infra402-facilitator`
- Filter by operation: `POST /settle`
- Filter by tags: `network=bsc`
- Min/max duration filters

## Admin Stats Endpoint

### Access

```bash
curl -H "X-Admin-Key: your-admin-key" http://localhost:8080/admin/stats
```

### Response

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

### Metrics

- **`total_ips_tracked`**: Number of unique IPs currently being tracked
- **`suspicious_ips`**: IPs flagged for suspicious activity (invalid signatures, etc.)
- **`active_queues`**: Number of active batch settlement queues (one per facilitator+network pair)

### Monitoring with Prometheus

Scrape the endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'facilitator'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/admin/stats'
    bearer_token: 'your-admin-key'
    scheme: 'http'
```

Convert JSON to Prometheus metrics with a sidecar exporter or custom script.

## Security Event Logging

### Configuration

Enable in `config.toml`:

```toml
[security]
log_security_events = true
```

### Event Types

#### Rate Limit Violations

```
WARN Rate limit exceeded ip=192.168.1.100 endpoint=/verify requests=15 limit=10
```

#### Authentication Failures

```
ERROR Unauthorized access attempt ip=203.0.113.10 endpoint=/admin/stats reason=invalid_key
```

#### IP Blocks

```
WARN IP blocked ip=10.0.0.50 reason=in_blocklist
```

#### Bans

```
WARN IP banned temporarily ip=192.168.1.100 reason=excessive_violations duration=300s
```

#### Invalid Signatures

```
WARN Invalid signature detected ip=203.0.113.15 network=base payer=0x...
```

#### Suspicious Patterns

```
WARN Suspicious activity detected ip=203.0.113.20 invalid_signatures=12 time_window=5m
```

### Audit Trail

Security logs provide a complete audit trail for compliance and incident response:

```bash
# Export security events
grep -E "(banned|blocked|unauthorized|invalid signature)" facilitator.log > security-audit.log
```

## Health Monitoring

### Health Check Endpoint

```bash
curl http://localhost:8080/health
```

Success (200 OK):
```json
{
  "kinds": [
    {"version": "1.0", "scheme": "ERC-3009-TransferWithAuthorization", "network": "base"},
    {"version": "1.0", "scheme": "ERC-3009-TransferWithAuthorization", "network": "bsc"}
  ]
}
```

### Monitoring Script

```bash
#!/bin/bash
ENDPOINT="http://localhost:8080/health"

response=$(curl -s -o /dev/null -w "%{http_code}" $ENDPOINT)

if [ $response -eq 200 ]; then
    echo "✓ Facilitator healthy"
    exit 0
else
    echo "✗ Facilitator unhealthy (HTTP $response)"
    exit 1
fi
```

### Docker Health Check

```yaml
# docker-compose.yml
services:
  facilitator:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

### Kubernetes Liveness/Readiness Probes

```yaml
# deployment.yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Performance Monitoring

### Key Metrics to Track

1. **Request Rate**: Requests per second to /verify and /settle
2. **Success Rate**: Percentage of successful settlements
3. **Latency**: p50, p95, p99 response times
4. **Queue Depth**: Pending settlements (if batching enabled)
5. **Gas Usage**: Total gas consumed per network
6. **Wallet Balances**: Gas token balances for all facilitator wallets
7. **RPC Health**: RPC node response times and error rates

### Custom Metrics Collection

Extend the facilitator with custom metrics:

```rust
// Example: Add Prometheus metrics
use prometheus::{IntCounter, Registry, TextEncoder, Encoder};

lazy_static! {
    static ref SETTLEMENTS_TOTAL: IntCounter =
        IntCounter::new("settlements_total", "Total settlements processed").unwrap();
}

// In settlement handler
SETTLEMENTS_TOTAL.inc();
```

## Alerting

### Example Alerts

**High Error Rate:**
```yaml
# Prometheus AlertManager
- alert: HighSettlementErrorRate
  expr: rate(settlements_failed[5m]) > 0.1
  annotations:
    summary: "High settlement failure rate"
```

**Low Wallet Balance:**
```bash
# Script-based alert
if [[ $(cast balance $WALLET --ether) < 0.05 ]]; then
    send_alert "Wallet balance below threshold"
fi
```

**Service Down:**
```yaml
# Kubernetes
- alert: FacilitatorDown
  expr: up{job="facilitator"} == 0
  for: 2m
```

**High Latency:**
```
# Honeycomb trigger
WHERE http.route = "/settle"
AND duration_ms > 10000
TRIGGER when COUNT > 10 in 5m
```

## Debugging

### Enable Debug Logs

```bash
RUST_LOG=debug cargo run
```

### Trace Specific Modules

```bash
# Trace chain interactions
RUST_LOG=infra402_facilitator::chain=trace

# Trace batch settlement
RUST_LOG=infra402_facilitator::batch_processor=trace

# Trace HTTP requests
RUST_LOG=tower_http=debug
```

### Network-Specific Debugging

```bash
# Filter logs for specific network
RUST_LOG=info cargo run | grep "network=bsc"

# Filter for specific wallet
RUST_LOG=debug cargo run | grep "0xYourWalletAddress"
```

### Transaction Debugging

When a settlement fails, logs include:

```
ERROR Settlement failed
  error=ContractCall("revert: ERC20: insufficient allowance")
  network=base
  payer=0x1234...
  to=0x5678...
  value=1000000
  tx_hash=0xabcd...
```

Use block explorers to inspect the transaction:
- Base: https://basescan.org/tx/0xabcd...
- BSC: https://bscscan.com/tx/0xabcd...

## Dashboard Example

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Facilitator Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [{"expr": "rate(http_requests_total[5m])"}]
      },
      {
        "title": "Settlement Success Rate",
        "targets": [{"expr": "rate(settlements_success[5m]) / rate(settlements_total[5m])"}]
      },
      {
        "title": "Latency (p95)",
        "targets": [{"expr": "histogram_quantile(0.95, http_request_duration_seconds)"}]
      }
    ]
  }
}
```

## Further Reading

- [Configuration Guide](CONFIGURATION.md) - Security logging configuration
- [Performance Guide](PERFORMANCE.md) - Performance metrics and tuning
- [Deployment Guide](DEPLOYMENT.md) - Production deployment best practices
- [Security Documentation](SECURITY.md) - Security monitoring and incident response
