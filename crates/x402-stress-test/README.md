# X402 Stress Test

A high-performance stress testing tool for the X402 payment facilitator service. This tool can generate hundreds of concurrent requests per second to test the `/verify` and `/settle` endpoints, measuring throughput, latency, and reliability.

## Features

- ✅ **Sign x402 messages** - Generates valid EIP-712 signatures for EVM chains
- ✅ **Test /verify endpoint** - Validates payment authorizations without settling
- ✅ **Test /settle endpoint** - Full on-chain settlement with batching support
- ✅ **100+ RPS capable** - Multi-threaded with configurable concurrency
- ✅ **Real-time statistics** - Success rate, latency percentiles, error breakdown
- ✅ **CLI progress** - Live progress updates every second
- ✅ **Configurable load** - Control RPS, duration, and test mix
- ✅ **Environment-based config** - All payment parameters via `.env` file

## Installation

### Prerequisites

- Rust 1.70+ and Cargo
- Test USDC tokens on your chosen network
- An EVM private key with test funds
- A running X402 facilitator instance

### Build

From the workspace root:

```bash
cargo build --release -p x402-stress-test
```

Or from this directory:

```bash
cargo build --release
```

The binary will be at `../../target/release/x402-stress-test`

## Dev vs Release Mode

The stress test tool works in **both dev and release modes**, but they have different performance characteristics:

### Release Mode (Recommended for Stress Testing)

```bash
cargo run --release -- [args]
```

**Characteristics:**
- ✅ **Fully optimized** (10-100x faster than dev)
- ✅ Accurate latency measurements reflecting server performance
- ✅ Can achieve true high RPS (100+)
- ✅ Minimal client-side bottleneck
- ❌ Slower first compilation (~30-60 seconds)

**Use for:**
- Actual stress testing and performance benchmarking
- Testing batch settlement behavior under load
- Validating facilitator throughput capabilities

### Dev Mode (For Development Only)

```bash
cargo run -- [args]
```

**Characteristics:**
- ✅ Faster compilation (~5-10 seconds)
- ✅ Includes debug symbols for troubleshooting
- ❌ **10-100x slower execution**
- ❌ Inaccurate latency (includes client overhead)
- ❌ Client becomes bottleneck at >10-20 RPS

**Use for:**
- Quick functional testing of the tool itself
- Verifying configuration is correct
- Low-volume testing (<10 RPS)

### Performance Impact Example

When targeting 100 RPS:

| Mode | Actual RPS | Bottleneck | Latency Accuracy |
|------|-----------|------------|------------------|
| **Dev** | ~10-20 | Client CPU | ❌ Inflated |
| **Release** | ~100 | Server capacity | ✅ Accurate |

**⚠️ Important:** In dev mode, you're stress testing the debug build of the client, not the facilitator!

## Configuration

### 1. Environment Variables

Copy the example environment file and edit it:

```bash
cd crates/x402-stress-test
cp .env.example .env
# Edit .env with your configuration
```

Required environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `FACILITATOR_URL` | Base URL of facilitator service | `http://localhost:3000` |
| `FACILITATOR_API_KEY` | Optional Bearer token | `your-api-key` |
| `EVM_PRIVATE_KEY` | Private key for signing (hex) | `0xac09...ff80` |
| `NETWORK` | Network identifier | `base-sepolia` |
| `PAY_TO` | Recipient address | `0x7099...c79C8` |
| `AMOUNT` | Amount in smallest unit | `1000000` (= $1 USDC) |
| `ASSET` | Token contract address | `0x036C...dCF7e` |
| `TOKEN_NAME` | EIP-712 token name | `USD Coin` |
| `TOKEN_VERSION` | EIP-712 token version | `2` |
| `MAX_TIMEOUT_SECONDS` | Payment validity window | `3600` |

### 2. Command-Line Arguments

Run `x402-stress-test --help` to see all options:

```
Options:
  --requests-per-second <N>      Requests per second (0 = unlimited) [default: 10]
  --duration-seconds <N>         Run for N seconds
  --total-requests <N>           Send N total requests (conflicts with duration)
  --verify-only                  Only test /verify endpoint
  --settle-only                  Only test /settle endpoint
  --workers <N>                  Number of concurrent workers [default: 10]
  --stats-interval-seconds <N>   Print stats every N seconds [default: 1]
```

## Usage Examples

### Quick Functional Test (Dev Mode)

For quick testing during development:

```bash
cargo run -- \
  --total-requests 10
```

**Note:** Use dev mode only for low-volume functional testing. For actual stress testing, use `--release` mode.

### Basic Stress Test: 50 RPS for 30 seconds

```bash
cargo run --release -- \
  --requests-per-second 50 \
  --duration-seconds 30
```

### High Load: 500 RPS for 1 minute

```bash
cargo run --release -- \
  --requests-per-second 500 \
  --duration-seconds 60 \
  --workers 50
```

### Fixed Request Count: 1000 total requests

```bash
cargo run --release -- \
  --total-requests 1000 \
  --requests-per-second 100
```

### Test Only /verify (no settlements)

```bash
cargo run --release -- \
  --verify-only \
  --requests-per-second 200 \
  --duration-seconds 30
```

### Test Only /settle (batch testing)

```bash
cargo run --release -- \
  --settle-only \
  --requests-per-second 100 \
  --duration-seconds 60
```

### Maximum Throughput Test (unlimited RPS)

```bash
cargo run --release -- \
  --requests-per-second 0 \
  --total-requests 10000 \
  --workers 100
```

## Output and Statistics

### Live Progress (printed every second)

```
=== PROGRESS ===
Elapsed: 15s
Total Requests: 752
Requests/sec: 50.13

Verify Requests: 376
  ✓ Valid: 372
  ✗ Invalid: 4
  Success Rate: 98.94%

Settle Requests: 376
  ✓ Success: 350
  ✗ Failure: 26
  Success Rate: 93.09%

Latency:
  Average: 245ms
  P50: 198ms
  P95: 456ms
  P99: 892ms

Error Breakdown:
  insufficient_funds: 26
  invalid_signature: 4
```

### Final Statistics

After completion (or Ctrl+C), a final summary is printed:

```
=== FINAL STATISTICS ===
Elapsed: 30s
Total Requests: 1500
Requests/sec: 50.00

[... detailed breakdown ...]
```

## Interpreting Results

### Key Metrics

| Metric | What it means | Good vs Bad |
|--------|---------------|-------------|
| **Requests/sec** | Actual throughput achieved | Should match your `--requests-per-second` setting |
| **Success Rate** | % of valid responses | >95% is good, <90% indicates issues |
| **Latency P50** | Median response time | <500ms is good for local testing |
| **Latency P95** | 95th percentile latency | <2s is acceptable under load |
| **Error Breakdown** | Types of failures | Helps identify bottlenecks |

### Common Error Reasons

| Error | Cause | Solution |
|-------|-------|----------|
| `insufficient_funds` | Payer doesn't have enough USDC | Fund the test account |
| `invalid_signature` | EIP-712 signing failed | Check TOKEN_NAME and TOKEN_VERSION |
| `invalid_network` | Network mismatch | Ensure NETWORK matches facilitator config |
| `nonce_already_used` | Duplicate nonce (shouldn't happen) | Report as bug |
| `http_error: ...` | Network/HTTP issue | Check facilitator is running and accessible |

## Testing Batch Settlement

To specifically test the batch settlement mechanism:

1. Configure the facilitator with batching enabled (`config.toml`):
   ```toml
   [batch_settlement]
   enabled = true
   max_batch_size = 150
   max_wait_ms = 500
   ```

2. Run a burst of settlement requests:
   ```bash
   cargo run --release -- \
     --settle-only \
     --requests-per-second 200 \
     --duration-seconds 30 \
     --workers 20
   ```

3. Monitor facilitator logs for batch processing messages

4. Check on-chain transactions - you should see fewer transactions than total settlements (multiple settlements per tx)

## Troubleshooting

### "Failed to parse EVM_PRIVATE_KEY"

- Ensure the private key is a valid hex string (with or without `0x` prefix)
- Use a test key only, never production keys

### "insufficient_funds" errors

- Check the payer account has enough USDC tokens
- Run `cast balance <address> --erc20 <ASSET>` to verify balance

### "invalid_signature" errors

- Verify `TOKEN_NAME` and `TOKEN_VERSION` match the token contract
- For Base Sepolia USDC: `TOKEN_NAME="USD Coin"`, `TOKEN_VERSION="2"`
- Check with: `cast call <ASSET> "name()(string)"` and `cast call <ASSET> "version()(string)"`

### Low throughput (RPS much lower than expected)

- Increase `--workers` (try 2-5x your target RPS)
- Check network latency to facilitator
- Monitor facilitator CPU/memory usage
- Disable rate limiting in facilitator config for testing

### Connection refused / timeout

- Ensure facilitator is running and accessible
- Check `FACILITATOR_URL` is correct
- Verify firewall/network settings

## Development

### Running Tests

```bash
cargo test
```

### Code Structure

```
src/
├── main.rs       # Entry point
├── config.rs     # Environment and CLI argument parsing
├── client.rs     # HTTP client for /verify and /settle
├── stats.rs      # Statistics tracking and reporting
└── runner.rs     # Multi-threaded test orchestration
```

### Adding New Features

- **Custom payment schemes**: Modify `execute_request()` in `runner.rs`
- **New statistics**: Add fields to `StatsInner` in `stats.rs`
- **Different signing methods**: Extend `EvmSenderWallet` usage in `runner.rs`

## Safety and Best Practices

⚠️ **Important Warnings:**

- **Only use test networks** (Base Sepolia, BSC Testnet, etc.)
- **Never commit private keys** to version control
- **Use test tokens only** - never test with real funds
- **Respect rate limits** - don't DDoS production services
- **Monitor resource usage** - high RPS can consume significant CPU/memory

## License

Same as the parent project.

## Support

For issues or questions:
- Check the main project documentation
- Review facilitator logs for detailed error messages
- Open an issue in the main repository
