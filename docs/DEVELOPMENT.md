# Development Guide

Guide for developers contributing to the infra402 facilitator project.

## Prerequisites

- **Rust**: 1.80+ ([rustup.rs](https://rustup.rs/))
- **Cargo**: Included with Rust
- **Git**: Version control

Optional tools:
- **Docker**: For container builds
- **cast** (Foundry): For testing with blockchain
- **curl** / **httpie**: For API testing

## Project Structure

```
infra402-facilitator/
├── src/
│   ├── main.rs                 # Application entry point
│   ├── handlers.rs             # HTTP endpoint handlers
│   ├── config.rs               # Configuration parsing
│   ├── chain/
│   │   ├── mod.rs              # Chain abstraction
│   │   ├── evm.rs              # EVM provider implementation
│   │   └── solana.rs           # Solana provider implementation
│   ├── batch_queue.rs          # Batch settlement queue manager
│   ├── batch_processor.rs      # Multicall3 batch processing
│   ├── facilitator.rs          # Core facilitator trait
│   ├── facilitator_local.rs    # Local facilitator implementation
│   ├── network.rs              # Network types and config
│   ├── provider_cache.rs       # Network provider cache
│   ├── security/                # Security middleware
│   │   ├── mod.rs
│   │   ├── api_key.rs          # API key authentication
│   │   ├── admin_auth.rs       # Admin authentication
│   │   ├── rate_limit.rs       # Rate limiting
│   │   ├── ip_filter.rs        # IP filtering
│   │   └── abuse.rs            # Abuse detection
│   ├── types.rs                # Shared types
│   ├── telemetry.rs            # OpenTelemetry setup
│   ├── sig_down.rs             # Graceful shutdown
│   └── timestamp.rs            # Timestamp utilities
├── docs/                       # Documentation
├── config.toml                 # Example configuration
├── Cargo.toml                  # Rust dependencies
├── Dockerfile                  # Docker image
└── README.md                   # High-level overview
```

## Getting Started

### Clone Repository

```bash
git clone https://github.com/your-org/infra402-facilitator.git
cd infra402-facilitator
```

### Install Dependencies

```bash
cargo build
```

### Configuration

Create `.env`:

```bash
cp .env.example .env
# Edit .env with your RPC URLs and keys
```

### Run Locally

```bash
cargo run
```

Or with logs:

```bash
RUST_LOG=debug cargo run
```

### Run Tests

```bash
# All tests
cargo test

# Specific module
cargo test config::tests

# With output
cargo test -- --nocapture

# Single test
cargo test test_batch_settlement_per_network_config
```

### Build Release

```bash
cargo build --release
./target/release/infra402-facilitator
```

## Development Workflow

### Branch Strategy

- `main`: Production-ready code
- `develop`: Integration branch
- `feature/*`: New features
- `fix/*`: Bug fixes
- `docs/*`: Documentation updates

### Creating a Feature

```bash
# Create feature branch
git checkout -b feature/my-feature

# Make changes
# ...

# Run tests
cargo test

# Check formatting
cargo fmt --check

# Lint
cargo clippy

# Commit with conventional commits
git commit -m "feat: add new feature"

# Push and create PR
git push origin feature/my-feature
```

### Conventional Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
feat: add batch settlement per-network configuration
fix: resolve nonce race condition in multi-wallet setup
docs: update deployment guide with Kubernetes examples
chore: upgrade alloy to v1.0.7
test: add integration tests for batch processor
refactor: simplify provider cache architecture
```

## Code Style

### Formatting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --check
```

### Linting

```bash
# Run clippy
cargo clippy

# Fix automatically
cargo clippy --fix
```

### Documentation

All public APIs should have rustdoc comments:

```rust
/// Verifies a payment payload against requirements.
///
/// # Arguments
///
/// * `request` - The verification request containing payment payload and requirements
///
/// # Returns
///
/// Returns `VerifyResponse::Valid` if the payment is valid, otherwise `VerifyResponse::Invalid`.
///
/// # Errors
///
/// Returns `FacilitatorLocalError` if verification fails due to:
/// - Invalid signature
/// - Insufficient funds
/// - Network mismatch
pub async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
    // implementation
}
```

Generate docs:

```bash
cargo doc --open
```

## Testing

### Unit Tests

Located in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_settlement_default() {
        let config = BatchSettlementConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_batch_size, 150);
    }
}
```

### Integration Tests

Located in `tests/` directory:

```rust
#[tokio::test]
async fn test_verify_endpoint() {
    let app = create_test_app().await;
    let response = app
        .post("/verify")
        .header("Authorization", "Bearer test-key")
        .json(&test_payload())
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}
```

### Test with Real Networks

Use testnets for integration testing:

```bash
# .env.test
RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
EVM_PRIVATE_KEY=0xTestPrivateKey
```

Run integration tests:

```bash
cargo test --test integration_tests -- --ignored
```

## Adding Features

### Adding a New Network

1. **Add network variant** (`src/network.rs`):
```rust
pub enum Network {
    // ...existing networks...
    #[serde(rename = "new-network")]
    NewNetwork,
}
```

2. **Add Display implementation**:
```rust
impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            // ...
            Network::NewNetwork => write!(f, "new-network"),
        }
    }
}
```

3. **Add to NetworkFamily**:
```rust
impl From<Network> for NetworkFamily {
    fn from(value: Network) -> Self {
        match value {
            // ...
            Network::NewNetwork => NetworkFamily::Evm,
        }
    }
}
```

4. **Add RPC environment variable** (`.env`):
```bash
RPC_URL_NEW_NETWORK=https://rpc.new-network.com
```

5. **Test**:
```bash
cargo test
cargo run
curl http://localhost:8080/supported | jq
```

### Adding a Security Feature

1. **Create module** (`src/security/my_feature.rs`):
```rust
use axum::{extract::Request, middleware::Next, response::Response};

pub struct MySecurityFeature {
    // config
}

impl MySecurityFeature {
    pub async fn middleware(&self, request: Request, next: Next) -> Response {
        // implement security logic
        next.run(request).await
    }
}
```

2. **Register in main.rs**:
```rust
let my_feature = MySecurityFeature::new(config);
let app = Router::new()
    .layer(axum::middleware::from_fn(move |req, next| {
        let feature = my_feature.clone();
        async move { feature.middleware(req, next).await }
    }));
```

3. **Add tests**:
```rust
#[tokio::test]
async fn test_my_security_feature() {
    // test logic
}
```

### Adding Configuration Options

1. **Add to config struct** (`src/config.rs`):
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MyFeatureConfig {
    pub enabled: bool,
    pub threshold: u32,
}

impl Default for MyFeatureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 100,
        }
    }
}
```

2. **Add to FacilitatorConfig**:
```rust
pub struct FacilitatorConfig {
    // ...existing fields...
    pub my_feature: MyFeatureConfig,
}
```

3. **Add tests**:
```rust
#[test]
fn test_my_feature_config() {
    let config_str = r#"
    [my_feature]
    enabled = true
    threshold = 200
    "#;

    let config: FacilitatorConfig = toml::from_str(config_str).unwrap();
    assert!(config.my_feature.enabled);
    assert_eq!(config.my_feature.threshold, 200);
}
```

## Debugging

### Local Development

```bash
# Run with debug logs
RUST_LOG=debug cargo run

# Trace specific module
RUST_LOG=infra402_facilitator::batch_processor=trace cargo run

# Pretty logs
RUST_LOG=debug cargo run 2>&1 | jq -R 'fromjson?'
```

### Using rust-lldb/gdb

```bash
# Build with debug symbols
cargo build

# Debug
rust-lldb target/debug/infra402-facilitator
# or
gdb target/debug/infra402-facilitator
```

### Testing API Locally

```bash
# Health check
curl http://localhost:8080/health | jq

# Verify (with API key)
curl -X POST http://localhost:8080/verify \
  -H "Authorization: Bearer test-key" \
  -H "Content-Type: application/json" \
  -d @test-payload.json | jq

# Admin stats
curl -H "X-Admin-Key: admin-key" http://localhost:8080/admin/stats | jq
```

## Performance Profiling

### CPU Profiling

```bash
# Install flamegraph
cargo install flamegraph

# Profile
cargo flamegraph --open
```

### Memory Profiling

```bash
# Install valgrind
sudo apt install valgrind

# Run
valgrind --tool=massif target/release/infra402-facilitator
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Build
        run: cargo build --verbose
      - name: Test
        run: cargo test --verbose
      - name: Clippy
        run: cargo clippy -- -D warnings
      - name: Format check
        run: cargo fmt -- --check
```

## Release Process

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md
3. Create git tag:
```bash
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0
```
4. Build and publish Docker image:
```bash
docker build -t ghcr.io/infra402/facilitator:v1.2.0 .
docker push ghcr.io/infra402/facilitator:v1.2.0
```
5. Create GitHub release with notes

## Contributing

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Run tests and lints
7. Create pull request with:
   - Clear title following conventional commits
   - Description of changes
   - Link to related issues
8. Address review feedback
9. Squash and merge when approved

### Code Review Guidelines

**For authors:**
- Keep PRs focused and small
- Write clear commit messages
- Add tests for new features
- Update docs

**For reviewers:**
- Check for correctness
- Verify test coverage
- Check for security issues
- Ensure docs are updated
- Be constructive and respectful

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Axum Documentation](https://docs.rs/axum/)
- [Tokio Documentation](https://docs.rs/tokio/)
- [Alloy Documentation](https://docs.rs/alloy/)
- [x402 Protocol](https://x402.org)

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/your-org/infra402-facilitator/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/infra402-facilitator/discussions)
- **Security**: See [Security Policy](SECURITY.md)

## License

Apache-2.0 - see [LICENSE](../LICENSE) file for details.
