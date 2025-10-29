# Environment Variables Setup for Cloudflare Deployment

## Overview

The infra402-facilitator container requires environment variables to be explicitly passed from the Cloudflare Worker. Environment variables set in the Cloudflare dashboard are only available to the Worker code, not automatically to the container.

## Required Environment Variables

### Required (Must be set):
- `SIGNER_TYPE` - Type of signer (e.g., "private-key")
- `EVM_PRIVATE_KEY` - Comma-separated EVM private keys for transaction signing
- `RPC_URL_BASE_SEPOLIA` - RPC endpoint for Base Sepolia testnet
- `RPC_URL_BASE` - RPC endpoint for Base mainnet

### Optional (Set as needed):
- `PORT` - Container port (default: "8080")
- `HOST` - Container host (default: "0.0.0.0")
- `RUST_LOG` - Log level (default: "info")
- `SOLANA_PRIVATE_KEY` - Solana private key for Solana payments
- `RPC_URL_XDC` - RPC endpoint for XDC mainnet
- `RPC_URL_AVALANCHE_FUJI` - RPC endpoint for Avalanche Fuji testnet
- `RPC_URL_AVALANCHE` - RPC endpoint for Avalanche mainnet
- `RPC_URL_POLYGON_AMOY` - RPC endpoint for Polygon Amoy testnet
- `RPC_URL_POLYGON` - RPC endpoint for Polygon mainnet
- `RPC_URL_SEI` - RPC endpoint for Sei mainnet
- `RPC_URL_SEI_TESTNET` - RPC endpoint for Sei testnet
- `RPC_URL_BSC_TESTNET` - RPC endpoint for BSC testnet
- `RPC_URL_BSC` - RPC endpoint for BSC mainnet
- `SOLANA_RPC_URL_MAINNET` - Solana mainnet RPC endpoint
- `SOLANA_RPC_URL_DEVNET` - Solana devnet RPC endpoint
- `API_KEYS` - Comma-separated API keys for authentication
- `ADMIN_API_KEY` - Admin API key for protected endpoints
- `CONFIG_FILE` - Path to config file (optional)
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OpenTelemetry endpoint
- `OTEL_EXPORTER_OTLP_HEADERS` - OpenTelemetry headers
- `OTEL_EXPORTER_OTLP_PROTOCOL` - OpenTelemetry protocol

## Setting Environment Variables

### Method 1: Using Wrangler CLI (Recommended for Secrets)

For sensitive values like private keys, use Wrangler secrets:

```bash
# Navigate to the cloudflare directory
cd infra402-facilitator-cloudflare

# Set secrets one by one
wrangler secret put EVM_PRIVATE_KEY
# Enter your private key when prompted

wrangler secret put API_KEYS
# Enter your API keys (comma-separated)

wrangler secret put ADMIN_API_KEY
# Enter your admin API key
```

### Method 2: Using Cloudflare Dashboard

For non-secret values:

1. Go to https://dash.cloudflare.com/
2. Navigate to **Workers & Pages**
3. Select your **infra402-facilitator-cloudflare** worker
4. Go to **Settings** → **Variables**
5. Add environment variables:
   - Click **Add variable**
   - Enter name (e.g., `RPC_URL_BASE_SEPOLIA`)
   - Enter value (e.g., `https://sepolia.base.org`)
   - Click **Save**

For secrets:
1. Click **Add variable**
2. Select **Encrypt** checkbox
3. Enter name and value
4. Click **Save**

### Method 3: Using wrangler.jsonc (Not Recommended for Secrets)

For non-secret default values, you can add them to `wrangler.jsonc`:

```jsonc
{
  // ... other config ...
  "vars": {
    "PORT": "8080",
    "HOST": "0.0.0.0",
    "RUST_LOG": "info",
    "RPC_URL_BASE_SEPOLIA": "https://sepolia.base.org",
    "RPC_URL_BASE": "https://mainnet.base.org"
  }
}
```

**⚠️ WARNING:** Never put secrets (private keys, API keys) in `wrangler.jsonc` as this file is committed to git!

## Deployment

After setting environment variables, deploy the worker:

```bash
npm run deploy
```

The Worker will automatically pass all configured environment variables to the container on startup.

## Verifying Environment Variables

After deployment, check the Cloudflare dashboard logs to verify the container is receiving the variables:

1. Go to your Worker in the Cloudflare dashboard
2. Click **Logs** → **Real-time logs**
3. Trigger a request to your Worker
4. Look for "Container successfully started" message
5. Check for any error messages about missing environment variables

## Troubleshooting

### Container doesn't receive environment variables
- **Cause:** Environment variables must be explicitly passed in `src/index.ts`
- **Solution:** Variables are automatically passed if set in dashboard or via wrangler secrets

### "Missing required environment variable" error
- **Cause:** Required variable not set in Cloudflare
- **Solution:** Set the variable using wrangler secrets or dashboard

### Container restarts frequently
- **Cause:** May be due to missing or incorrect environment variables
- **Solution:** Check logs for specific errors and set missing variables

### Changes not reflected after deployment
- **Cause:** Container may still be running with old environment
- **Solution:** Wait for container to sleep (10 minutes of inactivity) or redeploy

## Security Best Practices

1. **Always use Wrangler secrets for sensitive data** (private keys, API keys)
2. **Never commit secrets to git** (they should only be in Cloudflare)
3. **Use different keys for testnet and mainnet**
4. **Rotate API keys regularly**
5. **Use IP restrictions** if available in Cloudflare settings
6. **Monitor Worker logs** for suspicious activity

## GitHub Actions Secrets

For CI/CD deployment, add these secrets to your GitHub repository:

1. Go to **Repository Settings** → **Secrets and variables** → **Actions**
2. Add the following secrets:
   - `CLOUDFLARE_API_TOKEN` - Cloudflare API token with Workers deploy permission
   - `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID

Note: GitHub Actions only deploys the Worker code. Environment variables and secrets must be set separately in Cloudflare (they are not overwritten by deployments).
