# Testing Post-Settlement Hooks

## Prerequisites

1. Deploy a hook contract with a function to call (e.g., `notifySettlement(address from, address to, uint256 amount)`)
2. Get the contract ABI
3. Have admin API key configured (`ADMIN_API_KEY` env var)

## Setup Steps

### 1. Add Hook Contract ABI

Save your hook contract ABI to `abi/hooks/YourHook.json`:

```json
[
  {
    "type": "function",
    "name": "notifySettlement",
    "inputs": [
      {"name": "from", "type": "address"},
      {"name": "to", "type": "address"},
      {"name": "amount", "type": "uint256"}
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  }
]
```

### 2. Encode Calldata

Use Alloy or similar to encode the calldata for your hook function:

```rust
// Example with Alloy
use alloy::sol;

sol! {
    function notifySettlement(address from, address to, uint256 amount);
}

let calldata = notifySettlementCall {
    from: Address::ZERO,
    to: Address::ZERO,
    amount: U256::ZERO,
}.abi_encode();

println!("0x{}", hex::encode(calldata));
```

Or use cast:
```bash
cast calldata "notifySettlement(address,address,uint256)" 0x0000000000000000000000000000000000000000 0x0000000000000000000000000000000000000000 0
```

### 3. Configure hooks.toml

Edit `hooks.toml`:

```toml
[hooks]
enabled = true
allow_hook_failure = false

[hooks.mappings]
# Map your recipient address to your hook
"0xYourRecipientAddress" = ["notify_settlement"]

[hooks.definitions.notify_settlement]
enabled = true
description = "Notifies contract when settlement occurs"
contract = "0xYourHookContractAddress"
calldata = "0xYourEncodedCalldata"  # From step 2
gas_limit = 100000
```

### 4. Start Server

```bash
cargo run --release
```

Check logs for:
```
Hook manager initialized successfully
Hook admin routes registered
```

## Testing

### Test 1: Verify Hook Configuration

```bash
# Check status
curl http://localhost:8080/admin/hooks/status \
  -H "X-Admin-Key: your-admin-key"

# Expected response:
{
  "enabled": true,
  "hooks_count": 1,
  "mappings_count": 1
}
```

### Test 2: List Hooks

```bash
curl http://localhost:8080/admin/hooks \
  -H "X-Admin-Key: your-admin-key"

# Expected: JSON with your hook definition
```

### Test 3: Send Settlement to Mapped Address

Send a settlement request to the mapped recipient address:

```bash
curl -X POST http://localhost:8080/settle \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "x402Version": 1,
    "paymentPayload": { ... },  # Your payment payload
    "paymentRequirements": {
      "payTo": "0xYourRecipientAddress",  # The mapped address
      ...
    }
  }'
```

### Test 4: Verify On-Chain

Check the transaction on a block explorer:

1. Find the settlement transaction hash from the response
2. View the transaction on Etherscan/Basescan
3. Verify the transaction includes:
   - A call to Multicall3 (`0xcA11bde05977b3631167028862bE2a173976CA11`)
   - Multiple calls in the `aggregate3` array
   - Your hook contract should appear in the internal transactions
   - Events from both the token transfer AND your hook contract

### Test 5: Runtime Control

```bash
# Disable hook
curl -X POST http://localhost:8080/admin/hooks/notify_settlement/disable \
  -H "X-Admin-Key: your-admin-key"

# Verify disabled
curl http://localhost:8080/admin/hooks/status \
  -H "X-Admin-Key: your-admin-key"

# Send another settlement - hook should NOT execute

# Re-enable
curl -X POST http://localhost:8080/admin/hooks/notify_settlement/enable \
  -H "X-Admin-Key: your-admin-key"
```

### Test 6: Hot Reload

```bash
# Edit hooks.toml to add new mapping or hook
# Then reload without restarting server:

curl -X POST http://localhost:8080/admin/hooks/reload \
  -H "X-Admin-Key: your-admin-key"

# Expected response:
{
  "success": true,
  "message": "Reloaded 1 hook definitions"
}
```

## Batch Testing

### Test 7: Verify Call3 Counting

To test that max_batch_size counts Call3 structs correctly:

1. Configure multiple hooks per destination (e.g., 2 hooks)
2. Send 40 settlement requests to mapped address
3. Check logs for sub-batch splitting:
   ```
   split into 3 sub-batches based on Call3 limits
   processing sub-batch batch_size=30 total_call3s=90
   processing sub-batch batch_size=10 total_call3s=30
   ```

With 2 hooks per settlement and max_batch_size=150:
- 50 settlements × 3 Call3 each = 150 total (1 batch)
- 51 settlements × 3 Call3 each = 153 total (2 batches: 50 + 1)

## Troubleshooting

### Hook Not Executing

1. Check `hooks.toml` exists and is valid TOML
2. Verify `enabled = true` in both `[hooks]` and hook definition
3. Check destination address is mapped correctly
4. Verify calldata is hex-encoded with `0x` prefix
5. Check server logs for errors

### Hook Failing

1. Check gas limit is sufficient
2. Verify contract address is correct
3. Test calldata encoding independently
4. Check if `allow_hook_failure = false` is causing batch revert
5. Monitor transaction revert reasons on block explorer

### Hot Reload Not Working

1. Verify `X-Admin-Key` header matches `ADMIN_API_KEY` env var
2. Check file permissions on `hooks.toml`
3. Validate TOML syntax
4. Check server logs for parsing errors

## Expected Log Messages

```
INFO Hook manager initialized successfully
INFO Hook admin routes registered
INFO Retrieved hooks for destination destination=0x... hooks_count=1
INFO validated settlements - splitting into Call3-aware sub-batches
INFO processing sub-batch batch_size=1 total_call3s=3
```

## Security Checklist

- [ ] Hook contract is trusted and audited
- [ ] ABI file is correct and complete
- [ ] Calldata is properly encoded
- [ ] Gas limit is reasonable (not too high to prevent DoS)
- [ ] `allow_hook_failure` is set appropriately for your use case
- [ ] Admin API key is strong and secret
- [ ] Hook contract cannot drain facilitator funds
- [ ] Hook contract cannot manipulate settlement amounts

## Performance Testing

Monitor these metrics:

1. **Gas usage**: Compare transactions with/without hooks
2. **Batch size**: Verify Call3 counting splits batches correctly
3. **Latency**: Measure settlement time impact
4. **Success rate**: Track hook failure rate

Use block explorer or `eth_getTransactionReceipt` to analyze gas usage.
