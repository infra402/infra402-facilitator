# Post-Settlement Hooks Implementation Guide

This guide explains how to configure and use the post-settlement hook system in the x402 facilitator.

## Overview

Post-settlement hooks allow you to execute custom contract calls atomically with settlement transfers via Multicall3. This enables additional on-chain logic to run immediately after a payment is settled, all within the same transaction for atomicity.

## Hook Types

### Parameterized Hooks (Recommended)

Dynamic calldata built from payment data, runtime context, or static values. Provides full access to EIP-3009 parameters and runtime information.

**Advantages:**
- Type-safe parameter resolution
- Access to full EIP-3009 authorization data
- Runtime context (timestamps, block numbers, batch info)
- Flexible parameter composition

### Legacy Static Hooks (Deprecated)

Pre-encoded calldata that never changes. Simple but inflexible.

**Use only when:** You have completely static calldata with no dynamic values.

## Configuration Structure

Hooks are configured in `hooks.toml`:

```toml
[hooks]
enabled = true/false                    # Global enable/disable
allow_hook_failure = true/false        # Allow individual hooks to fail

[hooks.mappings]
"0xRecipientAddress" = ["hook_name"]   # Maps recipient → hooks

[hooks.definitions.hook_name]
enabled = true
contract = "0xContractAddress"
function_signature = "funcName(type1,type2,...)"
gas_limit = 100000
description = "What this hook does"

[[hooks.definitions.hook_name.parameters]]
type = "solidity_type"
source = { source_type = "payment|runtime|config|static", field = "..." }
```

## Available Parameter Sources

### Payment Fields (from EIP-3009 authorization)

Extract data from the EIP-3009 `transferWithAuthorization` parameters:

| Field | Type | Description |
|-------|------|-------------|
| `from` | address | Payer address |
| `to` | address | Recipient address |
| `value` | uint256 | Transfer amount |
| `validafter` | uint256 | Valid after timestamp |
| `validbefore` | uint256 | Valid before timestamp |
| `nonce` | bytes32 | Unique nonce |
| `contractaddress` | address | Token contract address |
| `signaturev` | uint8 | Signature v component |
| `signaturer` | bytes32 | Signature r component |
| `signatures` | bytes32 | Signature s component |

**Example:**
```toml
[[hooks.definitions.my_hook.parameters]]
type = "address"
source = { source_type = "payment", field = "from" }
```

### Runtime Fields (from settlement context)

Access dynamic values available at settlement time:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | uint256 | Block timestamp (block.timestamp) |
| `blocknumber` | uint256 | Block number (block.number) |
| `sender` | address | Facilitator address (msg.sender) |
| `batchindex` | uint256 | Position in current batch (0-indexed) |
| `batchsize` | uint256 | Total settlements in batch |

**Example:**
```toml
[[hooks.definitions.my_hook.parameters]]
type = "uint256"
source = { source_type = "runtime", field = "timestamp" }
```

### Config Values

Use values from the hook's custom configuration:

**Example:**
```toml
[hooks.definitions.my_hook.config_values]
recipient = "0x1111111111111111111111111111111111111111"
percentage = "250"

[[hooks.definitions.my_hook.parameters]]
type = "address"
source = { source_type = "config", field = "recipient" }
```

### Static Values

Use literal values directly in the configuration:

**Example:**
```toml
[[hooks.definitions.my_hook.parameters]]
type = "uint256"
source = { source_type = "static", value = "100" }
```

## Example Implementations

### Example 1: TokenMintWith3009 EIP-3009 Callback

Calls `onPaymentReceived` on TokenMintWith3009 contract with full EIP-3009 parameters.

**Solidity Interface:**
```solidity
interface ITokenMintWith3009 {
    function onPaymentReceived(
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}
```

**Configuration:**
```toml
[hooks.definitions.token_mint_callback]
enabled = true
description = "Calls onPaymentReceived with EIP-3009 authorization parameters"
contract = "0xYourTokenMintContractAddress"
function_signature = "onPaymentReceived(address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
gas_limit = 200000

[[hooks.definitions.token_mint_callback.parameters]]
type = "address"
source = { source_type = "payment", field = "from" }

[[hooks.definitions.token_mint_callback.parameters]]
type = "uint256"
source = { source_type = "payment", field = "value" }

[[hooks.definitions.token_mint_callback.parameters]]
type = "uint256"
source = { source_type = "payment", field = "validafter" }

[[hooks.definitions.token_mint_callback.parameters]]
type = "uint256"
source = { source_type = "payment", field = "validbefore" }

[[hooks.definitions.token_mint_callback.parameters]]
type = "bytes32"
source = { source_type = "payment", field = "nonce" }

[[hooks.definitions.token_mint_callback.parameters]]
type = "uint8"
source = { source_type = "payment", field = "signaturev" }

[[hooks.definitions.token_mint_callback.parameters]]
type = "bytes32"
source = { source_type = "payment", field = "signaturer" }

[[hooks.definitions.token_mint_callback.parameters]]
type = "bytes32"
source = { source_type = "payment", field = "signatures" }
```

**Mapping:**
```toml
[hooks.mappings]
"0xYourTokenMintContractAddress" = ["token_mint_callback"]
```

### Example 2: Simple Settlement Notification

Notifies a contract when a settlement occurs with basic information.

**Solidity Interface:**
```solidity
interface ISettlementNotifier {
    function notifySettlement(
        address from,
        address to,
        uint256 amount
    ) external;
}
```

**Configuration:**
```toml
[hooks.definitions.notify_settlement]
enabled = true
description = "Notifies contract of settlement with payer, recipient, and amount"
contract = "0xNotifierContractAddress"
function_signature = "notifySettlement(address,address,uint256)"
gas_limit = 100000

[[hooks.definitions.notify_settlement.parameters]]
type = "address"
source = { source_type = "payment", field = "from" }

[[hooks.definitions.notify_settlement.parameters]]
type = "address"
source = { source_type = "payment", field = "to" }

[[hooks.definitions.notify_settlement.parameters]]
type = "uint256"
source = { source_type = "payment", field = "value" }
```

### Example 3: Settlement with Runtime Context

Includes block timestamp and facilitator address.

**Solidity Interface:**
```solidity
interface ISettlementRecorder {
    function recordSettlement(
        address from,
        address to,
        uint256 amount,
        uint256 timestamp,
        address facilitator
    ) external;
}
```

**Configuration:**
```toml
[hooks.definitions.settlement_with_timestamp]
enabled = true
description = "Notifies contract with settlement details and block timestamp"
contract = "0xRecorderContractAddress"
function_signature = "recordSettlement(address,address,uint256,uint256,address)"
gas_limit = 120000

[[hooks.definitions.settlement_with_timestamp.parameters]]
type = "address"
source = { source_type = "payment", field = "from" }

[[hooks.definitions.settlement_with_timestamp.parameters]]
type = "address"
source = { source_type = "payment", field = "to" }

[[hooks.definitions.settlement_with_timestamp.parameters]]
type = "uint256"
source = { source_type = "payment", field = "value" }

[[hooks.definitions.settlement_with_timestamp.parameters]]
type = "uint256"
source = { source_type = "runtime", field = "timestamp" }

[[hooks.definitions.settlement_with_timestamp.parameters]]
type = "address"
source = { source_type = "runtime", field = "sender" }
```

### Example 4: Mixed Static and Dynamic Parameters

Combines payment data with static configuration values for royalty distribution.

**Solidity Interface:**
```solidity
interface IRoyaltyDistributor {
    function distributeRoyalty(
        address payer,
        uint256 amount,
        address royaltyRecipient,
        uint256 royaltyPercentage
    ) external;
}
```

**Configuration:**
```toml
[hooks.definitions.royalty_distribution]
enabled = true
description = "Distributes royalties with configured percentages"
contract = "0xRoyaltyContractAddress"
function_signature = "distributeRoyalty(address,uint256,address,uint256)"
gas_limit = 150000

[hooks.definitions.royalty_distribution.config_values]
royalty_recipient = "0x1111111111111111111111111111111111111111"
royalty_percentage = "250"  # 2.5% in basis points

[[hooks.definitions.royalty_distribution.parameters]]
type = "address"
source = { source_type = "payment", field = "from" }

[[hooks.definitions.royalty_distribution.parameters]]
type = "uint256"
source = { source_type = "payment", field = "value" }

[[hooks.definitions.royalty_distribution.parameters]]
type = "address"
source = { source_type = "config", field = "royalty_recipient" }

[[hooks.definitions.royalty_distribution.parameters]]
type = "uint256"
source = { source_type = "config", field = "royalty_percentage" }
```

### Example 5: Batch Context Tracking

Tracks settlement position within a batch for sequential processing.

**Solidity Interface:**
```solidity
interface IBatchTracker {
    function recordBatchSettlement(
        address from,
        uint256 amount,
        uint256 batchIndex,
        uint256 batchSize
    ) external;
}
```

**Configuration:**
```toml
[hooks.definitions.batch_tracker]
enabled = true
description = "Records settlement with batch context"
contract = "0xBatchTrackerAddress"
function_signature = "recordBatchSettlement(address,uint256,uint256,uint256)"
gas_limit = 100000

[[hooks.definitions.batch_tracker.parameters]]
type = "address"
source = { source_type = "payment", field = "from" }

[[hooks.definitions.batch_tracker.parameters]]
type = "uint256"
source = { source_type = "payment", field = "value" }

[[hooks.definitions.batch_tracker.parameters]]
type = "uint256"
source = { source_type = "runtime", field = "batchindex" }

[[hooks.definitions.batch_tracker.parameters]]
type = "uint256"
source = { source_type = "runtime", field = "batchsize" }
```

### Example 6: Legacy Static Calldata Hook (Deprecated)

Old-style hook with pre-encoded calldata. Use only for completely static calls.

**Configuration:**
```toml
[hooks.definitions.legacy_example]
enabled = false
description = "Legacy hook with static calldata (deprecated)"
contract = "0x0000000000000000000000000000000000000000"
calldata = "0x12345678"  # Pre-encoded function selector + parameters
gas_limit = 100000
```

## Admin API

Manage hooks at runtime without restarting the server:

### List All Hooks
```bash
curl -H "X-Admin-Key: your_admin_key" \
  http://localhost:8080/admin/hooks
```

### List Hook Mappings
```bash
curl -H "X-Admin-Key: your_admin_key" \
  http://localhost:8080/admin/hooks/mappings
```

### Reload Configuration
```bash
curl -X POST \
  -H "X-Admin-Key: your_admin_key" \
  http://localhost:8080/admin/hooks/reload
```

### Enable/Disable Specific Hook
```bash
# Enable
curl -X POST \
  -H "X-Admin-Key: your_admin_key" \
  http://localhost:8080/admin/hooks/hook_name/enable

# Disable
curl -X POST \
  -H "X-Admin-Key: your_admin_key" \
  http://localhost:8080/admin/hooks/hook_name/disable
```

### Check Hook Status
```bash
curl -H "X-Admin-Key: your_admin_key" \
  http://localhost:8080/admin/hooks/status
```

## Security Considerations

### Access Control
- All hook definitions must be manually added by admins via `hooks.toml`
- Only destination mappings can be modified via admin API (with authentication)
- Hook contract addresses are immutable once defined
- Admin API requires `X-Admin-Key` header authentication

### Gas Limits
- Set reasonable gas limits to prevent DoS attacks
- Monitor hook execution costs in production
- Consider batch size impact on total gas usage
- Use `allow_hook_failure = false` by default for safety

### Contract Validation
- Verify hook contract source code before deployment
- Test hooks thoroughly on testnet
- Ensure hook contracts handle failure gracefully
- Use established audit patterns for hook contracts

### Permission Model
- Hooks execute with facilitator's permissions
- Hook contracts can perform any action the facilitator can perform
- Treat hook contracts as highly privileged code
- Implement proper access controls in hook contracts

### Failure Handling
- `allow_hook_failure = false` (default): Any hook failure reverts entire batch
- `allow_hook_failure = true`: Individual hooks can fail without reverting transfers
- Failed hooks indicate potential issues - investigate immediately
- Monitor hook execution success rates

## Testing Hooks

### Local Testing

1. Deploy hook contract to testnet
2. Add hook definition to `hooks.toml`
3. Add recipient mapping
4. Enable hooks globally: `enabled = true`
5. Submit test payment to mapped recipient
6. Verify hook execution in transaction logs

### Unit Testing

See `src/hooks/manager.rs` tests for examples of testing hook encoding and execution.

### Integration Testing

1. Use testnet with test tokens
2. Monitor Multicall3 transaction for hook execution
3. Verify hook contract state changes
4. Test both success and failure scenarios
5. Validate batch behavior with multiple hooks

## Troubleshooting

### Hook Not Executing

1. Check `hooks.enabled = true` in config
2. Verify hook is `enabled = true`
3. Confirm recipient address is in mappings
4. Check admin logs for hook resolution
5. Verify gas limit is sufficient

### Hook Execution Failing

1. Check transaction logs for revert reason
2. Verify function signature matches contract ABI
3. Ensure parameter types match Solidity types
4. Test hook contract function directly
5. Increase gas limit if out-of-gas

### Parameter Encoding Issues

1. Verify field names match available sources
2. Check Solidity types are correct
3. Ensure config values exist for `config` source
4. Validate static values parse correctly
5. Review logs for encoding errors

## Best Practices

1. **Start with testnet**: Always test hooks on testnet first
2. **Use descriptive names**: Make hook names and descriptions clear
3. **Document parameters**: Comment what each parameter represents
4. **Monitor execution**: Watch hook execution in production
5. **Keep gas low**: Minimize gas usage in hook contracts
6. **Handle failures**: Implement proper error handling
7. **Version control**: Track `hooks.toml` in git
8. **Audit contracts**: Get hook contracts audited before mainnet
9. **Test edge cases**: Try batch scenarios, failures, gas limits
10. **Keep it simple**: Avoid complex logic in hooks when possible

## Advanced Topics

### Multiple Hooks per Recipient

You can attach multiple hooks to a single recipient:

```toml
[hooks.mappings]
"0xRecipient" = ["hook1", "hook2", "hook3"]
```

Hooks execute in array order. If `allow_hook_failure = false`, all hooks must succeed.

### Conditional Hook Execution

To conditionally execute hooks, implement the logic in the hook contract itself:

```solidity
function onPaymentReceived(...) external {
    if (amount < MIN_AMOUNT) return;  // Skip small payments
    // ... hook logic
}
```

### Hook Composability

Hooks can call other contracts, enabling complex workflows:

```solidity
function onPaymentReceived(...) external {
    // Mint NFT
    nftContract.mint(from, tokenId);

    // Update registry
    registry.recordMint(from, tokenId, amount);

    // Emit event
    emit PaymentProcessed(from, tokenId, amount);
}
```

### Performance Optimization

- Use `batchindex` and `batchsize` to optimize batch processing
- Minimize storage writes in hook contracts
- Use events instead of storage when possible
- Consider gas refunds for hook executions

## Architecture

### Components

1. **Hook Configuration** (`src/hooks/config.rs`): TOML parsing and validation
2. **Hook Manager** (`src/hooks/manager.rs`): Thread-safe hot-reloadable manager
3. **Admin API** (`src/hooks/admin.rs`): REST endpoints for runtime management
4. **Runtime Context** (`src/hooks/context.rs`): Dynamic parameter resolution
5. **Settlement Integration** (`src/chain/evm.rs`): Hook lookup and execution

### Call3-Aware Batching

The batch processor counts total Multicall3 Call3 structs:

```rust
for settlement in validated_settlements {
    let calls_needed = 1 + settlement.hooks.len();  // 1 transfer + N hooks
    if current_call3_count + calls_needed > MAX_CALL3_PER_BATCH {
        // Start new sub-batch
    }
}
```

With `max_batch_size = 100`:
- 30 settlements × 3 calls each (1 transfer + 2 hooks) = 90 Call3s ✓
- 100 settlements × 1 call each (transfer only) = 100 Call3s ✓

## Reference Implementation

See `abi/TokenMintWith3009.abi.json` for a complete reference implementation of an EIP-3009 aware hook contract.

## Support

For issues or questions:
- Review this documentation
- Check facilitator logs for errors
- Test on testnet first
- Review `docs/TESTING_HOOKS.md` for detailed testing guide
- Open GitHub issue with details
