# Post-Settlement Hooks Implementation

## Overview

This implementation adds support for post-settlement hooks - custom contract calls that execute atomically with settlement transfers via Multicall3.

## Architecture

### Option C: Hybrid Approach (Implemented)

- **Whitelisted contracts**: All hooks must have ABIs in `abi/hooks/` directory
- **Admin-controlled**: Hooks added manually through code + configuration
- **Hot-reloadable mappings**: Destination→hook mappings can be updated via admin API without restart
- **Call3-aware batching**: `max_batch_size` counts total Call3 structs (not settlement count)
- **Configurable failure handling**: `allow_hook_failure` flag controls atomicity

## Components

### 1. Hook Configuration (`src/hooks/config.rs`)

Defines configuration structures and TOML parsing:
- `HookDefinition`: Contract address, calldata, gas limit, enabled flag
- `HookConfig`: Global settings, mappings, and hook definitions
- Loads from `hooks.toml`

### 2. Hook Manager (`src/hooks/manager.rs`)

Thread-safe manager with hot-reload capability:
- `HookManager::new(config_path)`: Initialize from file
- `reload()`: Hot-reload configuration without restart
- `get_hooks_for_destination(address)`: Lookup hooks for recipient
- `enable_hook(name)` / `disable_hook(name)`: Runtime control
- Uses `Arc<RwLock<HookState>>` for concurrent access

### 3. Admin API (`src/hooks/admin.rs`)

REST endpoints requiring `X-Admin-Key` authentication:
- `GET /admin/hooks`: List all hook definitions
- `GET /admin/hooks/mappings`: List all destination mappings
- `GET /admin/hooks/status`: Get hook system status
- `POST /admin/hooks/reload`: Reload hooks.toml
- `POST /admin/hooks/:name/enable`: Enable specific hook
- `POST /admin/hooks/:name/disable`: Disable specific hook

### 4. Settlement Integration (`src/chain/evm.rs`)

Modified `validate_and_prepare_settlement()`:
- Accepts `Option<&Arc<HookManager>>` parameter
- Looks up hooks for destination address: `hook_manager.get_hooks_for_destination(to)`
- Adds hooks to `ValidatedSettlement.hooks: Vec<HookCall>`

Modified `settle_batch()`:
- Builds Multicall3 with hooks included
- For each settlement: 1 Call3 for transfer + N Call3s for hooks
- Uses `allow_hook_failure` setting when hooks present

### 5. Batch Processing (`src/batch_processor.rs`)

Call3-aware batch sizing:
```rust
let calls_needed = 1 + settlement.hooks.len(); // 1 transfer + N hooks
if current_call3_count + calls_needed > MAX_CALL3_PER_BATCH {
    // Flush current batch, start new one
}
```

Splits validated settlements into sub-batches based on total Call3 count.

### 6. Configuration (`src/config.rs`)

Added `allow_hook_failure` field to `BatchSettlementConfig`:
- Default: `false` (any hook failure reverts entire batch)
- When `true`: hooks can fail without reverting transfers

### 7. Main Integration (`src/main.rs`)

- Initializes `HookManager` at startup
- Registers admin hook routes
- Adds `hook_manager` as `Extension` for handlers

## Configuration Example

### hooks.toml

```toml
[hooks]
enabled = true
allow_hook_failure = false

[hooks.mappings]
"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb" = ["notify_settlement"]

[hooks.definitions.notify_settlement]
enabled = true
description = "Notify contract of settlement"
contract = "0x1234567890abcdef1234567890abcdef12345678"
calldata = "0x12345678..."  # Pre-encoded function call
gas_limit = 100000
```

## Usage

### Adding a New Hook

1. **Deploy hook contract** with desired functionality
2. **Create ABI**: Place contract ABI in `abi/hooks/YourHook.json`
3. **Encode calldata**: Generate the calldata for your function call
4. **Configure hook**: Add definition to `hooks.toml`:
   ```toml
   [hooks.definitions.your_hook]
   enabled = true
   description = "Your hook description"
   contract = "0x..."
   calldata = "0x..."
   gas_limit = 100000
   ```
5. **Map destinations**: Add destination→hook mapping:
   ```toml
   [hooks.mappings]
   "0xRecipientAddress" = ["your_hook"]
   ```
6. **Reload**: Call `POST /admin/hooks/reload` or restart server

### Runtime Management

Enable/disable hooks without restart:
```bash
# Enable hook
curl -X POST http://localhost:8080/admin/hooks/my_hook/enable \
  -H "X-Admin-Key: your-admin-key"

# Disable hook
curl -X POST http://localhost:8080/admin/hooks/my_hook/disable \
  -H "X-Admin-Key: your-admin-key"

# Reload configuration
curl -X POST http://localhost:8080/admin/hooks/reload \
  -H "X-Admin-Key: your-admin-key"

# Check status
curl http://localhost:8080/admin/hooks/status \
  -H "X-Admin-Key: your-admin-key"
```

## Batch Sizing Example

With `max_batch_size = 100` (Call3 count):
- 30 settlements with 2 hooks each = 90 Call3s (30×3)
- 10 settlements with 0 hooks = 10 Call3s (10×1)
- **Total: 40 settlements = 100 Call3s** ✓

The batch processor automatically splits based on Call3 count, not settlement count.

## Security Considerations

1. **Whitelist-only**: All hooks must be manually added by admins
2. **ABI Required**: Hook contracts must have ABIs in `abi/hooks/`
3. **Facilitator permissions**: Hooks execute with facilitator's signing key
4. **Atomicity control**: `allow_hook_failure` determines failure behavior
5. **Hot-reload auth**: Configuration reloads require `X-Admin-Key`

## Gas Considerations

- Each hook adds gas cost to the batch transaction
- Set appropriate `gas_limit` per hook to prevent DoS
- Use `allow_hook_failure = true` carefully - may mask important errors
- Monitor batch gas usage with hooks enabled

## Known Limitations / TODO

1. **Gas failure retry logic**: Not yet implemented (marked with TODO)
2. **allow_hook_failure config**: Currently uses `allow_partial_failure` (TODO: wire up proper setting)
3. **MAX_CALL3_PER_BATCH**: Hardcoded to 150 (TODO: make configurable)
4. **reload_hooks workaround**: Uses inline closure due to trait bound issue with axum

## Testing

The implementation compiles successfully with warnings only for unused code (expected when hooks.toml doesn't exist).

To test:
1. Create `hooks.toml` with test configuration
2. Deploy a test hook contract
3. Add hook ABI to `abi/hooks/`
4. Configure mapping for test recipient
5. Send settlement to mapped recipient
6. Verify hook executes in same transaction via block explorer

## Files Modified

- `src/lib.rs`: Added `pub mod hooks;`
- `src/main.rs`: Initialize HookManager, register admin routes, add Extension
- `src/config.rs`: Added `allow_hook_failure` field
- `src/chain/evm.rs`: Hook lookup in validation, Multicall3 building with hooks
- `src/batch_processor.rs`: Call3-aware batch sizing and sub-batching
- `src/hooks/` (new): config.rs, manager.rs, admin.rs, mod.rs
- `hooks.toml` (new): Configuration file
- `abi/hooks/ExampleHook.json` (new): Example ABI

## API Endpoints

All admin endpoints require `X-Admin-Key` header:

- `GET /admin/hooks` - List hook definitions
- `GET /admin/hooks/mappings` - List destination mappings  
- `GET /admin/hooks/status` - System status
- `POST /admin/hooks/reload` - Reload configuration
- `POST /admin/hooks/:name/enable` - Enable hook
- `POST /admin/hooks/:name/disable` - Disable hook

## Implementation Notes

### reload_hooks Fix

The `reload_hooks` endpoint had a trait bound issue because `Box<dyn std::error::Error>` is not `Send`. Fixed by changing error type to `String`:

```rust
pub async fn reload(&self) -> Result<(), String> {
    let config = HookConfig::from_file(&self.config_path)
        .map_err(|e| e.to_string())?;
    // ...
}
```

And using inline closure in router to avoid handler trait issues:
```rust
.route("/admin/hooks/reload", post(|State(manager): State<Arc<HookManager>>| async move {
    match manager.reload().await { /* ... */ }
}))
```

### Call3 Counting Logic

The batch processor counts Call3 structs correctly:
```rust
for (settlement, channel) in validated_settlements {
    let calls_needed = 1 + settlement.hooks.len();
    if current_call3_count + calls_needed > MAX_CALL3_PER_BATCH {
        // Start new sub-batch
    }
    current_call3_count += calls_needed;
}
```

This ensures `max_batch_size` represents total Multicall3 Call3 structs, not just settlement count.
