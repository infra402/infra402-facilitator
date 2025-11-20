//! Post-settlement hook system
//!
//! This module provides functionality for executing additional contract calls
//! atomically with settlement transfers via Multicall3.
//!
//! ## Architecture
//!
//! - `config`: Hook configuration structures (hooks.toml parsing)
//! - `manager`: HookManager with hot-reload capability
//! - `admin`: Admin API endpoints for managing hooks
//! - `context`: Runtime context for dynamic parameter resolution
//! - `errors`: Error types for hook operations
//!
//! ## Usage
//!
//! 1. Define hooks in `hooks.toml` with `function_signature` and `parameters`
//! 2. Parameters can extract values from EIP-3009 payment, runtime context, or static config
//! 3. Map destination addresses to hooks
//! 4. When settlement is sent to mapped destination, hooks execute atomically
//! 5. Calldata is dynamically encoded at settlement time
//!
//! ## Security
//!
//! - All hooks must be manually added by admins through code changes
//! - Hook ABIs must exist in `abi/hooks/` directory
//! - Destination mappings can be modified via admin API with authentication

pub mod admin;
pub mod config;
pub mod context;
pub mod errors;
pub mod manager;

// Public API exports
pub use context::RuntimeContext;
pub use manager::{HookCall, HookManager};
