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
//!
//! ## Usage
//!
//! 1. Define hooks in `hooks.toml` with contract address and calldata
//! 2. Map destination addresses to hooks
//! 3. When settlement is sent to mapped destination, hooks execute atomically
//!
//! ## Security
//!
//! - All hooks must be manually added by admins through code changes
//! - Hook ABIs must exist in `abi/hooks/` directory
//! - Destination mappings can be modified via admin API with authentication

pub mod admin;
pub mod config;
pub mod manager;

pub use config::{HookConfig, HookDefinition};
pub use manager::{HookCall, HookManager};
