//! Payment scheme system for x402 v2 protocol.
//!
//! This module provides the infrastructure for supporting multiple payment schemes
//! in the x402 protocol. A scheme defines how payment authorization and verification
//! work for a particular payment type.
//!
//! # Built-in Schemes
//!
//! - `exact`: The original x402 scheme requiring exact amount matching
//!
//! # Extending with Custom Schemes
//!
//! To add a new scheme:
//! 1. Implement [`X402SchemeFacilitator`] for your scheme's handler
//! 2. Register it with the [`SchemeRegistry`]
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use infra402_facilitator::scheme::{SchemeRegistry, ExactScheme};
//! use infra402_facilitator::types::Scheme;
//!
//! let mut registry = SchemeRegistry::new();
//! registry.register(Arc::new(ExactScheme));
//!
//! // Look up handler by scheme
//! if let Some(_handler) = registry.get(&Scheme::Exact) {
//!     println!("Found handler for exact scheme");
//! }
//! ```

// Allow unused items - this is scaffolding for v2 protocol support.
// These types will be used once v2 handlers are fully integrated.
#![allow(dead_code, unused_imports)]

mod traits;

pub use traits::{ExactScheme, SchemeRegistry, X402SchemeFacilitator, X402SchemeId};

use crate::types::Scheme;

/// Returns the default scheme (exact).
pub fn default_scheme() -> Scheme {
    Scheme::Exact
}

/// Returns all supported schemes.
pub fn supported_schemes() -> &'static [Scheme] {
    &[Scheme::Exact]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_scheme() {
        assert_eq!(default_scheme(), Scheme::Exact);
    }

    #[test]
    fn test_supported_schemes() {
        let schemes = supported_schemes();
        assert!(schemes.contains(&Scheme::Exact));
    }
}
