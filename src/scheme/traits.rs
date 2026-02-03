//! Scheme traits and registry for x402 v2 protocol.
//!
//! This module defines the core traits for payment scheme handlers and
//! the registry for looking up handlers by scheme identifier.

// These types are scaffolding for v2 protocol support and will be
// used once v2 handlers are fully implemented.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use crate::chain::FacilitatorLocalError;
use crate::proto::v2::{PaymentPayload, PaymentRequirements, VerifyResponse};
use crate::types::Scheme;

/// Trait for identifying a payment scheme.
///
/// Each scheme has a unique identifier used for routing requests
/// to the appropriate handler.
pub trait X402SchemeId: Send + Sync {
    /// Returns the scheme identifier.
    fn scheme_id(&self) -> Scheme;

    /// Returns a human-readable name for this scheme.
    fn name(&self) -> &str;

    /// Returns a description of this scheme's behavior.
    fn description(&self) -> &str;
}

/// Trait for payment scheme facilitators.
///
/// Implementors of this trait provide the verification and settlement
/// logic for a specific payment scheme. The type parameters allow
/// each scheme to define its own payload and requirements types.
///
/// # Type Parameters
///
/// - `P`: The payload type for this scheme (e.g., signed authorization)
/// - `R`: The requirements type for this scheme (e.g., exact amount requirements)
pub trait X402SchemeFacilitator<P = serde_json::Value, R = serde_json::Value>:
    X402SchemeId + Send + Sync
{
    /// The error type returned by this facilitator.
    type Error: Debug + Send;

    /// Verifies a payment payload against the given requirements.
    ///
    /// This should validate signatures, check timing constraints,
    /// verify amounts, and any other scheme-specific checks.
    fn verify(
        &self,
        payload: &PaymentPayload<P>,
        requirements: &PaymentRequirements<R>,
    ) -> impl Future<Output = Result<VerifyResponse, Self::Error>> + Send;

    /// Settles a verified payment on-chain.
    ///
    /// This should execute the payment transfer and return the
    /// transaction details.
    fn settle(
        &self,
        payload: &PaymentPayload<P>,
        requirements: &PaymentRequirements<R>,
    ) -> impl Future<Output = Result<crate::types::SettleResponse, Self::Error>> + Send;
}

/// A type-erased scheme facilitator handler.
///
/// This allows storing different scheme implementations in a single
/// registry without knowing their concrete types.
pub trait DynSchemeFacilitator: X402SchemeId + Send + Sync {
    /// Verifies a payment using JSON values for maximum flexibility.
    fn verify_json(
        &self,
        payload: &serde_json::Value,
        requirements: &serde_json::Value,
    ) -> impl Future<Output = Result<VerifyResponse, FacilitatorLocalError>> + Send;

    /// Settles a payment using JSON values.
    fn settle_json(
        &self,
        payload: &serde_json::Value,
        requirements: &serde_json::Value,
    ) -> impl Future<Output = Result<crate::types::SettleResponse, FacilitatorLocalError>> + Send;
}

/// Registry for payment scheme handlers.
///
/// The registry maps scheme identifiers to their handlers, allowing
/// the facilitator to route requests to the appropriate scheme
/// implementation.
///
/// # Example
///
/// ```ignore
/// let mut registry = SchemeRegistry::new();
/// registry.register(Arc::new(ExactSchemeHandler::new(provider)));
///
/// // Route a request
/// let scheme = Scheme::Exact;
/// if let Some(handler) = registry.get(&scheme) {
///     handler.verify_json(&payload, &requirements).await?;
/// }
/// ```
pub struct SchemeRegistry<T> {
    handlers: HashMap<Scheme, Arc<T>>,
}

impl<T> Default for SchemeRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SchemeRegistry<T> {
    /// Creates a new empty scheme registry.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Returns the number of registered schemes.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Returns true if no schemes are registered.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Returns an iterator over registered schemes.
    pub fn schemes(&self) -> impl Iterator<Item = &Scheme> {
        self.handlers.keys()
    }
}

impl<T: X402SchemeId> SchemeRegistry<T> {
    /// Registers a scheme handler.
    ///
    /// If a handler for this scheme is already registered, it will be replaced.
    pub fn register(&mut self, handler: Arc<T>) {
        let scheme = handler.scheme_id();
        self.handlers.insert(scheme, handler);
    }

    /// Gets a handler for the given scheme.
    pub fn get(&self, scheme: &Scheme) -> Option<&Arc<T>> {
        self.handlers.get(scheme)
    }

    /// Returns true if a handler is registered for the given scheme.
    pub fn contains(&self, scheme: &Scheme) -> bool {
        self.handlers.contains_key(scheme)
    }
}

/// Builder for constructing scheme registries.
pub struct SchemeRegistryBuilder<T> {
    registry: SchemeRegistry<T>,
}

impl<T: X402SchemeId> Default for SchemeRegistryBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: X402SchemeId> SchemeRegistryBuilder<T> {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {
            registry: SchemeRegistry::new(),
        }
    }

    /// Adds a scheme handler to the registry.
    pub fn with_handler(mut self, handler: Arc<T>) -> Self {
        self.registry.register(handler);
        self
    }

    /// Builds the registry.
    pub fn build(self) -> SchemeRegistry<T> {
        self.registry
    }
}

/// Marker type for the "exact" payment scheme.
///
/// The exact scheme requires the payment amount to exactly match
/// the required amount, with no allowance for over/underpayment.
pub struct ExactScheme;

impl X402SchemeId for ExactScheme {
    fn scheme_id(&self) -> Scheme {
        Scheme::Exact
    }

    fn name(&self) -> &str {
        "exact"
    }

    fn description(&self) -> &str {
        "Requires exact payment amount matching"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestScheme;

    impl X402SchemeId for TestScheme {
        fn scheme_id(&self) -> Scheme {
            Scheme::Exact
        }

        fn name(&self) -> &str {
            "test"
        }

        fn description(&self) -> &str {
            "Test scheme"
        }
    }

    #[test]
    fn test_registry_basic() {
        let mut registry = SchemeRegistry::new();
        assert!(registry.is_empty());

        registry.register(Arc::new(TestScheme));
        assert_eq!(registry.len(), 1);
        assert!(registry.contains(&Scheme::Exact));
        assert!(registry.get(&Scheme::Exact).is_some());
    }

    #[test]
    fn test_registry_builder() {
        let registry = SchemeRegistryBuilder::new()
            .with_handler(Arc::new(TestScheme))
            .build();

        assert_eq!(registry.len(), 1);
        assert!(registry.contains(&Scheme::Exact));
    }

    #[test]
    fn test_exact_scheme() {
        let scheme = ExactScheme;
        assert_eq!(scheme.scheme_id(), Scheme::Exact);
        assert_eq!(scheme.name(), "exact");
    }
}
