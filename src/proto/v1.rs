//! x402 Protocol Version 1 types.
//!
//! This module re-exports the original v1 protocol types from `crate::types`.
//! These types represent the initial x402 protocol specification with:
//! - Flat `PaymentRequirements` structure
//! - Single-scheme support ("exact")
//! - Network-specific addressing
//!
//! For the extended v2 protocol, see [`super::v2`].

// Re-export all v1 types from the main types module.
// These are public API re-exports for library consumers.
#[allow(unused_imports)]
pub use crate::types::{
    ErrorResponse, ExactEvmPayload, ExactEvmPayloadAuthorization, ExactPaymentPayload,
    ExactSolanaPayload, EvmAddress, EvmSignature, FacilitatorErrorReason, HexEncodedNonce,
    MixedAddress, MoneyAmount, PaymentPayload, PaymentRequiredResponse, PaymentRequirements,
    Scheme, SettleRequest, SettleResponse, SupportedPaymentKind, SupportedPaymentKindExtra,
    SupportedPaymentKindsResponse, TokenAmount, TokenAsset, TokenDeployment, TokenDeploymentEip712,
    TransactionHash, VerifyRequest, VerifyResponse, X402Version,
};
