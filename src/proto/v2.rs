//! x402 Protocol Version 2 types.
//!
//! This module defines the extended v2 protocol types that support:
//! - Generic payment scheme support (beyond just "exact")
//! - Resource metadata for payment-gated content
//! - Flexible payload structures per scheme
//! - CAIP-2 chain identifiers
//!
//! # Key Differences from v1
//!
//! - `PaymentRequirements<T>` is generic over the scheme-specific payload type
//! - `ResourceInfo` provides detailed metadata about the payment-gated resource
//! - Support for multiple concurrent payment requirements
//! - Chain identifiers use CAIP-2 format ("eip155:8453") instead of enum variants

use serde::{Deserialize, Serialize};
use url::Url;

use crate::chain::ChainId;
use crate::types::{MixedAddress, Scheme, TokenAmount};

/// x402 Protocol Version 2 marker.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct X402Version2;

impl Serialize for X402Version2 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(2)
    }
}

impl<'de> Deserialize<'de> for X402Version2 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = u8::deserialize(deserializer)?;
        if v == 2 {
            Ok(X402Version2)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected version 2, got {v}"
            )))
        }
    }
}

/// Metadata about a payment-gated resource.
///
/// Provides detailed information about what the payment unlocks,
/// including content type, size, and preview capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    /// The URL of the payment-gated resource.
    pub url: Url,

    /// Human-readable description of the resource.
    pub description: String,

    /// MIME type of the resource content.
    pub mime_type: String,

    /// Optional JSON schema describing the response structure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,

    /// Optional content length in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,

    /// Optional preview URL for partial content access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_url: Option<Url>,
}

/// Payment requirements for v2 protocol.
///
/// This is generic over the scheme-specific payload type `T`, allowing
/// different schemes to define their own requirement structures.
///
/// # Type Parameter
///
/// - `T`: The scheme-specific payload type (e.g., `ExactSchemePayload`)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements<T> {
    /// The payment scheme identifier.
    pub scheme: Scheme,

    /// CAIP-2 chain identifier (e.g., "eip155:8453").
    pub chain_id: ChainId,

    /// Maximum amount required for payment (in token base units).
    pub max_amount_required: TokenAmount,

    /// Information about the payment-gated resource.
    pub resource: ResourceInfo,

    /// Address to receive the payment.
    pub pay_to: MixedAddress,

    /// Maximum timeout for the payment in seconds.
    pub max_timeout_seconds: u64,

    /// Token address for the payment asset.
    pub asset: MixedAddress,

    /// Scheme-specific payload data.
    #[serde(flatten)]
    pub payload: T,

    /// Additional scheme-specific or extension data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Payload for the "exact" payment scheme in v2.
///
/// The exact scheme requires an exact match between the authorized
/// amount and the required amount.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactSchemePayload {
    // The exact scheme doesn't need additional fields beyond what's in PaymentRequirements
}

/// Payment payload for v2 protocol.
///
/// Contains the signed authorization data for a payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload<T> {
    /// Protocol version (always 2 for v2).
    pub x402_version: X402Version2,

    /// The payment scheme being used.
    pub scheme: Scheme,

    /// CAIP-2 chain identifier.
    pub chain_id: ChainId,

    /// Scheme-specific signed payload.
    pub payload: T,
}

/// Verify request for v2 protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest<T, R = ExactSchemePayload> {
    /// Protocol version (always 2).
    pub x402_version: X402Version2,

    /// The payment payload to verify.
    pub payment_payload: PaymentPayload<T>,

    /// The payment requirements to verify against.
    pub payment_requirements: PaymentRequirements<R>,
}

/// Verify response for v2 protocol.
///
/// Extends v1 response with additional metadata.
#[derive(Debug, Clone)]
pub enum VerifyResponse {
    /// Payment is valid.
    Valid {
        /// The payer address extracted from the payload.
        payer: MixedAddress,
        /// Optional metadata about the verification.
        metadata: Option<serde_json::Value>,
    },
    /// Payment is invalid.
    Invalid {
        /// The reason for invalidity.
        reason: crate::types::FacilitatorErrorReason,
        /// The payer address if it could be extracted.
        payer: Option<MixedAddress>,
        /// Optional additional error details.
        details: Option<serde_json::Value>,
    },
}

impl VerifyResponse {
    /// Creates a valid response.
    pub fn valid(payer: MixedAddress) -> Self {
        Self::Valid {
            payer,
            metadata: None,
        }
    }

    /// Creates a valid response with metadata.
    pub fn valid_with_metadata(payer: MixedAddress, metadata: serde_json::Value) -> Self {
        Self::Valid {
            payer,
            metadata: Some(metadata),
        }
    }

    /// Creates an invalid response.
    pub fn invalid(
        payer: Option<MixedAddress>,
        reason: crate::types::FacilitatorErrorReason,
    ) -> Self {
        Self::Invalid {
            reason,
            payer,
            details: None,
        }
    }

    /// Converts to a v1 verify response.
    pub fn to_v1(self) -> crate::types::VerifyResponse {
        match self {
            VerifyResponse::Valid { payer, .. } => crate::types::VerifyResponse::Valid { payer },
            VerifyResponse::Invalid { reason, payer, .. } => {
                crate::types::VerifyResponse::Invalid { reason, payer }
            }
        }
    }
}

impl Serialize for VerifyResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        match self {
            VerifyResponse::Valid { payer, metadata } => {
                let field_count = if metadata.is_some() { 3 } else { 2 };
                let mut s = serializer.serialize_struct("VerifyResponse", field_count)?;
                s.serialize_field("isValid", &true)?;
                s.serialize_field("payer", payer)?;
                if let Some(m) = metadata {
                    s.serialize_field("metadata", m)?;
                }
                s.end()
            }
            VerifyResponse::Invalid {
                reason,
                payer,
                details,
            } => {
                let field_count = 2 + payer.is_some() as usize + details.is_some() as usize;
                let mut s = serializer.serialize_struct("VerifyResponse", field_count)?;
                s.serialize_field("isValid", &false)?;
                s.serialize_field("invalidReason", reason)?;
                if let Some(p) = payer {
                    s.serialize_field("payer", p)?;
                }
                if let Some(d) = details {
                    s.serialize_field("details", d)?;
                }
                s.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for VerifyResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            is_valid: bool,
            payer: Option<MixedAddress>,
            invalid_reason: Option<crate::types::FacilitatorErrorReason>,
            metadata: Option<serde_json::Value>,
            details: Option<serde_json::Value>,
        }

        let raw = Raw::deserialize(deserializer)?;

        if raw.is_valid {
            let payer = raw.payer.ok_or_else(|| {
                serde::de::Error::custom("payer is required when isValid is true")
            })?;
            Ok(VerifyResponse::Valid {
                payer,
                metadata: raw.metadata,
            })
        } else {
            let reason = raw.invalid_reason.ok_or_else(|| {
                serde::de::Error::custom("invalidReason is required when isValid is false")
            })?;
            Ok(VerifyResponse::Invalid {
                reason,
                payer: raw.payer,
                details: raw.details,
            })
        }
    }
}

/// Convert v1 PaymentRequirements to v2 format.
impl From<&crate::types::PaymentRequirements> for PaymentRequirements<ExactSchemePayload> {
    fn from(v1: &crate::types::PaymentRequirements) -> Self {
        // Convert Network to ChainId
        let chain_id = ChainId::from(&v1.network);

        PaymentRequirements {
            scheme: v1.scheme,
            chain_id,
            max_amount_required: v1.max_amount_required,
            resource: ResourceInfo {
                url: v1.resource.clone(),
                description: v1.description.clone(),
                mime_type: v1.mime_type.clone(),
                output_schema: v1.output_schema.clone(),
                content_length: None,
                preview_url: None,
            },
            pay_to: v1.pay_to.clone(),
            max_timeout_seconds: v1.max_timeout_seconds,
            asset: v1.asset.clone(),
            payload: ExactSchemePayload::default(),
            extra: v1.extra.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FacilitatorErrorReason;

    #[test]
    fn test_x402_version2_serde() {
        let v = X402Version2;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "2");

        let parsed: X402Version2 = serde_json::from_str("2").unwrap();
        assert_eq!(parsed, X402Version2);

        // Invalid version should error
        assert!(serde_json::from_str::<X402Version2>("1").is_err());
    }

    #[test]
    fn test_verify_response_valid_serde() {
        let addr = MixedAddress::Offchain("test".to_string());
        let resp = VerifyResponse::valid(addr.clone());

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"isValid\":true"));
        assert!(json.contains("\"payer\":\"test\""));

        let parsed: VerifyResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            VerifyResponse::Valid { payer, .. } => assert_eq!(payer, addr),
            _ => panic!("expected Valid"),
        }
    }

    #[test]
    fn test_verify_response_invalid_serde() {
        let resp = VerifyResponse::invalid(None, FacilitatorErrorReason::InsufficientFunds);

        let json = serde_json::to_string(&resp).unwrap();
        eprintln!("Serialized JSON: {}", json);
        assert!(json.contains("\"isValid\":false"));
        assert!(json.contains("\"invalidReason\""));

        // Test deserialization with explicit JSON matching what we serialize
        let json_str = r#"{"isValid":false,"invalidReason":"insufficient_funds"}"#;
        let parsed: VerifyResponse = serde_json::from_str(json_str).unwrap();
        match parsed {
            VerifyResponse::Invalid { reason, payer, .. } => {
                assert!(matches!(reason, FacilitatorErrorReason::InsufficientFunds));
                assert!(payer.is_none());
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn test_verify_response_to_v1() {
        let addr = MixedAddress::Offchain("test".to_string());
        let v2_valid = VerifyResponse::valid(addr.clone());
        let v1 = v2_valid.to_v1();
        match v1 {
            crate::types::VerifyResponse::Valid { payer } => assert_eq!(payer, addr),
            crate::types::VerifyResponse::Invalid { .. } => panic!("expected Valid"),
        }
    }
}
