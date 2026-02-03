//! Protocol version types for x402.
//!
//! This module contains type definitions for different versions of the x402 protocol.
//! Currently supports:
//! - v1: Original protocol with flat PaymentRequirements
//! - v2: Extended protocol with generic payment scheme support
//!
//! # Version Selection
//!
//! The protocol version is determined by the `x402Version` field in requests:
//! - `1` or missing: Use v1 protocol types
//! - `2`: Use v2 protocol types
//!
//! # Backward Compatibility
//!
//! The v2 protocol is designed to be backward compatible with v1. A v1 request
//! can be processed by a v2-capable facilitator, and v2 responses include all
//! fields required by v1 clients.

// Allow unused items - this is scaffolding for v2 protocol support.
// These types will be used once v2 handlers are fully integrated.
#![allow(dead_code, unused_imports)]

pub mod v1;
pub mod v2;

// Re-export commonly used types
pub use v1::{
    PaymentPayload as PaymentPayloadV1, PaymentRequirements as PaymentRequirementsV1,
    SettleResponse as SettleResponseV1, VerifyRequest as VerifyRequestV1,
    VerifyResponse as VerifyResponseV1,
};
pub use v2::{
    ExactSchemePayload, PaymentPayload as PaymentPayloadV2,
    PaymentRequirements as PaymentRequirementsV2, ResourceInfo, VerifyResponse as VerifyResponseV2,
};

// Type alias for the common v2 verify request with exact scheme
pub type VerifyRequestV2 =
    v2::VerifyRequest<crate::types::ExactPaymentPayload, v2::ExactSchemePayload>;

use serde::{Deserialize, Serialize};

/// Protocol version enumeration.
///
/// Represents the x402 protocol version being used in a request or response.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum ProtocolVersion {
    /// Version 1 - original x402 protocol
    #[default]
    V1,
    /// Version 2 - extended protocol with generic scheme support
    V2,
}

impl ProtocolVersion {
    /// Returns the numeric version number.
    pub fn as_u8(&self) -> u8 {
        match self {
            ProtocolVersion::V1 => 1,
            ProtocolVersion::V2 => 2,
        }
    }

    /// Creates a protocol version from a numeric value.
    ///
    /// Returns `None` for unsupported version numbers.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ProtocolVersion::V1),
            2 => Some(ProtocolVersion::V2),
            _ => None,
        }
    }
}

impl From<ProtocolVersion> for u8 {
    fn from(v: ProtocolVersion) -> Self {
        v.as_u8()
    }
}

impl TryFrom<u8> for ProtocolVersion {
    type Error = UnsupportedVersionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        ProtocolVersion::from_u8(value).ok_or(UnsupportedVersionError(value))
    }
}

/// Error returned when an unsupported protocol version is requested.
#[derive(Debug, Clone, thiserror::Error)]
#[error("unsupported x402 protocol version: {0}")]
pub struct UnsupportedVersionError(pub u8);

impl Serialize for ProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        ProtocolVersion::from_u8(v)
            .ok_or_else(|| serde::de::Error::custom(format!("unsupported version: {v}")))
    }
}

/// A version-agnostic verify request that can hold either v1 or v2 data.
#[derive(Debug, Clone)]
pub enum VersionedVerifyRequest {
    V1(VerifyRequestV1),
    V2(Box<VerifyRequestV2>),
}

impl VersionedVerifyRequest {
    /// Returns the protocol version of this request.
    pub fn version(&self) -> ProtocolVersion {
        match self {
            VersionedVerifyRequest::V1(_) => ProtocolVersion::V1,
            VersionedVerifyRequest::V2(_) => ProtocolVersion::V2,
        }
    }

    /// Attempts to extract a v1 request, converting from v2 if necessary.
    pub fn as_v1(&self) -> Option<&VerifyRequestV1> {
        match self {
            VersionedVerifyRequest::V1(req) => Some(req),
            VersionedVerifyRequest::V2(_) => None,
        }
    }

    /// Attempts to extract a v2 request.
    pub fn as_v2(&self) -> Option<&VerifyRequestV2> {
        match self {
            VersionedVerifyRequest::V1(_) => None,
            VersionedVerifyRequest::V2(req) => Some(req),
        }
    }
}

/// Detects the protocol version from a JSON value.
///
/// Looks for the `x402Version` field to determine the protocol version.
/// Defaults to v1 if the field is missing.
pub fn detect_version(value: &serde_json::Value) -> ProtocolVersion {
    value
        .get("x402Version")
        .and_then(|v| v.as_u64())
        .and_then(|v| ProtocolVersion::from_u8(v as u8))
        .unwrap_or(ProtocolVersion::V1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_conversion() {
        assert_eq!(ProtocolVersion::V1.as_u8(), 1);
        assert_eq!(ProtocolVersion::V2.as_u8(), 2);
        assert_eq!(ProtocolVersion::from_u8(1), Some(ProtocolVersion::V1));
        assert_eq!(ProtocolVersion::from_u8(2), Some(ProtocolVersion::V2));
        assert_eq!(ProtocolVersion::from_u8(3), None);
    }

    #[test]
    fn test_detect_version() {
        let v1_json = serde_json::json!({
            "x402Version": 1,
            "paymentPayload": {}
        });
        assert_eq!(detect_version(&v1_json), ProtocolVersion::V1);

        let v2_json = serde_json::json!({
            "x402Version": 2,
            "paymentPayload": {}
        });
        assert_eq!(detect_version(&v2_json), ProtocolVersion::V2);

        let no_version = serde_json::json!({
            "paymentPayload": {}
        });
        assert_eq!(detect_version(&no_version), ProtocolVersion::V1);
    }

    #[test]
    fn test_serde_roundtrip() {
        let v = ProtocolVersion::V2;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "2");
        let parsed: ProtocolVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, v);
    }
}
