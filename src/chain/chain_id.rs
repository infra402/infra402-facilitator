//! CAIP-2 Chain Identifier support.
//!
//! This module implements the [CAIP-2] chain identifier standard, which provides
//! a human-readable, blockchain-agnostic way to reference blockchain networks.
//!
//! [CAIP-2]: https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md
//!
//! # Format
//!
//! A CAIP-2 chain identifier has the format `namespace:reference` where:
//! - `namespace`: A string identifying the blockchain ecosystem (e.g., "eip155", "solana", "aptos")
//! - `reference`: A string identifying the specific chain within that ecosystem
//!
//! # Examples
//!
//! ```
//! use infra402_facilitator::chain::ChainId;
//!
//! // EVM chains use the "eip155" namespace with chain ID as reference
//! let base = ChainId::eip155(8453);
//! assert_eq!(base.to_string(), "eip155:8453");
//!
//! // Parse from string
//! let parsed: ChainId = "eip155:84532".parse().unwrap();
//! assert_eq!(parsed, ChainId::eip155(84532));
//!
//! // Solana chains
//! let solana_mainnet = ChainId::solana_mainnet();
//! assert_eq!(solana_mainnet.to_string(), "solana:mainnet");
//! ```

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

/// A CAIP-2 compliant chain identifier.
///
/// This provides a standardized way to reference blockchain networks across
/// different ecosystems (EVM, Solana, Aptos, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainId {
    /// The namespace identifying the blockchain ecosystem.
    pub namespace: String,
    /// The reference identifying the specific chain within the namespace.
    pub reference: String,
}

/// Error type for ChainId parsing failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainIdParseError {
    /// The input string is empty.
    #[error("empty chain ID")]
    Empty,
    /// The input string does not contain a namespace:reference separator.
    #[error("missing separator ':' in chain ID")]
    MissingSeparator,
    /// The namespace portion is empty.
    #[error("empty namespace in chain ID")]
    EmptyNamespace,
    /// The reference portion is empty.
    #[error("empty reference in chain ID")]
    EmptyReference,
    /// The namespace contains invalid characters.
    #[error("invalid namespace: must be lowercase alphanumeric, got '{0}'")]
    InvalidNamespace(String),
    /// The reference contains invalid characters.
    #[error("invalid reference: must be alphanumeric or hyphen, got '{0}'")]
    InvalidReference(String),
}

impl ChainId {
    /// Creates a new ChainId with the given namespace and reference.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The blockchain ecosystem identifier (e.g., "eip155", "solana")
    /// * `reference` - The specific chain identifier within the namespace
    pub fn new(namespace: impl Into<String>, reference: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            reference: reference.into(),
        }
    }

    /// Creates an EIP-155 (EVM) chain identifier from a numeric chain ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use infra402_facilitator::chain::ChainId;
    ///
    /// let base = ChainId::eip155(8453);
    /// assert_eq!(base.to_string(), "eip155:8453");
    ///
    /// let ethereum = ChainId::eip155(1);
    /// assert_eq!(ethereum.to_string(), "eip155:1");
    /// ```
    pub fn eip155(chain_id: u64) -> Self {
        Self::new("eip155", chain_id.to_string())
    }

    /// Creates a Solana mainnet chain identifier.
    pub fn solana_mainnet() -> Self {
        Self::new("solana", "mainnet")
    }

    /// Creates a Solana devnet chain identifier.
    pub fn solana_devnet() -> Self {
        Self::new("solana", "devnet")
    }

    /// Creates an Aptos mainnet chain identifier.
    pub fn aptos_mainnet() -> Self {
        Self::new("aptos", "mainnet")
    }

    /// Creates an Aptos testnet chain identifier.
    pub fn aptos_testnet() -> Self {
        Self::new("aptos", "testnet")
    }

    /// Returns true if this is an EIP-155 (EVM) chain.
    pub fn is_evm(&self) -> bool {
        self.namespace == "eip155"
    }

    /// Returns true if this is a Solana chain.
    pub fn is_solana(&self) -> bool {
        self.namespace == "solana"
    }

    /// Returns true if this is an Aptos chain.
    pub fn is_aptos(&self) -> bool {
        self.namespace == "aptos"
    }

    /// For EVM chains, returns the numeric chain ID if parseable.
    pub fn evm_chain_id(&self) -> Option<u64> {
        if self.is_evm() {
            self.reference.parse().ok()
        } else {
            None
        }
    }

    /// Validates the namespace according to CAIP-2 rules.
    /// Namespace must be 3-8 lowercase alphanumeric characters.
    fn validate_namespace(namespace: &str) -> Result<(), ChainIdParseError> {
        if namespace.is_empty() {
            return Err(ChainIdParseError::EmptyNamespace);
        }
        // CAIP-2 specifies 3-8 chars but we're lenient for compatibility
        if !namespace
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(ChainIdParseError::InvalidNamespace(namespace.to_string()));
        }
        Ok(())
    }

    /// Validates the reference according to CAIP-2 rules.
    /// Reference must be 1-32 alphanumeric or hyphen characters.
    fn validate_reference(reference: &str) -> Result<(), ChainIdParseError> {
        if reference.is_empty() {
            return Err(ChainIdParseError::EmptyReference);
        }
        // CAIP-2 specifies 1-32 chars, alphanumeric or hyphen
        if !reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ChainIdParseError::InvalidReference(reference.to_string()));
        }
        Ok(())
    }
}

impl Display for ChainId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

impl FromStr for ChainId {
    type Err = ChainIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ChainIdParseError::Empty);
        }

        let (namespace, reference) = s
            .split_once(':')
            .ok_or(ChainIdParseError::MissingSeparator)?;

        Self::validate_namespace(namespace)?;
        Self::validate_reference(reference)?;

        Ok(Self::new(namespace, reference))
    }
}

impl Serialize for ChainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eip155_chain_id() {
        let base = ChainId::eip155(8453);
        assert_eq!(base.namespace, "eip155");
        assert_eq!(base.reference, "8453");
        assert_eq!(base.to_string(), "eip155:8453");
        assert!(base.is_evm());
        assert!(!base.is_solana());
        assert_eq!(base.evm_chain_id(), Some(8453));
    }

    #[test]
    fn test_solana_chain_id() {
        let solana = ChainId::solana_mainnet();
        assert_eq!(solana.namespace, "solana");
        assert_eq!(solana.reference, "mainnet");
        assert_eq!(solana.to_string(), "solana:mainnet");
        assert!(!solana.is_evm());
        assert!(solana.is_solana());
        assert_eq!(solana.evm_chain_id(), None);
    }

    #[test]
    fn test_aptos_chain_id() {
        let aptos = ChainId::aptos_mainnet();
        assert_eq!(aptos.namespace, "aptos");
        assert_eq!(aptos.reference, "mainnet");
        assert!(aptos.is_aptos());
    }

    #[test]
    fn test_parse_eip155() {
        let parsed: ChainId = "eip155:84532".parse().unwrap();
        assert_eq!(parsed, ChainId::eip155(84532));
    }

    #[test]
    fn test_parse_solana() {
        let parsed: ChainId = "solana:devnet".parse().unwrap();
        assert_eq!(parsed, ChainId::solana_devnet());
    }

    #[test]
    fn test_parse_errors() {
        assert!(matches!("".parse::<ChainId>(), Err(ChainIdParseError::Empty)));
        assert!(matches!(
            "eip155".parse::<ChainId>(),
            Err(ChainIdParseError::MissingSeparator)
        ));
        assert!(matches!(
            ":8453".parse::<ChainId>(),
            Err(ChainIdParseError::EmptyNamespace)
        ));
        assert!(matches!(
            "eip155:".parse::<ChainId>(),
            Err(ChainIdParseError::EmptyReference)
        ));
        assert!(matches!(
            "EIP155:8453".parse::<ChainId>(),
            Err(ChainIdParseError::InvalidNamespace(_))
        ));
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = ChainId::eip155(8453);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"eip155:8453\"");
        let parsed: ChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_equality() {
        let a = ChainId::eip155(8453);
        let b = ChainId::new("eip155", "8453");
        assert_eq!(a, b);
    }
}
