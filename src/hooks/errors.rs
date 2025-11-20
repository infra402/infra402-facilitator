//! Error types for the hook system

use thiserror::Error;

/// Errors that can occur during hook parameter resolution and encoding
#[derive(Error, Debug)]
pub enum HookError {
    /// Invalid function signature format
    #[error("Invalid function signature '{0}': {1}")]
    InvalidFunctionSignature(String, String),

    /// Invalid Solidity type specification
    #[error("Invalid Solidity type '{0}': {1}")]
    InvalidSolidityType(String, String),

    /// Missing required parameter in configuration
    #[error("Missing required parameter '{0}' for function '{1}'")]
    MissingParameter(String, String),

    /// Invalid parameter source specification
    #[error("Invalid parameter source '{0}': {1}")]
    InvalidParameterSource(String, String),

    /// ABI encoding failed
    #[error("ABI encoding failed: {0}")]
    EncodingFailed(String),

    /// Static value parsing failed
    #[error("Failed to parse static value '{0}' as {1}: {2}")]
    StaticValueParseFailed(String, String, String),

    /// Parameter count mismatch
    #[error("Parameter count mismatch: expected {expected}, got {actual} for function '{function}'")]
    ParameterCountMismatch {
        function: String,
        expected: usize,
        actual: usize,
    },

    /// Type mismatch between parameter definition and function signature
    #[error("Type mismatch for parameter '{param}': expected {expected}, got {actual}")]
    TypeMismatch {
        param: String,
        expected: String,
        actual: String,
    },

    /// Configuration file error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Runtime context fetch failed
    #[error("Failed to fetch runtime context: {0}")]
    RuntimeContextFailed(String),

    /// Hook definition not found
    #[error("Hook definition '{0}' not found")]
    HookNotFound(String),

    /// Invalid hex string
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    /// Deprecated feature used
    #[error("Deprecated: {0}. {1}")]
    DeprecatedFeature(String, String),
}

/// Result type for hook operations
pub type HookResult<T> = Result<T, HookError>;

impl From<alloy::dyn_abi::Error> for HookError {
    fn from(err: alloy::dyn_abi::Error) -> Self {
        HookError::EncodingFailed(err.to_string())
    }
}

impl From<alloy::hex::FromHexError> for HookError {
    fn from(err: alloy::hex::FromHexError) -> Self {
        HookError::InvalidHex(err.to_string())
    }
}
