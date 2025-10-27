//! API key authentication middleware.
//!
//! Validates API keys from the `Authorization: Bearer <key>` header.
//! API keys are loaded from the `API_KEYS` environment variable (comma-separated).

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashSet;
use std::sync::Arc;

/// API key authentication middleware.
#[derive(Clone)]
pub struct ApiKeyAuth {
    /// Set of valid API keys. If empty, authentication is disabled.
    api_keys: Arc<HashSet<String>>,
    log_events: bool,
}

impl ApiKeyAuth {
    /// Create a new API key authenticator from environment variable.
    ///
    /// Reads the `API_KEYS` environment variable (comma-separated list).
    /// If not set or empty, authentication is disabled.
    pub fn from_env() -> Self {
        let api_keys = std::env::var("API_KEYS")
            .ok()
            .map(|keys| {
                keys.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();

        let enabled = !api_keys.is_empty();
        if enabled {
            tracing::info!(count = api_keys.len(), "API key authentication enabled");
        } else {
            tracing::info!("API key authentication disabled (no API_KEYS configured)");
        }

        Self {
            api_keys: Arc::new(api_keys),
            log_events: true,
        }
    }

    /// Check if authentication is enabled.
    pub fn is_enabled(&self) -> bool {
        !self.api_keys.is_empty()
    }

    /// Middleware function to validate API keys.
    pub async fn middleware(&self, req: Request, next: Next) -> Response {
        // If no API keys configured, allow all requests
        if !self.is_enabled() {
            return next.run(req).await;
        }

        // Extract and validate API key
        match self.validate_request_auth(req.headers()) {
            Ok(()) => next.run(req).await,
            Err(error) => {
                if self.log_events {
                    tracing::warn!("Authentication failed: {}", error);
                }
                (StatusCode::UNAUTHORIZED, error).into_response()
            }
        }
    }

    /// Validate the Authorization header.
    pub fn validate_request_auth(&self, headers: &HeaderMap) -> Result<(), String> {
        let auth_header = headers
            .get("authorization")
            .ok_or("Missing Authorization header")?
            .to_str()
            .map_err(|_| "Invalid Authorization header")?;

        // Expect "Bearer <token>"
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or("Invalid Authorization header format (expected 'Bearer <token>')")?;

        if self.api_keys.contains(token) {
            Ok(())
        } else {
            Err("Invalid API key".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_auth_disabled_by_default() {
        unsafe {
            std::env::remove_var("API_KEYS");
        }
        let auth = ApiKeyAuth::from_env();
        assert!(!auth.is_enabled());
    }

    #[test]
    fn test_valid_api_key() {
        let mut api_keys = HashSet::new();
        api_keys.insert("test-key-123".to_string());

        let auth = ApiKeyAuth {
            api_keys: Arc::new(api_keys),
            log_events: false,
        };

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer test-key-123"));

        assert!(auth.validate_request_auth(&headers).is_ok());
    }

    #[test]
    fn test_invalid_api_key() {
        let mut api_keys = HashSet::new();
        api_keys.insert("test-key-123".to_string());

        let auth = ApiKeyAuth {
            api_keys: Arc::new(api_keys),
            log_events: false,
        };

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer wrong-key"));

        assert!(auth.validate_request_auth(&headers).is_err());
    }

    #[test]
    fn test_missing_bearer_prefix() {
        let mut api_keys = HashSet::new();
        api_keys.insert("test-key-123".to_string());

        let auth = ApiKeyAuth {
            api_keys: Arc::new(api_keys),
            log_events: false,
        };

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("test-key-123"));

        assert!(auth.validate_request_auth(&headers).is_err());
    }
}
