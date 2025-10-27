//! Admin-only API key authentication middleware.
//!
//! Separate from regular API key authentication to provide elevated access
//! to administrative endpoints like security statistics.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Admin authentication middleware.
///
/// Checks for `X-Admin-Key` header and validates it against the `ADMIN_API_KEY` environment variable.
#[derive(Clone, Debug)]
pub struct AdminAuth {
    /// Optional admin API key. If None, admin endpoints are disabled.
    admin_key: Option<String>,
}

impl AdminAuth {
    /// Load admin authentication from environment variables.
    ///
    /// Reads the `ADMIN_API_KEY` environment variable. If not set, admin endpoints will be disabled.
    pub fn from_env() -> Self {
        let admin_key = std::env::var("ADMIN_API_KEY").ok();

        if admin_key.is_some() {
            tracing::info!("Admin API key authentication enabled");
        } else {
            tracing::info!("Admin API key not configured - admin endpoints disabled");
        }

        Self { admin_key }
    }

    /// Middleware function to enforce admin authentication.
    ///
    /// Checks the `X-Admin-Key` header against the configured admin key.
    /// Returns 401 Unauthorized if authentication fails or admin key is not configured.
    pub async fn middleware(&self, req: Request, next: Next) -> Response {
        // Check if admin key is configured
        let Some(ref configured_key) = self.admin_key else {
            tracing::warn!("Admin endpoint accessed but ADMIN_API_KEY not configured");
            return (
                StatusCode::UNAUTHORIZED,
                "Admin access disabled - ADMIN_API_KEY not configured",
            )
                .into_response();
        };

        // Extract the X-Admin-Key header
        let provided_key = req
            .headers()
            .get("X-Admin-Key")
            .and_then(|v| v.to_str().ok());

        match provided_key {
            Some(key) if key == configured_key => {
                // Authentication successful
                next.run(req).await
            }
            Some(_) => {
                tracing::warn!("Admin endpoint accessed with invalid key");
                (StatusCode::UNAUTHORIZED, "Invalid admin key").into_response()
            }
            None => {
                tracing::warn!("Admin endpoint accessed without X-Admin-Key header");
                (StatusCode::UNAUTHORIZED, "X-Admin-Key header required").into_response()
            }
        }
    }
}
