//! Security middleware and utilities for the x402 facilitator.
//!
//! This module provides:
//! - Rate limiting with temporary IP bans
//! - API key authentication
//! - IP allow/block listing
//! - Request validation and abuse detection

pub mod abuse;
pub mod auth;
pub mod ip_filter;
pub mod rate_limit;

pub use abuse::AbuseDetector;
pub use auth::ApiKeyAuth;
pub use ip_filter::IpFilter;
pub use rate_limit::RateLimiter;
