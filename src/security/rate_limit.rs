//! Rate limiting with temporary IP bans.
//!
//! This module provides:
//! - Per-IP rate limiting using tower-governor
//! - Per-endpoint rate limit overrides
//! - Temporary IP bans after repeated violations
//! - 429 Too Many Requests responses

use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Rate limiter with ban tracking.
#[derive(Clone)]
pub struct RateLimiter {
    config: Arc<RateLimiterConfig>,
    /// Tracks violations per IP
    violations: Arc<DashMap<IpAddr, ViolationTracker>>,
    /// Tracks banned IPs with expiration time
    bans: Arc<DashMap<IpAddr, SystemTime>>,
    /// Tracks request timestamps per IP for rate limiting
    request_history: Arc<DashMap<IpAddr, Vec<SystemTime>>>,
}

#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub ban_duration: Duration,
    pub ban_threshold: u32,
    pub whitelisted_ips: Vec<ipnetwork::IpNetwork>,
}

#[derive(Debug, Clone)]
struct ViolationTracker {
    count: u32,
    last_reset: SystemTime,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config: Arc::new(config),
            violations: Arc::new(DashMap::new()),
            bans: Arc::new(DashMap::new()),
            request_history: Arc::new(DashMap::new()),
        }
    }

    /// Middleware function to apply rate limiting.
    pub async fn middleware(&self, req: Request, next: Next) -> Response {
        if !self.config.enabled {
            return next.run(req).await;
        }

        let ip = match extract_ip_from_request(&req) {
            Some(ip) => ip,
            None => {
                tracing::warn!("Could not extract IP from request");
                return next.run(req).await;
            }
        };

        // Check if IP is whitelisted
        if self.is_whitelisted(&ip) {
            if self.config_log_enabled() {
                tracing::trace!(ip = %ip, "Request bypassing rate limit: IP is whitelisted");
            }
            return next.run(req).await;
        }

        // Check if IP is banned
        if self.is_banned(&ip) {
            if self.config_log_enabled() {
                tracing::warn!(ip = %ip, "Request blocked: IP is temporarily banned");
            }
            return (StatusCode::TOO_MANY_REQUESTS, "IP temporarily banned").into_response();
        }

        // Check rate limit (simplified - in production use tower-governor)
        if self.should_rate_limit(&ip) {
            self.record_violation(&ip);

            if self.config_log_enabled() {
                tracing::warn!(ip = %ip, "Rate limit exceeded");
            }

            // Check if we should ban this IP
            if self.should_ban(&ip) {
                self.ban_ip(&ip);
                if self.config_log_enabled() {
                    tracing::warn!(
                        ip = %ip,
                        ban_duration_secs = self.config.ban_duration.as_secs(),
                        "IP banned due to repeated violations"
                    );
                }
            }

            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded",
            )
                .into_response();
        }

        next.run(req).await
    }

    fn is_banned(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.bans.get(ip) {
            let ban_expiry = *entry.value();
            if SystemTime::now() < ban_expiry {
                return true;
            } else {
                // Ban expired, remove it
                drop(entry);
                self.bans.remove(ip);
                self.violations.remove(ip);
            }
        }
        false
    }

    fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.config
            .whitelisted_ips
            .iter()
            .any(|network| network.contains(*ip))
    }

    fn should_rate_limit(&self, ip: &IpAddr) -> bool {
        let now = SystemTime::now();
        let window = Duration::from_secs(1);
        let max_requests = self.config.requests_per_second as usize;

        // Get or create request history for this IP
        let mut history = self.request_history
            .entry(*ip)
            .or_insert_with(Vec::new);

        // Remove requests older than 1 second
        history.value_mut().retain(|&timestamp| {
            now.duration_since(timestamp).unwrap_or_default() < window
        });

        // Check if we've exceeded the rate limit
        if history.value().len() >= max_requests {
            return true;
        }

        // Record this request
        history.value_mut().push(now);
        false
    }

    fn record_violation(&self, ip: &IpAddr) {
        let now = SystemTime::now();
        self.violations
            .entry(*ip)
            .and_modify(|tracker| {
                // Reset if more than 1 minute has passed
                if now.duration_since(tracker.last_reset).unwrap_or_default() > Duration::from_secs(60) {
                    tracker.count = 1;
                    tracker.last_reset = now;
                } else {
                    tracker.count += 1;
                }
            })
            .or_insert_with(|| ViolationTracker {
                count: 1,
                last_reset: now,
            });
    }

    fn should_ban(&self, ip: &IpAddr) -> bool {
        if let Some(tracker) = self.violations.get(ip) {
            tracker.count >= self.config.ban_threshold
        } else {
            false
        }
    }

    fn ban_ip(&self, ip: &IpAddr) {
        let ban_until = SystemTime::now() + self.config.ban_duration;
        self.bans.insert(*ip, ban_until);
    }

    fn config_log_enabled(&self) -> bool {
        // This will be updated when we wire in the full config
        true
    }

    /// Clean up expired bans (should be called periodically).
    pub fn cleanup_expired_bans(&self) {
        let now = SystemTime::now();
        self.bans.retain(|_, &mut expiry| now < expiry);
    }
}

/// Extract IP address from request.
///
/// Checks X-Forwarded-For, X-Real-IP, and then falls back to peer address.
fn extract_ip_from_request(req: &Request<Body>) -> Option<IpAddr> {
    // Check X-Forwarded-For header
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            // Take the first IP in the list
            if let Some(ip_str) = value.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.parse() {
                return Some(ip);
            }
        }
    }

    // Fallback to peer address from ConnectInfo
    req.extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        let config = RateLimiterConfig {
            enabled: true,
            requests_per_second: 10,
            ban_duration: Duration::from_secs(300),
            ban_threshold: 5,
            whitelisted_ips: vec![],
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.config.enabled);
    }

    #[test]
    fn test_violation_tracking() {
        let config = RateLimiterConfig {
            enabled: true,
            requests_per_second: 10,
            ban_duration: Duration::from_secs(300),
            ban_threshold: 3,
            whitelisted_ips: vec![],
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record violations
        limiter.record_violation(&ip);
        limiter.record_violation(&ip);
        limiter.record_violation(&ip);

        // Should trigger ban
        assert!(limiter.should_ban(&ip));
    }

    #[test]
    fn test_ban_expiry() {
        let config = RateLimiterConfig {
            enabled: true,
            requests_per_second: 10,
            ban_duration: Duration::from_millis(100),
            ban_threshold: 1,
            whitelisted_ips: vec![],
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Ban the IP
        limiter.ban_ip(&ip);
        assert!(limiter.is_banned(&ip));

        // Wait for ban to expire
        std::thread::sleep(Duration::from_millis(150));
        assert!(!limiter.is_banned(&ip));
    }
}
