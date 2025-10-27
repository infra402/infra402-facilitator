//! IP address filtering middleware.
//!
//! Supports allow lists and block lists using IP addresses and CIDR notation.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::sync::Arc;

/// IP filtering middleware supporting allow/block lists.
#[derive(Clone)]
pub struct IpFilter {
    config: Arc<IpFilterConfig>,
}

#[derive(Debug, Clone)]
pub struct IpFilterConfig {
    /// List of allowed IP ranges. Empty = allow all.
    pub allowed_ips: Vec<IpNetwork>,
    /// List of blocked IP ranges.
    pub blocked_ips: Vec<IpNetwork>,
    pub log_events: bool,
}

impl IpFilter {
    pub fn new(config: IpFilterConfig) -> Self {
        if !config.allowed_ips.is_empty() {
            tracing::info!(
                count = config.allowed_ips.len(),
                "IP allow list enabled"
            );
        }
        if !config.blocked_ips.is_empty() {
            tracing::info!(
                count = config.blocked_ips.len(),
                "IP block list enabled"
            );
        }

        Self {
            config: Arc::new(config),
        }
    }

    /// Middleware function to filter requests by IP.
    pub async fn middleware(&self, req: Request, next: Next) -> Response {
        let ip = match extract_ip_from_request(&req) {
            Some(ip) => ip,
            None => {
                if self.config.log_events {
                    tracing::warn!("Could not extract IP from request");
                }
                return (StatusCode::FORBIDDEN, "Could not determine client IP").into_response();
            }
        };

        // Check block list first
        if self.is_blocked(&ip) {
            if self.config.log_events {
                tracing::warn!(ip = %ip, "Request blocked: IP is on block list");
            }
            return (StatusCode::FORBIDDEN, "IP address blocked").into_response();
        }

        // Check allow list (if configured)
        if !self.config.allowed_ips.is_empty() && !self.is_allowed(&ip) {
            if self.config.log_events {
                tracing::warn!(ip = %ip, "Request blocked: IP not on allow list");
            }
            return (StatusCode::FORBIDDEN, "IP address not allowed").into_response();
        }

        next.run(req).await
    }

    fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.config
            .blocked_ips
            .iter()
            .any(|network| network.contains(*ip))
    }

    fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.config
            .allowed_ips
            .iter()
            .any(|network| network.contains(*ip))
    }
}

/// Extract IP address from request.
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

    // Fallback to peer address
    req.extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ip_in_network() {
        let network = IpNetwork::from_str("192.168.1.0/24").unwrap();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(network.contains(ip));
    }

    #[test]
    fn test_ip_not_in_network() {
        let network = IpNetwork::from_str("192.168.1.0/24").unwrap();
        let ip: IpAddr = "192.168.2.100".parse().unwrap();
        assert!(!network.contains(ip));
    }

    #[test]
    fn test_block_list() {
        let config = IpFilterConfig {
            allowed_ips: vec![],
            blocked_ips: vec![IpNetwork::from_str("192.168.1.0/24").unwrap()],
            log_events: false,
        };

        let filter = IpFilter::new(config);
        let blocked_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let allowed_ip: IpAddr = "192.168.2.100".parse().unwrap();

        assert!(filter.is_blocked(&blocked_ip));
        assert!(!filter.is_blocked(&allowed_ip));
    }

    #[test]
    fn test_allow_list() {
        let config = IpFilterConfig {
            allowed_ips: vec![IpNetwork::from_str("10.0.0.0/8").unwrap()],
            blocked_ips: vec![],
            log_events: false,
        };

        let filter = IpFilter::new(config);
        let allowed_ip: IpAddr = "10.1.2.3".parse().unwrap();
        let not_allowed_ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(filter.is_allowed(&allowed_ip));
        assert!(!filter.is_allowed(&not_allowed_ip));
    }
}
