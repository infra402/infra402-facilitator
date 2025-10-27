//! Request validation and abuse detection.
//!
//! Tracks repeated invalid signatures, malformed payloads, and suspicious patterns.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Tracks abuse patterns per IP address.
#[derive(Clone)]
pub struct AbuseDetector {
    config: Arc<AbuseDetectorConfig>,
    /// Tracks invalid signature attempts per IP
    invalid_signatures: Arc<DashMap<IpAddr, InvalidSignatureTracker>>,
}

#[derive(Debug, Clone)]
pub struct AbuseDetectorConfig {
    /// Enable abuse detection.
    pub enabled: bool,
    /// Number of invalid signatures before flagging as abusive.
    pub invalid_signature_threshold: u32,
    /// Time window for counting invalid signatures (default: 5 minutes).
    pub tracking_window: Duration,
    /// Log security events.
    pub log_events: bool,
}

impl Default for AbuseDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            invalid_signature_threshold: 10,
            tracking_window: Duration::from_secs(300), // 5 minutes
            log_events: true,
        }
    }
}

#[derive(Debug, Clone)]
struct InvalidSignatureTracker {
    count: u32,
    first_seen: SystemTime,
    last_seen: SystemTime,
}

impl AbuseDetector {
    pub fn new(config: AbuseDetectorConfig) -> Self {
        Self {
            config: Arc::new(config),
            invalid_signatures: Arc::new(DashMap::new()),
        }
    }

    /// Record an invalid signature attempt.
    pub fn record_invalid_signature(&self, ip: IpAddr) {
        if !self.config.enabled {
            return;
        }

        let now = SystemTime::now();
        self.invalid_signatures
            .entry(ip)
            .and_modify(|tracker| {
                // Check if we're still within the tracking window
                if now.duration_since(tracker.first_seen).unwrap_or_default() > self.config.tracking_window {
                    // Reset tracking window
                    tracker.count = 1;
                    tracker.first_seen = now;
                    tracker.last_seen = now;
                } else {
                    tracker.count += 1;
                    tracker.last_seen = now;

                    // Log if threshold exceeded
                    if tracker.count == self.config.invalid_signature_threshold && self.config.log_events {
                        tracing::warn!(
                            ip = %ip,
                            count = tracker.count,
                            "Suspicious activity: repeated invalid signatures detected"
                        );
                    }
                }
            })
            .or_insert_with(|| InvalidSignatureTracker {
                count: 1,
                first_seen: now,
                last_seen: now,
            });
    }

    /// Check if an IP has exceeded the invalid signature threshold.
    pub fn is_suspicious(&self, ip: &IpAddr) -> bool {
        if !self.config.enabled {
            return false;
        }

        if let Some(tracker) = self.invalid_signatures.get(ip) {
            let now = SystemTime::now();
            // Check if still within tracking window
            if now.duration_since(tracker.first_seen).unwrap_or_default() <= self.config.tracking_window {
                return tracker.count >= self.config.invalid_signature_threshold;
            }
        }
        false
    }

    /// Record a malformed payload attempt.
    pub fn record_malformed_payload(&self, ip: IpAddr, error: &str) {
        if !self.config.enabled {
            return;
        }

        if self.config.log_events {
            tracing::debug!(
                ip = %ip,
                error = error,
                "Malformed payload received"
            );
        }
    }

    /// Clean up old tracking data (should be called periodically).
    pub fn cleanup_old_data(&self) {
        let now = SystemTime::now();
        let tracking_window = self.config.tracking_window;

        self.invalid_signatures.retain(|_, tracker| {
            now.duration_since(tracker.last_seen).unwrap_or_default() <= tracking_window
        });
    }

    /// Get statistics for monitoring.
    pub fn get_stats(&self) -> AbuseStats {
        let total_ips_tracked = self.invalid_signatures.len();
        let suspicious_ips = self
            .invalid_signatures
            .iter()
            .filter(|entry| {
                let now = SystemTime::now();
                let tracker = entry.value();
                now.duration_since(tracker.first_seen).unwrap_or_default() <= self.config.tracking_window
                    && tracker.count >= self.config.invalid_signature_threshold
            })
            .count();

        AbuseStats {
            total_ips_tracked,
            suspicious_ips,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AbuseStats {
    pub total_ips_tracked: usize,
    pub suspicious_ips: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_signature_tracking() {
        let config = AbuseDetectorConfig {
            enabled: true,
            invalid_signature_threshold: 3,
            tracking_window: Duration::from_secs(60),
            log_events: false,
        };

        let detector = AbuseDetector::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record multiple invalid signatures
        detector.record_invalid_signature(ip);
        detector.record_invalid_signature(ip);
        assert!(!detector.is_suspicious(&ip));

        detector.record_invalid_signature(ip);
        assert!(detector.is_suspicious(&ip));
    }

    #[test]
    fn test_tracking_window_reset() {
        let config = AbuseDetectorConfig {
            enabled: true,
            invalid_signature_threshold: 5,
            tracking_window: Duration::from_millis(100),
            log_events: false,
        };

        let detector = AbuseDetector::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record invalid signature
        detector.record_invalid_signature(ip);
        assert_eq!(detector.invalid_signatures.get(&ip).unwrap().count, 1);

        // Wait for tracking window to expire
        std::thread::sleep(Duration::from_millis(150));

        // Record another - should reset
        detector.record_invalid_signature(ip);
        assert_eq!(detector.invalid_signatures.get(&ip).unwrap().count, 1);
    }

    #[test]
    fn test_get_stats() {
        let config = AbuseDetectorConfig {
            enabled: true,
            invalid_signature_threshold: 2,
            tracking_window: Duration::from_secs(60),
            log_events: false,
        };

        let detector = AbuseDetector::new(config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        detector.record_invalid_signature(ip1);
        detector.record_invalid_signature(ip1);
        detector.record_invalid_signature(ip1);

        detector.record_invalid_signature(ip2);

        let stats = detector.get_stats();
        assert_eq!(stats.total_ips_tracked, 2);
        assert_eq!(stats.suspicious_ips, 1);
    }
}
