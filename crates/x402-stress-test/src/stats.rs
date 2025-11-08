use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum RequestType {
    Verify,
    Settle,
}

#[derive(Debug, Clone)]
pub enum RequestOutcome {
    VerifyValid,
    VerifyInvalid { reason: String },
    SettleSuccess,
    SettleFailure { reason: String },
    HttpError { error: String },
}

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub request_type: RequestType,
    pub outcome: RequestOutcome,
    pub latency_ms: u64,
    #[allow(dead_code)]
    pub timestamp: DateTime<Utc>,
}

/// Thread-safe statistics tracker
#[derive(Clone)]
pub struct Stats {
    inner: Arc<Mutex<StatsInner>>,
}

struct StatsInner {
    start_time: DateTime<Utc>,
    records: Vec<RequestRecord>,

    // Quick counters for common queries
    verify_count: u64,
    settle_count: u64,
    verify_valid: u64,
    verify_invalid: u64,
    settle_success: u64,
    settle_failure: u64,
    http_errors: u64,

    // Error reasons histogram
    error_reasons: HashMap<String, u64>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StatsInner {
                start_time: Utc::now(),
                records: Vec::new(),
                verify_count: 0,
                settle_count: 0,
                verify_valid: 0,
                verify_invalid: 0,
                settle_success: 0,
                settle_failure: 0,
                http_errors: 0,
                error_reasons: HashMap::new(),
            })),
        }
    }

    /// Record a completed request
    pub fn record(&self, record: RequestRecord) {
        let mut inner = self.inner.lock().unwrap();

        // Update counters
        match &record.request_type {
            RequestType::Verify => inner.verify_count += 1,
            RequestType::Settle => inner.settle_count += 1,
        }

        match &record.outcome {
            RequestOutcome::VerifyValid => inner.verify_valid += 1,
            RequestOutcome::VerifyInvalid { reason } => {
                inner.verify_invalid += 1;
                *inner.error_reasons.entry(reason.clone()).or_insert(0) += 1;
            }
            RequestOutcome::SettleSuccess => inner.settle_success += 1,
            RequestOutcome::SettleFailure { reason } => {
                inner.settle_failure += 1;
                *inner.error_reasons.entry(reason.clone()).or_insert(0) += 1;
            }
            RequestOutcome::HttpError { error } => {
                inner.http_errors += 1;
                *inner.error_reasons.entry(format!("http_error: {}", error)).or_insert(0) += 1;
            }
        }

        inner.records.push(record);
    }

    /// Get a snapshot of current statistics
    pub fn snapshot(&self) -> StatsSnapshot {
        let inner = self.inner.lock().unwrap();

        let elapsed = Utc::now() - inner.start_time;
        let total_requests = inner.verify_count + inner.settle_count;

        // Calculate latency percentiles
        let mut latencies: Vec<u64> = inner.records.iter().map(|r| r.latency_ms).collect();
        latencies.sort_unstable();

        let p50 = percentile(&latencies, 0.5);
        let p95 = percentile(&latencies, 0.95);
        let p99 = percentile(&latencies, 0.99);
        let avg = if !latencies.is_empty() {
            latencies.iter().sum::<u64>() / latencies.len() as u64
        } else {
            0
        };

        // Calculate requests per second
        let rps = if elapsed.num_seconds() > 0 {
            total_requests as f64 / elapsed.num_seconds() as f64
        } else {
            0.0
        };

        StatsSnapshot {
            elapsed_seconds: elapsed.num_seconds() as u64,
            total_requests,
            verify_count: inner.verify_count,
            settle_count: inner.settle_count,
            verify_valid: inner.verify_valid,
            verify_invalid: inner.verify_invalid,
            settle_success: inner.settle_success,
            settle_failure: inner.settle_failure,
            http_errors: inner.http_errors,
            requests_per_second: rps,
            latency_avg_ms: avg,
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_p99_ms: p99,
            error_reasons: inner.error_reasons.clone(),
        }
    }

    /// Reset all statistics (useful for testing)
    #[allow(dead_code)]
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.start_time = Utc::now();
        inner.records.clear();
        inner.verify_count = 0;
        inner.settle_count = 0;
        inner.verify_valid = 0;
        inner.verify_invalid = 0;
        inner.settle_success = 0;
        inner.settle_failure = 0;
        inner.http_errors = 0;
        inner.error_reasons.clear();
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64) * p).floor() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub elapsed_seconds: u64,
    pub total_requests: u64,
    pub verify_count: u64,
    pub settle_count: u64,
    pub verify_valid: u64,
    pub verify_invalid: u64,
    pub settle_success: u64,
    pub settle_failure: u64,
    pub http_errors: u64,
    pub requests_per_second: f64,
    pub latency_avg_ms: u64,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub latency_p99_ms: u64,
    pub error_reasons: HashMap<String, u64>,
}

impl StatsSnapshot {
    /// Print statistics in a readable format
    pub fn print(&self, is_final: bool) {
        let header = if is_final {
            "=== FINAL STATISTICS ==="
        } else {
            "=== PROGRESS ==="
        };

        println!("\n{}", header);
        println!("Elapsed: {}s", self.elapsed_seconds);
        println!("Total Requests: {}", self.total_requests);
        println!("Requests/sec: {:.2}", self.requests_per_second);
        println!();

        if self.verify_count > 0 {
            println!("Verify Requests: {}", self.verify_count);
            println!("  ✓ Valid: {}", self.verify_valid);
            println!("  ✗ Invalid: {}", self.verify_invalid);
            if self.verify_count > 0 {
                let success_rate = (self.verify_valid as f64 / self.verify_count as f64) * 100.0;
                println!("  Success Rate: {:.2}%", success_rate);
            }
            println!();
        }

        if self.settle_count > 0 {
            println!("Settle Requests: {}", self.settle_count);
            println!("  ✓ Success: {}", self.settle_success);
            println!("  ✗ Failure: {}", self.settle_failure);
            if self.settle_count > 0 {
                let success_rate = (self.settle_success as f64 / self.settle_count as f64) * 100.0;
                println!("  Success Rate: {:.2}%", success_rate);
            }
            println!();
        }

        if self.http_errors > 0 {
            println!("HTTP Errors: {}", self.http_errors);
            println!();
        }

        if self.total_requests > 0 {
            println!("Latency:");
            println!("  Average: {}ms", self.latency_avg_ms);
            println!("  P50: {}ms", self.latency_p50_ms);
            println!("  P95: {}ms", self.latency_p95_ms);
            println!("  P99: {}ms", self.latency_p99_ms);
            println!();
        }

        if !self.error_reasons.is_empty() {
            println!("Error Breakdown:");
            let mut reasons: Vec<_> = self.error_reasons.iter().collect();
            reasons.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            for (reason, count) in reasons {
                println!("  {}: {}", reason, count);
            }
            println!();
        }

        if is_final {
            println!("=======================\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_recording() {
        let stats = Stats::new();

        stats.record(RequestRecord {
            request_type: RequestType::Verify,
            outcome: RequestOutcome::VerifyValid,
            latency_ms: 100,
            timestamp: Utc::now(),
        });

        stats.record(RequestRecord {
            request_type: RequestType::Settle,
            outcome: RequestOutcome::SettleSuccess,
            latency_ms: 200,
            timestamp: Utc::now(),
        });

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_requests, 2);
        assert_eq!(snapshot.verify_count, 1);
        assert_eq!(snapshot.settle_count, 1);
        assert_eq!(snapshot.verify_valid, 1);
        assert_eq!(snapshot.settle_success, 1);
    }
}
