//! HTTP endpoints implemented by the x402 **facilitator**.
//!
//! These are the server-side handlers for processing client-submitted x402 payments.
//! They include both protocol-critical endpoints (`/verify`, `/settle`) and discovery endpoints (`/supported`, etc).
//!
//! All payloads follow the types defined in the `x402-rs` crate, and are compatible
//! with the TypeScript and Go client SDKs.
//!
//! Each endpoint consumes or produces structured JSON payloads defined in `x402-rs`,
//! and is compatible with official x402 client SDKs.

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{Html, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router, response::IntoResponse};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::instrument;

use crate::chain::FacilitatorLocalError;
use crate::facilitator::Facilitator;
use crate::security::abuse::AbuseDetector;
use crate::types::{
    ErrorResponse, FacilitatorErrorReason, MixedAddress, SettleRequest, VerifyRequest,
    VerifyResponse,
};

pub fn routes() -> Router<Arc<crate::facilitator_local::FacilitatorLocal<crate::provider_cache::ProviderCache>>>
{
    type FacilitatorType = crate::facilitator_local::FacilitatorLocal<crate::provider_cache::ProviderCache>;
    Router::new()
        .route("/", get(get_root))
        .route("/verify", post(post_verify::<FacilitatorType>))
        .route("/settle", post(post_settle))
        .route("/supported", get(get_supported::<FacilitatorType>))
        .route("/health", get(get_health::<FacilitatorType>))
}

pub fn admin_routes() -> Router {
    Router::new()
        .route("/admin/stats", get(get_admin_stats))
}

/// `GET /`: Returns API information with links to all available endpoints.
#[instrument(skip_all)]
pub async fn get_root() -> impl IntoResponse {
    let pkg_version = env!("CARGO_PKG_VERSION");
    let pkg_description = env!("CARGO_PKG_DESCRIPTION");

    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Multi-chain x402 Facilitator by Infra402</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        details {{ margin: 10px 0; }}
        summary {{ cursor: pointer; padding: 8px; background: #f5f5f5; border-radius: 4px; }}
        summary:hover {{ background: #e8e8e8; }}
        summary strong {{ font-family: monospace; }}
        pre {{ background: #f8f8f8; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; line-height: 1.4; }}
        .method-get {{ color: #22863a; }}
        .method-post {{ color: #6f42c1; }}
    </style>
</head>
<body>
    <h1>Multi-chain x402 Facilitator by Infra402</h1>
    <p>Version: {pkg_version}</p>
    <p>{pkg_description}</p>

    <h2>Available Endpoints</h2>

    <details>
        <summary><strong class="method-get">GET</strong> <strong>/</strong> — API root</summary>
        <pre>Response: This HTML page with endpoint documentation</pre>
    </details>

    <details>
        <summary><strong class="method-get">GET</strong> <strong><a href="/health">/health</a></strong> — Health check</summary>
        <pre>Response:
{{
  "kinds": [
    {{ "version": "1.0", "scheme": "exact", "network": "base-sepolia" }},
    {{ "version": "1.0", "scheme": "exact", "network": "base" }},
    ...
  ]
}}</pre>
    </details>

    <details>
        <summary><strong class="method-get">GET</strong> <strong><a href="/supported">/supported</a></strong> — Supported networks/schemes</summary>
        <pre>Response: Same format as /health</pre>
    </details>

    <details>
        <summary><strong class="method-post">POST</strong> <strong>/verify</strong> — Verify payment signatures</summary>
        <pre>Request Body:
{{
  "x402Version": 1,
  "paymentPayload": {{
    "x402Version": 1,
    "scheme": "exact",
    "network": "&lt;network&gt;",
    "payload": {{
      "signature": "0x...",           // 65-byte hex signature
      "authorization": {{
        "from": "0x...",              // payer address
        "to": "0x...",                // recipient address
        "value": "1000000",           // amount in token units
        "validAfter": "0",            // unix timestamp
        "validBefore": "1735689600",  // unix timestamp
        "nonce": "0x..."              // 32-byte hex nonce
      }}
    }}
  }},
  "paymentRequirements": {{
    "scheme": "exact",
    "network": "&lt;network&gt;",
    "maxAmountRequired": "1000000",
    "resource": "https://example.com/api",
    "description": "API access",
    "mimeType": "application/json",
    "payTo": "0x...",
    "maxTimeoutSeconds": 300,
    "asset": "0x..."                  // token contract address
  }}
}}

Supported networks:
  EVM: base-sepolia, base, xdc, avalanche-fuji, avalanche,
       polygon-amoy, polygon, sei, sei-testnet, bsc, bsc-testnet
  Solana: solana, solana-devnet

Response (success):
{{ "valid": true, "payer": "0x..." }}

Response (failure):
{{ "valid": false, "payer": "0x...", "reason": {{ "type": "InvalidSignature", "message": "..." }} }}</pre>
    </details>

    <details>
        <summary><strong class="method-post">POST</strong> <strong>/settle</strong> — Submit payment to blockchain</summary>
        <pre>Request Body: Same as POST /verify

Response (success):
{{
  "success": true,
  "payer": "0x...",
  "transaction": "0xabc123...",       // transaction hash
  "network": "base-sepolia"
}}

Response (failure):
{{
  "success": false,
  "payer": "0x...",
  "errorReason": {{ "type": "InsufficientFunds", "message": "..." }},
  "transaction": null,
  "network": "base-sepolia"
}}</pre>
    </details>

    <details>
        <summary><strong class="method-get">GET</strong> <strong>/admin/stats</strong> — Admin statistics (requires X-Admin-Key header)</summary>
        <pre>Response:
{{
  "abuse_detection": {{
    "total_ips_tracked": 42,
    "suspicious_ips": 3
  }},
  "batch_settlement": {{
    "active_queues": 5
  }}
}}</pre>
    </details>

    <p style="margin-top: 30px;">Documentation: <a href="https://github.com/infra402/infra402-facilitator">https://github.com/infra402/infra402-facilitator</a></p>
</body>
</html>"#);

    (StatusCode::OK, Html(html)).into_response()
}

/// `GET /admin/stats`: Returns abuse detection and batch queue statistics.
///
/// This endpoint requires admin authentication via the `X-Admin-Key` header.
/// Returns current statistics about tracked IPs, suspicious activity, and batch processing.
#[instrument(skip_all)]
pub async fn get_admin_stats(
    Extension(abuse_detector): Extension<AbuseDetector>,
    Extension(batch_queue_manager): Extension<Option<Arc<crate::batch_queue::BatchQueueManager>>>,
) -> impl IntoResponse {
    let abuse_stats = abuse_detector.get_stats();

    let mut response = json!({
        "abuse_detection": {
            "total_ips_tracked": abuse_stats.total_ips_tracked,
            "suspicious_ips": abuse_stats.suspicious_ips,
        }
    });

    // Add batch queue stats if batching is enabled
    if let Some(manager) = batch_queue_manager {
        let batch_stats = manager.stats();
        response["batch_settlement"] = json!({
            "active_queues": batch_stats.active_queues,
        });
    }

    (StatusCode::OK, Json(response)).into_response()
}

/// `GET /supported`: Lists the x402 payment schemes and networks supported by this facilitator.
///
/// Facilitators may expose this to help clients dynamically configure their payment requests
/// based on available network and scheme support.
#[instrument(skip_all)]
pub async fn get_supported<F>(State(facilitator): State<Arc<F>>) -> impl IntoResponse
where
    F: Facilitator<Error = FacilitatorLocalError>,
{
    match facilitator.supported().await {
        Ok(supported) => (StatusCode::OK, Json(json!(supported))).into_response(),
        Err(error) => error.into_response(),
    }
}

#[instrument(skip_all)]
pub async fn get_health<F>(State(facilitator): State<Arc<F>>) -> impl IntoResponse
where
    F: Facilitator<Error = FacilitatorLocalError>,
{
    get_supported(State(facilitator)).await
}

/// `POST /verify`: Facilitator-side verification of a proposed x402 payment.
///
/// This endpoint checks whether a given payment payload satisfies the declared
/// [`PaymentRequirements`], including signature validity, scheme match, and fund sufficiency.
///
/// Responds with a [`VerifyResponse`] indicating whether the payment can be accepted.
///
/// Requires API key authentication if enabled via `API_KEYS` environment variable.
#[instrument(skip_all)]
pub async fn post_verify<F>(
    State(facilitator): State<Arc<F>>,
    Extension(abuse_detector): Extension<AbuseDetector>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse
where
    F: Facilitator<Error = FacilitatorLocalError>,
{
    match facilitator.verify(&body).await {
        Ok(valid_response) => (StatusCode::OK, Json(valid_response)).into_response(),
        Err(error) => {
            // Track invalid signatures for abuse detection
            if matches!(error, FacilitatorLocalError::InvalidSignature(..)) {
                abuse_detector.record_invalid_signature(addr.ip());
            }

            tracing::warn!(
                error = ?error,
                body = %serde_json::to_string(&body).unwrap_or_else(|_| "<can-not-serialize>".to_string()),
                "Verification failed"
            );
            error.into_response()
        }
    }
}

/// `POST /settle`: Facilitator-side execution of a valid x402 payment on-chain.
///
/// Given a valid [`SettleRequest`], this endpoint attempts to execute the payment
/// via ERC-3009 `transferWithAuthorization`, and returns a [`SettleResponse`] with transaction details.
///
/// This endpoint is typically called after a successful `/verify` step.
///
/// Requires API key authentication if enabled via `API_KEYS` environment variable.
#[instrument(skip_all)]
pub async fn post_settle(
    State(facilitator): State<Arc<crate::facilitator_local::FacilitatorLocal<crate::provider_cache::ProviderCache>>>,
    Extension(batch_queue_manager): Extension<Option<Arc<crate::batch_queue::BatchQueueManager>>>,
    Extension(batch_config): Extension<crate::config::BatchSettlementConfig>,
    Extension(abuse_detector): Extension<AbuseDetector>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<SettleRequest>,
) -> impl IntoResponse
{
    // Extract network from request
    let network = body.payment_payload.network;
    let network_str = network.to_string();

    // Check if batching is enabled for this network
    let use_batching = batch_queue_manager.is_some() && batch_config.is_enabled_for_network(&network_str);

    // Route to batch queue or direct settlement based on per-network configuration
    let result = if use_batching {
        tracing::debug!(%network, "using batch settlement for this network");
        let manager = batch_queue_manager.as_ref().unwrap();

        // Get network provider for this network to pre-select facilitator address
        use crate::provider_cache::ProviderMap;
        let network_provider = match facilitator.provider_map().by_network(network) {
            Some(provider) => provider,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Unsupported network: {}", network),
                    }),
                )
                    .into_response();
            }
        };

        // Pre-select facilitator address using round-robin
        use crate::chain::NetworkProviderOps;
        let facilitator_addr: alloy::primitives::Address = match network_provider.as_ref() {
            crate::chain::NetworkProvider::Evm(evm_provider) => {
                evm_provider.next_signer_address()
            }
            crate::chain::NetworkProvider::Solana(solana_provider) => {
                // For Solana, extract address from signer_address
                use crate::types::MixedAddress;
                match solana_provider.signer_address() {
                    MixedAddress::Evm(addr) => addr.0,  // Extract inner Address
                    MixedAddress::Solana(_) | MixedAddress::Offchain(_) => {
                        // Solana doesn't use EVM-style facilitator addresses
                        // Use a dummy address for queue key (won't be used for signing)
                        alloy::primitives::Address::ZERO
                    }
                }
            }
        };

        tracing::debug!(
            %facilitator_addr,
            %network,
            "enqueuing settlement request for batch processing"
        );

        // Enqueue to batch queue manager with network provider
        let rx = manager.enqueue(facilitator_addr, network, network_provider, body.clone()).await;

        // Wait for batch processing to complete
        match rx.await {
            Ok(result) => result,
            Err(_) => {
                tracing::error!("batch processor dropped response channel");
                Err(FacilitatorLocalError::ContractCall(
                    "Batch processing failed - channel closed".to_string(),
                ))
            }
        }
    } else {
        tracing::debug!(%network, "using direct settlement for this network");
        // Direct settlement (no batching) - use settlement lock to prevent nonce collisions

        use crate::provider_cache::ProviderMap;
        let network_provider = match facilitator.provider_map().by_network(network) {
            Some(provider) => provider,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Unsupported network: {}", network),
                    }),
                )
                    .into_response();
            }
        };

        // Use locked settlement for EVM to prevent nonce collisions
        match network_provider.as_ref() {
            crate::chain::NetworkProvider::Evm(evm_provider) => {
                tracing::debug!(%network, "direct settlement with lock");
                evm_provider.settle_with_lock(&body).await
            }
            crate::chain::NetworkProvider::Solana(_solana_provider) => {
                // Solana settlements are sequential by nature
                tracing::debug!(%network, "direct solana settlement");
                use crate::facilitator::Facilitator;
                network_provider.as_ref().settle(&body).await
            }
        }
    };

    match result {
        Ok(valid_response) => (StatusCode::OK, Json(valid_response)).into_response(),
        Err(error) => {
            // Track invalid signatures for abuse detection
            if matches!(error, FacilitatorLocalError::InvalidSignature(..)) {
                abuse_detector.record_invalid_signature(addr.ip());
            }

            tracing::warn!(
                error = ?error,
                body = %serde_json::to_string(&body).unwrap_or_else(|_| "<can-not-serialize>".to_string()),
                "Settlement failed"
            );
            error.into_response()
        }
    }
}

fn invalid_schema(payer: Option<MixedAddress>) -> VerifyResponse {
    VerifyResponse::invalid(payer, FacilitatorErrorReason::InvalidScheme)
}

impl IntoResponse for FacilitatorLocalError {
    fn into_response(self) -> Response {
        let error = self;

        match error {
            FacilitatorLocalError::SchemeMismatch(payer, ..) => {
                (StatusCode::OK, Json(invalid_schema(payer))).into_response()
            }
            FacilitatorLocalError::ReceiverMismatch(payer, ..)
            | FacilitatorLocalError::InvalidSignature(payer, ..)
            | FacilitatorLocalError::InvalidTiming(payer, ..)
            | FacilitatorLocalError::InsufficientValue(payer) => {
                (StatusCode::OK, Json(invalid_schema(Some(payer)))).into_response()
            }
            FacilitatorLocalError::NetworkMismatch(payer, ..)
            | FacilitatorLocalError::UnsupportedNetwork(payer) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    payer,
                    FacilitatorErrorReason::InvalidNetwork,
                )),
            )
                .into_response(),
            FacilitatorLocalError::DecodingError(reason) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    None,
                    FacilitatorErrorReason::FreeForm(reason),
                )),
            )
                .into_response(),
            FacilitatorLocalError::InsufficientFunds(payer) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    Some(payer),
                    FacilitatorErrorReason::InsufficientFunds,
                )),
            )
                .into_response(),
            // Client errors (4xx) - invalid input from user
            FacilitatorLocalError::InvalidAddress(..) => (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid address format".to_string(),
                }),
            )
                .into_response(),
            // Server errors (5xx) - internal/infrastructure issues
            FacilitatorLocalError::ContractCall(details) => {
                tracing::error!("Contract call failed: {details}");
                (
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse {
                        error: format!("Contract error: {}", details),
                    }),
                )
                    .into_response()
            }
            FacilitatorLocalError::RpcProviderError(details) => {
                tracing::error!("RPC provider error: {details}");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        error: "Service temporarily unavailable".to_string(),
                    }),
                )
                    .into_response()
            }
            FacilitatorLocalError::ResourceExhaustion(details) => {
                tracing::error!("Resource exhaustion: {details}");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        error: "Service temporarily unavailable".to_string(),
                    }),
                )
                    .into_response()
            }
            FacilitatorLocalError::ClockError(details) => {
                tracing::error!("System clock error: {:?}", details);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EvmAddress;
    use alloy::primitives::Address;

    /// Helper to get expected status code for each error type
    fn expected_status(err: &FacilitatorLocalError) -> StatusCode {
        match err {
            FacilitatorLocalError::UnsupportedNetwork(_) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::NetworkMismatch(_, _, _) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::SchemeMismatch(_, _, _) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::InvalidAddress(_) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::ReceiverMismatch(_, _, _) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::ClockError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            FacilitatorLocalError::InvalidTiming(_, _) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::ContractCall(_) => StatusCode::BAD_GATEWAY,
            FacilitatorLocalError::RpcProviderError(_) => StatusCode::SERVICE_UNAVAILABLE,
            FacilitatorLocalError::ResourceExhaustion(_) => StatusCode::SERVICE_UNAVAILABLE,
            FacilitatorLocalError::InvalidSignature(_, _) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::InsufficientFunds(_) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::InsufficientValue(_) => StatusCode::BAD_REQUEST,
            FacilitatorLocalError::DecodingError(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn test_evm_address() -> MixedAddress {
        MixedAddress::Evm(EvmAddress(Address::ZERO))
    }

    #[test]
    fn test_contract_call_error_is_502() {
        let err = FacilitatorLocalError::ContractCall("Invalid signature order".to_string());
        assert_eq!(expected_status(&err), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_rpc_error_is_503() {
        let err = FacilitatorLocalError::RpcProviderError("Connection refused".to_string());
        assert_eq!(expected_status(&err), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_resource_exhaustion_is_503() {
        let err = FacilitatorLocalError::ResourceExhaustion("Too many connections".to_string());
        assert_eq!(expected_status(&err), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_insufficient_funds_is_400() {
        let err = FacilitatorLocalError::InsufficientFunds(test_evm_address());
        assert_eq!(expected_status(&err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_invalid_timing_is_400() {
        let err =
            FacilitatorLocalError::InvalidTiming(test_evm_address(), "validBefore expired".into());
        assert_eq!(expected_status(&err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_invalid_signature_is_400() {
        let err =
            FacilitatorLocalError::InvalidSignature(test_evm_address(), "signature mismatch".into());
        assert_eq!(expected_status(&err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_unsupported_network_is_400() {
        let err = FacilitatorLocalError::UnsupportedNetwork(None);
        assert_eq!(expected_status(&err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_decoding_error_is_400() {
        let err = FacilitatorLocalError::DecodingError("invalid payload".to_string());
        assert_eq!(expected_status(&err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_insufficient_value_is_400() {
        let err = FacilitatorLocalError::InsufficientValue(test_evm_address());
        assert_eq!(expected_status(&err), StatusCode::BAD_REQUEST);
    }
}
