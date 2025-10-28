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

/// `GET /verify`: Returns a machine-readable description of the `/verify` endpoint.
///
/// This is served by the facilitator to help clients understand how to construct
/// a valid [`VerifyRequest`] for payment verification.
///
/// This is optional metadata and primarily useful for discoverability and debugging tools.
#[instrument(skip_all)]
pub async fn get_verify_info() -> impl IntoResponse {
    Json(json!({
        "endpoint": "/verify",
        "description": "POST to verify x402 payments",
        "body": {
            "paymentPayload": "PaymentPayload",
            "paymentRequirements": "PaymentRequirements",
        }
    }))
}

/// `GET /settle`: Returns a machine-readable description of the `/settle` endpoint.
///
/// This is served by the facilitator to describe the structure of a valid
/// [`SettleRequest`] used to initiate on-chain payment settlement.
#[instrument(skip_all)]
pub async fn get_settle_info() -> impl IntoResponse {
    Json(json!({
        "endpoint": "/settle",
        "description": "POST to settle x402 payments",
        "body": {
            "paymentPayload": "PaymentPayload",
            "paymentRequirements": "PaymentRequirements",
        }
    }))
}

pub fn routes<F>() -> Router<Arc<F>>
where
    F: Facilitator<Error = FacilitatorLocalError> + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(get_root))
        .route("/verify", get(get_verify_info))
        .route("/verify", post(post_verify::<F>))
        .route("/settle", get(get_settle_info))
        .route("/settle", post(post_settle::<F>))
        .route("/supported", get(get_supported::<F>))
        .route("/health", get(get_health::<F>))
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
</head>
<body>
    <h1>Multi-chain x402 Facilitator by Infra402</h1>
    <p>Version: {pkg_version}</p>
    <p>{pkg_description}</p>

    <h2>Available Endpoints</h2>
    <ul>
        <li>
            <a href="/">/</a> (GET) - API root with endpoint information
        </li>
        <li>
            <a href="/health">/health</a> (GET) - Health check endpoint - returns supported networks and payment schemes
        </li>
        <li>
            <a href="/supported">/supported</a> (GET) - Lists all supported payment schemes and blockchain networks
        </li>
        <li>
            <a href="/verify">/verify</a> (GET) - Returns endpoint information for POST /verify
        </li>
        <li>
            /verify (POST) - Verify payment payload signatures and requirements (currently no API key required, rate limits applied)
        </li>
        <li>
            <a href="/settle">/settle</a> (GET) - Returns endpoint information for POST /settle
        </li>
        <li>
            /settle (POST) - Submit verified payment to blockchain for on-chain settlement (currently no API key required, rate limits applied)
        </li>
    </ul>

    <p>Documentation: <a href="https://github.com/infra402/infra402-facilitator">https://github.com/infra402/infra402-facilitator</a></p>
</body>
</html>"#);

    (StatusCode::OK, Html(html)).into_response()
}

/// `GET /admin/stats`: Returns abuse detection statistics.
///
/// This endpoint requires admin authentication via the `X-Admin-Key` header.
/// Returns current statistics about tracked IPs and suspicious activity.
#[instrument(skip_all)]
pub async fn get_admin_stats(
    Extension(abuse_detector): Extension<AbuseDetector>,
) -> impl IntoResponse {
    let stats = abuse_detector.get_stats();
    (StatusCode::OK, Json(json!({
        "total_ips_tracked": stats.total_ips_tracked,
        "suspicious_ips": stats.suspicious_ips,
    }))).into_response()
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
pub async fn post_settle<F>(
    State(facilitator): State<Arc<F>>,
    Extension(abuse_detector): Extension<AbuseDetector>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<SettleRequest>,
) -> impl IntoResponse
where
    F: Facilitator<Error = FacilitatorLocalError>,
{
    match facilitator.settle(&body).await {
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

        let bad_request = (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid request".to_string(),
            }),
        )
            .into_response();

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
            FacilitatorLocalError::ContractCall(..)
            | FacilitatorLocalError::InvalidAddress(..)
            | FacilitatorLocalError::ClockError(_) => bad_request,
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
        }
    }
}
