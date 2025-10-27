//! x402 Facilitator HTTP entrypoint.
//!
//! This binary launches an Axum-based HTTP server that exposes the x402 protocol interface
//! for payment verification and settlement via Ethereum-compatible networks.
//!
//! Endpoints:
//! - `GET /verify` – Supported verification schema
//! - `POST /verify` – Verify a payment payload against requirements
//! - `GET /settle` – Supported settlement schema
//! - `POST /settle` – Settle an accepted payment payload on-chain
//! - `GET /supported` – List supported payment kinds (version/scheme/network)
//!
//! This server includes:
//! - OpenTelemetry tracing via `TraceLayer`
//! - CORS support for cross-origin clients
//! - Ethereum provider cache for per-network RPC routing
//!
//! Environment:
//! - `.env` values loaded at startup
//! - `HOST`, `PORT` control binding address
//! - `OTEL_*` variables enable tracing to systems like Honeycomb

use axum::Router;
use axum::http::Method;
use dotenvy::dotenv;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors;

use crate::config::FacilitatorConfig;
use crate::facilitator_local::FacilitatorLocal;
use crate::provider_cache::ProviderCache;
use crate::security::{ApiKeyAuth, IpFilter, RateLimiter};
use crate::sig_down::SigDown;
use crate::telemetry::Telemetry;

mod chain;
mod config;
mod facilitator;
mod facilitator_local;
mod from_env;
mod handlers;
mod network;
mod provider_cache;
mod security;
mod sig_down;
mod telemetry;
mod timestamp;
mod types;

/// Initializes the x402 facilitator server.
///
/// - Loads `.env` variables.
/// - Initializes OpenTelemetry tracing.
/// - Connects to Ethereum providers for supported networks.
/// - Starts an Axum HTTP server with the x402 protocol handlers.
///
/// Binds to the address specified by the `HOST` and `PORT` env vars.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env variables
    dotenv().ok();

    let telemetry = Telemetry::new()
        .with_name(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .register();

    // Load configuration
    let app_config = match FacilitatorConfig::from_env() {
        Ok(config) => {
            tracing::info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            tracing::error!("Failed to load configuration: {}", e);
            tracing::info!("Using default configuration");
            FacilitatorConfig::default()
        }
    };

    let provider_cache = ProviderCache::from_env().await;
    // Abort if we can't initialise Ethereum providers early
    let provider_cache = match provider_cache {
        Ok(provider_cache) => provider_cache,
        Err(e) => {
            tracing::error!("Failed to create Ethereum providers: {}", e);
            std::process::exit(1);
        }
    };
    let facilitator = FacilitatorLocal::new(provider_cache);
    let axum_state = Arc::new(facilitator);

    // Initialize security components
    let api_key_auth = ApiKeyAuth::from_env();
    let ip_filter = IpFilter::new(security::ip_filter::IpFilterConfig {
        allowed_ips: app_config.ip_filtering.allowed_ips.clone(),
        blocked_ips: app_config.ip_filtering.blocked_ips.clone(),
        log_events: app_config.security.log_security_events,
    });
    let rate_limiter = RateLimiter::new(security::rate_limit::RateLimiterConfig {
        enabled: app_config.rate_limiting.enabled,
        requests_per_second: app_config.rate_limiting.requests_per_second,
        ban_duration: std::time::Duration::from_secs(app_config.rate_limiting.ban_duration_seconds),
        ban_threshold: app_config.rate_limiting.ban_threshold,
    });
    // Configure CORS
    let cors_layer = if app_config.cors.allowed_origins.is_empty() {
        tracing::info!("CORS: Allowing all origins (*)");
        cors::CorsLayer::new()
            .allow_origin(cors::Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(cors::Any)
    } else {
        tracing::info!("CORS: Restricting to {:?}", app_config.cors.allowed_origins);
        let origins: Vec<_> = app_config
            .cors
            .allowed_origins
            .iter()
            .filter_map(|origin| origin.parse().ok())
            .collect();
        cors::CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(cors::Any)
    };

    let http_endpoints = Router::new()
        .merge(handlers::routes().with_state(axum_state))
        .layer(tower::ServiceBuilder::new()
            .layer(axum::middleware::from_fn(move |req, next| {
                let auth = api_key_auth.clone();
                async move { auth.middleware(req, next).await }
            }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let limiter = rate_limiter.clone();
                async move { limiter.middleware(req, next).await }
            }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let filter = ip_filter.clone();
                async move { filter.middleware(req, next).await }
            }))
        )
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            app_config.request.max_body_size_bytes,
        ))
        .layer(telemetry.http_tracing())
        .layer(cors_layer);

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::new(host.parse().expect("HOST must be a valid IP address"), port);
    tracing::info!("Starting server at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        });

    let sig_down = SigDown::try_new()?;
    let axum_cancellation_token = sig_down.cancellation_token();
    let axum_graceful_shutdown = async move { axum_cancellation_token.cancelled().await };
    axum::serve(
        listener,
        http_endpoints.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(axum_graceful_shutdown)
    .await?;

    Ok(())
}
