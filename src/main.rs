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
use crate::security::{AdminAuth, ApiKeyAuth, IpFilter, RateLimiter};
use crate::security::abuse::{AbuseDetector, AbuseDetectorConfig};
use crate::sig_down::SigDown;
use crate::telemetry::Telemetry;

mod batch_processor;
mod batch_queue;
mod chain;
mod config;
mod facilitator;
mod facilitator_local;
mod from_env;
mod handlers;
mod hooks;
mod network;
mod provider_cache;
mod security;
mod sig_down;
mod telemetry;
mod timestamp;
mod tokens;
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

    // Initialize hook manager first (needed by batch queue manager)
    let hook_manager = match crate::hooks::HookManager::new("hooks.toml") {
        Ok(manager) => {
            tracing::info!("Hook manager initialized successfully");
            Some(Arc::new(manager))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to initialize hook manager - hooks will be disabled");
            None
        }
    };

    // Initialize batch queue manager if enabled globally or for any network
    let batch_queue_manager = if app_config.batch_settlement.is_enabled_anywhere() {
        tracing::info!(
            global_enabled = app_config.batch_settlement.enabled,
            max_batch_size = app_config.batch_settlement.max_batch_size,
            max_wait_ms = app_config.batch_settlement.max_wait_ms,
            min_batch_size = app_config.batch_settlement.min_batch_size,
            allow_partial_failure = app_config.batch_settlement.allow_partial_failure,
            "Batch settlement enabled - initializing queue manager"
        );

        // Log per-network batch settlement status
        let mut enabled_networks = vec![];
        let mut disabled_networks = vec![];
        for (network_name, network_config) in &app_config.batch_settlement.networks {
            if let Some(enabled) = network_config.enabled {
                if enabled {
                    enabled_networks.push(network_name.as_str());
                } else {
                    disabled_networks.push(network_name.as_str());
                }
            }
        }
        if !enabled_networks.is_empty() {
            tracing::info!(
                networks = ?enabled_networks,
                "Networks with batch settlement explicitly enabled"
            );
        }
        if !disabled_networks.is_empty() {
            tracing::info!(
                networks = ?disabled_networks,
                "Networks with batch settlement explicitly disabled"
            );
        }

        let manager = Arc::new(crate::batch_queue::BatchQueueManager::new(
            app_config.batch_settlement.clone(),
            hook_manager.clone(),
        ));

        Some(manager)
    } else {
        tracing::info!("Batch settlement disabled globally - using direct settlement for all networks");
        None
    };

    // Initialize security components
    let api_key_auth = ApiKeyAuth::from_env();
    let admin_auth = AdminAuth::from_env();
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
        whitelisted_ips: app_config.rate_limiting.whitelisted_ips.clone(),
    });
    let abuse_detector = AbuseDetector::new(AbuseDetectorConfig {
        enabled: app_config.security.log_security_events,
        invalid_signature_threshold: 10,
        tracking_window: std::time::Duration::from_secs(300), // 5 minutes
        log_events: app_config.security.log_security_events,
    });

    // Clone instances for use in different middleware layers and cleanup task
    let abuse_detector_middleware = abuse_detector.clone();
    let rate_limiter_middleware = rate_limiter.clone();
    let ip_filter_middleware = ip_filter.clone();
    let api_key_auth_middleware = api_key_auth.clone();
    let admin_auth_middleware = admin_auth.clone();

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

    // Admin routes with separate authentication
    let mut admin_endpoints = Router::new()
        .merge(handlers::admin_routes())
        .layer(axum::Extension(batch_queue_manager.clone()))
        .layer(axum::Extension(abuse_detector.clone()))
        .layer(axum::middleware::from_fn(move |req, next| {
            let auth = admin_auth_middleware.clone();
            async move { auth.middleware(req, next).await }
        }));

    // Add hook admin routes if hook manager is initialized
    if let Some(ref manager) = hook_manager {
        let hook_routes = crate::hooks::admin::admin_hook_routes(
            Arc::clone(manager),
            admin_auth.clone(),
        );
        admin_endpoints = admin_endpoints.merge(hook_routes);
        tracing::info!("Hook admin routes registered");
    }

    let http_endpoints = Router::new()
        .merge(handlers::routes().with_state(axum_state))
        .merge(admin_endpoints)
        .layer(axum::Extension(hook_manager.clone()))
        .layer(axum::Extension(batch_queue_manager.clone()))
        .layer(axum::Extension(app_config.batch_settlement.clone()))
        .layer(axum::Extension(abuse_detector.clone()))
        .layer(tower::ServiceBuilder::new()
            .layer(axum::middleware::from_fn(move |req, next| {
                let auth = api_key_auth_middleware.clone();
                async move { auth.middleware(req, next).await }
            }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let limiter = rate_limiter_middleware.clone();
                async move { limiter.middleware(req, next).await }
            }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let filter = ip_filter_middleware.clone();
                async move { filter.middleware(req, next).await }
            }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let detector = abuse_detector_middleware.clone();
                async move { detector.middleware(req, next).await }
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

    // Spawn background cleanup task for abuse detector and rate limiter
    let cleanup_cancellation_token = sig_down.cancellation_token();
    let cleanup_interval_secs = app_config.security.cleanup_interval_seconds;
    tracing::info!(
        "Starting security cleanup task with interval of {} seconds",
        cleanup_interval_secs
    );
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(cleanup_interval_secs));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tracing::debug!("Running periodic cleanup for abuse detector and rate limiter");
                    abuse_detector.cleanup_old_data();
                    rate_limiter.cleanup_expired_bans();
                }
                _ = cleanup_cancellation_token.cancelled() => {
                    tracing::info!("Stopping cleanup task");
                    break;
                }
            }
        }
    });

    let axum_graceful_shutdown = async move { axum_cancellation_token.cancelled().await };
    axum::serve(
        listener,
        http_endpoints.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(axum_graceful_shutdown)
    .await?;

    Ok(())
}
