use std::net::Ipv4Addr;

use axum::{Router, routing::get, response::{Response, IntoResponse}, http::StatusCode};
use otel::setup_otel;
use tower_http::trace::{TraceLayer, self};
use tracing::Level;

pub mod otel;
pub mod util_routes;

#[tokio::main]
async fn main() {
    pub const DEFAULT_SERVICE_PORT: u16 = 8080;
    pub const DEFAULT_SERVICE_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

    let _guard = setup_otel();

    let app = Router::new()
        .route("/", get(root))
        // .route_layer(middleware::from_fn(auth_guard::auth)) // All routes above will require 'access_token' cookie
        // .route("/auth/login", post(auth_routes::user_login))
        // .route("/auth/account", post(user_routes::create_user))
        .layer(
            TraceLayer::new_for_http()
                .on_request(trace::DefaultOnRequest::new().level(Level::INFO))
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .nest("/health", util_routes::health_router())
        .fallback(util_routes::not_found);

    let listener = tokio::net::TcpListener::bind((DEFAULT_SERVICE_IP, DEFAULT_SERVICE_PORT)).await.unwrap();

    tracing::info!("Listening on: {}", listener.local_addr().expect("listener has a valid local address"));

    axum::serve(listener, app).await.unwrap();
}

#[tracing::instrument]
pub async fn root() -> Result<Response, StatusCode> {
    Ok((StatusCode::BAD_REQUEST, format!("This is the root endpoint")).into_response())
}