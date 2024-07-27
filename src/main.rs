use std::net::Ipv4Addr;

use axum::{Router, routing::get, response::{Response, IntoResponse}, http::{StatusCode, self,}, middleware::{Next, self}, extract::Request};
use otel::setup_otel;
use tower_http::trace::{TraceLayer, self};
use tracing::Level;

pub mod otel;
pub mod util_routes;

const AUTH_TOKEN_KEY: &'static str = "TOKEN";

#[tokio::main]
async fn main() {
    pub const DEFAULT_SERVICE_PORT: u16 = 8080;
    pub const DEFAULT_SERVICE_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

    let _guard = setup_otel();

    let app = Router::new()
        .route("/", get(root))
        .route("/protected", get(protected))
        .route_layer(middleware::from_fn(auth)) // All routes above will require 'auth'
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

#[tracing::instrument]
pub async fn protected() -> Result<Response, StatusCode> {
    Ok((StatusCode::OK, format!("This is the protected endpoint, you must be logged in!")).into_response())
}

#[tracing::instrument(skip_all, err)]
pub async fn auth(
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = extract_access_token(&req)?;

    tracing::info!("token: {token:#?}");
    tracing::info!("req: {req:#?}");

    if token != "yersh" {
        tracing::warn!("invalid token '{token}', was provided");
        Err(StatusCode::UNAUTHORIZED)
    } else {
        tracing::info!("token was valid!");
        Ok(next.run(req).await)
    }
}

#[tracing::instrument(skip_all, err)]
fn extract_access_token(req: &Request) -> Result<String, StatusCode> {
    if let Some(cookie_header) = req.headers().get(http::header::COOKIE) {
        let cookies: Vec<_> = cookie_header.to_str().unwrap().split(';').collect();
        for cookie in cookies {
            if cookie.contains(AUTH_TOKEN_KEY) {
                let jwt_access_token =
                    cookie.replace(&format!("{}=", AUTH_TOKEN_KEY), "");
                tracing::trace!("extracted jwt from headers");
                return Ok(jwt_access_token);
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}