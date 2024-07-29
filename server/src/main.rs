use auth::{login, logout};
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use bson::oid::ObjectId;
use lib_core::{
    config::{env_key::config, otel},
    ctx::UserInfo,
    model::ModelManager,
};
use lib_web::middleware::{ctx_require, mw_ctx_resolver};
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use uuid::Uuid;

pub mod auth;
pub mod util_routes;

#[tokio::main]
async fn main() {
    let _guard = otel::setup_otel(&config().OTEL_COLLECTOR_URI);

    let seed_uid = Uuid::new_v4();

    let mm = ModelManager::new().await.unwrap();

    let app = Router::new()
        .route("/", get(root))
        .nest(
            "/auth",
            Router::new()
                .route("/login", post(login))
                .route("/logout", post(logout)), // .route("/passkeys", get(get_passkeys))
                                                 // .route(
                                                 //     "/request-credential-create-options",
                                                 //     post(request_credential_creation_options),
                                                 // )
                                                 // .route(
                                                 //     "/register-created-credentials",
                                                 //     post(register_created_credentials),
                                                 // )
                                                 // .route(
                                                 //     "/validate-authenticated-credentials",
                                                 //     post(validate_authenticated_credential),
                                                 // )
        )
        .nest(
            "/api",
            Router::new()
                .route("/user/info", post(user_info))
                .route("/protected", get(protected))
                .route_layer(middleware::from_fn(ctx_require)),
        )
        .layer(middleware::from_fn_with_state(mm.clone(), mw_ctx_resolver))
        .with_state(mm.clone())
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

    let listener = tokio::net::TcpListener::bind((config().SERVICE_IP, config().SERVICE_PORT))
        .await
        .unwrap();

    tracing::info!(
        "Listening on: {}",
        listener
            .local_addr()
            .expect("listener has a valid local address")
    );

    axum::serve(listener, app).await.unwrap();
}

#[tracing::instrument]
pub async fn user_info(req: Request) -> Result<Response, StatusCode> {
    dbg!(&req);
    dbg!(&req.extensions());
    dbg!(&req.body());
    dbg!(&req.headers());

    Ok((
        StatusCode::OK,
        Json(vec![UserInfo {
            id: ObjectId::new(),
            username: "test".to_string(),
        }]),
    )
        .into_response())
}

#[tracing::instrument]
pub async fn root() -> Result<Response, StatusCode> {
    Ok((
        StatusCode::BAD_REQUEST,
        "This is the root endpoint".to_string(),
    )
        .into_response())
}

#[tracing::instrument(skip_all)]
pub async fn protected(_mm: State<ModelManager>) -> Result<Response, StatusCode> {
    Ok((StatusCode::OK, "").into_response())
}
