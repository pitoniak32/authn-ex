use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use auth::AccessClaims;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use otel::setup_otel;
use tokio::sync::Mutex;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use uuid::Uuid;

use crate::auth::{
    get_passkeys, login, logout, register_created_credentials, request_credential_creation_options,
    validate_authenticated_credential, CredentialStore, SessionStore, UserInfo, UserStore,
};

pub mod auth;
pub mod otel;
pub mod util_routes;

const ACCESS_TOKEN_KEY: &str = "ACCESS_TOKEN";
const REFRESH_TOKEN_KEY: &str = "REFRESH_TOKEN";

#[derive(Debug)]
pub struct AppState {
    creds: CredentialStore,
    sessions: SessionStore,
    users: UserStore,
}

type SharedState = Arc<Mutex<AppState>>;

#[tokio::main]
async fn main() {
    pub const DEFAULT_SERVICE_PORT: u16 = 8081;
    pub const DEFAULT_SERVICE_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

    let _guard = setup_otel();

    let seed_uid = Uuid::new_v4();

    let app_state = AppState {
        creds: HashMap::new(),
        sessions: HashMap::new(),
        users: HashMap::from([(
            seed_uid,
            UserInfo::new(seed_uid, "uname", "User Name"),
        )]),
    };

    let shared_state = Arc::new(Mutex::new(app_state));

    let app = Router::new()
        .route("/", get(root))
        .route("/auth/passkeys", get(get_passkeys))
        .route(
            "/auth/request-credential-create-options",
            post(request_credential_creation_options),
        )
        .route(
            "/auth/register-created-credentials",
            post(register_created_credentials),
        )
        .route(
            "/auth/validate-authenticated-credentials",
            post(validate_authenticated_credential),
        )
        .route("/user/info", post(user_info))
        .route("/protected", get(protected))
        .route("/auth/logout", post(logout))
        .route("/auth/login", post(login))
        .with_state(shared_state)
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

    let listener = tokio::net::TcpListener::bind((DEFAULT_SERVICE_IP, DEFAULT_SERVICE_PORT))
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
            id: Uuid::new_v4(),
            username: "test".to_string(),
            display_name: "Test Name".to_string(),
            refresh_token_version: 0,
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
pub async fn protected(
    access_claims: AccessClaims,
    state: State<SharedState>,
) -> Result<Response, StatusCode> {
    Ok((
        StatusCode::OK,
        format!("{:#?},{:#?}", access_claims, state.lock().await.sessions),
    )
        .into_response())
}
