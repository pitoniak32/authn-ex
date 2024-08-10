use auth::{login, logout};
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use bson::{doc, oid::ObjectId};
use futures::StreamExt;
use lib_core::{
    config::{env_key::config, otel},
    ctx::{Ctx, UserInfo},
    model::{model_manager::ModelManager, UserBmc, UserForCreate},
};
use lib_web::middleware::{ctx_require, mw_ctx_resolver, CtxW};
use tower_cookies::CookieManagerLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

pub mod auth;
pub mod util_routes;

#[tokio::main]
async fn main() {
    let _guard = otel::setup_otel(&config().OTEL_COLLECTOR_URI, env!("CARGO_PKG_NAME"));

    // let seed_uid = Uuid::new_v4();

    let mm = ModelManager::new().await.unwrap();

    let app = Router::new()
        .route("/", get(root))
        .route("/user/create", post(create_test_user))
        .nest(
            "/auth",
            Router::new()
                .route("/login", post(login))
                .route("/logout", post(logout)),
        )
        .nest(
            "/api",
            Router::new()
                .route("/user/info", post(user_info))
                .route("/protected", get(protected))
                .route("/sessions", get(list_sessions))
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
        .layer(CookieManagerLayer::new())
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
            user_agent: None,
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
pub async fn create_test_user(mm: State<ModelManager>) -> Result<Response, StatusCode> {
    let ctx = Ctx::root_ctx();
    let result = UserBmc::create(
        &ctx,
        &mm,
        UserForCreate {
            username: "test".to_string(),
            password: "test".to_string(),
            email: "test".to_string(),
        },
    )
    .await;

    dbg!(&result);

    Ok((StatusCode::OK, "").into_response())
}

#[tracing::instrument(skip_all)]
pub async fn list_sessions(ctx: CtxW, mm: State<ModelManager>) -> Result<Response, StatusCode> {
    let ctx = ctx.0;

    let sessions: Vec<_> = mm
        .sessions
        .find(doc! {"user_id": ctx.user().id })
        .await
        .unwrap()
        .collect()
        .await;

    dbg!(&sessions);

    Ok((StatusCode::OK, "").into_response())
}

#[tracing::instrument(skip_all)]
pub async fn protected(ctx: CtxW, _mm: State<ModelManager>) -> Result<Response, StatusCode> {
    let ctx = ctx.0;
    Ok((StatusCode::OK, Json(ctx.user())).into_response())
}
