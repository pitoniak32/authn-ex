use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{self, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use coset::iana;
use otel::setup_otel;
use passkey::types::{
    rand::random_vec,
    webauthn::{
        AttestationConveyancePreference, AuthenticatorAttestationResponse,
        CreatedPublicKeyCredential, CredentialCreationOptions, PublicKeyCredentialCreationOptions,
        PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
        PublicKeyCredentialUserEntity, AuthenticatedPublicKeyCredential, CollectedClientData,
    },
};
use tokio::sync::Mutex;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use url::Url;

use base64::prelude::*;

pub mod otel;
pub mod util_routes;

const AUTH_TOKEN_KEY: &'static str = "TOKEN";

#[tracing::instrument(skip_all)]
pub async fn get_passkeys(
    State(state): State<Arc<Mutex<HashMap<String, AuthenticatorAttestationResponse>>>>,
) -> Result<Response, StatusCode> {

    tracing::info!("getting passkeys from store");

    Ok((StatusCode::OK, Json(state.lock().await.iter().map(|(_key, value)| value.clone()).collect::<Vec<_>>())).into_response())
}

/// Return the creation options for credentials
///
/// Currently returning mocked values for learning.
#[tracing::instrument(skip_all)]
pub async fn request_credential_creation_options() -> Result<Response, StatusCode> {
    let origin = Url::parse("https://future.1password.com").expect("origin url should parse");
    let options = CredentialCreationOptions {
        public_key: PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: None, // Leaving the ID as None means use the effective domain
                name: origin.domain().unwrap().into(),
            },
            user: PublicKeyCredentialUserEntity {
                id: random_vec(32).into(),
                display_name: "Johnny Passkey".into(),
                name: "jpasskey@example.org".into(),
            },
            challenge: random_vec(32).into(),
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                ty: PublicKeyCredentialType::PublicKey,
                alg: iana::Algorithm::ES256,
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };
    Ok((StatusCode::OK, Json(options)).into_response())
}

/// Return the creation options for credentials
///
/// Currently returning mocked values for learning.
#[tracing::instrument(skip_all)]
pub async fn register_created_credentials(
    State(state): State<Arc<Mutex<HashMap<String, AuthenticatorAttestationResponse>>>>,
    Json(credentials): Json<CreatedPublicKeyCredential>,
) -> Result<Response, StatusCode> {

    println!("registering!");

    dbg!(&state.lock().await.insert(credentials.id.clone(), credentials.response.clone()));

    Ok((StatusCode::CREATED, "thank you, come again!").into_response())
}

/// Return the creation options for credentials
///
/// Currently returning mocked values for learning.
#[tracing::instrument(skip_all)]
pub async fn validate_authenticated_credential(
    Json(credentials): Json<AuthenticatedPublicKeyCredential>,
) -> Result<Response, StatusCode> {


    tracing::info!("validating!");

    let result: CollectedClientData = serde_json::from_slice(&credentials.response.client_data_json.to_vec()).unwrap();

    dbg!(&result);

    Ok((StatusCode::OK, "yup, looks good!").into_response())
}

trait CredentialRepo: Send + Sync {
    async fn get_credentials(&self) -> Vec<AuthenticatorAttestationResponse>;

    async fn save_credential(&self, user: &CreatedPublicKeyCredential);
}

#[tokio::main]
async fn main() {
    pub const DEFAULT_SERVICE_PORT: u16 = 8080;
    pub const DEFAULT_SERVICE_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

    let _guard = setup_otel();

    let cred_store: Arc<Mutex<HashMap<String, AuthenticatorAttestationResponse>>> = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route("/", get(root))
        .route("/protected", get(protected))
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
        .with_state(cred_store)
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
pub async fn root() -> Result<Response, StatusCode> {
    Ok((
        StatusCode::BAD_REQUEST,
        format!("This is the root endpoint"),
    )
        .into_response())
}

#[tracing::instrument]
pub async fn protected() -> Result<Response, StatusCode> {
    Ok((
        StatusCode::OK,
        format!("This is the protected endpoint, you must be logged in!"),
    )
        .into_response())
}

#[tracing::instrument(skip_all, err)]
pub async fn auth(req: Request, next: Next) -> Result<Response, StatusCode> {
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
                let jwt_access_token = cookie.replace(&format!("{}=", AUTH_TOKEN_KEY), "");
                tracing::trace!("extracted jwt from headers");
                return Ok(jwt_access_token);
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}
