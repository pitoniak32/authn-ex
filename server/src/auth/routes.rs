use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{FromRef, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};
use base64::prelude::*;
use passkey::types::webauthn::AuthenticatorAttestationResponse;

use serde::{Deserialize, Serialize};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

use crate::{SharedState, ACCESS_TOKEN_KEY, REFRESH_TOKEN_KEY};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::{async_trait, Json};
use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::decode;
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header, Validation};

use once_cell::sync::Lazy;
use rand::distributions::{Alphanumeric, DistString};

use serde_json::json;

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 60);
    Keys::new(secret.as_bytes())
});

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

pub type CredentialStore = HashMap<String, AuthenticatorAttestationResponse>;
pub type SessionStore = HashMap<Uuid, UserSession>;
pub type UserStore = HashMap<Uuid, UserInfo>;

#[derive(Debug)]
pub struct UserSession {
    pub valid_refresh_tokens: Vec<String>,
}

/// What is required when a user is logging in.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DtoUserLogin {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub refresh_token_version: u16,
}

impl UserInfo {
    pub fn new<T>(id: impl Into<Uuid>, username: T, display_name: T) -> Self
    where
        T: Into<String>,
    {
        UserInfo {
            id: id.into(),
            username: username.into(),
            display_name: display_name.into(),
            refresh_token_version: 0,
        }
    }
}

impl TryFrom<String> for UserInfo {
    type Error = AuthError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parts = value.split(".").collect::<Vec<&str>>();
        let claims = parts.get(1).ok_or(AuthError::InvalidToken)?;
        let decoded = String::from_utf8(
            BASE64_STANDARD_NO_PAD
                .decode(claims)
                .map_err(|_| AuthError::InvalidToken)?,
        )
        .map_err(|_| AuthError::InvalidToken)?;
        Ok(serde_json::from_str::<AccessClaims>(&decoded)
            .map_err(|_| AuthError::InvalidToken)?
            .user)
    }
}

pub fn get_access_token(user: UserInfo) -> Result<String, AuthError> {
    let access_token = encode(
        &Header::default(),
        &AccessClaims {
            user,
            exp: (chrono::Utc::now().naive_utc() + chrono::Duration::seconds(5))
                .and_utc()
                .timestamp() as usize,
        },
        &KEYS.encoding,
    )
    .map_err(|_| AuthError::TokenCreation)?;

    Ok(access_token)
}

pub fn get_refresh_token(user: UserInfo) -> Result<String, AuthError> {
    let refresh_token = encode(
        &Header::default(),
        &RefreshClaims {
            user,
            version: 0,
            exp: (chrono::Utc::now().naive_utc() + chrono::Duration::minutes(1))
                .and_utc()
                .timestamp() as usize,
        },
        &KEYS.encoding,
    )
    .map_err(|_| AuthError::TokenCreation)?;

    Ok(refresh_token)
}

#[tracing::instrument(skip_all)]
pub async fn login(
    app_state: State<SharedState>,
    user_form: Form<DtoUserLogin>,
) -> Result<Response, AuthError> {
    // Check if the user sent the credentials
    if user_form.username.is_empty() || user_form.password.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    let mut app_state = app_state.lock().await;
    let (id, user) = app_state
        .users
        .iter()
        .find(|(_key, value)| value.username == user_form.username)
        .ok_or(AuthError::WrongCredentials)?;

    let access_token = get_access_token(user.clone())?;
    let refresh_token = get_refresh_token(user.clone())?;

    let id = *id;

    // Add the refresh token to the user sessions
    if let Some(session) = app_state.sessions.get_mut(&id) {
        session.valid_refresh_tokens.push(refresh_token.clone());
    } else {
        app_state.sessions.insert(
            id,
            UserSession {
                valid_refresh_tokens: vec![refresh_token.clone()],
            },
        );
    }

    tracing::info!("logging user in");

    // Send the authorized token
    build_login_response(access_token, refresh_token)
}

#[tracing::instrument(skip_all)]
pub async fn logout(app_state: State<SharedState>, jar: CookieJar) -> Result<Response, AuthError> {
    tracing::info!("logging user out");

    let refresh_token = jar
        .get(REFRESH_TOKEN_KEY)
        .map(|cookie| cookie.value().to_owned());

    let user = UserInfo::try_from(refresh_token.clone().unwrap())?;

    dbg!(&user);

    if let (Some(session), Some(r_tok)) = (
        app_state.lock().await.sessions.get_mut(&user.id),
        refresh_token,
    ) {
        session.valid_refresh_tokens.retain(|tok| *tok != r_tok);
    }

    build_logout_response()
}

fn build_login_response(
    access_token: String,
    refresh_token: String,
) -> Result<Response, AuthError> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            "Set-Cookie",
            format!(
                "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=999999{}",
                ACCESS_TOKEN_KEY, access_token, "",
            ),
        )
        .header(
            "Set-Cookie",
            format!(
                "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=999999{}",
                REFRESH_TOKEN_KEY, refresh_token, "",
            ),
        )
        .body(Body::empty())
        .map_err(|_err| AuthError::TokenCreation)?
        .into_response())
}

fn build_logout_response() -> Result<Response, AuthError> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            "Set-Cookie",
            format!(
                "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=999999{}",
                ACCESS_TOKEN_KEY, "invalidated", ""
            ),
        )
        .header(
            "Set-Cookie",
            format!(
                "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=999999{}",
                REFRESH_TOKEN_KEY, "invalidated", ""
            ),
        )
        .body(Body::empty())
        .map_err(|_err| AuthError::TokenCreation)?
        .into_response())
}

pub enum AuthError {
    InvalidToken,
    WrongCredentials,
    TokenCreation,
    MissingCredentials,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub user: UserInfo,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub user: UserInfo,
    pub version: u16,
    pub exp: usize,
}

#[async_trait]
impl<S> FromRequestParts<S> for AccessClaims
where
    SharedState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    #[tracing::instrument(skip_all)]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from cookies
        let cookies = CookieJar::from_headers(&parts.headers);
        let app_state = SharedState::from_ref(state);
        dbg!(&app_state.lock().await.sessions);
        match cookies
            .get(ACCESS_TOKEN_KEY)
            .map(|cookie| cookie.value().to_owned())
        {
            Some(token) => {
                // Decode the user data
                let mut validation = Validation::default();
                validation.leeway = 5;
                let decode_result = decode::<AccessClaims>(&token, &KEYS.decoding, &validation);

                dbg!(&decode_result);

                match decode_result {
                    Ok(token_data) => {
                        tracing::Span::current().set_attribute(
                            "user.username",
                            token_data.claims.user.username.clone(),
                        );
                        Ok(token_data.claims)
                    }
                    Err(e) if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        // Turn off expiration validation to get the user from the claims.
                        validation.validate_exp = false;
                        let token_data =
                            decode::<AccessClaims>(&token, &KEYS.decoding, &validation)
                                .map_err(|_| AuthError::TokenCreation)?;
                        if let Some(user_session) = &app_state
                            .lock()
                            .await
                            .sessions
                            .get(&token_data.claims.user.id)
                        {
                            if user_session
                                .valid_refresh_tokens
                                .iter()
                                .any(|tok| *tok == token)
                            {}
                        }
                        Err(AuthError::InvalidToken)
                    }
                    Err(e) => {
                        tracing::error!(error.kind = ?e.kind(), "encountered error decoding / validating access jwt");

                        Err(AuthError::InvalidToken)
                    }
                }
            }
            None => Err(AuthError::InvalidToken),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Serialize)]
pub struct AuthBody {
    pub access_token: String,
    pub token_type: String,
}

impl AuthBody {
    pub fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}
