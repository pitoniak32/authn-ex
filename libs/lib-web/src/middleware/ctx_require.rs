use std::str::FromStr;

use axum::{
    async_trait,
    body::Body,
    extract::{FromRequestParts, Request, State},
    http::request::Parts,
    middleware::Next,
    response::Response,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use base64::prelude::*;
use bson::oid::ObjectId;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use lib_core::{
    ctx::{Ctx, UserInfo},
    model::{user, ModelManager},
};
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use tracing_opentelemetry::OpenTelemetrySpanExt;

use once_cell::sync::Lazy;

use crate::{Error, Result};

pub const ACCESS_TOKEN_KEY: &str = "ACCESS_TOKEN";
pub const REFRESH_TOKEN_KEY: &str = "REFRESH_TOKEN";

pub static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 60);
    Keys::new(secret.as_bytes())
});

pub static ACCESS_TOKEN_EXPIRATION: Lazy<chrono::Duration> =
    Lazy::new(|| chrono::Duration::seconds(5));

pub static REFRESH_TOKEN_EXPIRATION: Lazy<chrono::Duration> =
    Lazy::new(|| chrono::Duration::minutes(5));

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

pub fn get_access_token(
    user: &UserInfo,
    encoding_key: &EncodingKey,
    duration: chrono::Duration,
) -> Result<String> {
    let access_token = encode(
        &Header::default(),
        &AccessClaims {
            user: user.clone(),
            exp: (chrono::Utc::now().naive_utc() + duration)
                .and_utc()
                .timestamp() as usize,
        },
        encoding_key,
    )
    .map_err(|_| Error::CtxExt(CtxExtError::CannotEncodeToken))?;

    Ok(access_token)
}

pub fn get_refresh_token(
    user: &UserInfo,
    encoding_key: &EncodingKey,
    duration: chrono::Duration,
) -> Result<String> {
    let refresh_token = encode(
        &Header::default(),
        &RefreshClaims {
            user: user.clone(),
            version: 0,
            exp: (chrono::Utc::now().naive_utc() + duration)
                .and_utc()
                .timestamp() as usize,
        },
        encoding_key,
    )
    .map_err(|_| Error::CtxExt(CtxExtError::CannotEncodeToken))?;

    Ok(refresh_token)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub user: UserInfo,
    pub exp: usize,
}

impl FromStr for AccessClaims {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts = s.split(".").collect::<Vec<&str>>();
        let claims = parts
            .get(1)
            .ok_or(Error::CtxExt(CtxExtError::InvalidToken))?;
        let decoded = String::from_utf8(
            BASE64_STANDARD_NO_PAD
                .decode(claims)
                .map_err(|_| Error::CtxExt(CtxExtError::InvalidToken))?,
        )
        .map_err(|_| Error::CtxExt(CtxExtError::InvalidToken))?;
        Ok(serde_json::from_str::<AccessClaims>(&decoded)
            .map_err(|_| Error::CtxExt(CtxExtError::InvalidToken))?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub user: UserInfo,
    pub version: u16,
    pub exp: usize,
}

impl FromStr for RefreshClaims {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts = s.split(".").collect::<Vec<&str>>();
        let claims = parts
            .get(1)
            .ok_or(Error::CtxExt(CtxExtError::InvalidToken))?;
        let decoded = String::from_utf8(
            BASE64_STANDARD_NO_PAD
                .decode(claims)
                .map_err(|_| Error::CtxExt(CtxExtError::InvalidToken))?,
        )
        .map_err(|_| Error::CtxExt(CtxExtError::InvalidToken))?;
        Ok(serde_json::from_str::<RefreshClaims>(&decoded)
            .map_err(|_| Error::CtxExt(CtxExtError::InvalidToken))?)
    }
}

pub async fn ctx_require(ctx: Result<CtxW>, req: Request<Body>, next: Next) -> Result<Response> {
    dbg!(&ctx);
    ctx?;

    Ok(next.run(req).await)
}

// IMPORTANT: This resolver must never fail, but rather capture the potential Auth error and put in in the
//            request extension as CtxExtResult.
//            This way it won't prevent downstream middleware to be executed, and will still capture the error
//            for the appropriate middleware (.e.g., mw_ctx_require which forces successful auth) or handler
//            to get the appropriate information.
pub async fn mw_ctx_resolver(
    State(mm): State<ModelManager>,
    cookies: CookieJar,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    tracing::debug!("{:<12} - mw_ctx_resolve", "MIDDLEWARE");

    let ctx_ext_result = ctx_resolve(mm, &cookies).await;

    if ctx_ext_result.is_err() && !matches!(ctx_ext_result, Err(CtxExtError::TokenNotInCookie)) {
        cookies.remove(ACCESS_TOKEN_KEY);
    }

    // Store the ctx_ext_result in the request extension
    // (for Ctx extractor).
    req.extensions_mut().insert(ctx_ext_result);

    next.run(req).await
}

async fn ctx_resolve(mm: ModelManager, cookies: &CookieJar) -> CtxExtResult {
    let res = match cookies
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
                    tracing::Span::current()
                        .set_attribute("claims.username", token_data.clone().claims.user.username);
                    Ok(token_data.claims)
                }
                Err(e) if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    let rf_tok = cookies
                        .get(REFRESH_TOKEN_KEY)
                        .map(|cookie| cookie.value().to_owned())
                        .ok_or(CtxExtError::InvalidToken)?;

                    let token_data = decode::<RefreshClaims>(&rf_tok, &KEYS.decoding, &validation)
                        .map_err(|_| CtxExtError::InvalidToken)?;

                    dbg!(&token_data);

                    tracing::Span::current()
                        .set_attribute("claims.username", token_data.clone().claims.user.username);

                    let new_access_token = get_access_token(
                        &token_data.claims.user,
                        &KEYS.encoding,
                        *ACCESS_TOKEN_EXPIRATION,
                    )
                    .map_err(|_| CtxExtError::InvalidToken)?;

                // TODO: add the new access_token into the cookies.....

                    let _ = cookies
                        .clone()
                        .add(Cookie::new(ACCESS_TOKEN_KEY, new_access_token.clone()));

                    tracing::warn!("created new access_token, using refresh token old one expired");

                    Ok(
                        decode::<AccessClaims>(&new_access_token, &KEYS.decoding, &validation)
                            .map_err(|_| CtxExtError::CannotDecodeToken)?
                            .claims,
                    )
                }
                Err(e) => {
                    tracing::error!(error.kind = ?e.kind(), "encountered error decoding / validating access jwt");

                    Err(CtxExtError::InvalidToken)
                }
            }
        }
        None => Err(CtxExtError::InvalidToken),
    };

    // -- Create CtxExtResult
    match res {
        Ok(claim) => Ctx::new(&claim.user)
            .map(CtxW)
            .map_err(|ex| CtxExtError::CtxCreateFail(ex.to_string())),
        Err(e) => Err(e),
    }
}

// region:    --- Ctx Extractor
#[derive(Debug, Clone)]
pub struct CtxW(pub Ctx);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for CtxW {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        tracing::debug!("{:<12} - Ctx", "EXTRACTOR");
        parts
            .extensions
            .get::<CtxExtResult>()
            .ok_or(Error::CtxExt(CtxExtError::CtxNotInRequestExt))?
            .clone()
            .map_err(Error::CtxExt)
    }
}
// endregion: --- Ctx Extractor

// region:    --- Ctx Extractor Result/Error
type CtxExtResult = core::result::Result<CtxW, CtxExtError>;

#[derive(Clone, Serialize, Debug)]
pub enum CtxExtError {
    TokenNotInCookie,
    InvalidToken,
    CannotEncodeToken,
    CannotDecodeToken,

    UserNotFound,
    ModelAccessError(String),
    FailValidate,
    CannotSetTokenCookie,

    CtxNotInRequestExt,
    CtxCreateFail(String),
}
// endregion: --- Ctx Extractor Result/Error

// #[cfg(test)]
// mod tests {
//     use jsonwebtoken::decode;
//     use jsonwebtoken::Validation;
//     use lib_core::ctx::UserInfo;
//     use rstest::rstest;
//     use uuid::Uuid;

//     #[rstest]
//     #[case(
//         "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjp7ImlkIjoiOTk2ZDkwMzUtMzRlNy00YzZmLWE1MjUtOTUyZGI4NDI4ODc2IiwidXNlcm5hbWUiOiJ1bmFtZSIsImRpc3BsYXlOYW1lIjoiVXNlciBOYW1lcnNvbiIsInJlZnJlc2hUb2tlblZlcnNpb24iOjB9LCJleHAiOjE3MjIxOTg2OTJ9.sk8eb1Y70HArDCtHhGXRwtz627I9nuGUU0K0pX5t6uk",
//         UserInfo::with_id(Uuid::parse_str("996d9035-34e7-4c6f-a525-952db8428876").unwrap(), "uname", "User Namerson"),
//     )]
//     fn test_try_from_jwt(#[case] input: &str, #[case] expected: UserInfo) {
//         // Arrange / Act

//         use lib_core::ctx::UserInfo;
//         let result = UserInfo::try_from(input).unwrap();

//         // Assert
//         assert_eq!(result, expected)
//     }

//     #[rstest]
//     #[case(
//         UserInfo::with_id(Uuid::parse_str("996d9035-34e7-4c6f-a525-952db8428876").unwrap(), "uname", "User Namerson"),
//     )]
//     fn test_get_access_token(#[case] input: UserInfo) {
//         // Arrange
//         let mut validation = Validation::default();
//         validation.validate_exp = false;
//         let keys = Keys::new("test_secret_key".as_bytes());

//         // Act
//         insta::assert_debug_snapshot!(decode::<AccessClaims>(
//             &input
//                 .get_access_token(&keys.encoding, chrono::Duration::seconds(1234))
//                 .unwrap(),
//             &keys.decoding,
//             &validation
//         ));
//     }

//     #[rstest]
//     #[case(
//         UserInfo::with_id(Uuid::parse_str("996d9035-34e7-4c6f-a525-952db8428876").unwrap(), "uname", "User Namerson"),
//     )]
//     fn test_get_refresh_token(#[case] input: UserInfo) {
//         // Arrange
//         let mut validation = Validation::default();
//         validation.validate_exp = false;
//         let keys = Keys::new("test_secret_key".as_bytes());

//         // Act
//         insta::assert_debug_snapshot!(decode::<AccessClaims>(
//             &input
//                 .get_refresh_token(&keys.encoding, chrono::Duration::seconds(12345))
//                 .unwrap(),
//             &keys.decoding,
//             &validation
//         ));
//     }
// }
