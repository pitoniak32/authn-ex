use axum::{
    async_trait,
    body::Body,
    extract::{FromRequestParts, Request, State},
    http::request::Parts,
    middleware::Next,
    response::Response,
};

use jsonwebtoken::{decode, Validation};
use lib_core::{
    ctx::Ctx,
    model::ModelManager,
    token::{
        get_token_cookie, AccessClaims, RefreshClaims, COOKIE_ACCESS_TOKEN_KEY,
        COOKIE_REFRESH_TOKEN_KEY, KEYS,
    },
};
use serde::Serialize;
use tower_cookies::{cookie::CookieBuilder, Cookie, Cookies};

use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::{Error, Result};

#[tracing::instrument(level = "debug", skip_all, err)]
pub async fn ctx_require(ctx: Result<CtxW>, req: Request<Body>, next: Next) -> Result<Response> {
    tracing::debug!("checking for Ctx");

    ctx?;

    Ok(next.run(req).await)
}

// IMPORTANT: This resolver must never fail, but rather capture the potential Auth error and put in in the
//            request extension as CtxExtResult.
//            This way it won't prevent downstream middleware to be executed, and will still capture the error
//            for the appropriate middleware (.e.g., mw_ctx_require which forces successful auth) or handler
//            to get the appropriate information.

#[tracing::instrument(skip_all)]
pub async fn mw_ctx_resolver(
    State(mm): State<ModelManager>,
    cookies: Cookies,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let ctx_ext_result = ctx_resolve(mm, &cookies).await;

    if ctx_ext_result.is_err() && !matches!(ctx_ext_result, Err(CtxExtError::TokenNotInCookie)) {
        tracing::debug!("removing access_token, and refresh_token from cookies");
        cookies.remove(
            CookieBuilder::from(Cookie::from(COOKIE_ACCESS_TOKEN_KEY))
                .path("/")
                .build(),
        );
        cookies.remove(
            CookieBuilder::from(Cookie::from(COOKIE_REFRESH_TOKEN_KEY))
                .path("/")
                .build(),
        );
    }

    // Store the ctx_ext_result in the request extension
    // (for Ctx extractor).
    req.extensions_mut().insert(ctx_ext_result);

    next.run(req).await
}

#[tracing::instrument(skip_all)]
async fn ctx_resolve(mm: ModelManager, cookies: &Cookies) -> CtxExtResult {
    // Check access token
    let access_token = cookies
        .get(COOKIE_ACCESS_TOKEN_KEY)
        .map(|cookie| cookie.value().to_owned())
        .ok_or(CtxExtError::TokenNotInCookie)?;

    // If access_token is good return
    tracing::debug!("cookie contained access_token");

    // Decode the user data
    let mut validation = Validation::default();
    validation.leeway = 5;
    let decode_result = decode::<AccessClaims>(&access_token, &KEYS.decoding, &validation);

    match decode_result {
        Ok(token_data) => {
            tracing::debug!("access_token was valid");
            tracing::Span::current()
                .set_attribute("claims.username", token_data.clone().claims.user.username);
            Ok(Ctx::new(&token_data.claims.user)
                .map(CtxW)
                .map_err(|ex| CtxExtError::CtxCreateFail(ex.to_string()))?)
        }
        Err(e) if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            tracing::debug!("access_token was expired");

            mm.user_sessions;

            let rf_tok = cookies
                .get(COOKIE_REFRESH_TOKEN_KEY)
                .map(|cookie| cookie.value().to_owned())
                .ok_or(CtxExtError::TokenNotInCookie)?;

            let refresh_token_data =
                match decode::<RefreshClaims>(&rf_tok, &KEYS.decoding, &validation) {
                    Ok(refresh_token_data) => Ok(refresh_token_data),
                    Err(e) if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        tracing::debug!("refresh_token was expired, user must login");
                        Err(CtxExtError::ExpiredRefreshToken)
                    }
                    Err(e) => {
                        tracing::debug!(error.kind = ?e.kind(), "refresh_token was invalid");
                        Err(CtxExtError::InvalidRefreshToken)
                    }
                }?;

            tracing::debug!("using refresh_token to generate new access_token");
            // tracing::Span::current()
            //     .set_attribute("claims.username", token_data.clone().claims.user.username);

            let new_access_token = AccessClaims::new(refresh_token_data.claims.user.clone())
                .tokenize()
                .map_err(|_| CtxExtError::InvalidAccessToken)?;

            tracing::debug!("adding new access_token cookie");

            cookies.add(get_token_cookie(new_access_token, COOKIE_ACCESS_TOKEN_KEY));

            Ok(Ctx::new(&refresh_token_data.claims.user)
                .map(CtxW)
                .map_err(|ex| CtxExtError::CtxCreateFail(ex.to_string()))?)
        }
        Err(e) => {
            tracing::debug!(error.kind = ?e.kind(), "access_token was invalid");

            Err(CtxExtError::InvalidAccessToken)
        }
    }
}

// region:    --- Ctx Extractor
#[derive(Debug, Clone)]
pub struct CtxW(pub Ctx);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for CtxW {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
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

    InvalidAccessToken,
    InvalidRefreshToken,

    ExpiredAccessToken,
    ExpiredRefreshToken,

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
