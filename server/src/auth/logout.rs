use std::str::FromStr;

use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use futures::StreamExt;
use lib_core::{
    model::model_manager::ModelManager,
    token::{claims::RefreshClaims, COOKIE_ACCESS_TOKEN_KEY, COOKIE_REFRESH_TOKEN_KEY},
};
use mongodb::bson::doc;
use tower_cookies::Cookies;

use super::error::Error;

#[tracing::instrument(skip_all)]
pub async fn logout(State(mm): State<ModelManager>, jar: Cookies) -> Result<Response, Error> {
    tracing::debug!("logging user out");

    let refresh_token = jar
        .get(COOKIE_REFRESH_TOKEN_KEY)
        .map(|cookie| cookie.value().to_owned());

    if let Some(tok) = refresh_token {
        let refresh_claims =
            RefreshClaims::from_str(tok.as_str()).map_err(|_| Error::InvalidToken)?;

        let sessions: Vec<_> = mm
            .sessions
            .find(doc! { "username": refresh_claims.user.username })
            .await
            .map_err(|_| Error::WrongCredentials)?
            .collect()
            .await;

        for session in sessions {}
    } else {
        return Ok((
            StatusCode::BAD_REQUEST,
            "No credentials found in request, you are already logged out!",
        )
            .into_response());
    }

    build_logout_response()
}

fn build_logout_response() -> Result<Response, Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            "Set-Cookie",
            format!(
                "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=999999{}",
                COOKIE_ACCESS_TOKEN_KEY, "invalidated", ""
            ),
        )
        .header(
            "Set-Cookie",
            format!(
                "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=999999{}",
                COOKIE_REFRESH_TOKEN_KEY, "invalidated", ""
            ),
        )
        .body(Body::empty())
        .map_err(|_err| Error::TokenCreation)?
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::build_logout_response;

    #[test]
    fn test_build_logout_response() {
        // Arrange / Act
        let result = build_logout_response();

        // Assert
        insta::assert_debug_snapshot!(result)
    }
}
