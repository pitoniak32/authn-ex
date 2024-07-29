use std::str::FromStr;

use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use axum_extra::extract::CookieJar;
use futures::StreamExt;
use lib_core::{ctx::UserInfo, model::ModelManager};
use lib_web::middleware::{AccessClaims, RefreshClaims, ACCESS_TOKEN_KEY, REFRESH_TOKEN_KEY};
use mongodb::{bson::doc, Client};

use super::error::Error;

#[tracing::instrument(skip_all)]
pub async fn logout(State(mm): State<ModelManager>, jar: CookieJar) -> Result<Response, Error> {
    tracing::info!("logging user out");

    let refresh_token = jar
        .get(REFRESH_TOKEN_KEY)
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

        for session in sessions {
            match session {
                Ok(session) => {
                    if session.refresh_token == tok {
                        mm.sessions
                            .delete_one(doc! { "_id": session._id})
                            .await
                            .map_err(|_| Error::WrongCredentials)?;
                    }
                }
                Err(_) => todo!(),
            }
        }
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
