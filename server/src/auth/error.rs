use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidToken,
    WrongCredentials,
    TokenCreation,
    MissingCredentials,
    CtxExt,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Error::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            Error::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            Error::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            Error::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            Error::CtxExt => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to retrieve CTX"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}
