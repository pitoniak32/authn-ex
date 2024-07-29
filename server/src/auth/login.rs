use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};
use bson::oid::ObjectId;
use lib_core::{ctx::UserInfo, model::ModelManager};
use lib_web::middleware::{
    get_access_token, get_refresh_token, ACCESS_TOKEN_EXPIRATION, ACCESS_TOKEN_KEY, KEYS,
    REFRESH_TOKEN_EXPIRATION, REFRESH_TOKEN_KEY,
};
use mongodb::{bson::doc, Client};
use serde::{Deserialize, Serialize};

use super::error::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DtoUserLogin {
    pub username: String,
    pub password: String,
}

#[tracing::instrument(skip_all)]
pub async fn login(
    State(mm): State<ModelManager>,
    user_form: Form<DtoUserLogin>,
) -> Result<Response, Error> {
    // Check if the user sent the credentials
    if user_form.username.is_empty() || user_form.password.is_empty() {
        return Err(Error::MissingCredentials);
    }

    let user = if user_form.username != "uname" {
        let user = mm
            .users
            .find_one(doc! { "username": &user_form.username })
            .await
            .map_err(|_err| Error::WrongCredentials)?
            .ok_or(Error::WrongCredentials)?;

        UserInfo::new(user._id, user.username)
    } else {
        UserInfo::new(ObjectId::new(), "uname")
    };


    let access_token = get_access_token(&user, &KEYS.encoding, *ACCESS_TOKEN_EXPIRATION)
        .map_err(|_| Error::TokenCreation)?;
    let refresh_token = get_refresh_token(&user, &KEYS.encoding, *REFRESH_TOKEN_EXPIRATION)
        .map_err(|_| Error::TokenCreation)?;

    tracing::info!("logging user in");

    // Send the authorized token
    build_login_response(access_token, refresh_token)
}

fn build_login_response(access_token: String, refresh_token: String) -> Result<Response, Error> {
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
        .map_err(|_err| Error::TokenCreation)?
        .into_response())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::build_login_response;

    #[rstest]
    #[case(
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjp7ImlkIjoiOTk2ZDkwMzUtMzRlNy00YzZmLWE1MjUtOTUyZGI4NDI4ODc2IiwidXNlcm5hbWUiOiJ1bmFtZSIsImRpc3BsYXlOYW1lIjoiVXNlciBOYW1lcnNvbiIsInJlZnJlc2hUb2tlblZlcnNpb24iOjB9LCJleHAiOjE3MjIxOTg2OTJ9.sk8eb1Y70HArDCtHhGXRwtz627I9nuGUU0K0pX5t6uk",
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjp7ImlkIjoiOTk2ZDkwMzUtMzRlNy00YzZmLWE1MjUtOTUyZGI4NDI4ODc2IiwidXNlcm5hbWUiOiJ1bmFtZSIsImRpc3BsYXlOYW1lIjoiVXNlciBOYW1lcnNvbiIsInJlZnJlc2hUb2tlblZlcnNpb24iOjB9LCJleHAiOjE3MjIxOTg2OTJ9.sk8eb1Y70HArDCtHhGXRwtz627I9nuGUU0K0pX5t6uk",
    )]
    fn test_build_login_response(#[case] access_token: String, #[case] refresh_token: String) {
        // Arrange / Act
        let result = build_login_response(access_token, refresh_token);

        // Assert
        insta::assert_debug_snapshot!(result)
    }
}
