use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form,
};
use lib_core::{
    ctx::{Ctx, UserInfo},
    model::{
        model_manager::ModelManager,
        session::{SessionForCreate, UserSessionBmc},
        UserBmc,
    },
    token::{
        get_access_token, get_refresh_token, get_token_cookie,
        keys::{ACCESS_TOKEN_EXPIRATION, KEYS, REFRESH_TOKEN_EXPIRATION},
        COOKIE_ACCESS_TOKEN_KEY, COOKIE_REFRESH_TOKEN_KEY,
    },
};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use super::error::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DtoUserLogin {
    pub username: String,
    pub password: String,
}

#[tracing::instrument(skip_all)]
#[axum::debug_handler]
pub async fn login(
    mm: State<ModelManager>,
    headers: HeaderMap,
    user_form: Form<DtoUserLogin>,
) -> Result<Response, Error> {
    // Check if the user sent the credentials
    if user_form.username.is_empty() || user_form.password.is_empty() {
        return Err(Error::MissingCredentials);
    }

    let user_agent = headers
        .get("user-agent")
        .and_then(|agent| agent.to_str().ok())
        .map(String::from);

    let user_model = UserBmc::get_one_username(&Ctx::root_ctx(), &mm, &user_form.username)
        .await
        .unwrap();

    if user_form.password != user_model.password {
        return Err(Error::WrongCredentials);
    }

    let user = UserInfo::new(user_model._id, user_model.username, user_agent.clone());

    let access_token = get_access_token(&user, &KEYS.encoding, *ACCESS_TOKEN_EXPIRATION)
        .map_err(|_| Error::TokenCreation)?;
    let refresh_token = get_refresh_token(&user, &KEYS.encoding, *REFRESH_TOKEN_EXPIRATION)
        .map_err(|_| Error::TokenCreation)?;

    UserSessionBmc::create(
        &Ctx::root_ctx(),
        &mm,
        SessionForCreate {
            user_id: user_model._id,
            user_agent,
            refresh_token: refresh_token.clone(),
            version: user_model.session_version,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!("{e:?}");
        Error::WrongCredentials
    })?;

    tracing::debug!("added new session to current user");

    // Send the authorized token
    build_login_response(access_token, refresh_token)
}

fn build_login_response(access_token: String, refresh_token: String) -> Result<Response, Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            "Set-Cookie",
            get_token_cookie(access_token, COOKIE_ACCESS_TOKEN_KEY).to_string(),
        )
        .header(
            "Set-Cookie",
            get_token_cookie(refresh_token, COOKIE_REFRESH_TOKEN_KEY).to_string(),
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
