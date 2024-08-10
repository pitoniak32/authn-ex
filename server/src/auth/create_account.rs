use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};
use lib_core::{
    ctx::Ctx,
    model::{Bmc, ModelManager, UserBmc, UserForCreate},
};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use super::error::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DtoUserCreateAccount {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[tracing::instrument(skip_all)]
pub async fn create_account(
    mm: State<ModelManager>,
    user_form: Form<DtoUserCreateAccount>,
) -> Result<Response, Error> {
    if user_form.username.is_empty() || user_form.password.is_empty() || user_form.email.is_empty()
    {
        return Err(Error::MissingCredentials);
    }

    let result = UserBmc::create(
        &Ctx::root_ctx(),
        &mm,
        UserForCreate {
            username: user_form.username.clone(),
            password: user_form.password.clone(),
            email: user_form.email.clone(),
        },
    )
    .await;

    match result {
        Ok(new_user_id) => Ok((
            StatusCode::ACCEPTED,
            format!("User was created: {new_user_id:?}"),
        )
            .into_response()),
        Err(lib_core::model::Error::EntityAlreadyExists {
            collection_name: UserBmc::COLLECTION_NAME,
        }) => Ok((StatusCode::BAD_REQUEST, "User already exists").into_response()),
        Err(_) => todo!(),
    }
}
