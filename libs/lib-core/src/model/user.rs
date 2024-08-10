use chrono::{DateTime, Utc};
use futures::StreamExt;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;

use super::model_manager::ModelManager;
use super::{Error, Result};
pub struct UserBmc;

impl UserBmc {
    pub async fn create(ctx: &Ctx, mm: &ModelManager, user_c: UserForCreate) -> Result<ObjectId> {
        let UserForCreate {
            username,
            password,
            email,
        } = user_c;

        if !ctx.is_root() {
            return Err(Error::NonRootUserCantCreate);
        }

        if mm
            .users
            .find_one(doc! { "username": username.clone() })
            .await
            .map_err(Error::MongoDb)?
            .is_some()
        {
            return Err(Error::UserAlreadyExists { username });
        }

        let user = UserModel::new(username, password, email);

        let result = mm.users.insert_one(user.clone()).await?;

        let id = result
            .inserted_id
            .as_object_id()
            .ok_or(Error::InvalidObjectIdInserted)?;

        Ok(id)
    }

    pub async fn get_one_username(
        _ctx: &Ctx,
        mm: &ModelManager,
        username: &str,
    ) -> Result<UserModel> {
        let user = mm
            .users
            .find_one(doc! { "username": username })
            .await?
            .ok_or(Error::EntityNotFound)?;

        Ok(user)
    }

    pub async fn get_one_id(_ctx: &Ctx, mm: &ModelManager, id: &ObjectId) -> Result<UserModel> {
        let user = mm
            .users
            .find_one(doc! { "_id": id })
            .await?
            .ok_or(Error::EntityNotFound)?;

        Ok(user)
    }

    pub async fn get_all(
        _ctx: &Ctx,
        mm: &ModelManager,
        username: String,
    ) -> Result<Vec<UserModel>> {
        let users: Vec<_> = mm
            .users
            .find(doc! { "username": username.clone() })
            .await?
            .collect()
            .await;

        users
            .into_iter()
            .map(|r| r.map_err(Error::MongoDb))
            .collect::<Result<Vec<_>>>()
    }
}

/// The final product of user that will go into Database.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserModel {
    pub _id: ObjectId,
    pub username: String,
    pub password: String,
    pub email: String,
    pub session_version: u32,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub updated_at: DateTime<Utc>,
}

impl UserModel {
    pub fn new(username: String, password: String, email: String) -> Self {
        UserModel {
            _id: ObjectId::new(),
            username: username.clone(),
            password: password.clone(),
            email: email.clone(),
            session_version: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }
}

pub struct UserForCreate {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use bson::oid::ObjectId;
    use rstest::rstest;
    use similar_asserts::assert_eq;

    use crate::{
        ctx::{Ctx, UserInfo},
        model::user::{ModelManager, UserBmc, UserForCreate},
    };

    #[rstest]
    #[case(
        "bmc_user_create username_ok",
        "bmc_user_create password_ok",
        "bmc_user_create email_ok"
    )]
    async fn test_bmc_user_create_ok(
        #[case] username: &str,
        #[case] password: &str,
        #[case] email: &str,
    ) -> Result<()> {
        // Arrange

        let ctx = Ctx::new(&UserInfo::new(
            ObjectId::new(),
            "root",
            Some("test_agent".to_string()),
        ))?;
        let mm = ModelManager::new().await?;

        // Act
        let id = UserBmc::create(
            &ctx,
            &mm,
            UserForCreate {
                username: username.to_string(),
                password: password.to_string(),
                email: email.to_string(),
            },
        )
        .await
        .unwrap();

        // Assert
        let user = UserBmc::get_one_username(&ctx, &mm, username)
            .await
            .unwrap();
        assert_eq!(id, user._id);
        assert_eq!(user.username, username);
        assert_eq!(user.password, password);
        assert_eq!(user.email, email);

        Ok(())
    }
}
