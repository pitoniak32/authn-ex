use bson::Document;
use chrono::{DateTime, Utc};
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

use crate::config::MONGO_COLL_NAME_USERS;
use crate::ctx::Ctx;

use super::bmc_base::{create, delete_many, delete_one, find_all, find_many, find_one, Bmc};
use super::model_manager::ModelManager;
use super::{Error, Result};

pub struct UserBmc;

impl Bmc for UserBmc {
    const COLLECTION_NAME: &'static str = MONGO_COLL_NAME_USERS;
}

impl UserBmc {
    pub async fn create(ctx: &Ctx, mm: &ModelManager, user_c: UserForCreate) -> Result<ObjectId> {
        if find_one::<Self, _>(ctx, &mm.users, doc! { "username": &user_c.username })
            .await
            .is_ok()
        {
            return Err(Error::EntityAlreadyExists {
                collection_name: Self::COLLECTION_NAME,
            });
        }

        let id = create::<Self, _>(ctx, &mm.users, UserModel::from(user_c)).await?;

        Ok(id)
    }

    pub async fn find_one_username(
        ctx: &Ctx,
        mm: &ModelManager,
        username: &str,
    ) -> Result<UserModel> {
        find_one::<Self, _>(ctx, &mm.users, doc! {"username": username}).await
    }

    pub async fn find_one_id(ctx: &Ctx, mm: &ModelManager, id: &ObjectId) -> Result<UserModel> {
        find_one::<Self, _>(ctx, &mm.users, doc! { "_id": id }).await
    }

    pub async fn find_many(
        ctx: &Ctx,
        mm: &ModelManager,
        filter_document: impl Into<Document>,
    ) -> Result<Vec<UserModel>> {
        find_many::<Self, _>(ctx, &mm.users, filter_document).await
    }

    pub async fn find_all(ctx: &Ctx, mm: &ModelManager) -> Result<Vec<UserModel>> {
        find_all::<Self, _>(ctx, &mm.users).await
    }

    pub async fn delete_one(ctx: &Ctx, mm: &ModelManager, username: String) -> Result<()> {
        delete_one::<Self, _>(ctx, &mm.users, doc! { "username": username }).await
    }

    pub async fn delete_many(
        ctx: &Ctx,
        mm: &ModelManager,
        filter_document: impl Into<Document>,
    ) -> Result<u64> {
        delete_many::<Self, _>(ctx, &mm.users, filter_document).await
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

impl From<UserForCreate> for UserModel {
    fn from(value: UserForCreate) -> Self {
        UserModel::new(value.username, value.password, value.email)
    }
}

pub struct UserForCreate {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::Result;
    use bson::oid::ObjectId;
    use rstest::*;
    use serial_test::serial;
    use similar_asserts::assert_eq;

    use crate::{
        ctx::Ctx,
        model::{
            bmc_base::base_functions::Bmc,
            user::{ModelManager, UserBmc, UserForCreate},
            Error,
        },
    };

    #[rstest::fixture]
    fn fx_root_ctx() -> Ctx {
        Ctx::root_ctx()
    }

    #[rstest::fixture]
    async fn fx_mm() -> ModelManager {
        ModelManager::new()
            .await
            .expect("fixture ModelManager can be created")
    }

    #[rstest::fixture]
    async fn fx_create_test_user(
        #[default("create_test_user_default-username")] username: impl Into<String>,
        #[default("create_test_user_default-password")] password: impl Into<String>,
        #[default("create_test_user_default-email")] email: impl Into<String>,
        #[future] fx_mm: ModelManager,
        fx_root_ctx: Ctx,
    ) -> ObjectId {
        let username = username.into();

        UserBmc::create(
            &fx_root_ctx,
            &fx_mm.await,
            UserForCreate {
                username: username.clone(),
                password: password.into(),
                email: email.into(),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("fixture user '{username}' should be created successfully"))
    }

    #[rstest::fixture]
    async fn fx_create_test_users(
        #[default(1)] user_count: usize,
        #[future] fx_mm: ModelManager,
        fx_root_ctx: Ctx,
    ) -> Vec<String> {
        let mut ids = vec![];
        let mm_arc = Arc::new(fx_mm.await);

        for i in 0..user_count {
            let username = format!("test_user-username-{i}");
            let _ = UserBmc::create(
                &fx_root_ctx,
                &mm_arc,
                UserForCreate {
                    username: username.clone(),
                    password: format!("test_user-password-{i}"),
                    email: format!("test_user-email-{i}"),
                },
            )
            .await
            .unwrap_or_else(|_| panic!("fixture user '{username}' should be created successfully"));
            ids.push(username.clone());
        }

        ids
    }

    #[rstest]
    #[case(
        "bmc_user_create username_ok",
        "bmc_user_create password_ok",
        "bmc_user_create email_ok"
    )]
    #[serial]
    #[tokio::test]
    async fn test_bmc_user_create_ok(
        #[future] fx_mm: ModelManager,
        fx_root_ctx: Ctx,
        #[case] username: &str,
        #[case] password: &str,
        #[case] email: &str,
    ) -> Result<()> {
        // Arrange
        let mm = fx_mm.await;

        // Act
        let id = UserBmc::create(
            &fx_root_ctx,
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
        let user = UserBmc::find_one_username(&fx_root_ctx, &mm, username)
            .await
            .unwrap();
        assert_eq!(id, user._id);
        assert_eq!(user.username, username);
        assert_eq!(user.password, password);
        assert_eq!(user.email, email);

        // Cleanup
        assert!(
            UserBmc::delete_one(&fx_root_ctx, &mm, username.to_string())
                .await
                .is_ok(),
            "cleanup should succeed"
        );

        Ok(())
    }

    #[rstest]
    #[case(
        "bmc_user_get_one_username username_ok",
        "bmc_user_get_one_username password_ok",
        "bmc_user_get_one_username email_ok"
    )]
    #[serial]
    #[tokio::test]
    async fn test_bmc_user_get_one_username_ok(
        #[case] username: &str,
        #[case] password: &str,
        #[case] email: &str,
        #[future]
        #[with(username, password, email)]
        fx_create_test_user: ObjectId,
        #[future] fx_mm: ModelManager,
        fx_root_ctx: Ctx,
    ) -> Result<()> {
        // Arrange
        let mm = fx_mm.await;
        let test_user_id = fx_create_test_user.await;

        // Act
        let user = UserBmc::find_one_username(&fx_root_ctx, &mm, username)
            .await
            .unwrap();

        // Assert
        assert_eq!(test_user_id, user._id);
        assert_eq!(user.username, username);
        assert_eq!(user.password, password);
        assert_eq!(user.email, email);

        // Cleanup
        UserBmc::delete_one(&fx_root_ctx, &mm, username.to_string()).await?;

        Ok(())
    }

    #[rstest]
    #[serial]
    #[tokio::test]
    async fn test_get_all_users(
        #[future]
        #[with(3)]
        fx_create_test_users: Vec<String>,
        #[future] fx_mm: ModelManager,
        fx_root_ctx: Ctx,
    ) -> Result<()> {
        // Arrange
        let mm = fx_mm.await;
        let fx_usernames = fx_create_test_users.await;

        // Act
        let users = UserBmc::find_all(&fx_root_ctx, &mm)
            .await
            .expect("cleanup can delete user model");

        // Adjust
        let users = users
            .iter()
            .filter(|u| u.username.contains("test_user"))
            .collect::<Vec<_>>();

        // Assert
        assert_eq!(users.len(), 3);

        // Cleanup
        for username in fx_usernames {
            UserBmc::delete_one(&fx_root_ctx, &mm, username).await?;
        }

        Ok(())
    }

    #[rstest]
    #[case(
        "bmc_user_delete_ok-username",
        "bmc_user_delete_ok-password",
        "bmc_user_delete_ok-email"
    )]
    #[serial]
    #[tokio::test]
    async fn test_bmc_user_delete_ok(
        #[case] username: &str,
        #[allow(unused_variables)]
        #[case]
        password: &str,
        #[allow(unused_variables)]
        #[case]
        email: &str,
        #[future]
        #[with(username, password, email)]
        fx_create_test_user: ObjectId,
        #[future] fx_mm: ModelManager,
        fx_root_ctx: Ctx,
    ) -> Result<()> {
        // Arrange
        let mm = fx_mm.await;
        let _ = fx_create_test_user.await;

        // Act
        let deleted_result = UserBmc::delete_one(&fx_root_ctx, &mm, username.to_string()).await;

        // Assert
        assert!(deleted_result.is_ok());
        assert!(matches!(
            UserBmc::find_one_username(&fx_root_ctx, &mm, username).await,
            Err(Error::EntityNotFound {
                collection_name: UserBmc::COLLECTION_NAME
            })
        ));

        Ok(())
    }
}
