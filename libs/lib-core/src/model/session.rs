use bson::Document;
use chrono::{DateTime, Utc};
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

use crate::config::MONGO_COLL_NAME_USER_SESSIONS;
use crate::ctx::Ctx;

use super::bmc_base::base_functions::Bmc;
use super::bmc_base::{self, create, find_one};
use super::model_manager::ModelManager;
use super::{Error, Result};

pub struct UserSessionBmc;

impl Bmc for UserSessionBmc {
    const COLLECTION_NAME: &'static str = MONGO_COLL_NAME_USER_SESSIONS;
}

impl UserSessionBmc {
    pub async fn create(
        ctx: &Ctx,
        mm: &ModelManager,
        session_c: UserSessionForCreate,
    ) -> Result<ObjectId> {
        if !ctx.is_root() {
            return Err(Error::NonRootCantCreateEntity {
                collection_name: Self::COLLECTION_NAME,
            });
        }
        if find_one::<Self, _>(
            ctx,
            &mm.user_sessions,
            doc! { "user_id": &session_c.user_id, "user_agent": &session_c.user_agent },
        )
        .await
        .is_ok()
        {
            return Err(Error::EntityAlreadyExists {
                collection_name: Self::COLLECTION_NAME,
            });
        }

        let id =
            create::<Self, _>(ctx, &mm.user_sessions, UserSessionModel::from(session_c)).await?;

        Ok(id)
    }

    pub async fn get_one_id(
        ctx: &Ctx,
        mm: &ModelManager,
        id: ObjectId,
    ) -> Result<UserSessionModel> {
        bmc_base::find_one::<Self, _>(ctx, &mm.user_sessions, doc! { "_id": id }).await
    }

    pub async fn delete_one(ctx: &Ctx, mm: &ModelManager, id: ObjectId) -> Result<()> {
        bmc_base::delete_one::<Self, _>(ctx, &mm.user_sessions, doc! { "_id": id }).await
    }

    pub async fn delete_many(
        ctx: &Ctx,
        mm: &ModelManager,
        filter_document: impl Into<Document>,
    ) -> Result<u64> {
        bmc_base::delete_many::<Self, _>(ctx, &mm.users, filter_document).await
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserSessionModel {
    _id: ObjectId,
    user_id: ObjectId,
    user_agent: Option<String>,
    refresh_token: String,
    version: u32,
    expires_at_unix_sec: usize,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    created_at: DateTime<Utc>,
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    evaluated_at: DateTime<Utc>,
}

impl UserSessionModel {
    pub fn new(
        user_id: &ObjectId,
        user_agent: Option<String>,
        refresh_token: impl Into<String>,
        version: u32,
        expires_at_unix_sec: usize,
    ) -> Self {
        UserSessionModel {
            _id: ObjectId::new(),
            user_id: *user_id,
            user_agent,
            refresh_token: refresh_token.into(),
            version,
            expires_at_unix_sec,
            created_at: chrono::Utc::now(),
            evaluated_at: chrono::Utc::now(),
        }
    }
}

impl From<UserSessionForCreate> for UserSessionModel {
    fn from(value: UserSessionForCreate) -> Self {
        UserSessionModel::new(
            &value.user_id,
            value.user_agent,
            value.refresh_token,
            value.version,
            value.expires_at_unix_secs,
        )
    }
}

pub struct UserSessionForCreate {
    pub user_id: ObjectId,
    pub user_agent: Option<String>,
    pub refresh_token: String,
    pub version: u32,
    pub expires_at_unix_secs: usize,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use bson::oid::ObjectId;
    use rstest::*;
    use serial_test::serial;
    use similar_asserts::assert_eq;

    use crate::{ctx::Ctx, model::model_manager::ModelManager};

    use super::{UserSessionBmc, UserSessionForCreate};

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
    async fn create_test_user_session(
        #[default(ObjectId::new())] user_id: ObjectId,
        #[default("create_test_user_session_default-user_agent")] user_agent: String,
        #[default("create_test_user_session_default-refresh_token")] refresh_token: impl Into<String>,
        #[default(0)] version: u32,
        #[default(133769420)] expires_at_unix_secs: usize,
        #[future] fx_mm: ModelManager,
        fx_root_ctx: Ctx,
    ) -> ObjectId {
        UserSessionBmc::create(
            &fx_root_ctx,
            &fx_mm.await,
            UserSessionForCreate {
                user_id,
                user_agent: Some(user_agent),
                refresh_token: refresh_token.into(),
                version,
                expires_at_unix_secs,
            },
        )
        .await
        .unwrap_or_else(|_| {
            panic!("fixture user_session '{user_id:?}' should be created successfully")
        })
    }

    #[rstest]
    #[serial]
    #[tokio::test]
    async fn test_bmc_user_session_get_one_id_ok(
        #[future] create_test_user_session: ObjectId,
        #[future] fx_mm: ModelManager,
        fx_root_ctx: Ctx,
    ) -> Result<()> {
        // Arrange
        let mm = fx_mm.await;
        let test_user_session_id = create_test_user_session.await;

        // Act
        let user_session = UserSessionBmc::get_one_id(&fx_root_ctx, &mm, test_user_session_id)
            .await
            .unwrap();

        // Assert
        assert_eq!(test_user_session_id, user_session._id);

        // Cleanup
        UserSessionBmc::delete_one(&fx_root_ctx, &mm, test_user_session_id).await?;

        Ok(())
    }
}
