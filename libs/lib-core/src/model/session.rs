use chrono::{DateTime, Utc};
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;

use super::model_manager::ModelManager;
use super::{Error, Result};

pub struct UserSessionBmc;

impl UserSessionBmc {
    pub async fn create(
        ctx: &Ctx,
        mm: &ModelManager,
        session_c: SessionForCreate,
    ) -> Result<ObjectId> {
        let SessionForCreate {
            user_id,
            user_agent,
            refresh_token,
            version,
        } = session_c;

        if !ctx.is_root() {
            return Err(Error::NonRootUserCantCreate);
        }

        if mm
            .sessions
            .find_one(doc! { "user_id": user_id, "user_agent": user_agent.clone(), })
            .await
            .map_err(Error::MongoDb)?
            .is_some()
        {
            return Err(Error::SessionAlreadyExists);
        }

        let session = UserSessionModel::new(&user_id, user_agent, refresh_token, version);

        let result = mm.sessions.insert_one(session).await?;

        let id = result
            .inserted_id
            .as_object_id()
            .ok_or(Error::InvalidObjectIdInserted)?;

        Ok(id)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserSessionModel {
    _id: ObjectId,
    user_id: ObjectId,
    user_agent: Option<String>,
    refresh_token: String,
    version: u32,
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
    ) -> Self {
        UserSessionModel {
            _id: ObjectId::new(),
            user_id: *user_id,
            user_agent,
            refresh_token: refresh_token.into(),
            version,
            created_at: chrono::Utc::now(),
            evaluated_at: chrono::Utc::now(),
        }
    }
}

pub struct SessionForCreate {
    pub user_id: ObjectId,
    pub user_agent: Option<String>,
    pub refresh_token: String,
    pub version: u32,
}

#[cfg(test)]
mod tests {}
