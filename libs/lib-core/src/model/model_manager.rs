use mongodb::Collection;

use crate::config::{
    env_key::config,
    mongo::{get_sessions_collection, get_users_collection, init_mongo},
};

use super::{session::UserSessionModel, UserModel};

use super::Result;

#[derive(Debug, Clone)]
pub struct ModelManager {
    pub users: Collection<UserModel>,
    pub sessions: Collection<UserSessionModel>,
}

impl ModelManager {
    pub async fn new() -> Result<Self> {
        let client = init_mongo(&config().MONGO_DB_URI).await;

        let users = get_users_collection(&client);
        let sessions = get_sessions_collection(&client);

        Ok(ModelManager { users, sessions })
    }
}
