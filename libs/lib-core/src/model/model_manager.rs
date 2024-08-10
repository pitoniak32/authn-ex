use mongodb::Collection;

use crate::config::{get_sessions_collection, get_users_collection, init_mongo};

use super::{session::UserSessionModel, Result, UserModel};

#[derive(Debug, Clone)]
pub struct ModelManager {
    pub users: Collection<UserModel>,
    pub user_sessions: Collection<UserSessionModel>,
}

impl ModelManager {
    pub async fn new() -> Result<Self> {
        let client = init_mongo().await;

        let users = get_users_collection(&client);
        let sessions = get_sessions_collection(&client);

        Ok(ModelManager {
            users,
            user_sessions: sessions,
        })
    }
}
