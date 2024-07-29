use mongodb::{bson::oid::ObjectId, Client, Collection};
use serde::{Deserialize, Serialize};

use crate::model::UserModel;

use super::env_key::APP_NAME;

pub const MONGO_DB_NAME: &str = APP_NAME;
pub const MONGO_COLL_NAME_USER_SESSIONS: &str = "user_sessions";
pub const MONGO_COLL_NAME_USERS: &str = "users";

/// The final product of user that will go into Database.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserSessionModel {
    pub _id: ObjectId,
    pub user_id: ObjectId,
    pub device: String,
    pub refresh_token: String,
    pub created_at: mongodb::bson::DateTime,
    pub updated_at: mongodb::bson::DateTime,
}

pub async fn init_mongo(uri: &str) -> mongodb::Client {
    // TODO: add way to timeout if mongo does not connect.
    let client = mongodb::Client::with_uri_str(uri)
        .await
        .expect("failed to connect");

    register_collection::<UserModel>(&client, MONGO_COLL_NAME_USERS, "username").await;
    register_collection::<UserSessionModel>(&client, MONGO_COLL_NAME_USER_SESSIONS, "user_id")
        .await;

    client
}

pub async fn register_collection<T>(
    client: &mongodb::Client,
    collection_name: &str,
    index_key: &str,
) where
    T: Send + Sync,
{
    let options = mongodb::options::IndexOptions::builder()
        .unique(true)
        .build();

    let index = mongodb::IndexModel::builder()
        .keys(mongodb::bson::doc! { index_key: 1 })
        .options(options.clone())
        .build();

    client
        .database(MONGO_DB_NAME)
        .collection::<T>(collection_name)
        .create_index(index)
        .await
        .expect(&format!(
            "creating database index for {collection_name} should succeed"
        ));
}

pub fn get_users_collection(client: &Client) -> Collection<UserModel> {
    client
        .database(MONGO_DB_NAME)
        .collection(MONGO_COLL_NAME_USERS)
}

pub fn get_sessions_collection(client: &Client) -> Collection<UserSessionModel> {
    client
        .database(MONGO_DB_NAME)
        .collection(MONGO_COLL_NAME_USER_SESSIONS)
}
