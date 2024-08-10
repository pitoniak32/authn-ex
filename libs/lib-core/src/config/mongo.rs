use mongodb::{Client, Collection};

use crate::model::{session::UserSessionModel, UserModel};

use super::env_key::APP_NAME;

pub const MONGO_DB_NAME: &str = APP_NAME;
pub const MONGO_COLL_NAME_USER_SESSIONS: &str = "user_sessions";
pub const MONGO_COLL_NAME_USERS: &str = "users";

pub async fn init_mongo(uri: &str) -> mongodb::Client {
    // TODO: add way to timeout if mongo does not connect.
    let client = mongodb::Client::with_uri_str(uri)
        .await
        .expect("failed to connect");

    client
        .database(MONGO_DB_NAME)
        .collection::<UserModel>(MONGO_COLL_NAME_USERS)
        .create_index(
            mongodb::IndexModel::builder()
                .keys(mongodb::bson::doc! { "username": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .build(),
                )
                .build(),
        )
        .await
        .unwrap_or_else(|e| {
            dbg!(&e);
            panic!("creating database index for {MONGO_COLL_NAME_USERS} should succeed")
        });

    client
        .database(MONGO_DB_NAME)
        .collection::<UserSessionModel>(MONGO_COLL_NAME_USER_SESSIONS)
        .create_index(
            mongodb::IndexModel::builder()
                .keys(mongodb::bson::doc! { "user_id": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(false)
                        .build(),
                )
                .build(),
        )
        .await
        .unwrap_or_else(|e| {
            dbg!(&e);
            panic!("creating database index for {MONGO_COLL_NAME_USER_SESSIONS} should succeed")
        });

    client
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
