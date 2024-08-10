use mongodb::{Client, Collection};

use crate::model::{UserModel, UserSessionModel};

use super::get_config;

pub const MONGO_COLL_NAME_USER_SESSIONS: &str = "user_sessions";
pub const MONGO_COLL_NAME_USERS: &str = "users";

pub async fn init_mongo() -> mongodb::Client {
    // TODO: add way to timeout if mongo does not connect.
    let client = mongodb::Client::with_uri_str(&get_config().MONGO_DB_URI)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "failed to connect to mongo with uri: {}",
                get_config().MONGO_DB_URI
            )
        });

    client
        .database(&get_config().MONGO_DB_NAME)
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
        .database(&get_config().MONGO_DB_NAME)
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
        .database(&get_config().MONGO_DB_NAME)
        .collection(MONGO_COLL_NAME_USERS)
}

pub fn get_sessions_collection(client: &Client) -> Collection<UserSessionModel> {
    client
        .database(&get_config().MONGO_DB_NAME)
        .collection(MONGO_COLL_NAME_USER_SESSIONS)
}
