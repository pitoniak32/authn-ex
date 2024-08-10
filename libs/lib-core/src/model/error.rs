use derive_more::derive::From;
use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr};

pub type Result<T> = std::result::Result<T, Error>;

#[serde_as]
#[derive(Debug, Serialize, From)]
pub enum Error {
    UserAlreadyExists {
        username: String,
    },
    NonRootUserCantCreate,

    SessionAlreadyExists,

    EntityNotFound,

    InvalidObjectIdInserted,

    #[from]
    MongoDb(#[serde_as(as = "DisplayFromStr")] mongodb::error::Error),

    #[from]
    Bson(#[serde_as(as = "DisplayFromStr")] bson::ser::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}
