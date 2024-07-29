// region:    --- Modules
mod error;

use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

pub use self::error::{Error, Result};

// endregion: --- Modules

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ctx {
    user: UserInfo,
    is_root: bool,
}

// Constructors.
impl Ctx {
    pub fn root_ctx() -> Self {
        Ctx {
            user: UserInfo::new(ObjectId::new(), "root"),
            is_root: true,
        }
    }

    pub fn new(user: &UserInfo) -> Result<Self> {
        Ok(Self {
            user: user.clone(),
            is_root: false,
        })
    }
}

// Property Accessors.
impl Ctx {
    pub fn user(&self) -> UserInfo {
        self.user.clone()
    }

    pub fn is_root(&self) -> bool {
        self.is_root
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub id: ObjectId,
    pub username: String,
}

impl UserInfo {
    pub fn new(id: impl Into<ObjectId>, username: impl Into<String>) -> Self {
        UserInfo {
            id: id.into(),
            username: username.into(),
        }
    }
}
