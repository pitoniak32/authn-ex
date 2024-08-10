use std::str::FromStr;

use base64::prelude::*;
use jsonwebtoken::{encode, Header};
use serde::{Deserialize, Serialize};

use crate::ctx::UserInfo;

use super::{
    error::Error,
    keys::{ACCESS_TOKEN_EXPIRATION, KEYS, REFRESH_TOKEN_EXPIRATION},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub user: UserInfo,
    pub exp: usize,
}

impl AccessClaims {
    pub fn new(user: UserInfo) -> Self {
        AccessClaims {
            user,
            exp: (chrono::Utc::now().naive_utc() + *ACCESS_TOKEN_EXPIRATION)
                .and_utc()
                .timestamp() as usize,
        }
    }

    pub fn tokenize(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let access_token = encode(&Header::default(), self, &KEYS.encoding)?;

        Ok(access_token)
    }
}

impl FromStr for AccessClaims {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts = s.split(".").collect::<Vec<&str>>();
        let claims = parts.get(1).ok_or(Error::InvalidAccessToken)?;
        let decoded = String::from_utf8(
            BASE64_STANDARD_NO_PAD
                .decode(claims)
                .map_err(Error::Base64)?,
        )
        .map_err(Error::FromUtf8)?;
        serde_json::from_str::<AccessClaims>(&decoded)
            .map_err(|_| Error::CouldNotDeserializeAccessClaim)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub user: UserInfo,
    pub version: u16,
    pub exp: usize,
}

impl RefreshClaims {
    pub fn new(user: UserInfo) -> Self {
        RefreshClaims {
            user: user.clone(),
            version: 0,
            exp: (chrono::Utc::now().naive_utc() + *REFRESH_TOKEN_EXPIRATION)
                .and_utc()
                .timestamp() as usize,
        }
    }

    pub fn tokenize(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let access_token = encode(&Header::default(), self, &KEYS.encoding)?;

        Ok(access_token)
    }
}

impl FromStr for RefreshClaims {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts = s.split(".").collect::<Vec<&str>>();
        let claims = parts.get(1).ok_or(Error::InvalidAccessToken)?;
        let decoded = String::from_utf8(
            BASE64_STANDARD_NO_PAD
                .decode(claims)
                .map_err(Error::Base64)?,
        )
        .map_err(Error::FromUtf8)?;
        serde_json::from_str::<RefreshClaims>(&decoded)
            .map_err(|_| Error::CouldNotDeserializeRefreshClaim)
    }
}
