use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::distributions::{Alphanumeric, DistString};
use std::sync::LazyLock;

pub static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 60);
    Keys::new(secret.as_bytes())
});

pub static ACCESS_TOKEN_EXPIRATION: LazyLock<chrono::Duration> =
    LazyLock::new(|| chrono::Duration::seconds(5));

pub static REFRESH_TOKEN_EXPIRATION: LazyLock<chrono::Duration> =
    LazyLock::new(|| chrono::Duration::seconds(10));

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}
