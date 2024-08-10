use tower_cookies::{cookie::time::Duration, Cookie};

use crate::config::get_config;

pub const COOKIE_ACCESS_TOKEN_KEY: &str = "ACCESS_TOKEN";
pub const COOKIE_REFRESH_TOKEN_KEY: &str = "REFRESH_TOKEN";
pub const COOKIE_TOKEN_PATH: &str = "/";
pub const COOKIE_HTTP_ONLY: bool = true;
pub const COOKIE_MAX_AGE: Duration = Duration::seconds(999999);

pub fn get_token_cookie<'r>(token: impl Into<String>, key: &'static str) -> Cookie<'r> {
    let mut cookie = Cookie::new(key, token.into());
    if !get_config().DEV_MODE {
        cookie.set_secure(true)
    }
    cookie.set_path(COOKIE_TOKEN_PATH);
    cookie.set_http_only(COOKIE_HTTP_ONLY);
    cookie.set_max_age(COOKIE_MAX_AGE);
    cookie
}

#[cfg(test)]
mod tests {
    use super::get_token_cookie;

    use rstest::rstest;

    #[rstest]
    async fn test_get_token_cookie() {
        // Act
        let cookie = get_token_cookie("test_get_token_cookie ok", "TEST_ACCESS_TOKEN_KEY");

        // Assert
        insta::assert_debug_snapshot!(cookie);
    }
}
