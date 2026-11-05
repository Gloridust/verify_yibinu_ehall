//! 宜宾学院统一身份认证 (wisedu authserver) 登录验证。
//!
//! * 账号密码登录（`cllt=userNameLogin`），含图形验证码
//! * 短信验证码登录（`cllt=dynamicLogin`）
//! * 滑块验证码（`captchaSwitch=2`）无法自动完成，会返回明确错误
//!
//! 验证码需要由调用方展示给用户并取得答案，本库不做识别。
//!
//! ```no_run
//! use yibinu_auth::{Client, Config, AuthError};
//!
//! let client = Client::new(Config::default())?;
//! client.load_login_page()?;
//! let result = match client.login_with_password("230110128", "secret", None) {
//!     Err(AuthError::CaptchaRequired) => {
//!         let image = client.fetch_captcha()?;          // 展示给用户
//!         let answer = "ab12";                           // 用户输入
//!         client.login_with_password("230110128", "secret", Some(answer))?
//!     }
//!     other => other?,
//! };
//! println!("{} {}", result.success, result.message);
//! # Ok::<(), AuthError>(())
//! ```

mod client;
pub mod crypto;
mod error;
pub mod page;
mod proxy;
mod tls;

pub use client::{
    Client, Config, LoginResult, SmsResult, DEFAULT_BASE_URL, DEFAULT_FRONT_BACK_KEY,
    DEFAULT_SERVICE,
};
pub use crypto::encrypt_password;
pub use error::{AuthError, Result};
pub use page::{LoginForm, LoginPage};
