//! Node.js 绑定（napi-rs）。网络请求在 libuv 线程池中执行，JS 侧拿到的是 Promise。
//!
//! 错误以 JSON `{"kind","message"}` 作为 reason 抛出，由 `index.js` 转换成带 `code` 的错误类。

use std::collections::HashMap;
use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi::{Env, Task};
use napi_derive::napi;
use yibinu_auth as core;

fn to_napi(e: core::AuthError) -> Error {
    let reason = serde_json::json!({"kind": e.kind(), "message": e.to_string()}).to_string();
    Error::new(Status::GenericFailure, reason)
}

/// 在线程池中执行一次阻塞调用，把结果 `O` 转成 JS 值 `J`。
pub struct Op<O: Send + 'static, J> {
    f: Option<Box<dyn FnOnce() -> core::Result<O> + Send>>,
    _j: std::marker::PhantomData<fn() -> J>,
}

impl<O: Send + 'static, J> Op<O, J> {
    fn new(f: impl FnOnce() -> core::Result<O> + Send + 'static) -> AsyncTask<Self>
    where
        Self: Task,
    {
        AsyncTask::new(Self {
            f: Some(Box::new(f)),
            _j: std::marker::PhantomData,
        })
    }
}

impl<O, J> Task for Op<O, J>
where
    O: Send + 'static,
    J: From<O> + ToNapiValue + TypeName,
{
    type Output = O;
    type JsValue = J;

    fn compute(&mut self) -> Result<O> {
        let f = self
            .f
            .take()
            .ok_or_else(|| Error::from_reason("task already consumed"))?;
        f().map_err(to_napi)
    }

    fn resolve(&mut self, _env: Env, output: O) -> Result<J> {
        Ok(J::from(output))
    }
}

#[napi(object)]
#[derive(Default)]
pub struct ClientOptions {
    /// authserver 根地址，默认宜宾学院正式环境
    pub base_url: Option<String>,
    /// 登录成功后跳转的 service
    pub service: Option<String>,
    /// 单次请求超时（秒），默认 10
    pub timeout_secs: Option<u32>,
    /// 是否校验服务器证书，默认 true
    pub verify_tls: Option<bool>,
    /// 是否读取 HTTPS_PROXY / NO_PROXY 环境变量，默认 true
    pub use_env_proxy: Option<bool>,
}

#[napi(object)]
pub struct LoginForm {
    pub fields: HashMap<String, String>,
    pub salt: String,
}

#[napi(object)]
pub struct LoginPage {
    /// "1" = 图形验证码，"2" = 滑块验证码
    pub captcha_switch: String,
    pub front_back_key: String,
    pub password_form: Option<LoginForm>,
    pub sms_form: Option<LoginForm>,
}

impl From<core::LoginForm> for LoginForm {
    fn from(f: core::LoginForm) -> Self {
        Self {
            fields: f.fields.into_iter().collect(),
            salt: f.salt,
        }
    }
}

impl From<core::LoginPage> for LoginPage {
    fn from(p: core::LoginPage) -> Self {
        Self {
            captcha_switch: p.captcha_switch,
            front_back_key: p.front_back_key,
            password_form: p.password_form.map(Into::into),
            sms_form: p.sms_form.map(Into::into),
        }
    }
}

/// 登录结果。凭据错误不会 reject，而是 `success === false`。
#[napi(object)]
pub struct LoginResult {
    pub success: bool,
    pub message: String,
    /// 成功时上游 302 跳转的地址（含 ticket）
    pub redirect: Option<String>,
}

impl From<core::LoginResult> for LoginResult {
    fn from(r: core::LoginResult) -> Self {
        Self {
            success: r.success,
            message: r.message,
            redirect: r.redirect,
        }
    }
}

/// 发送短信验证码的结果。`code` 为 success / error / captchaError / timeExpire。
#[napi(object)]
pub struct SmsResult {
    pub sent: bool,
    pub code: String,
    pub message: String,
    /// 需要等待多少秒后才能再次发送
    pub retry_after: Option<u32>,
}

impl From<core::SmsResult> for SmsResult {
    fn from(r: core::SmsResult) -> Self {
        Self {
            sent: r.sent,
            code: r.code,
            message: r.message,
            retry_after: r.retry_after.map(|s| s.min(u32::MAX as u64) as u32),
        }
    }
}

/// 原生客户端（请通过 index.js 中的 `Client` 使用）。
#[napi(js_name = "NativeClient")]
pub struct NativeClient {
    inner: Arc<core::Client>,
}

#[napi]
impl NativeClient {
    #[napi(constructor)]
    pub fn new(options: Option<ClientOptions>) -> Result<Self> {
        let o = options.unwrap_or_default();
        let d = core::Config::default();
        let cfg = core::Config {
            base_url: o.base_url.unwrap_or(d.base_url),
            service: o.service.unwrap_or(d.service),
            timeout_secs: o.timeout_secs.map(u64::from).unwrap_or(d.timeout_secs),
            verify_tls: o.verify_tls.unwrap_or(d.verify_tls),
            use_env_proxy: o.use_env_proxy.unwrap_or(d.use_env_proxy),
        };
        Ok(Self {
            inner: Arc::new(core::Client::new(cfg).map_err(to_napi)?),
        })
    }

    #[napi(ts_return_type = "Promise<LoginPage>")]
    pub fn load_login_page(&self) -> AsyncTask<Op<core::LoginPage, LoginPage>> {
        let c = self.inner.clone();
        Op::new(move || c.load_login_page())
    }

    #[napi(ts_return_type = "Promise<boolean>")]
    pub fn need_captcha(&self, username: String) -> AsyncTask<Op<bool, bool>> {
        let c = self.inner.clone();
        Op::new(move || c.need_captcha(&username))
    }

    #[napi(ts_return_type = "Promise<Buffer>")]
    pub fn fetch_captcha(&self) -> AsyncTask<Op<Vec<u8>, Buffer>> {
        let c = self.inner.clone();
        Op::new(move || c.fetch_captcha())
    }

    #[napi(ts_return_type = "Promise<LoginResult>")]
    pub fn login_with_password(
        &self,
        username: String,
        password: String,
        captcha: Option<String>,
    ) -> AsyncTask<Op<core::LoginResult, LoginResult>> {
        let c = self.inner.clone();
        Op::new(move || c.login_with_password(&username, &password, captcha.as_deref()))
    }

    #[napi(ts_return_type = "Promise<SmsResult>")]
    pub fn send_sms_code(
        &self,
        mobile: String,
        captcha: String,
    ) -> AsyncTask<Op<core::SmsResult, SmsResult>> {
        let c = self.inner.clone();
        Op::new(move || c.send_sms_code(&mobile, &captcha))
    }

    #[napi(ts_return_type = "Promise<LoginResult>")]
    pub fn login_with_sms(
        &self,
        mobile: String,
        dynamic_code: String,
    ) -> AsyncTask<Op<core::LoginResult, LoginResult>> {
        let c = self.inner.clone();
        Op::new(move || c.login_with_sms(&mobile, &dynamic_code))
    }
}

/// 按上游算法加密（测试 / 调试用）。
#[napi]
pub fn encrypt_password(plain: String, salt: String) -> Result<String> {
    core::encrypt_password(&plain, &salt).map_err(to_napi)
}

#[napi]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
