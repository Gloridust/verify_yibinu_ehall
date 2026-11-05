use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::crypto::encrypt_password;
use crate::error::{AuthError, Result};
use crate::page::{
    parse_error_message, parse_login_page, LoginForm, LoginPage, FORM_PASSWORD, FORM_SMS,
};
use crate::proxy::proxy_for;
use crate::tls::OpenSslConnector;

pub const DEFAULT_BASE_URL: &str = "https://authserver.yibinu.edu.cn/authserver";
pub const DEFAULT_SERVICE: &str =
    "https://ehall.yibinu.edu.cn:443/login?service=https://ehall.yibinu.edu.cn/new/index.html";
/// 页面缺少 frontBackKey 时的兜底（用于加密手机号），优先使用页面实时下发的值。
pub const DEFAULT_FRONT_BACK_KEY: &str = "rjBFAaHsNkKAhpoi";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const MAX_BODY: u64 = 10 * 1024 * 1024;

/// 客户端配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// authserver 根地址，默认宜宾学院正式环境
    pub base_url: String,
    /// 登录成功后跳转的 service
    pub service: String,
    /// 单次请求超时（秒）
    pub timeout_secs: u64,
    /// 是否校验服务器证书（默认 true）
    pub verify_tls: bool,
    /// 是否读取 HTTPS_PROXY / NO_PROXY 等环境变量（默认 true）
    pub use_env_proxy: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.into(),
            service: DEFAULT_SERVICE.into(),
            timeout_secs: 10,
            verify_tls: true,
            use_env_proxy: true,
        }
    }
}

/// 登录结果。凭据错误不是 `Err`，而是 `success == false`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResult {
    pub success: bool,
    pub message: String,
    /// 成功时上游 302 跳转的地址（含 ticket）
    pub redirect: Option<String>,
}

/// 发送短信验证码的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmsResult {
    pub sent: bool,
    /// 上游返回的 code：success / error / captchaError / timeExpire
    pub code: String,
    pub message: String,
    /// 需要等待多少秒后才能再次发送（如果上游给出）
    pub retry_after: Option<u64>,
}

#[derive(Default)]
struct State {
    page: Option<LoginPage>,
    last_captcha: String,
}

/// 一次认证会话。验证码图片、短信验证码都绑定在 cookie 会话上，
/// 所以「取验证码 → 发短信 → 登录」必须使用同一个实例。
///
/// `Client` 是 `Send + Sync` 的，可在线程间共享（方法都是 `&self`）。
#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
    config: Config,
    base: Url,
    state: Arc<Mutex<State>>,
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn read_body(resp: ureq::Response) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    resp.into_reader().take(MAX_BODY).read_to_end(&mut buf)?;
    Ok(buf)
}

/// 上游页面固定为 UTF-8，不依赖响应头的 charset。
fn decode(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.strip_prefix('\u{feff}').unwrap_or(&s).to_string()
}

/// 读取 JSON 响应；非 200 或非 JSON 都视为上游异常。
fn read_json(resp: ureq::Response, endpoint: &str) -> Result<serde_json::Value> {
    let status = resp.status();
    let body = decode(&read_body(resp)?);
    if status != 200 {
        return Err(AuthError::UnexpectedResponse(format!(
            "{endpoint} 返回 HTTP {status}"
        )));
    }
    serde_json::from_str(&body)
        .map_err(|_| AuthError::UnexpectedResponse(format!("{endpoint} 返回了非 JSON 内容")))
}

/// 4xx/5xx 在 ureq 中是 `Err(Status)`，这里统一转回 Response。
fn send(r: std::result::Result<ureq::Response, ureq::Error>) -> Result<ureq::Response> {
    match r {
        Ok(r) => Ok(r),
        Err(ureq::Error::Status(_, r)) => Ok(r),
        Err(e) => Err(e.into()),
    }
}

impl Client {
    pub fn new(config: Config) -> Result<Self> {
        let base = Url::parse(config.base_url.trim_end_matches('/'))
            .map_err(|e| AuthError::InvalidArgument(format!("base_url 无效: {e}")))?;
        let tls = OpenSslConnector::new(config.verify_tls)
            .map_err(|e| AuthError::Network(format!("初始化 TLS 失败: {e}")))?;

        let mut builder = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(config.timeout_secs.max(1)))
            .redirects(0)
            .user_agent(USER_AGENT)
            .tls_connector(Arc::new(tls));
        if config.use_env_proxy {
            if let Some(p) = proxy_for(base.scheme(), base.host_str().unwrap_or_default()) {
                let proxy = ureq::Proxy::new(&p)
                    .map_err(|e| AuthError::InvalidArgument(format!("代理地址无效 {p}: {e}")))?;
                builder = builder.proxy(proxy);
            }
        }

        Ok(Self {
            agent: builder.build(),
            config,
            base,
            state: Default::default(),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base.as_str().trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    /// 登录地址（带 service 参数）。
    pub fn login_url(&self) -> String {
        let mut u = Url::parse(&self.url("login")).expect("valid base url");
        if !self.config.service.is_empty() {
            u.query_pairs_mut()
                .append_pair("service", &self.config.service);
        }
        u.into()
    }

    // -- 页面 -----------------------------------------------------------------

    /// 获取并解析登录页（同时建立会话 cookie）。每次调用都会刷新页面状态。
    pub fn load_login_page(&self) -> Result<LoginPage> {
        let resp = send(self.agent.get(&self.login_url()).call())?;
        let status = resp.status();
        let html = decode(&read_body(resp)?);
        if status != 200 {
            return Err(AuthError::UnexpectedResponse(format!(
                "登录页返回 HTTP {status}"
            )));
        }
        let page = parse_login_page(&html);
        if page.captcha_switch == "2" {
            return Err(AuthError::SliderCaptchaUnsupported);
        }
        self.state.lock().unwrap().page = Some(page.clone());
        Ok(page)
    }

    fn page(&self) -> Result<LoginPage> {
        if let Some(p) = self.state.lock().unwrap().page.clone() {
            return Ok(p);
        }
        self.load_login_page()
    }

    fn form(&self, id: &str) -> Result<LoginForm> {
        let page = self.page()?;
        let form = if id == FORM_PASSWORD {
            page.password_form
        } else {
            page.sms_form
        };
        form.ok_or_else(|| {
            AuthError::PageStructure(format!(
                "未找到表单 '{id}'，上游页面结构可能已变更或该登录方式已关闭"
            ))
        })
    }

    // -- 图形验证码 -------------------------------------------------------------

    /// 账号密码登录是否需要图形验证码 (`checkNeedCaptcha.htl`)。
    pub fn need_captcha(&self, username: &str) -> Result<bool> {
        self.page()?; // 确保已有会话 cookie
        let ts = now_millis().to_string();
        let resp = send(
            self.agent
                .get(&self.url("checkNeedCaptcha.htl"))
                .query("username", username)
                .query("_", &ts)
                .call(),
        )?;
        let v = read_json(resp, "checkNeedCaptcha.htl")?;
        Ok(v.get("isNeed").and_then(|x| x.as_bool()).unwrap_or(false))
    }

    /// 获取一张新的图形验证码 (`getCaptcha.htl`)，返回图片字节（JPEG）。
    pub fn fetch_captcha(&self) -> Result<Vec<u8>> {
        self.page()?; // 确保已有会话 cookie
        let ts = now_millis().to_string();
        let resp = send(
            self.agent
                .get(&self.url("getCaptcha.htl"))
                .query("t", &ts)
                .call(),
        )?;
        if resp.status() != 200 {
            return Err(AuthError::UnexpectedResponse(format!(
                "getCaptcha.htl 返回 HTTP {}",
                resp.status()
            )));
        }
        if !resp.content_type().starts_with("image/") {
            return Err(AuthError::UnexpectedResponse(format!(
                "getCaptcha.htl 返回的不是图片 ({})",
                resp.content_type()
            )));
        }
        read_body(resp)
    }

    // -- 账号密码登录 -------------------------------------------------------------

    /// 账号密码登录。
    ///
    /// 若上游要求验证码而 `captcha` 为 `None`，返回 [`AuthError::CaptchaRequired`]；
    /// 此时调用 [`Client::fetch_captcha`] 取图，再带上答案重新调用本方法。
    pub fn login_with_password(
        &self,
        username: &str,
        password: &str,
        captcha: Option<&str>,
    ) -> Result<LoginResult> {
        if username.trim().is_empty() || password.is_empty() {
            return Err(AuthError::InvalidArgument("用户名和密码不能为空".into()));
        }
        let form = self.form(FORM_PASSWORD)?;
        if form.salt.is_empty() {
            return Err(AuthError::PageStructure(
                "登录页未下发 pwdEncryptSalt".into(),
            ));
        }
        let captcha = captcha.map(str::trim).filter(|c| !c.is_empty());
        if captcha.is_none() && self.need_captcha(username)? {
            return Err(AuthError::CaptchaRequired);
        }

        let mut data = form.fields.clone();
        data.insert("username".into(), username.into());
        data.insert("password".into(), encrypt_password(password, &form.salt)?);
        // captcha 字段始终提交；不需要验证码时为空，与浏览器行为一致
        data.insert("captcha".into(), captcha.unwrap_or("").into());
        self.submit(data)
    }

    // -- 短信登录 ---------------------------------------------------------------

    /// 发送短信验证码 (`dynamicCode/getDynamicCode.htl`)。图形验证码必填。
    pub fn send_sms_code(&self, mobile: &str, captcha: &str) -> Result<SmsResult> {
        if mobile.trim().is_empty() {
            return Err(AuthError::InvalidArgument("手机号不能为空".into()));
        }
        let captcha = captcha.trim();
        if captcha.is_empty() {
            return Err(AuthError::CaptchaRequired);
        }
        let page = self.page()?;
        let key = if page.front_back_key.is_empty() {
            DEFAULT_FRONT_BACK_KEY
        } else {
            &page.front_back_key
        };
        let enc = encrypt_password(mobile.trim(), key)?;

        let resp = send(
            self.agent
                .post(&self.url("dynamicCode/getDynamicCode.htl"))
                .send_form(&[("mobile", enc.as_str()), ("captcha", captcha)]),
        )?;
        let v = read_json(resp, "getDynamicCode.htl")?;

        let code = v
            .get("code")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let message = v
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let as_secs = |k: &str| {
            v.get(k).and_then(|x| {
                x.as_u64()
                    .or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))
            })
        };
        let sent = code == "success";
        if sent {
            self.state.lock().unwrap().last_captcha = captcha.to_string();
        }
        let retry_after = if sent {
            as_secs("intervalTime")
        } else {
            as_secs("time")
        };
        let message = match (message.is_empty(), code.as_str()) {
            (false, _) => message,
            (true, "success") => "短信验证码已发送".into(),
            (true, "timeExpire") => "发送过于频繁，请稍后重试".into(),
            (true, c) => format!("发送失败 ({c})"),
        };
        Ok(SmsResult {
            sent,
            code,
            message,
            retry_after,
        })
    }

    /// 用短信验证码登录。需先在同一实例上成功调用 [`Client::send_sms_code`]。
    pub fn login_with_sms(&self, mobile: &str, dynamic_code: &str) -> Result<LoginResult> {
        if mobile.trim().is_empty() || dynamic_code.trim().is_empty() {
            return Err(AuthError::InvalidArgument(
                "手机号和短信验证码不能为空".into(),
            ));
        }
        let form = self.form(FORM_SMS)?;
        let mut data = form.fields.clone();
        data.insert("username".into(), mobile.trim().into());
        data.insert("dynamicCode".into(), dynamic_code.trim().into());
        data.insert(
            "captcha".into(),
            self.state.lock().unwrap().last_captcha.clone(),
        );
        self.submit(data)
    }

    // -- 提交 -----------------------------------------------------------------

    fn submit(&self, data: std::collections::BTreeMap<String, String>) -> Result<LoginResult> {
        let pairs: Vec<(&str, &str)> = data.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let resp = send(self.agent.post(&self.login_url()).send_form(&pairs))?;
        let status = resp.status();
        let location = resp.header("Location").map(str::to_string);

        if (300..400).contains(&status) {
            let location = location.unwrap_or_default();
            let path = Url::parse(&location)
                .or_else(|_| self.base.join(&location))
                .map(|u| u.path().trim_end_matches('/').to_string())
                .unwrap_or_default();
            if path.ends_with("/login") && path.contains("/authserver") {
                return Ok(LoginResult {
                    success: false,
                    message: "Login failed: redirected back to login page".into(),
                    redirect: Some(location),
                });
            }
            return Ok(LoginResult {
                success: true,
                message: "Login successful".into(),
                redirect: Some(location),
            });
        }
        let html = decode(&read_body(resp)?);
        Ok(LoginResult {
            success: false,
            message: parse_error_message(&html),
            redirect: None,
        })
    }
}
