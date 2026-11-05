//! Python 绑定（模块 `verify_yibinu._native`）。网络请求期间释放 GIL。

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use yibinu_auth as core;

create_exception!(
    verify_yibinu,
    AuthError,
    PyException,
    "认证流程中的可预期错误"
);
create_exception!(verify_yibinu, CaptchaRequired, AuthError, "需要图形验证码");
create_exception!(
    verify_yibinu,
    SliderCaptchaUnsupported,
    AuthError,
    "上游启用了滑块验证码，无法自动完成"
);
create_exception!(
    verify_yibinu,
    PageStructureError,
    AuthError,
    "登录页结构变化"
);
create_exception!(
    verify_yibinu,
    UnexpectedResponseError,
    AuthError,
    "上游返回了意料之外的内容"
);
create_exception!(
    verify_yibinu,
    NetworkError,
    AuthError,
    "网络 / TLS / 超时错误"
);
create_exception!(verify_yibinu, InvalidArgumentError, AuthError, "参数非法");

fn to_py(e: core::AuthError) -> PyErr {
    let msg = e.to_string();
    match e {
        core::AuthError::CaptchaRequired => CaptchaRequired::new_err(msg),
        core::AuthError::SliderCaptchaUnsupported => SliderCaptchaUnsupported::new_err(msg),
        core::AuthError::PageStructure(_) => PageStructureError::new_err(msg),
        core::AuthError::UnexpectedResponse(_) => UnexpectedResponseError::new_err(msg),
        core::AuthError::Network(_) => NetworkError::new_err(msg),
        core::AuthError::InvalidArgument(_) => InvalidArgumentError::new_err(msg),
    }
}

/// 登录结果。凭据错误不会抛异常，而是 `success == False`。
#[pyclass(frozen, get_all, module = "verify_yibinu._native")]
#[derive(Clone)]
pub struct LoginResult {
    success: bool,
    message: String,
    redirect: Option<String>,
}

#[pymethods]
impl LoginResult {
    fn __repr__(&self) -> String {
        format!(
            "LoginResult(success={}, message={:?})",
            if self.success { "True" } else { "False" },
            self.message
        )
    }
    fn __bool__(&self) -> bool {
        self.success
    }
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
#[pyclass(frozen, get_all, module = "verify_yibinu._native")]
#[derive(Clone)]
pub struct SmsResult {
    sent: bool,
    code: String,
    message: String,
    retry_after: Option<u64>,
}

#[pymethods]
impl SmsResult {
    fn __repr__(&self) -> String {
        format!(
            "SmsResult(sent={}, code={:?}, message={:?})",
            if self.sent { "True" } else { "False" },
            self.code,
            self.message
        )
    }
    fn __bool__(&self) -> bool {
        self.sent
    }
}

impl From<core::SmsResult> for SmsResult {
    fn from(r: core::SmsResult) -> Self {
        Self {
            sent: r.sent,
            code: r.code,
            message: r.message,
            retry_after: r.retry_after,
        }
    }
}

/// 一次认证会话。验证码与短信验证码绑定在会话上，取图 / 发短信 / 登录必须使用同一个 Client。
#[pyclass(frozen, module = "verify_yibinu._native")]
pub struct Client {
    inner: core::Client,
}

fn form_to_dict<'py>(
    py: Python<'py>,
    f: &Option<core::LoginForm>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let Some(f) = f else { return Ok(None) };
    let d = PyDict::new(py);
    let fields = PyDict::new(py);
    for (k, v) in &f.fields {
        fields.set_item(k, v)?;
    }
    d.set_item("fields", fields)?;
    d.set_item("salt", &f.salt)?;
    Ok(Some(d))
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (*, base_url=None, service=None, timeout=10, verify_tls=true, use_env_proxy=true))]
    fn new(
        base_url: Option<String>,
        service: Option<String>,
        timeout: u64,
        verify_tls: bool,
        use_env_proxy: bool,
    ) -> PyResult<Self> {
        let d = core::Config::default();
        let cfg = core::Config {
            base_url: base_url.unwrap_or(d.base_url),
            service: service.unwrap_or(d.service),
            timeout_secs: timeout,
            verify_tls,
            use_env_proxy,
        };
        Ok(Self {
            inner: core::Client::new(cfg).map_err(to_py)?,
        })
    }

    /// 获取并解析登录页（建立会话 cookie），返回 dict。
    fn load_login_page<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let page = py.detach(|| self.inner.load_login_page()).map_err(to_py)?;
        let d = PyDict::new(py);
        d.set_item("captcha_switch", &page.captcha_switch)?;
        d.set_item("front_back_key", &page.front_back_key)?;
        d.set_item("password_form", form_to_dict(py, &page.password_form)?)?;
        d.set_item("sms_form", form_to_dict(py, &page.sms_form)?)?;
        Ok(d)
    }

    /// 账号密码登录是否需要图形验证码。
    fn need_captcha(&self, py: Python<'_>, username: &str) -> PyResult<bool> {
        py.detach(|| self.inner.need_captcha(username))
            .map_err(to_py)
    }

    /// 获取一张新的图形验证码，返回 JPEG 字节。
    fn fetch_captcha<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let img = py.detach(|| self.inner.fetch_captcha()).map_err(to_py)?;
        Ok(PyBytes::new(py, &img))
    }

    /// 账号密码登录。上游要求验证码而 captcha 为 None 时抛 CaptchaRequired。
    #[pyo3(signature = (username, password, captcha=None))]
    fn login_with_password(
        &self,
        py: Python<'_>,
        username: &str,
        password: &str,
        captcha: Option<&str>,
    ) -> PyResult<LoginResult> {
        py.detach(|| self.inner.login_with_password(username, password, captcha))
            .map(Into::into)
            .map_err(to_py)
    }

    /// 发送短信验证码（图形验证码必填）。
    fn send_sms_code(&self, py: Python<'_>, mobile: &str, captcha: &str) -> PyResult<SmsResult> {
        py.detach(|| self.inner.send_sms_code(mobile, captcha))
            .map(Into::into)
            .map_err(to_py)
    }

    /// 用短信验证码登录（需先在同一 Client 上成功调用 send_sms_code）。
    fn login_with_sms(
        &self,
        py: Python<'_>,
        mobile: &str,
        dynamic_code: &str,
    ) -> PyResult<LoginResult> {
        py.detach(|| self.inner.login_with_sms(mobile, dynamic_code))
            .map(Into::into)
            .map_err(to_py)
    }

    fn __repr__(&self) -> String {
        format!("Client(base_url={:?})", self.inner.config().base_url)
    }
}

/// 按上游算法加密（测试 / 调试用）。
#[pyfunction]
fn encrypt_password(plain: &str, salt: &str) -> PyResult<String> {
    core::encrypt_password(plain, salt).map_err(to_py)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<Client>()?;
    m.add_class::<LoginResult>()?;
    m.add_class::<SmsResult>()?;
    m.add_function(wrap_pyfunction!(encrypt_password, m)?)?;
    m.add("AuthError", py.get_type::<AuthError>())?;
    m.add("CaptchaRequired", py.get_type::<CaptchaRequired>())?;
    m.add(
        "SliderCaptchaUnsupported",
        py.get_type::<SliderCaptchaUnsupported>(),
    )?;
    m.add("PageStructureError", py.get_type::<PageStructureError>())?;
    m.add(
        "UnexpectedResponseError",
        py.get_type::<UnexpectedResponseError>(),
    )?;
    m.add("NetworkError", py.get_type::<NetworkError>())?;
    m.add(
        "InvalidArgumentError",
        py.get_type::<InvalidArgumentError>(),
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("DEFAULT_BASE_URL", core::DEFAULT_BASE_URL)?;
    Ok(())
}
