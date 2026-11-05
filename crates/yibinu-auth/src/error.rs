use thiserror::Error;

/// 认证流程中的错误。登录失败（密码错误、短信码错误等）不是错误，
/// 而是 [`crate::LoginResult`] 里 `success == false` 的正常结果。
#[derive(Debug, Error)]
pub enum AuthError {
    /// 需要图形验证码：先调用 `fetch_captcha()` 取图，再把答案作为 `captcha` 传入。
    #[error("需要图形验证码：请先调用 fetch_captcha() 获取图片，再传入 captcha")]
    CaptchaRequired,

    /// 上游启用了滑块验证码 (captchaSwitch=2)，无法自动完成。
    #[error("上游已启用滑块验证码 (captchaSwitch=2)，当前不支持自动完成，请使用浏览器登录")]
    SliderCaptchaUnsupported,

    /// 登录页中找不到需要的表单 / 字段，上游页面结构可能再次变更。
    #[error("登录页解析失败：{0}")]
    PageStructure(String),

    /// 上游接口返回了意料之外的内容。
    #[error("上游响应异常：{0}")]
    UnexpectedResponse(String),

    /// 网络 / TLS / 超时错误。
    #[error("网络错误：{0}")]
    Network(String),

    /// 参数不合法（如空用户名）。
    #[error("参数错误：{0}")]
    InvalidArgument(String),
}

impl AuthError {
    /// 稳定的错误类型标识，供各语言绑定映射成各自的异常类型。
    pub fn kind(&self) -> &'static str {
        match self {
            AuthError::CaptchaRequired => "captcha_required",
            AuthError::SliderCaptchaUnsupported => "slider_captcha_unsupported",
            AuthError::PageStructure(_) => "page_structure",
            AuthError::UnexpectedResponse(_) => "unexpected_response",
            AuthError::Network(_) => "network",
            AuthError::InvalidArgument(_) => "invalid_argument",
        }
    }
}

impl From<ureq::Error> for AuthError {
    fn from(e: ureq::Error) -> Self {
        AuthError::Network(e.to_string())
    }
}

impl From<std::io::Error> for AuthError {
    fn from(e: std::io::Error) -> Self {
        AuthError::Network(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;
