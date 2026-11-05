//! 端到端流程测试：真实 HTTP 往返到本地假 authserver（不访问外网）。

use yibinu_auth::{AuthError, Client, Config};
use yibinu_mock_upstream::{
    decrypt, Behavior, MockUpstream, CAPTCHA_ANSWER, FIXTURE, FRONT_BACK_KEY, JPEG, PWD_SALT,
    SMS_CODE,
};

fn client(mock: &MockUpstream) -> Client {
    Client::new(Config {
        base_url: mock.base_url(),
        use_env_proxy: false,
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn password_login_with_captcha() {
    let mock = MockUpstream::start(Behavior::default());
    let c = client(&mock);
    c.load_login_page().unwrap();

    // 第一次不带验证码 → CaptchaRequired
    let err = c
        .login_with_password("230110128", "secret!", None)
        .unwrap_err();
    assert!(matches!(err, AuthError::CaptchaRequired));
    assert_eq!(err.kind(), "captcha_required");

    assert_eq!(c.fetch_captcha().unwrap(), JPEG);
    let r = c
        .login_with_password("230110128", "secret!", Some(CAPTCHA_ANSWER))
        .unwrap();
    assert!(r.success, "{r:?}");
    assert!(r.redirect.unwrap().contains("ticket="));

    let form = mock.last_login_form().unwrap();
    assert_eq!(form["username"], "230110128");
    assert_eq!(form["cllt"], "userNameLogin");
    assert_eq!(form["execution"], "e1s1");
    assert_eq!(form["captcha"], CAPTCHA_ANSWER);
    assert_eq!(
        decrypt(&form["password"], PWD_SALT).as_deref(),
        Some("secret!")
    );
    assert!(!form.contains_key("passwordText"));

    // 会话 cookie 在所有后续请求中保持
    assert!(mock
        .requests()
        .iter()
        .skip(1)
        .all(|r| r.cookie.contains("JSESSIONID=mock-session")));
}

#[test]
fn login_url_carries_encoded_service() {
    let mock = MockUpstream::start(Behavior::default());
    let c = client(&mock);
    c.load_login_page().unwrap();
    let first = &mock.requests()[0];
    assert_eq!(first.path, "/authserver/login");
    assert_eq!(first.query["service"], yibinu_auth::DEFAULT_SERVICE);
}

#[test]
fn password_login_without_captcha() {
    let mock = MockUpstream::start(Behavior {
        need_captcha: false,
        ..Default::default()
    });
    let c = client(&mock);
    let r = c.login_with_password("u", "secret!", None).unwrap(); // 自动加载登录页
    assert!(r.success);
    assert!(!mock.captcha_fetched());
    assert_eq!(mock.last_login_form().unwrap()["captcha"], "");
}

#[test]
fn wrong_password_message() {
    let mock = MockUpstream::start(Behavior {
        need_captcha: false,
        ..Default::default()
    });
    let c = client(&mock);
    let r = c.login_with_password("u", "wrong", None).unwrap();
    assert!(!r.success);
    assert_eq!(r.message, "您提供的用户名或者密码有误");
}

#[test]
fn wrong_captcha_message() {
    let mock = MockUpstream::start(Behavior::default());
    let c = client(&mock);
    c.fetch_captcha().unwrap();
    let r = c.login_with_password("u", "secret!", Some("zzzz")).unwrap();
    assert!(!r.success);
    assert_eq!(r.message, "验证码错误");
}

#[test]
fn redirect_back_to_login_is_failure() {
    let mock = MockUpstream::start(Behavior {
        need_captcha: false,
        success_location: "https://authserver.yibinu.edu.cn/authserver/login?x=1".into(),
        ..Default::default()
    });
    let r = client(&mock)
        .login_with_password("u", "secret!", None)
        .unwrap();
    assert!(!r.success);
}

#[test]
fn slider_captcha_detected() {
    let mock = MockUpstream::start(Behavior {
        login_html: FIXTURE.replace(r#"var captchaSwitch = "1""#, r#"var captchaSwitch = "2""#),
        ..Default::default()
    });
    let err = client(&mock).load_login_page().unwrap_err();
    assert!(matches!(err, AuthError::SliderCaptchaUnsupported));
}

#[test]
fn missing_form_is_page_structure_error() {
    let mock = MockUpstream::start(Behavior {
        login_html: "<html>维护中</html>".into(),
        ..Default::default()
    });
    let err = client(&mock)
        .login_with_password("u", "p", Some("x"))
        .unwrap_err();
    assert_eq!(err.kind(), "page_structure");
}

#[test]
fn empty_arguments_rejected() {
    let mock = MockUpstream::start(Behavior::default());
    let c = client(&mock);
    assert_eq!(
        c.login_with_password("", "p", None).unwrap_err().kind(),
        "invalid_argument"
    );
    assert_eq!(
        c.send_sms_code("", "abcd").unwrap_err().kind(),
        "invalid_argument"
    );
    assert_eq!(
        c.send_sms_code("13800000000", " ").unwrap_err().kind(),
        "captcha_required"
    );
}

#[test]
fn sms_login_flow() {
    let mock = MockUpstream::start(Behavior::default());
    let c = client(&mock);
    c.load_login_page().unwrap();
    c.fetch_captcha().unwrap();

    let s = c.send_sms_code("13800000000", CAPTCHA_ANSWER).unwrap();
    assert!(s.sent, "{s:?}");
    assert_eq!(s.code, "success");
    assert_eq!(s.retry_after, Some(120));
    assert_eq!(mock.sms_sent_to().as_deref(), Some("13800000000"));

    let r = c.login_with_sms("13800000000", SMS_CODE).unwrap();
    assert!(r.success, "{r:?}");
    let form = mock.last_login_form().unwrap();
    assert_eq!(form["cllt"], "dynamicLogin");
    assert_eq!(form["username"], "13800000000");
    assert_eq!(form["dynamicCode"], SMS_CODE);
    assert_eq!(form["captcha"], CAPTCHA_ANSWER);
}

#[test]
fn sms_wrong_captcha_and_wrong_code() {
    let mock = MockUpstream::start(Behavior::default());
    let c = client(&mock);
    c.fetch_captcha().unwrap();

    let s = c.send_sms_code("13800000000", "zzzz").unwrap();
    assert!(!s.sent);
    assert_eq!(s.code, "captchaError");
    assert_eq!(s.message, "图形验证码错误");

    c.send_sms_code("13800000000", CAPTCHA_ANSWER).unwrap();
    let r = c.login_with_sms("13800000000", "000000").unwrap();
    assert!(!r.success);
    assert_eq!(r.message, "动态码错误");
}

#[test]
fn mobile_encrypted_with_front_back_key() {
    let mock = MockUpstream::start(Behavior::default());
    let c = client(&mock);
    c.fetch_captcha().unwrap();
    c.send_sms_code("1-888888", CAPTCHA_ANSWER).unwrap();
    let req = mock
        .requests()
        .into_iter()
        .find(|r| r.path.ends_with("getDynamicCode.htl"))
        .unwrap();
    assert_eq!(
        decrypt(&req.form["mobile"], FRONT_BACK_KEY).as_deref(),
        Some("1-888888")
    );
}

#[test]
fn network_error_kind() {
    let c = Client::new(Config {
        base_url: "http://127.0.0.1:1/authserver".into(),
        use_env_proxy: false,
        timeout_secs: 2,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(c.load_login_page().unwrap_err().kind(), "network");
}

#[test]
fn client_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Client>();
}

#[test]
fn need_captcha_establishes_session_first() {
    let mock = MockUpstream::start(Behavior::default());
    let c = client(&mock);
    assert!(c.need_captcha("u").unwrap()); // 未手动 load_login_page
    assert_eq!(mock.requests()[0].path, "/authserver/login");
}

#[test]
fn send_sms_establishes_session_first() {
    let mock = MockUpstream::start(Behavior::default());
    // 未手动 load_login_page：会先建立会话，请求到达业务层（没取过图，所以是 captchaError）
    let r = client(&mock).send_sms_code("13800000000", "abcd").unwrap();
    assert_eq!(r.code, "captchaError");
    assert_eq!(mock.requests()[0].path, "/authserver/login");
}
