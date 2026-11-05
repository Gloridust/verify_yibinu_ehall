//! 测试用的假 authserver。只监听 127.0.0.1，行为与升级后的上游一致：
//!
//! * `GET  /authserver/login`                         → 登录页（真实页面裁剪的 fixture），下发会话 cookie
//! * `GET  /authserver/checkNeedCaptcha.htl`          → `{"isNeed": <need_captcha>}`
//! * `GET  /authserver/getCaptcha.htl`                → JPEG，并把答案设为 `captcha`
//! * `POST /authserver/dynamicCode/getDynamicCode.htl`→ 校验图形验证码后 "发送" 短信
//! * `POST /authserver/login`                         → 校验密码 / 短信码，成功 302，失败 401 + `#showErrorTip`
//!
//! 所有接口都要求带上登录页下发的 cookie，用来验证客户端的会话保持。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use tiny_http::{Header, Request, Response, Server};

pub const FIXTURE: &str = include_str!("../../yibinu-auth/tests/fixtures/login_page.html");
pub const PWD_SALT: &str = "G9KhHtvLf0t2HKrD";
pub const FRONT_BACK_KEY: &str = "rjBFAaHsNkKAhpoi";
pub const CAPTCHA_ANSWER: &str = "abcd";
pub const SMS_CODE: &str = "123456";
pub const JPEG: &[u8] = b"\xff\xd8\xff\xe0fake-jpeg";
const COOKIE: &str = "JSESSIONID=mock-session";

/// 一次请求的记录。
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub form: HashMap<String, String>,
    pub cookie: String,
}

/// 服务行为配置。
#[derive(Debug, Clone)]
pub struct Behavior {
    pub login_html: String,
    pub need_captcha: bool,
    /// 正确的明文密码（服务端会按上游算法解密后比对）
    pub expected_password: String,
    pub login_status_on_success: u16,
    pub success_location: String,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            login_html: FIXTURE.to_string(),
            need_captcha: true,
            expected_password: "secret!".into(),
            login_status_on_success: 302,
            success_location: "https://ehall.yibinu.edu.cn/login?ticket=ST-1-mock".into(),
        }
    }
}

#[derive(Default)]
struct State {
    captcha_issued: bool,
    sms_sent_to: Option<String>,
    requests: Vec<Recorded>,
}

pub struct MockUpstream {
    pub port: u16,
    state: Arc<Mutex<State>>,
    server: Arc<Server>,
}

impl MockUpstream {
    pub fn start(behavior: Behavior) -> Self {
        let server = Arc::new(Server::http("127.0.0.1:0").expect("bind mock server"));
        let port = server.server_addr().to_ip().unwrap().port();
        let state = Arc::new(Mutex::new(State::default()));
        let (s, st) = (server.clone(), state.clone());
        thread::spawn(move || {
            for req in s.incoming_requests() {
                handle(req, &behavior, &st);
            }
        });
        Self {
            port,
            state,
            server,
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/authserver", self.port)
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }

    /// 最后一次 POST /authserver/login 的表单
    pub fn last_login_form(&self) -> Option<HashMap<String, String>> {
        self.requests()
            .into_iter()
            .rev()
            .find(|r| r.method == "POST" && r.path == "/authserver/login")
            .map(|r| r.form)
    }

    pub fn captcha_fetched(&self) -> bool {
        self.requests()
            .iter()
            .any(|r| r.path == "/authserver/getCaptcha.htl")
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

fn parse_pairs(s: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(s.as_bytes())
        .into_owned()
        .collect()
}

fn header(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}

fn json(body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body).with_header(header("Content-Type", "text/plain;charset=UTF-8"))
}

fn html(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_status_code(status)
        .with_header(header("Content-Type", "text/html;charset=UTF-8"))
}

fn handle(mut req: Request, b: &Behavior, st: &Arc<Mutex<State>>) {
    let method = req.method().to_string();
    let (path, query) = match req.url().split_once('?') {
        Some((p, q)) => (p.to_string(), parse_pairs(q)),
        None => (req.url().to_string(), HashMap::new()),
    };
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let form = parse_pairs(&body);
    let cookie = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Cookie"))
        .map(|h| h.value.to_string())
        .unwrap_or_default();
    st.lock().unwrap().requests.push(Recorded {
        method: method.clone(),
        path: path.clone(),
        query,
        form: form.clone(),
        cookie: cookie.clone(),
    });

    let has_session = cookie.contains(COOKIE);
    let resp = match (method.as_str(), path.as_str()) {
        ("GET", "/authserver/login") => html(200, &b.login_html)
            .with_header(header("Set-Cookie", &format!("{COOKIE}; Path=/authserver"))),
        _ if !has_session => html(403, "<span id=\"showErrorTip\">会话已失效</span>"),
        ("GET", "/authserver/checkNeedCaptcha.htl") => {
            json(format!("{{\"isNeed\":{}}}", b.need_captcha))
        }
        ("GET", "/authserver/getCaptcha.htl") => {
            st.lock().unwrap().captcha_issued = true;
            Response::from_data(JPEG.to_vec())
                .with_header(header("Content-Type", "image/jpeg;charset=UTF-8"))
        }
        ("POST", "/authserver/dynamicCode/getDynamicCode.htl") => {
            let mut s = st.lock().unwrap();
            if !s.captcha_issued || form.get("captcha").map(String::as_str) != Some(CAPTCHA_ANSWER)
            {
                json("{\"code\":\"captchaError\",\"message\":\"图形验证码错误\"}".into())
            } else if form
                .get("mobile")
                .and_then(|m| decrypt(m, FRONT_BACK_KEY))
                .is_none_or(|m| m.is_empty())
            {
                json("{\"code\":\"error\",\"message\":\"手机号无效\"}".into())
            } else {
                s.sms_sent_to = form.get("mobile").and_then(|m| decrypt(m, FRONT_BACK_KEY));
                json(
                    "{\"code\":\"success\",\"message\":\"验证码已发送\",\"intervalTime\":120}"
                        .into(),
                )
            }
        }
        ("POST", "/authserver/login") => login(b, st, &form),
        _ => html(404, "not found"),
    };
    let _ = req.respond(resp);
}

fn login(
    b: &Behavior,
    st: &Arc<Mutex<State>>,
    form: &HashMap<String, String>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let fail = |msg: &str| {
        html(
            401,
            &format!("<html><span id=\"showErrorTip\">{msg}</span></html>"),
        )
    };
    let ok = || {
        Response::from_string("")
            .with_status_code(b.login_status_on_success)
            .with_header(header("Location", &b.success_location))
    };
    let s = st.lock().unwrap();
    match form.get("cllt").map(String::as_str) {
        Some("userNameLogin") => {
            if b.need_captcha && form.get("captcha").map(String::as_str) != Some(CAPTCHA_ANSWER) {
                return fail("验证码错误");
            }
            let pwd = form.get("password").cloned().unwrap_or_default();
            if decrypt(&pwd, PWD_SALT).as_deref() == Some(b.expected_password.as_str()) {
                ok()
            } else {
                fail("您提供的用户名或者密码有误")
            }
        }
        Some("dynamicLogin") => {
            if s.sms_sent_to.is_none() {
                fail("请先获取短信验证码")
            } else if form.get("dynamicCode").map(String::as_str) != Some(SMS_CODE) {
                fail("动态码错误")
            } else {
                ok()
            }
        }
        _ => fail("不支持的登录方式"),
    }
}

/// 服务端视角解密：IV 任意（只影响被丢弃的前 64 个字符），返回去掉随机前缀后的明文。
pub fn decrypt(token: &str, salt: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    let raw = STANDARD.decode(token).ok()?;
    let plain = cbc::Decryptor::<aes::Aes128>::new_from_slices(salt.as_bytes(), &[b'0'; 16])
        .ok()?
        .decrypt_padded_vec_mut::<Pkcs7>(&raw)
        .ok()?;
    (plain.len() >= 64).then(|| String::from_utf8_lossy(&plain[64..]).into_owned())
}

impl MockUpstream {
    /// 服务端解密出的、最近一次发送短信的手机号
    pub fn sms_sent_to(&self) -> Option<String> {
        self.state.lock().unwrap().sms_sent_to.clone()
    }
}
