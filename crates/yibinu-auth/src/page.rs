//! 登录页解析。
//!
//! 页面里同一个 id（lt / execution / pwdEncryptSalt ...）在多个表单中重复出现，
//! 必须按表单作用域解析，不能全局查找。

use std::collections::BTreeMap;

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};

pub const FORM_PASSWORD: &str = "pwdFromId";
pub const FORM_SMS: &str = "phoneFromId";

/// 单个登录表单。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginForm {
    /// 需要原样回传的隐藏字段（_eventId / cllt / dllt / lt / execution ...）
    pub fields: BTreeMap<String, String>,
    /// 表单内的 `pwdEncryptSalt`
    pub salt: String,
}

/// 解析后的登录页。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginPage {
    /// "1" = 图形验证码，"2" = 滑块验证码
    pub captcha_switch: String,
    /// 页面下发的 `frontBackKey`，用于加密手机号
    pub front_back_key: String,
    pub password_form: Option<LoginForm>,
    pub sms_form: Option<LoginForm>,
}

pub fn parse_login_page(html: &str) -> LoginPage {
    let doc = Html::parse_document(html);
    LoginPage {
        captcha_switch: find_js_string_var(html, "captchaSwitch").unwrap_or_default(),
        front_back_key: find_js_string_var(html, "frontBackKey").unwrap_or_default(),
        password_form: parse_form(&doc, FORM_PASSWORD),
        sms_form: parse_form(&doc, FORM_SMS),
    }
}

fn parse_form(doc: &Html, form_id: &str) -> Option<LoginForm> {
    let form_sel = Selector::parse(&format!("form#{form_id}")).ok()?;
    let hidden_sel = Selector::parse("input[type=hidden]").unwrap();
    let salt_sel = Selector::parse("input#pwdEncryptSalt").unwrap();

    let form = doc.select(&form_sel).next()?;
    let mut fields = BTreeMap::new();
    for input in form.select(&hidden_sel) {
        if let Some(name) = input.value().attr("name") {
            fields.insert(
                name.to_string(),
                input.value().attr("value").unwrap_or("").to_string(),
            );
        }
    }
    let salt = form
        .select(&salt_sel)
        .next()
        .and_then(|e| e.value().attr("value"))
        .unwrap_or("")
        .to_string();
    Some(LoginForm { fields, salt })
}

/// 提取 `var name = "value";` 形式的 JS 字符串变量。
pub fn find_js_string_var(html: &str, name: &str) -> Option<String> {
    let needle = format!("var {name}");
    let mut rest = html;
    while let Some(pos) = rest.find(&needle) {
        let after = &rest[pos + needle.len()..];
        // 确保是完整的变量名（排除 captchaSwitchXxx 之类）
        let tail = after.trim_start();
        if after.starts_with(|c: char| c.is_whitespace() || c == '=') {
            if let Some(tail) = tail.strip_prefix('=') {
                let tail = tail.trim_start();
                if let Some(quote) = tail.chars().next().filter(|c| *c == '"' || *c == '\'') {
                    let body = &tail[1..];
                    if let Some(end) = body.find(quote) {
                        return Some(body[..end].to_string());
                    }
                }
            }
        }
        rest = &rest[pos + needle.len()..];
    }
    None
}

/// 从登录失败的页面中提取错误提示（新版 `#showErrorTip`，旧版 `#errorMsg`）。
pub fn parse_error_message(html: &str) -> String {
    let doc = Html::parse_document(html);
    for id in ["showErrorTip", "errorMsg", "msg"] {
        let sel = Selector::parse(&format!("#{id}")).unwrap();
        for el in doc.select(&sel) {
            let text: String = el.text().collect::<String>().trim().to_string();
            if !text.is_empty() {
                return text;
            }
        }
    }
    "Login failed: Invalid credentials or session timeout".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = include_str!("../tests/fixtures/login_page.html");

    #[test]
    fn parses_real_page() {
        let p = parse_login_page(PAGE);
        assert_eq!(p.captcha_switch, "1");
        assert_eq!(p.front_back_key, "rjBFAaHsNkKAhpoi");
        let pwd = p.password_form.unwrap();
        assert_eq!(pwd.salt, "G9KhHtvLf0t2HKrD");
        assert_eq!(pwd.fields["cllt"], "userNameLogin");
        assert_eq!(pwd.fields["execution"], "e1s1");
        assert_eq!(pwd.fields["_eventId"], "submit");
        let sms = p.sms_form.unwrap();
        assert_eq!(sms.fields["cllt"], "dynamicLogin");
        assert_eq!(sms.salt, "G9KhHtvLf0t2HKrD");
    }

    #[test]
    fn js_var_exact_name() {
        let html = r#"var captchaSwitchX = "9"; var captchaSwitch  =  '1';"#;
        assert_eq!(
            find_js_string_var(html, "captchaSwitch").as_deref(),
            Some("1")
        );
        assert_eq!(find_js_string_var(html, "missing"), None);
    }

    #[test]
    fn error_message() {
        assert_eq!(
            parse_error_message(r#"<span id="showErrorTip">用户名或密码有误</span>"#),
            "用户名或密码有误"
        );
        assert_eq!(
            parse_error_message(r#"<span id="errorMsg">旧版</span>"#),
            "旧版"
        );
        assert!(parse_error_message("<html></html>").starts_with("Login failed"));
    }

    #[test]
    fn missing_forms() {
        let p = parse_login_page("<html><body>maintenance</body></html>");
        assert!(p.password_form.is_none() && p.sms_form.is_none());
    }
}
