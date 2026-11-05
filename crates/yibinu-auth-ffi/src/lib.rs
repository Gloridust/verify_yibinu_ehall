//! yibinu-auth 的 C ABI。
//!
//! 约定（详见 `include/yibinu_auth.h`）：
//! * 除 `yibinu_client_free` / `yibinu_string_free` / `yibinu_version` 外，所有函数都返回一个
//!   以 NUL 结尾的 UTF-8 JSON 字符串，调用方必须用 `yibinu_string_free` 释放：
//!   `{"ok":true,"data":...}` 或 `{"ok":false,"error":{"kind":"...","message":"..."}}`
//! * `YibinuClient` 线程安全，可在多个线程中同时使用；同一会话的步骤需按顺序调用。
//! * 任何 panic 都会被捕获并转成 `{"kind":"internal"}` 错误，不会跨越 FFI 边界。

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use yibinu_auth::{AuthError, Client, Config};

/// 不透明句柄。
pub struct YibinuClient(Client);

fn envelope(r: Result<Value, (String, String)>) -> *mut c_char {
    let v = match r {
        Ok(data) => json!({"ok": true, "data": data}),
        Err((kind, message)) => json!({"ok": false, "error": {"kind": kind, "message": message}}),
    };
    // serde_json 输出不会包含内部 NUL
    CString::new(v.to_string()).unwrap_or_default().into_raw()
}

fn auth_err(e: AuthError) -> (String, String) {
    (e.kind().to_string(), e.to_string())
}

fn invalid(msg: &str) -> (String, String) {
    ("invalid_argument".into(), msg.into())
}

/// 读取 C 字符串参数。`null` → None。
unsafe fn opt_str<'a>(p: *const c_char, name: &str) -> Result<Option<&'a str>, (String, String)> {
    if p.is_null() {
        return Ok(None);
    }
    CStr::from_ptr(p)
        .to_str()
        .map(Some)
        .map_err(|_| invalid(&format!("{name} 不是合法的 UTF-8")))
}

unsafe fn req_str<'a>(p: *const c_char, name: &str) -> Result<&'a str, (String, String)> {
    opt_str(p, name)?.ok_or_else(|| invalid(&format!("{name} 不能为 NULL")))
}

unsafe fn client<'a>(c: *const YibinuClient) -> Result<&'a Client, (String, String)> {
    c.as_ref()
        .map(|c| &c.0)
        .ok_or_else(|| invalid("client 不能为 NULL"))
}

/// 执行并捕获 panic。
fn guard(f: impl FnOnce() -> Result<Value, (String, String)>) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => envelope(r),
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            envelope(Err(("internal".into(), msg)))
        }
    }
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, (String, String)> {
    serde_json::to_value(v).map_err(|e| ("internal".into(), e.to_string()))
}

/// 创建客户端。`config_json` 可为 NULL 或 JSON 对象（字段见 `Config`，缺省字段使用默认值）。
/// 成功时 `*out` 为新句柄，用 `yibinu_client_free` 释放。
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_client_new(
    config_json: *const c_char,
    out: *mut *mut YibinuClient,
) -> *mut c_char {
    guard(|| {
        if out.is_null() {
            return Err(invalid("out 不能为 NULL"));
        }
        *out = ptr::null_mut();
        let config: Config = match opt_str(config_json, "config_json")? {
            None => Config::default(),
            Some(s) if s.trim().is_empty() => Config::default(),
            Some(s) => {
                serde_json::from_str(s).map_err(|e| invalid(&format!("config_json 无效: {e}")))?
            }
        };
        let c = Client::new(config).map_err(auth_err)?;
        *out = Box::into_raw(Box::new(YibinuClient(c)));
        Ok(Value::Null)
    })
}

/// 释放客户端。传 NULL 无副作用。
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_client_free(c: *mut YibinuClient) {
    if !c.is_null() {
        drop(Box::from_raw(c));
    }
}

/// 释放本库返回的字符串。传 NULL 无副作用。
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// 库版本（静态字符串，无需释放）。
#[no_mangle]
pub extern "C" fn yibinu_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// data: LoginPage 对象
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_load_login_page(c: *const YibinuClient) -> *mut c_char {
    guard(|| to_value(client(c)?.load_login_page().map_err(auth_err)?))
}

/// data: bool
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_need_captcha(
    c: *const YibinuClient,
    username: *const c_char,
) -> *mut c_char {
    guard(|| {
        let u = req_str(username, "username")?;
        Ok(Value::Bool(client(c)?.need_captcha(u).map_err(auth_err)?))
    })
}

/// data: Base64 编码的验证码图片（JPEG）
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_fetch_captcha(c: *const YibinuClient) -> *mut c_char {
    guard(|| {
        Ok(Value::String(
            STANDARD.encode(client(c)?.fetch_captcha().map_err(auth_err)?),
        ))
    })
}

/// data: LoginResult。`captcha` 可为 NULL；需要验证码时返回 kind=captcha_required。
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_login_with_password(
    c: *const YibinuClient,
    username: *const c_char,
    password: *const c_char,
    captcha: *const c_char,
) -> *mut c_char {
    guard(|| {
        let (u, p) = (
            req_str(username, "username")?,
            req_str(password, "password")?,
        );
        let cap = opt_str(captcha, "captcha")?;
        to_value(
            client(c)?
                .login_with_password(u, p, cap)
                .map_err(auth_err)?,
        )
    })
}

/// data: SmsResult
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_send_sms_code(
    c: *const YibinuClient,
    mobile: *const c_char,
    captcha: *const c_char,
) -> *mut c_char {
    guard(|| {
        let (m, cap) = (
            req_str(mobile, "mobile")?,
            opt_str(captcha, "captcha")?.unwrap_or(""),
        );
        to_value(client(c)?.send_sms_code(m, cap).map_err(auth_err)?)
    })
}

/// data: LoginResult
///
/// # Safety
/// 指针参数必须为 NULL，或指向有效的 NUL 结尾字符串 / 由本库创建且尚未释放的对象。
#[no_mangle]
pub unsafe extern "C" fn yibinu_login_with_sms(
    c: *const YibinuClient,
    mobile: *const c_char,
    dynamic_code: *const c_char,
) -> *mut c_char {
    guard(|| {
        let (m, code) = (
            req_str(mobile, "mobile")?,
            req_str(dynamic_code, "dynamic_code")?,
        );
        to_value(client(c)?.login_with_sms(m, code).map_err(auth_err)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn take(p: *mut c_char) -> Value {
        let v = serde_json::from_str(CStr::from_ptr(p).to_str().unwrap()).unwrap();
        yibinu_string_free(p);
        v
    }

    #[test]
    fn null_handling() {
        unsafe {
            let v = take(yibinu_need_captcha(ptr::null(), ptr::null()));
            assert_eq!(v["ok"], false);
            assert_eq!(v["error"]["kind"], "invalid_argument");
            yibinu_client_free(ptr::null_mut());
            yibinu_string_free(ptr::null_mut());
        }
    }

    #[test]
    fn bad_config() {
        unsafe {
            let mut out = ptr::null_mut();
            let cfg = CString::new("{not json").unwrap();
            let v = take(yibinu_client_new(cfg.as_ptr(), &mut out));
            assert_eq!(v["error"]["kind"], "invalid_argument");
            assert!(out.is_null());

            let cfg = CString::new(r#"{"timeout_secs":3}"#).unwrap();
            let v = take(yibinu_client_new(cfg.as_ptr(), &mut out));
            assert_eq!(v["ok"], true);
            assert!(!out.is_null());
            assert_eq!((*out).0.config().timeout_secs, 3);
            yibinu_client_free(out);
        }
    }

    #[test]
    fn version() {
        let v = unsafe { CStr::from_ptr(yibinu_version()) };
        assert_eq!(v.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    }
}
