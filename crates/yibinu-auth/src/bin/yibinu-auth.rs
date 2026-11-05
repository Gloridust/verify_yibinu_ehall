//! 命令行工具，用法与原 Python 版 verify_yibinu.py 保持一致：
//!
//!   yibinu-auth password <学号> '<密码>'
//!   yibinu-auth <学号> '<密码>'            # 旧用法
//!   yibinu-auth sms <手机号>
//!
//! 选项：--insecure  --timeout <秒>  --base-url <url>

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use yibinu_auth::{AuthError, Client, Config, LoginResult};

const USAGE: &str = "\
宜宾学院统一身份认证登录验证

用法:
  yibinu-auth [选项] password <学号> '<密码>'
  yibinu-auth [选项] sms <手机号>
  yibinu-auth [选项] <学号> '<密码>'          (兼容旧用法)

选项:
  --insecure         不校验服务器证书（不推荐）
  --timeout <秒>     单次请求超时，默认 10
  --base-url <url>   authserver 地址，默认宜宾学院正式环境
  -h, --help         显示帮助

需要图形验证码时，图片会保存到临时文件并打印路径，查看后在终端输入。
成功退出码 0，登录失败 1，其他错误 2。";

fn prompt(msg: &str) -> io::Result<String> {
    eprint!("{msg}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn ask_captcha(client: &Client) -> Result<String, AuthError> {
    let image = client.fetch_captcha()?;
    let path = std::env::temp_dir().join(format!("yibinu_captcha_{}.jpg", std::process::id()));
    std::fs::write(&path, image)?;
    eprintln!("图形验证码已保存到: {}", path.display());
    Ok(prompt("请输入图形验证码: ")?)
}

fn run_password(client: &Client, username: &str, password: &str) -> Result<LoginResult, AuthError> {
    client.load_login_page()?;
    match client.login_with_password(username, password, None) {
        Err(AuthError::CaptchaRequired) => {
            let captcha = ask_captcha(client)?;
            client.login_with_password(username, password, Some(&captcha))
        }
        other => other,
    }
}

fn run_sms(client: &Client, mobile: &str) -> Result<LoginResult, AuthError> {
    client.load_login_page()?;
    let captcha = ask_captcha(client)?;
    let sent = client.send_sms_code(mobile, &captcha)?;
    if !sent.sent {
        return Ok(LoginResult {
            success: false,
            message: sent.message,
            redirect: None,
        });
    }
    eprintln!("{}", sent.message);
    let code = prompt("请输入短信验证码: ")?;
    client.login_with_sms(mobile, &code)
}

fn main() -> ExitCode {
    let mut config = Config::default();
    let mut positional = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--insecure" => config.verify_tls = false,
            "--timeout" => match args.next().and_then(|v| v.parse().ok()) {
                Some(t) => config.timeout_secs = t,
                None => return usage_error("--timeout 需要一个整数"),
            },
            "--base-url" => match args.next() {
                Some(u) => config.base_url = u,
                None => return usage_error("--base-url 需要一个地址"),
            },
            s if s.starts_with('-') && s.len() > 1 => return usage_error(&format!("未知选项 {s}")),
            _ => positional.push(a),
        }
    }

    let client = match Client::new(config) {
        Ok(c) => c,
        Err(e) => return report_error(e),
    };
    let result = match positional
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["password", user, pwd] => run_password(&client, user, pwd),
        ["sms", mobile] => run_sms(&client, mobile),
        [user, pwd] if *user != "password" && *user != "sms" => run_password(&client, user, pwd),
        _ => return usage_error("参数数量不正确"),
    };

    match result {
        Ok(r) => {
            println!("\nResult: {}", if r.success { "Success" } else { "Failed" });
            println!("Message: {}", r.message);
            if r.success {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => report_error(e),
    }
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("错误: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn report_error(e: AuthError) -> ExitCode {
    println!("\nResult: Failed");
    println!("Message: {e}");
    ExitCode::from(2)
}
