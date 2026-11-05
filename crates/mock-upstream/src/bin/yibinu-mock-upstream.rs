//! 启动假 authserver，供 Python / Go / Node 绑定的测试使用。
//! 打印一行 `PORT=<port>` 后持续运行，直到 stdin 关闭。
use std::io::{Read, Write};

fn main() {
    let need_captcha = !std::env::args().any(|a| a == "--no-captcha");
    let mock = yibinu_mock_upstream::MockUpstream::start(yibinu_mock_upstream::Behavior {
        need_captcha,
        ..Default::default()
    });
    println!("PORT={}", mock.port);
    std::io::stdout().flush().unwrap();
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
}
