# verify_yibinu_ehall

宜宾学院 (Yibin University) 统一身份认证登录验证。核心用 **Rust** 实现，提供 **Python / Go / Node.js** 绑定、C ABI 和命令行工具。

## 特性

- **账号密码登录**：同步上游 `encrypt.js` 的 AES-CBC 加密，支持图形验证码。
- **短信验证码登录**：取图形验证码 → 发送短信 → 校验短信码，手机号按上游要求 AES 加密。
- **TLS**：基于 OpenSSL，**最高协议版本固定为 TLS 1.2**（上游只支持 1.2），`SECLEVEL=1` 兼容旧加密套件，**默认校验证书**。
- **按表单作用域解析**：登录页同一 id 在多个表单中重复，分别从 `pwdFromId` / `phoneFromId` 取 `lt`、`execution`、`pwdEncryptSalt`。
- **滑块验证码检测**：上游 `captchaSwitch=2` 时返回明确错误，不静默失败。
- **代理**：读取 `HTTPS_PROXY` / `NO_PROXY` 环境变量（可关闭）。
- **验证码不做识别**：图片交给调用方展示，由用户输入答案。

## 项目结构

| 路径 | 说明 |
|---|---|
| `crates/yibinu-auth` | Rust 核心库 + 命令行工具 `yibinu-auth` |
| `crates/yibinu-auth-ffi` | C ABI（`include/yibinu_auth.h`），供 Go / C / 其他语言调用 |
| `bindings/python` | Python 绑定（PyO3 + maturin），包名 `verify_yibinu`，兼容旧版 API |
| `bindings/go` | Go 绑定（cgo，静态链接） |
| `bindings/node` | Node.js 绑定（napi-rs），全部异步，不阻塞事件循环 |
| `crates/mock-upstream` | 测试用的假 authserver，所有语言的端到端测试共用 |

## 构建依赖

- Rust ≥ 1.82（`rustup` 安装）
- OpenSSL 开发库：Debian/Ubuntu `apt install libssl-dev pkg-config`，macOS `brew install openssl`
  - 或者开启 `vendored-openssl` 特性静态编译 OpenSSL（需要 `perl`、`make`），产物不再依赖目标机器的 libssl。Python wheel 默认开启。
- 按需：Python ≥ 3.9 + `pip install maturin`；Go ≥ 1.21；Node.js ≥ 16

## 使用

所有语言的 API 形状一致：

1. 创建 `Client`（一个 Client = 一次会话；**取图、发短信、登录必须用同一个 Client**，因为验证码绑定在会话 cookie 上）
2. 登录时如果上游要求图形验证码，会得到 `captcha_required` 错误 → 调用 `fetch_captcha()` 取图展示给用户 → 带上答案重新登录
3. **凭据错误不是异常**：返回 `success = false` 的结果，`message` 为上游提示（如「您提供的用户名或者密码有误」）

### 命令行

```bash
cargo build --release -p yibinu-auth
./target/release/yibinu-auth password <学号> '<密码>'
./target/release/yibinu-auth sms <手机号>
./target/release/yibinu-auth <学号> '<密码>'          # 兼容旧用法
# 选项：--insecure（不校验证书，不推荐）  --timeout <秒>  --base-url <url>
```

需要图形验证码时，图片保存到临时文件并打印路径，查看后在终端输入。退出码：成功 0，登录失败 1，其他错误 2。

### Rust

```rust
use yibinu_auth::{AuthError, Client, Config};

let client = Client::new(Config::default())?;
client.load_login_page()?;
let result = match client.login_with_password("230110128", "secret", None) {
    Err(AuthError::CaptchaRequired) => {
        let image = client.fetch_captcha()?;   // JPEG 字节，展示给用户
        client.login_with_password("230110128", "secret", Some("ab12"))?
    }
    other => other?,
};
println!("{} {}", result.success, result.message);

// 短信登录
client.fetch_captcha()?;
let sent = client.send_sms_code("13800000000", "ab12")?;
if sent.sent {
    let r = client.login_with_sms("13800000000", "123456")?;
}
```

### Python

```bash
cd bindings/python
pip install maturin
maturin develop --release          # 安装到当前环境；或 maturin build --release 生成 wheel
```

```python
from verify_yibinu import Client, CaptchaRequired

c = Client()                       # 可选参数：base_url, timeout, verify_tls, use_env_proxy
c.load_login_page()
try:
    r = c.login_with_password("230110128", "secret")
except CaptchaRequired:
    image = c.fetch_captcha()      # bytes
    r = c.login_with_password("230110128", "secret", captcha=input("验证码: "))
print(r.success, r.message)

# 旧版 API 仍可用（返回 (success, message)，不抛异常）
from verify_yibinu import verify_login, verify_sms_login
ok, msg = verify_login("230110128", "secret", captcha_solver=lambda img: "ab12")
```

安装后提供命令行 `verify-yibinu`（也可用 `python -m verify_yibinu`），参数与上面的 CLI 相同。网络请求期间会释放 GIL，可在多线程中使用。

### Go

```bash
./bindings/go/build.sh             # 构建静态库到 bindings/go/lib/（可加 --vendored-openssl）
```

```go
import (
    "errors"
    yibinu "github.com/Gloridust/verify_yibinu_ehall/bindings/go"
)

c, err := yibinu.NewClient(nil)    // nil = DefaultConfig()
if err != nil { return err }
defer c.Close()

res, err := c.LoginWithPassword("230110128", "secret", "")
if errors.Is(err, yibinu.ErrCaptchaRequired) {
    img, _ := c.FetchCaptcha()      // []byte，展示给用户
    res, err = c.LoginWithPassword("230110128", "secret", answer)
}

// 便捷函数
res, err = yibinu.VerifyLogin(nil, "230110128", "secret", func(img []byte) (string, error) { return answer, nil })
```

`Client` 可在多个 goroutine 间共享。错误可用 `errors.Is` 与 `ErrCaptchaRequired`、`ErrNetwork` 等哨兵比较。

### Node.js

```bash
cd bindings/node
npm run build                      # cargo 构建并生成 yibinu_auth.node（可加 -- --vendored-openssl）
```

```js
const { Client, CaptchaRequiredError, verifyLogin } = require('verify-yibinu');

const c = new Client();            // 可选：{ baseUrl, timeoutSecs, verifyTls, useEnvProxy }
await c.loadLoginPage();
let r;
try {
  r = await c.loginWithPassword('230110128', 'secret');
} catch (e) {
  if (!(e instanceof CaptchaRequiredError)) throw e;
  const image = await c.fetchCaptcha();   // Buffer
  r = await c.loginWithPassword('230110128', 'secret', answer);
}

// 便捷函数
r = await verifyLogin('230110128', 'secret', { captchaSolver: async (img) => answer });
```

附带 TypeScript 类型定义（`index.d.ts`）。所有错误都有 `code` 属性。

### C / 其他语言

链接 `target/release/libyibinu_auth_ffi.{a,so,dylib}`，接口见 [`crates/yibinu-auth-ffi/include/yibinu_auth.h`](crates/yibinu-auth-ffi/include/yibinu_auth.h)。每个函数返回 JSON 信封 `{"ok":true,"data":...}` / `{"ok":false,"error":{"kind","message"}}`，用 `yibinu_string_free()` 释放。

### 错误类型

| kind | Python | Go | Node.js | 含义 |
|---|---|---|---|---|
| `captcha_required` | `CaptchaRequired` | `ErrCaptchaRequired` | `CaptchaRequiredError` | 需要图形验证码 |
| `slider_captcha_unsupported` | `SliderCaptchaUnsupported` | `ErrSliderCaptchaUnsupported` | `SliderCaptchaUnsupportedError` | 上游启用了滑块验证码 |
| `page_structure` | `PageStructureError` | `ErrPageStructure` | `PageStructureError` | 登录页结构变化 |
| `unexpected_response` | `UnexpectedResponseError` | `ErrUnexpectedResponse` | `UnexpectedResponseError` | 上游返回异常内容 |
| `network` | `NetworkError` | `ErrNetwork` | `NetworkError` | 网络 / TLS / 超时 |
| `invalid_argument` | `InvalidArgumentError` | `ErrInvalidArgument` | `InvalidArgumentError` | 参数非法 |

Python 的异常都继承自 `AuthError`，Node.js 的都继承自 `YibinuError`。

## 测试

### 1. 离线测试（不联网）

所有语言的端到端测试都访问本地假 authserver（`crates/mock-upstream`），页面 fixture 取自升级后的真实登录页。

```bash
# Rust（核心库、C ABI、假上游）
cargo test --workspace

# Go
./bindings/go/build.sh && (cd bindings/go && go test ./...)

# Python
(cd bindings/python && maturin develop && python -m unittest discover -s tests -v)

# Node.js
(cd bindings/node && npm run build && npm test)
```

### 2. 真实上游联调（需要你本人的账号）

验证码需要人工查看并输入：图片保存到临时文件并打印路径，打开后在终端输入。

```bash
cargo build --release -p yibinu-auth

# 账号密码登录（密码用单引号包裹）
./target/release/yibinu-auth password <学号> '<密码>'

# 短信登录：依次输入图形验证码、收到的短信验证码
./target/release/yibinu-auth sms <手机号>

# 服务器证书链有问题时的临时排查手段（不推荐）
./target/release/yibinu-auth --insecure password <学号> '<密码>'
```

预期结果：成功输出 `Result: Success`（退出码 0）；失败输出 `Result: Failed` 和上游返回的原因（退出码 1）。

### 3. 只测只读接口（不提交任何凭据）

```bash
cargo run --example live_probe
# captcha_switch = 1        （1 = 图形验证码；2 = 滑块，不支持）
# password form  = true
# sms form       = true
# need_captcha   = true / false
# captcha bytes  = 约 1~2 KB
```

## 上游接口（2026-11 升级后）

| 用途 | 接口 |
|---|---|
| 是否需要验证码 | `GET /authserver/checkNeedCaptcha.htl?username=` → `{"isNeed": bool}` |
| 图形验证码 | `GET /authserver/getCaptcha.htl` → JPEG |
| 发送短信 | `POST /authserver/dynamicCode/getDynamicCode.htl`，`mobile`（AES，密钥为页面 `frontBackKey`）+ `captcha`；返回 `code`: `success` / `error` / `captchaError` / `timeExpire` |
| 登录 | `POST /authserver/login`，`cllt=userNameLogin`（`password` 为 AES，密钥为表单内 `pwdEncryptSalt`）或 `cllt=dynamicLogin`（`dynamicCode`）；成功返回 302 |

加密算法：明文 = 64 位随机字符 + 原文，key = salt，IV = 16 位随机字符，AES-CBC + PKCS7，Base64 输出。

## 从旧版 Python 脚本迁移

旧的单文件 `verify_yibinu.py` 已由 Rust 实现替代：

- **Python 调用方**：安装 `bindings/python` 后，`from verify_yibinu import verify_login, verify_sms_login, YibinuAuth` 用法不变。
- **命令行**：`python verify_yibinu.py <学号> '<密码>'` 改为 `verify-yibinu <学号> '<密码>'`（Python 包）或 `yibinu-auth <学号> '<密码>'`（Rust 二进制）。
- 依赖从 `requests` / `beautifulsoup4` / `pycryptodome` 变为单个原生扩展。

## 许可证

MIT License
