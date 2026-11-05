# verify_yibinu_ehall

宜宾学院 (Yibin University) 统一身份认证登录验证脚本。已适配升级后的上游认证系统（图形验证码、短信登录等新接口）。

## 特性

- **账号密码登录**：同步 wisedu 登录页的 AES-CBC 加密算法，支持图形验证码。
- **短信验证码登录**：取图形验证码 → 发送短信 → 校验短信码，手机号按上游要求 AES 加密。
- **Legacy TLS 支持**：内置 `TLSAdapter` 降级安全策略，并**把最高协议版本固定为 TLS 1.2**（上游只支持 1.2，OpenSSL 3.x 默认先发 1.3 握手会导致 `UNEXPECTED_EOF_WHILE_READING` / 连接重置）。**默认校验证书**，仅在显式传 `--insecure` / `verify_tls=False` 时关闭。
- **按表单作用域解析**：登录页同一 id 在多个表单中重复，脚本按 `pwdFromId` / `phoneFromId` 分别取 `lt`、`execution`、`pwdEncryptSalt`。
- **滑块验证码检测**：上游 `captchaSwitch=2` 时会明确报错，而不是静默失败。

## 依赖

```bash
pip install requests beautifulsoup4 pycryptodome
```

## 命令行

```bash
# 账号密码（建议对密码使用单引号包裹，防止 Shell 字符转义）
python verify_yibinu.py password <学号> '<密码>'
python verify_yibinu.py <学号> '<密码>'      # 旧用法，仍然兼容

# 短信登录：会提示输入图形验证码，再输入收到的短信验证码
python verify_yibinu.py sms <手机号>

# 选项
#   --insecure    不校验服务器证书（不推荐）
#   --timeout N   请求超时秒数
#   --debug       输出调试日志
```

需要图形验证码时，图片会保存到临时文件并提示路径，由你查看后手动输入。成功时退出码为 0，失败为 1。

## 作为库使用

```python
from verify_yibinu import verify_login, verify_sms_login, YibinuAuth

# 简单接口，返回 (success, message)
ok, msg = verify_login("230110128", "password123", captcha_solver=lambda img_bytes: "ab12")
ok, msg = verify_sms_login("13800000000", code_provider=lambda: input("短信码: "),
                           captcha_solver=lambda img_bytes: "ab12")

# 需要自行控制流程时使用 YibinuAuth（验证码、短信码都绑定在会话上，必须复用同一个实例）
client = YibinuAuth()
client.load_login_page()
image = client.fetch_captcha()                       # 展示给用户
ok, msg = client.send_sms_code("13800000000", captcha="ab12")
ok, msg = client.login_with_sms("13800000000", "123456")
```

未提供 `captcha_solver` 且上游要求验证码时，`verify_login` 返回 `(False, "需要图形验证码...")`；直接使用 `YibinuAuth` 则抛出携带图片字节的 `CaptchaRequired`。

## 上游接口（升级后）

| 用途 | 接口 |
|---|---|
| 是否需要验证码 | `GET /authserver/checkNeedCaptcha.htl?username=` → `{"isNeed": bool}` |
| 图形验证码 | `GET /authserver/getCaptcha.htl` → 图片 |
| 发送短信 | `POST /authserver/dynamicCode/getDynamicCode.htl`，`mobile`（AES，密钥为页面 `frontBackKey`）+ `captcha`；返回 `code`: `success` / `error` / `captchaError` / `timeExpire` |
| 登录 | `POST /authserver/login`，`cllt=userNameLogin`（`password` 为 AES，密钥为表单内 `pwdEncryptSalt`）或 `cllt=dynamicLogin`（`dynamicCode`）；成功返回 302 |

旧的 `needCaptcha.html`（同时下发 salt）已不可用，salt 现在只能从登录页表单取。

## 测试

### 1. 离线单元测试（不联网）

```bash
pip install requests beautifulsoup4 pycryptodome
python -m unittest discover -s tests -v
```

用假适配器模拟上游接口，页面 fixture 取自升级后的真实登录页。

### 2. 真实上游联调（需要你本人的账号）

验证码需要人工查看并输入，脚本会把图片保存到临时文件并打印路径，请打开图片后在终端输入。

```bash
# 账号密码登录（密码用单引号包裹）
python verify_yibinu.py password <学号> '<密码>'

# 短信登录：依次输入图形验证码、收到的短信验证码
python verify_yibinu.py sms <手机号>

# 输出调试日志
python verify_yibinu.py --debug password <学号> '<密码>'

# 服务器证书链有问题时的临时排查手段（不推荐）
python verify_yibinu.py --insecure password <学号> '<密码>'
```

预期结果：成功输出 `Result: Success`（退出码 0）；失败输出 `Result: Failed` 和上游返回的原因（退出码 1）。

### 3. 只测只读接口（不提交任何凭据）

```bash
python - <<'EOF'
import verify_yibinu as v
c = v.YibinuAuth()
page = c.load_login_page()
print(page["captcha_switch"], list(page["forms"]))   # 期望: 1 ['pwdFromId', 'phoneFromId']
print(c.need_captcha("任意学号"))                      # 期望: True / False
print(len(c.fetch_captcha()))                         # 期望: 约 1~2 KB 的图片字节数
EOF
```

## 许可证

MIT License
