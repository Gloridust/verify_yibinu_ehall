# verify_yibinu_ehall

宜宾学院 (Yibin University) 统一身份认证登录验证脚本。

## 特性

- **AES 逆向实现**：同步 wisedu 登录页面的 AES-CBC 加密算法。
- **Legacy TLS 支持**：内置 `TLSAdapter` 强制降级安全策略，解决 `UNEXPECTED_EOF_WHILE_READING` 握手异常。
- **自动化流**：自动处理 `lt`, `execution`, `salt` 等动态参数及验证码状态检查。

## 依赖

```bash
pip install requests beautifulsoup4 pycryptodome
```

## 运行

```bash
# 建议对密码使用单引号包裹，防止 Shell 字符转义
python verify_yibinu.py <学号> '<密码>'
# 示例
python verify_yibinu.py 230110128 'password123'
```

## 核心逻辑

1. **Session 初始化**：挂载自定义 `HTTPAdapter` 以兼容陈旧的服务器 TLS 配置。
2. **预检**：获取登录页面隐藏字段，并根据 `needCaptcha.html` 判定加密盐值。
3. **加密**：构造 64 位随机前缀并进行 AES-CBC 加密。
4. **验证**：通过重定向状态码 (302) 判定认证状态。

## 许可证

MIT License
