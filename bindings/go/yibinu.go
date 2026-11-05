// Package yibinu 是宜宾学院统一身份认证登录验证的 Go 绑定（基于 Rust 核心库的 C ABI）。
//
// 使用前先构建静态库：在仓库根目录运行 ./bindings/go/build.sh
//
//	c, err := yibinu.NewClient(nil)
//	if err != nil { ... }
//	defer c.Close()
//	res, err := c.LoginWithPassword("230110128", "secret", "")
//	if errors.Is(err, yibinu.ErrCaptchaRequired) {
//	    img, _ := c.FetchCaptcha()      // 展示给用户
//	    res, err = c.LoginWithPassword("230110128", "secret", answer)
//	}
package yibinu

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/yibinu-auth-ffi/include
#cgo LDFLAGS: ${SRCDIR}/lib/libyibinu_auth_ffi.a
#cgo linux LDFLAGS: -lssl -lcrypto -ldl -lpthread -lm
#cgo darwin LDFLAGS: -lssl -lcrypto -framework Security -framework CoreFoundation
#cgo windows LDFLAGS: -lssl -lcrypto -lws2_32 -luserenv -lbcrypt -lntdll
#include <stdlib.h>
#include "yibinu_auth.h"
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// Config 客户端配置。用 DefaultConfig() 获取默认值后再修改。
type Config struct {
	BaseURL     string `json:"base_url"`
	Service     string `json:"service"`
	TimeoutSecs int    `json:"timeout_secs"`
	VerifyTLS   bool   `json:"verify_tls"`
	UseEnvProxy bool   `json:"use_env_proxy"`
}

// DefaultConfig 返回默认配置（宜宾学院正式环境、校验证书、读取代理环境变量）。
func DefaultConfig() Config {
	return Config{
		BaseURL:     "https://authserver.yibinu.edu.cn/authserver",
		Service:     "https://ehall.yibinu.edu.cn:443/login?service=https://ehall.yibinu.edu.cn/new/index.html",
		TimeoutSecs: 10,
		VerifyTLS:   true,
		UseEnvProxy: true,
	}
}

// LoginForm 登录表单的隐藏字段与 salt。
type LoginForm struct {
	Fields map[string]string `json:"fields"`
	Salt   string            `json:"salt"`
}

// LoginPage 解析后的登录页。
type LoginPage struct {
	CaptchaSwitch string     `json:"captcha_switch"`
	FrontBackKey  string     `json:"front_back_key"`
	PasswordForm  *LoginForm `json:"password_form"`
	SMSForm       *LoginForm `json:"sms_form"`
}

// LoginResult 登录结果。凭据错误不是 error，而是 Success == false。
type LoginResult struct {
	Success  bool    `json:"success"`
	Message  string  `json:"message"`
	Redirect *string `json:"redirect"`
}

// SMSResult 发送短信验证码的结果。Code 为 success / error / captchaError / timeExpire。
type SMSResult struct {
	Sent       bool    `json:"sent"`
	Code       string  `json:"code"`
	Message    string  `json:"message"`
	RetryAfter *uint64 `json:"retry_after"`
}

// Error 认证流程错误。Kind 为稳定的错误类型标识。
type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Is 按 Kind 比较，使 errors.Is(err, ErrCaptchaRequired) 可用。
func (e *Error) Is(target error) bool {
	var t *Error
	return errors.As(target, &t) && t.Kind == e.Kind
}

// 可与 errors.Is 一起使用的哨兵错误。
var (
	ErrCaptchaRequired          = &Error{Kind: "captcha_required"}
	ErrSliderCaptchaUnsupported = &Error{Kind: "slider_captcha_unsupported"}
	ErrPageStructure            = &Error{Kind: "page_structure"}
	ErrUnexpectedResponse       = &Error{Kind: "unexpected_response"}
	ErrNetwork                  = &Error{Kind: "network"}
	ErrInvalidArgument          = &Error{Kind: "invalid_argument"}
	ErrInternal                 = &Error{Kind: "internal"}
	ErrClosed                   = &Error{Kind: "closed", Message: "client 已关闭"}
)

type envelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"error"`
}

// decode 解析 C 返回的 JSON 信封并释放字符串。
func decode(p *C.char, out any) error {
	if p == nil {
		return &Error{Kind: "internal", Message: "FFI 返回了 NULL"}
	}
	raw := C.GoString(p)
	C.yibinu_string_free(p)
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return &Error{Kind: "internal", Message: fmt.Sprintf("无法解析 FFI 返回值: %v", err)}
	}
	if !env.OK {
		if env.Error == nil {
			return &Error{Kind: "internal", Message: "FFI 返回失败但缺少错误信息"}
		}
		return &Error{Kind: env.Error.Kind, Message: env.Error.Message}
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

// cstr 把 Go 字符串转成 C 字符串；空字符串且 nullable 时返回 NULL。调用方负责 free。
func cstr(s string, nullable bool) *C.char {
	if s == "" && nullable {
		return nil
	}
	return C.CString(s)
}

func free(ps ...*C.char) {
	for _, p := range ps {
		if p != nil {
			C.free(unsafe.Pointer(p))
		}
	}
}

// Client 一次认证会话。可在多个 goroutine 间共享；取图 / 发短信 / 登录必须使用同一个 Client。
type Client struct {
	mu  sync.RWMutex
	ptr *C.YibinuClient
}

// NewClient 创建客户端；cfg 为 nil 时使用 DefaultConfig()。用完调用 Close()。
func NewClient(cfg *Config) (*Client, error) {
	c := DefaultConfig()
	if cfg != nil {
		c = *cfg
	}
	js, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	cjs := C.CString(string(js))
	defer free(cjs)
	var out *C.YibinuClient
	if err := decode(C.yibinu_client_new(cjs, &out), nil); err != nil {
		return nil, err
	}
	client := &Client{ptr: out}
	runtime.SetFinalizer(client, func(c *Client) { c.Close() })
	return client, nil
}

// Close 释放底层资源，可重复调用。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ptr != nil {
		C.yibinu_client_free(c.ptr)
		c.ptr = nil
	}
	return nil
}

func (c *Client) call(fn func(*C.YibinuClient) *C.char, out any) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil {
		return ErrClosed
	}
	return decode(fn(c.ptr), out)
}

// LoadLoginPage 获取并解析登录页（建立会话 cookie）。
func (c *Client) LoadLoginPage() (*LoginPage, error) {
	var p LoginPage
	err := c.call(func(h *C.YibinuClient) *C.char { return C.yibinu_load_login_page(h) }, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// NeedCaptcha 账号密码登录是否需要图形验证码。
func (c *Client) NeedCaptcha(username string) (bool, error) {
	u := cstr(username, false)
	defer free(u)
	var need bool
	err := c.call(func(h *C.YibinuClient) *C.char { return C.yibinu_need_captcha(h, u) }, &need)
	return need, err
}

// FetchCaptcha 获取一张新的图形验证码，返回 JPEG 字节。
func (c *Client) FetchCaptcha() ([]byte, error) {
	var b64 string
	if err := c.call(func(h *C.YibinuClient) *C.char { return C.yibinu_fetch_captcha(h) }, &b64); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(b64)
}

// LoginWithPassword 账号密码登录。captcha 为空且上游要求验证码时返回 ErrCaptchaRequired。
func (c *Client) LoginWithPassword(username, password, captcha string) (*LoginResult, error) {
	u, p, cap := cstr(username, false), cstr(password, false), cstr(captcha, true)
	defer free(u, p, cap)
	var r LoginResult
	err := c.call(func(h *C.YibinuClient) *C.char { return C.yibinu_login_with_password(h, u, p, cap) }, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// SendSMSCode 发送短信验证码（图形验证码必填）。
func (c *Client) SendSMSCode(mobile, captcha string) (*SMSResult, error) {
	m, cap := cstr(mobile, false), cstr(captcha, false)
	defer free(m, cap)
	var r SMSResult
	err := c.call(func(h *C.YibinuClient) *C.char { return C.yibinu_send_sms_code(h, m, cap) }, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// LoginWithSMS 用短信验证码登录（需先在同一 Client 上成功调用 SendSMSCode）。
func (c *Client) LoginWithSMS(mobile, code string) (*LoginResult, error) {
	m, d := cstr(mobile, false), cstr(code, false)
	defer free(m, d)
	var r LoginResult
	err := c.call(func(h *C.YibinuClient) *C.char { return C.yibinu_login_with_sms(h, m, d) }, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// CaptchaSolver 接收验证码图片，返回用户输入的答案。
type CaptchaSolver func(image []byte) (string, error)

// VerifyLogin 便捷函数：账号密码登录，需要验证码时调用 solver。cfg 为 nil 时使用默认配置。
func VerifyLogin(cfg *Config, username, password string, solver CaptchaSolver) (*LoginResult, error) {
	c, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.LoadLoginPage(); err != nil {
		return nil, err
	}
	res, err := c.LoginWithPassword(username, password, "")
	if !errors.Is(err, ErrCaptchaRequired) || solver == nil {
		return res, err
	}
	img, err := c.FetchCaptcha()
	if err != nil {
		return nil, err
	}
	answer, err := solver(img)
	if err != nil {
		return nil, err
	}
	return c.LoginWithPassword(username, password, answer)
}

// Version 返回底层 Rust 库版本。
func Version() string { return C.GoString(C.yibinu_version()) }
