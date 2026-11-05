package yibinu

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// 端到端测试：通过 FFI 访问本地假 authserver（crates/mock-upstream），不访问外网。

const (
	captchaAnswer = "abcd"
	smsCode       = "123456"
)

var jpeg = []byte("\xff\xd8\xff\xe0fake-jpeg")

func mockBin(t *testing.T) string {
	t.Helper()
	root, _ := filepath.Abs("../..")
	if p := os.Getenv("YIBINU_MOCK_BIN"); p != "" {
		return p
	}
	bin := filepath.Join(root, "target", "release", "yibinu-mock-upstream")
	if _, err := os.Stat(bin); err != nil {
		cmd := exec.Command("cargo", "build", "--release", "-p", "yibinu-mock-upstream")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("构建 mock 失败: %v\n%s", err, out)
		}
	}
	return bin
}

// startMock 启动假上游，返回指向它的配置。
func startMock(t *testing.T, args ...string) *Config {
	t.Helper()
	cmd := exec.Command(mockBin(t), args...)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "PORT=") {
		t.Fatalf("mock 启动失败: %q %v", line, err)
	}
	cfg := DefaultConfig()
	cfg.BaseURL = "http://127.0.0.1:" + strings.TrimSpace(strings.TrimPrefix(line, "PORT=")) + "/authserver"
	cfg.UseEnvProxy = false
	return &cfg
}

func newClient(t *testing.T, cfg *Config) *Client {
	t.Helper()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestPasswordLoginWithCaptcha(t *testing.T) {
	c := newClient(t, startMock(t))
	page, err := c.LoadLoginPage()
	if err != nil {
		t.Fatal(err)
	}
	if page.CaptchaSwitch != "1" || page.PasswordForm == nil || page.SMSForm == nil {
		t.Fatalf("page = %+v", page)
	}
	if page.PasswordForm.Fields["cllt"] != "userNameLogin" {
		t.Fatalf("fields = %v", page.PasswordForm.Fields)
	}

	_, err = c.LoginWithPassword("230110128", "secret!", "")
	if !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("want ErrCaptchaRequired, got %v", err)
	}
	var e *Error
	if !errors.As(err, &e) || e.Message == "" {
		t.Fatalf("error message missing: %v", err)
	}

	img, err := c.FetchCaptcha()
	if err != nil || !bytes.Equal(img, jpeg) {
		t.Fatalf("captcha = %q, %v", img, err)
	}
	res, err := c.LoginWithPassword("230110128", "secret!", captchaAnswer)
	if err != nil || !res.Success || res.Redirect == nil || !strings.Contains(*res.Redirect, "ticket=") {
		t.Fatalf("res = %+v, %v", res, err)
	}
}

func TestWrongPasswordIsResultNotError(t *testing.T) {
	c := newClient(t, startMock(t, "--no-captcha"))
	res, err := c.LoginWithPassword("u", "wrong", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Success || res.Message != "您提供的用户名或者密码有误" {
		t.Fatalf("res = %+v", res)
	}
}

func TestSMSFlow(t *testing.T) {
	c := newClient(t, startMock(t))
	if _, err := c.FetchCaptcha(); err != nil {
		t.Fatal(err)
	}
	bad, err := c.SendSMSCode("13800000000", "zzzz")
	if err != nil || bad.Sent || bad.Code != "captchaError" {
		t.Fatalf("bad = %+v, %v", bad, err)
	}
	sent, err := c.SendSMSCode("13800000000", captchaAnswer)
	if err != nil || !sent.Sent || sent.RetryAfter == nil || *sent.RetryAfter != 120 {
		t.Fatalf("sent = %+v, %v", sent, err)
	}
	wrong, err := c.LoginWithSMS("13800000000", "000000")
	if err != nil || wrong.Success || wrong.Message != "动态码错误" {
		t.Fatalf("wrong = %+v, %v", wrong, err)
	}
	ok, err := c.LoginWithSMS("13800000000", smsCode)
	if err != nil || !ok.Success {
		t.Fatalf("ok = %+v, %v", ok, err)
	}
}

func TestVerifyLoginHelper(t *testing.T) {
	cfg := startMock(t)
	var seen []byte
	res, err := VerifyLogin(cfg, "u", "secret!", func(img []byte) (string, error) {
		seen = img
		return captchaAnswer, nil
	})
	if err != nil || !res.Success || !bytes.Equal(seen, jpeg) {
		t.Fatalf("res = %+v, err = %v, seen = %q", res, err, seen)
	}
	// 没有 solver 时把 ErrCaptchaRequired 交给调用方
	if _, err := VerifyLogin(cfg, "u", "secret!", nil); !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("want ErrCaptchaRequired, got %v", err)
	}
}

func TestErrorKinds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseURL = "http://127.0.0.1:1/authserver"
	cfg.UseEnvProxy = false
	cfg.TimeoutSecs = 2
	c := newClient(t, &cfg)
	if _, err := c.LoadLoginPage(); !errors.Is(err, ErrNetwork) {
		t.Fatalf("want ErrNetwork, got %v", err)
	}
	if _, err := c.LoginWithPassword("", "p", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument, got %v", err)
	}
	bad := DefaultConfig()
	bad.BaseURL = "::not a url"
	if _, err := NewClient(&bad); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument, got %v", err)
	}
}

func TestCloseAndConcurrency(t *testing.T) {
	c := newClient(t, startMock(t, "--no-captcha"))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.NeedCaptcha("u"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	c.Close()
	c.Close() // 幂等
	if _, err := c.NeedCaptcha("u"); !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestVersion(t *testing.T) {
	if Version() == "" {
		t.Fatal("empty version")
	}
}
