"""端到端测试：Python → PyO3 → Rust → 本地假 authserver（crates/mock-upstream），不访问外网。

运行: maturin develop && python -m unittest discover -s tests -v
"""
import os
import subprocess
import unittest

import verify_yibinu as v

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CAPTCHA = "abcd"
SMS_CODE = "123456"
JPEG = b"\xff\xd8\xff\xe0fake-jpeg"


def mock_bin() -> str:
    path = os.environ.get("YIBINU_MOCK_BIN") or os.path.join(ROOT, "target", "release", "yibinu-mock-upstream")
    if not os.path.exists(path):
        subprocess.run(["cargo", "build", "--release", "-p", "yibinu-mock-upstream"], cwd=ROOT, check=True)
    return path


class MockUpstream:
    def __init__(self, *args):
        self.proc = subprocess.Popen([mock_bin(), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline().strip()
        assert line.startswith("PORT="), line
        self.base_url = f"http://127.0.0.1:{line[5:]}/authserver"

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


class Base(unittest.TestCase):
    mock_args = ()

    def setUp(self):
        self.mock = MockUpstream(*self.mock_args)
        self.addCleanup(self.mock.close)
        self.kw = dict(base_url=self.mock.base_url, use_env_proxy=False)

    def client(self):
        return v.Client(**self.kw)


class ClientTests(Base):
    def test_page(self):
        page = self.client().load_login_page()
        self.assertEqual(page["captcha_switch"], "1")
        self.assertEqual(page["password_form"]["salt"], "G9KhHtvLf0t2HKrD")
        self.assertEqual(page["sms_form"]["fields"]["cllt"], "dynamicLogin")

    def test_password_login_with_captcha(self):
        c = self.client()
        with self.assertRaises(v.CaptchaRequired):
            c.login_with_password("230110128", "secret!")
        self.assertEqual(c.fetch_captcha(), JPEG)
        r = c.login_with_password("230110128", "secret!", captcha=CAPTCHA)
        self.assertTrue(r.success, r)
        self.assertTrue(r)  # __bool__
        self.assertIn("ticket=", r.redirect)

    def test_wrong_captcha(self):
        c = self.client()
        c.fetch_captcha()
        r = c.login_with_password("u", "secret!", "zzzz")
        self.assertFalse(r)
        self.assertEqual(r.message, "验证码错误")

    def test_sms(self):
        c = self.client()
        c.fetch_captcha()
        s = c.send_sms_code("13800000000", CAPTCHA)
        self.assertTrue(s.sent)
        self.assertEqual(s.retry_after, 120)
        self.assertEqual(c.login_with_sms("13800000000", "000000").message, "动态码错误")
        self.assertTrue(c.login_with_sms("13800000000", SMS_CODE).success)

    def test_exception_hierarchy(self):
        self.assertTrue(issubclass(v.CaptchaRequired, v.AuthError))
        self.assertTrue(issubclass(v.NetworkError, v.AuthError))
        self.assertEqual(v.CaptchaRequired.__module__, "verify_yibinu")
        with self.assertRaises(v.InvalidArgumentError):
            self.client().login_with_password("", "p")
        with self.assertRaises(v.NetworkError):
            v.Client(base_url="http://127.0.0.1:1/authserver", use_env_proxy=False, timeout=2).load_login_page()
        with self.assertRaises(v.InvalidArgumentError):
            v.Client(base_url="::bad")

    def test_encrypt_password(self):
        self.assertNotEqual(v.encrypt_password("x", "G9KhHtvLf0t2HKrD"), v.encrypt_password("x", "G9KhHtvLf0t2HKrD"))
        with self.assertRaises(v.InvalidArgumentError):
            v.encrypt_password("x", "short")


class LegacyApiTests(Base):
    """旧版纯 Python verify_yibinu 的 API 仍然可用。"""

    def test_verify_login_with_solver(self):
        seen = []
        ok, msg = v.verify_login("u", "secret!", captcha_solver=lambda img: seen.append(img) or CAPTCHA, **self.kw)
        self.assertTrue(ok, msg)
        self.assertEqual(seen, [JPEG])

    def test_verify_login_without_solver_returns_tuple(self):
        ok, msg = v.verify_login("u", "secret!", **self.kw)
        self.assertFalse(ok)
        self.assertIn("验证码", msg)

    def test_verify_login_wrong_password(self):
        ok, msg = v.verify_login("u", "bad", captcha_solver=lambda img: CAPTCHA, **self.kw)
        self.assertEqual((ok, msg), (False, "您提供的用户名或者密码有误"))

    def test_verify_sms_login(self):
        ok, msg = v.verify_sms_login("13800000000", code_provider=lambda: SMS_CODE,
                                     captcha_solver=lambda img: CAPTCHA, **self.kw)
        self.assertTrue(ok, msg)

    def test_yibinu_auth_captcha_required_has_image(self):
        auth = v.YibinuAuth(**self.kw)
        auth.load_login_page()
        with self.assertRaises(v.CaptchaRequired) as ctx:
            auth.login_with_password("u", "secret!")
        self.assertEqual(ctx.exception.image, JPEG)
        # 拿到答案后在同一个实例上重试
        self.assertEqual(auth.login_with_password("u", "secret!", captcha=CAPTCHA), (True, "Login successful"))

    def test_cli(self):
        from unittest import mock
        with mock.patch("builtins.input", return_value=CAPTCHA), mock.patch("builtins.print"):
            self.assertEqual(v.main(["--base-url", self.mock.base_url, "230110128", "secret!"]), 0)
            self.assertEqual(v.main(["--base-url", self.mock.base_url, "password", "u", "bad"]), 1)
            self.assertEqual(v.main(["--timeout", "5", "--base-url", self.mock.base_url, "u", "secret!"]), 0)

    def test_legacy_argv_detection(self):
        from verify_yibinu._cli import _insert_legacy_subcommand as f
        self.assertEqual(f(["u", "p"]), ["password", "u", "p"])
        self.assertEqual(f(["--timeout", "5", "u", "p"]), ["--timeout", "5", "password", "u", "p"])
        self.assertEqual(f(["sms", "138"]), ["sms", "138"])
        self.assertEqual(f(["--insecure", "password", "u", "p"]), ["--insecure", "password", "u", "p"])


class NoCaptchaTests(Base):
    mock_args = ("--no-captcha",)

    def test_login_without_captcha(self):
        self.assertTrue(self.client().login_with_password("u", "secret!").success)

    def test_releases_gil_threads(self):
        import concurrent.futures as cf
        c = self.client()
        with cf.ThreadPoolExecutor(8) as ex:
            self.assertTrue(all(ex.map(lambda _: c.login_with_password("u", "secret!").success, range(16))))


if __name__ == "__main__":
    unittest.main()
