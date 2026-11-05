"""离线测试：用假的 HTTP 适配器模拟升级后的上游认证接口，不访问网络。

运行: python -m unittest discover -s tests -v
"""
import base64
import json
import os
import sys
import unittest
from urllib.parse import parse_qs, urlparse

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import verify_yibinu as v  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "login_page.html")
with open(FIXTURE, encoding="utf-8") as f:
    LOGIN_HTML = f.read()

PWD_SALT = "G9KhHtvLf0t2HKrD"
FRONT_BACK_KEY = "rjBFAaHsNkKAhpoi"
JPEG = b"\xff\xd8\xff\xe0fake-jpeg"


def decrypt(token: str, salt: str) -> str:
    """服务端视角解密：IV 无关紧要，前 64 字符是随机前缀。"""
    raw = base64.b64decode(token)
    plain = unpad(AES.new(salt.encode(), AES.MODE_CBC, b"0" * 16).decrypt(raw), 16)
    return plain.decode()[64:]


class FakeUpstream(requests.adapters.BaseAdapter):
    """模拟 authserver：记录请求，按路径返回预设响应。"""

    def __init__(self, login_html=LOGIN_HTML, need_captcha=True, valid_captcha="abcd",
                 sms_code="123456", login_status=302, login_location=None, login_body=""):
        super().__init__()
        self.login_html = login_html
        self.need_captcha = need_captcha
        self.valid_captcha = valid_captcha
        self.sms_code = sms_code
        self.login_status = login_status
        self.login_location = login_location or "https://ehall.yibinu.edu.cn/login?ticket=ST-1"
        self.login_body = login_body
        self.requests = []
        self.captcha_fetched = False

    def close(self):
        pass

    @staticmethod
    def _resp(request, status=200, body=b"", headers=None):
        r = requests.Response()
        r.status_code = status
        r._content = body if isinstance(body, bytes) else body.encode()
        r.headers.update(headers or {})
        r.url = request.url
        r.request = request
        return r

    def _json(self, request, obj):
        return self._resp(request, 200, json.dumps(obj),
                          {"Content-Type": "application/json;charset=UTF-8"})

    def send(self, request, **kwargs):
        self.requests.append(request)
        path = urlparse(request.url).path
        body = parse_qs(request.body or "") if isinstance(request.body, str) else {}

        if request.method == "GET" and path == "/authserver/login":
            return self._resp(request, 200, self.login_html, {"Content-Type": "text/html"})
        if path == "/authserver/checkNeedCaptcha.htl":
            return self._json(request, {"isNeed": self.need_captcha})
        if path == "/authserver/getCaptcha.htl":
            self.captcha_fetched = True
            return self._resp(request, 200, JPEG, {"Content-Type": "image/jpeg;charset=UTF-8"})
        if path == "/authserver/dynamicCode/getDynamicCode.htl":
            if body.get("captcha", [""])[0] != self.valid_captcha:
                return self._json(request, {"code": "captchaError", "message": "图形验证码错误"})
            return self._json(request, {"code": "success", "message": "验证码已发送", "intervalTime": 120})
        if request.method == "POST" and path == "/authserver/login":
            if self.login_status == 302:
                return self._resp(request, 302, b"", {"Location": self.login_location})
            return self._resp(request, self.login_status, self.login_body)
        return self._resp(request, 404, "not found")

    def posted_form(self):
        last = [r for r in self.requests if r.method == "POST" and urlparse(r.url).path == "/authserver/login"][-1]
        return {k: val[0] for k, val in parse_qs(last.body, keep_blank_values=True).items()}


def make_client(fake, solver=None):
    session = requests.Session()
    session.mount("https://", fake)
    return v.YibinuAuth(session=session, captcha_solver=solver)


class EncryptTests(unittest.TestCase):
    def test_roundtrip(self):
        token = v.encrypt_password("p@ss!word", PWD_SALT)
        self.assertEqual(decrypt(token, PWD_SALT), "p@ss!word")

    def test_random_each_time(self):
        self.assertNotEqual(v.encrypt_password("x", PWD_SALT), v.encrypt_password("x", PWD_SALT))


class ParseTests(unittest.TestCase):
    def test_parse_real_page(self):
        page = v.parse_login_page(LOGIN_HTML)
        self.assertEqual(page["captcha_switch"], "1")
        self.assertEqual(page["front_back_key"], FRONT_BACK_KEY)
        pwd = page["forms"][v.FORM_PASSWORD]
        self.assertEqual(pwd["salt"], PWD_SALT)
        self.assertEqual(pwd["fields"]["cllt"], "userNameLogin")
        self.assertEqual(pwd["fields"]["execution"], "e1s1")
        sms = page["forms"][v.FORM_SMS]
        self.assertEqual(sms["fields"]["cllt"], "dynamicLogin")

    def test_error_message_new_and_legacy(self):
        self.assertEqual(v.parse_error_message('<span id="showErrorTip">用户名或密码有误</span>'), "用户名或密码有误")
        self.assertEqual(v.parse_error_message('<span id="errorMsg">旧版错误</span>'), "旧版错误")
        self.assertIn("Login failed", v.parse_error_message("<html></html>"))


class PasswordLoginTests(unittest.TestCase):
    def test_success_with_captcha(self):
        fake = FakeUpstream()
        client = make_client(fake, solver=lambda img: "abcd")
        client.load_login_page()
        ok, msg = client.login_with_password("230110128", "secret!")
        self.assertTrue(ok, msg)
        form = fake.posted_form()
        self.assertEqual(form["username"], "230110128")
        self.assertEqual(form["captcha"], "abcd")
        self.assertEqual(form["cllt"], "userNameLogin")
        self.assertEqual(decrypt(form["password"], PWD_SALT), "secret!")
        self.assertNotIn("passwordText", form)

    def test_no_captcha_needed(self):
        fake = FakeUpstream(need_captcha=False)
        client = make_client(fake)
        client.load_login_page()
        ok, _ = client.login_with_password("u", "p")
        self.assertTrue(ok)
        self.assertFalse(fake.captcha_fetched)
        self.assertEqual(fake.posted_form()["captcha"], "")

    def test_captcha_required_without_solver(self):
        fake = FakeUpstream()
        client = make_client(fake)
        client.load_login_page()
        with self.assertRaises(v.CaptchaRequired) as ctx:
            client.login_with_password("u", "p")
        self.assertEqual(ctx.exception.image, JPEG)

    def test_failure_message_from_showErrorTip(self):
        fake = FakeUpstream(login_status=401, login_body='<span id="showErrorTip">您提供的用户名或者密码有误</span>')
        client = make_client(fake, solver=lambda img: "abcd")
        client.load_login_page()
        ok, msg = client.login_with_password("u", "bad")
        self.assertFalse(ok)
        self.assertEqual(msg, "您提供的用户名或者密码有误")

    def test_redirect_back_to_login_is_failure(self):
        fake = FakeUpstream(login_location="https://authserver.yibinu.edu.cn/authserver/login?x=1")
        client = make_client(fake, solver=lambda img: "abcd")
        client.load_login_page()
        ok, _ = client.login_with_password("u", "p")
        self.assertFalse(ok)

    def test_slider_captcha_detected(self):
        fake = FakeUpstream(login_html=LOGIN_HTML.replace('var captchaSwitch = "1"', 'var captchaSwitch = "2"'))
        client = make_client(fake)
        with self.assertRaises(v.SliderCaptchaUnsupported):
            client.load_login_page()

    def test_missing_form_gives_clear_error(self):
        fake = FakeUpstream(login_html="<html><body>maintenance</body></html>")
        client = make_client(fake)
        client.load_login_page()
        with self.assertRaises(v.AuthError):
            client.login_with_password("u", "p")


class SmsLoginTests(unittest.TestCase):
    def test_send_and_login(self):
        fake = FakeUpstream()
        client = make_client(fake, solver=lambda img: "abcd")
        client.load_login_page()
        ok, msg = client.send_sms_code("13800000000")
        self.assertTrue(ok, msg)

        sms_req = [r for r in fake.requests if urlparse(r.url).path.endswith("getDynamicCode.htl")][0]
        sent = {k: x[0] for k, x in parse_qs(sms_req.body).items()}
        self.assertEqual(decrypt(sent["mobile"], FRONT_BACK_KEY), "13800000000")
        self.assertEqual(sent["captcha"], "abcd")

        ok, msg = client.login_with_sms("13800000000", "123456")
        self.assertTrue(ok, msg)
        form = fake.posted_form()
        self.assertEqual(form["cllt"], "dynamicLogin")
        self.assertEqual(form["username"], "13800000000")
        self.assertEqual(form["dynamicCode"], "123456")
        self.assertEqual(form["captcha"], "abcd")

    def test_wrong_captcha_reports_message(self):
        fake = FakeUpstream(valid_captcha="zzzz")
        client = make_client(fake, solver=lambda img: "abcd")
        client.load_login_page()
        ok, msg = client.send_sms_code("13800000000")
        self.assertFalse(ok)
        self.assertEqual(msg, "图形验证码错误")

    def test_wrong_sms_code(self):
        fake = FakeUpstream(login_status=401, login_body='<span id="showErrorTip">动态码错误</span>')
        client = make_client(fake, solver=lambda img: "abcd")
        client.load_login_page()
        client.send_sms_code("13800000000")
        ok, msg = client.login_with_sms("13800000000", "000000")
        self.assertFalse(ok)
        self.assertEqual(msg, "动态码错误")


if __name__ == "__main__":
    unittest.main()
