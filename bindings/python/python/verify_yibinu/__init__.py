"""
宜宾学院统一身份认证 (wisedu authserver) 登录验证 —— Rust 核心库的 Python 绑定。

新 API（推荐）::

    from verify_yibinu import Client, CaptchaRequired

    c = Client()
    c.load_login_page()
    try:
        r = c.login_with_password("230110128", "secret")
    except CaptchaRequired:
        image = c.fetch_captcha()                 # bytes (JPEG)，展示给用户
        r = c.login_with_password("230110128", "secret", captcha=input("验证码: "))
    print(r.success, r.message)

兼容旧 API（纯 Python 版 verify_yibinu.py）::

    ok, msg = verify_login(username, password, captcha_solver=lambda img: "ab12")
"""
from typing import Callable, Optional, Tuple

from ._native import (  # noqa: F401
    DEFAULT_BASE_URL,
    AuthError,
    CaptchaRequired,
    Client,
    InvalidArgumentError,
    LoginResult,
    NetworkError,
    PageStructureError,
    SliderCaptchaUnsupported,
    SmsResult,
    UnexpectedResponseError,
    __version__,
    encrypt_password,
)

CaptchaSolver = Callable[[bytes], str]

__all__ = [
    "Client", "LoginResult", "SmsResult", "YibinuAuth",
    "AuthError", "CaptchaRequired", "SliderCaptchaUnsupported", "PageStructureError",
    "UnexpectedResponseError", "NetworkError", "InvalidArgumentError",
    "verify_login", "verify_sms_login", "encrypt_password", "main", "__version__",
]


class YibinuAuth:
    """
    兼容旧版的会话类：方法返回 ``(success, message)``，并支持 ``captcha_solver`` 自动处理验证码。

    需要验证码但没有 solver 时抛出 :class:`CaptchaRequired`，异常的 ``image`` 属性是验证码图片字节；
    之后可把答案作为 ``captcha=`` 传回同一个实例。
    """

    def __init__(self, timeout: int = 10, verify_tls: bool = True,
                 captcha_solver: Optional[CaptchaSolver] = None, **client_kwargs):
        self.captcha_solver = captcha_solver
        self.client = Client(timeout=timeout, verify_tls=verify_tls, **client_kwargs)

    def load_login_page(self) -> dict:
        return self.client.load_login_page()

    def need_captcha(self, username: str) -> bool:
        return self.client.need_captcha(username)

    def fetch_captcha(self) -> bytes:
        return self.client.fetch_captcha()

    def _solve(self, err: Optional[CaptchaRequired] = None) -> str:
        image = self.client.fetch_captcha()
        if self.captcha_solver is None:
            exc = err or CaptchaRequired("需要图形验证码：请传入 captcha 或 captcha_solver")
            exc.image = image
            raise exc
        answer = self.captcha_solver(image)
        if not answer:
            raise AuthError("未获得验证码答案")
        return answer

    def login_with_password(self, username: str, password: str,
                            captcha: Optional[str] = None) -> Tuple[bool, str]:
        try:
            r = self.client.login_with_password(username, password, captcha)
        except CaptchaRequired as e:
            r = self.client.login_with_password(username, password, self._solve(e))
        return r.success, r.message

    def send_sms_code(self, mobile: str, captcha: Optional[str] = None) -> Tuple[bool, str]:
        r = self.client.send_sms_code(mobile, captcha or self._solve())
        return r.sent, r.message

    def login_with_sms(self, mobile: str, dynamic_code: str) -> Tuple[bool, str]:
        r = self.client.login_with_sms(mobile, dynamic_code)
        return r.success, r.message


def _guard(fn) -> Tuple[bool, str]:
    try:
        return fn()
    except AuthError as e:
        return False, str(e)
    except Exception as e:  # noqa: BLE001 —— 与旧版一致：便捷函数不抛异常
        return False, f"Unexpected error: {e}"


def verify_login(username: str, password: str, timeout: int = 10,
                 captcha_solver: Optional[CaptchaSolver] = None,
                 verify_tls: bool = True, **client_kwargs) -> Tuple[bool, str]:
    """账号密码登录验证，返回 ``(success, message)``，不抛异常。"""
    def run():
        auth = YibinuAuth(timeout=timeout, verify_tls=verify_tls,
                          captcha_solver=captcha_solver, **client_kwargs)
        auth.load_login_page()
        return auth.login_with_password(username, password)
    return _guard(run)


def verify_sms_login(mobile: str, code_provider: Callable[[], str], timeout: int = 10,
                     captcha_solver: Optional[CaptchaSolver] = None,
                     verify_tls: bool = True, **client_kwargs) -> Tuple[bool, str]:
    """短信登录：取图形验证码 → 发短信 → ``code_provider()`` 取短信码 → 登录。返回 ``(success, message)``。"""
    def run():
        auth = YibinuAuth(timeout=timeout, verify_tls=verify_tls,
                          captcha_solver=captcha_solver, **client_kwargs)
        auth.load_login_page()
        ok, msg = auth.send_sms_code(mobile)
        if not ok:
            return False, msg
        return auth.login_with_sms(mobile, code_provider())
    return _guard(run)


def main(argv=None) -> int:
    from ._cli import main as _main
    return _main(argv)
