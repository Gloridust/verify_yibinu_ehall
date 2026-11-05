"""
宜宾学院统一身份认证 (wisedu authserver) 登录验证。

适配升级后的上游认证系统：

* 账号密码登录 (``cllt=userNameLogin``)，含图形验证码 ``checkNeedCaptcha.htl`` / ``getCaptcha.htl``
* 短信验证码登录 (``cllt=dynamicLogin``)，含 ``dynamicCode/getDynamicCode.htl``
* 滑块验证码 (``captchaSwitch=2``) 无法自动化，检测到后会明确报错

向后兼容：``verify_login(username, password)`` 仍返回 ``(success, message)``。
"""
import argparse
import base64
import getpass
import logging
import os
import random
import re
import ssl
import sys
import tempfile
import time
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

BASE_URL = "https://authserver.yibinu.edu.cn/authserver"
LOGIN_URL = (
    BASE_URL + "/login"
    "?service=https%3A%2F%2Fehall.yibinu.edu.cn%3A443%2Flogin"
    "%3Fservice%3Dhttps%3A%2F%2Fehall.yibinu.edu.cn%2Fnew%2Findex.html"
)
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)

# 页面表单 id：账号密码 / 短信登录
FORM_PASSWORD = "pwdFromId"
FORM_SMS = "phoneFromId"

# 页面脚本里 frontBackKey 缺失时的兜底（用于加密手机号）。优先使用页面实时下发的值。
DEFAULT_FRONT_BACK_KEY = "rjBFAaHsNkKAhpoi"

CaptchaSolver = Callable[[bytes], str]


# --------------------------------------------------------------------------- #
# 异常
# --------------------------------------------------------------------------- #
class AuthError(Exception):
    """认证流程中的可预期错误，message 可直接展示给用户。"""


class CaptchaRequired(AuthError):
    """需要图形验证码，但调用方没有提供答案或 solver。"""

    def __init__(self, image: bytes):
        super().__init__("需要图形验证码：请传入 captcha 或 captcha_solver")
        self.image = image


class SliderCaptchaUnsupported(AuthError):
    """上游启用了滑块验证码 (captchaSwitch=2)，无法自动完成。"""

    def __init__(self):
        super().__init__("上游已启用滑块验证码 (captchaSwitch=2)，当前不支持自动完成，请使用浏览器登录")


# --------------------------------------------------------------------------- #
# 传输层 / 加密
# --------------------------------------------------------------------------- #
class TLSAdapter(requests.adapters.HTTPAdapter):
    """
    Custom TLS adapter to handle legacy SSL/TLS versions and ciphers.

    默认仍然校验证书；只有显式 ``verify_tls=False`` 才会关闭校验。
    """

    def __init__(self, *args, verify_tls: bool = True, **kwargs):
        self._verify_tls = verify_tls
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        # Set security level to 1 to allow legacy ciphers if needed
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        if not self._verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)


def get_random_string(length: int) -> str:
    """Generate a random string of fixed length."""
    chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    return ''.join(random.choice(chars) for _ in range(length))


def encrypt_password(password: str, salt: str) -> str:
    """
    Encrypt a value using AES-CBC, following the logic in encrypt.js (``encryptPassword``).

    密码、手机号都用同一算法，只是 salt 不同：
    密码用表单内的 ``pwdEncryptSalt``，手机号用页面的 ``frontBackKey``。
    """
    data = get_random_string(64) + password
    key = salt.strip().encode('utf-8')
    iv = get_random_string(16).encode('utf-8')

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')


# --------------------------------------------------------------------------- #
# 页面解析
# --------------------------------------------------------------------------- #
def parse_login_page(html: str) -> Dict:
    """
    解析登录页，返回::

        {
          "captcha_switch": "1" | "2" | "",
          "front_back_key": str,
          "forms": {form_id: {"fields": {name: value}, "salt": str}},
        }

    页面里同一个 id（lt / execution / pwdEncryptSalt ...）在多个表单中重复出现，
    因此必须按表单作用域解析，不能全局 find。
    """
    soup = BeautifulSoup(html, 'html.parser')

    switch_match = re.search(r'var\s+captchaSwitch\s*=\s*"(\d*)"', html)
    key_match = re.search(r'var\s+frontBackKey\s*=\s*"(.*?)"', html)

    forms = {}
    for form_id in (FORM_PASSWORD, FORM_SMS):
        form = soup.find('form', {'id': form_id})
        if form is None:
            continue
        fields = {}
        for inp in form.find_all('input', {'type': 'hidden'}):
            name = inp.get('name')
            if name:
                fields[name] = inp.get('value', '')
        salt_input = form.find('input', {'id': 'pwdEncryptSalt'})
        forms[form_id] = {
            'fields': fields,
            'salt': salt_input.get('value', '') if salt_input else '',
        }

    return {
        'captcha_switch': switch_match.group(1) if switch_match else '',
        'front_back_key': key_match.group(1) if key_match else '',
        'forms': forms,
    }


def parse_error_message(html: str) -> str:
    """从登录失败的页面里提取错误提示（新版为 ``#showErrorTip``，旧版为 ``#errorMsg``）。"""
    soup = BeautifulSoup(html, 'html.parser')
    for element_id in ('showErrorTip', 'errorMsg', 'msg'):
        element = soup.find(id=element_id)
        if element and element.get_text(strip=True):
            return element.get_text(strip=True)
    return "Login failed: Invalid credentials or session timeout"


def _decode(response: requests.Response) -> str:
    """上游页面固定为 UTF-8；不依赖响应头的 charset（缺失时 requests 会回退成 ISO-8859-1 导致中文乱码）。"""
    return response.content.decode('utf-8-sig', errors='replace')


# --------------------------------------------------------------------------- #
# 客户端
# --------------------------------------------------------------------------- #
class YibinuAuth:
    """
    单次认证会话。验证码图片、短信验证码都绑定在 cookie 会话上，
    所以「取验证码 → 发短信 → 登录」必须使用同一个实例。
    """

    def __init__(
        self,
        timeout: int = 10,
        verify_tls: bool = True,
        captcha_solver: Optional[CaptchaSolver] = None,
        session: Optional[requests.Session] = None,
    ):
        self.timeout = timeout
        self.captcha_solver = captcha_solver
        if session is None:
            session = requests.Session()
            session.mount('https://', TLSAdapter(verify_tls=verify_tls))
            session.verify = verify_tls
            session.headers.update({'User-Agent': USER_AGENT})
        self.session = session
        self._page: Optional[Dict] = None
        self._last_captcha: str = ''

    # -- 页面 ---------------------------------------------------------------
    def load_login_page(self) -> Dict:
        """获取并解析登录页（同时建立会话 cookie）。"""
        logger.debug("Fetching login page...")
        response = self.session.get(LOGIN_URL, timeout=self.timeout)
        response.raise_for_status()
        self._page = parse_login_page(_decode(response))
        if self._page['captcha_switch'] == '2':
            raise SliderCaptchaUnsupported()
        return self._page

    def _form(self, form_id: str) -> Dict:
        page = self._page or self.load_login_page()
        form = page['forms'].get(form_id)
        if form is None:
            raise AuthError(f"登录页中未找到表单 '{form_id}'，上游页面结构可能再次变更或该登录方式已被关闭")
        return form

    # -- 图形验证码 ----------------------------------------------------------
    def need_captcha(self, username: str) -> bool:
        """账号密码登录是否需要图形验证码 (checkNeedCaptcha.htl)。"""
        response = self.session.get(
            BASE_URL + "/checkNeedCaptcha.htl",
            params={'username': username, '_': int(time.time() * 1000)},
            timeout=self.timeout,
        )
        response.raise_for_status()
        try:
            return bool(response.json().get('isNeed'))
        except ValueError:
            raise AuthError("checkNeedCaptcha.htl 返回了非 JSON 内容，上游接口可能再次变更")

    def fetch_captcha(self) -> bytes:
        """获取一张新的图形验证码图片 (getCaptcha.htl)，返回图片字节。"""
        response = self.session.get(
            BASE_URL + "/getCaptcha.htl",
            params={'t': int(time.time() * 1000)},
            timeout=self.timeout,
        )
        response.raise_for_status()
        if not response.headers.get('Content-Type', '').startswith('image/'):
            raise AuthError("getCaptcha.htl 返回的不是图片，上游接口可能再次变更")
        return response.content

    def _solve_captcha(self, captcha: Optional[str]) -> str:
        if captcha:
            return captcha
        image = self.fetch_captcha()
        if self.captcha_solver is None:
            raise CaptchaRequired(image)
        answer = self.captcha_solver(image)
        if not answer:
            raise AuthError("未获得验证码答案")
        return answer

    # -- 账号密码登录 --------------------------------------------------------
    def login_with_password(self, username: str, password: str, captcha: Optional[str] = None) -> Tuple[bool, str]:
        form = self._form(FORM_PASSWORD)
        if not form['salt']:
            raise AuthError("登录页未下发 pwdEncryptSalt，无法加密密码")

        data = dict(form['fields'])
        data['username'] = username
        data['password'] = encrypt_password(password, form['salt'])

        # captcha 字段始终提交；不需要验证码时为空，与浏览器行为一致
        if self.need_captcha(username):
            data['captcha'] = self._solve_captcha(captcha)
        else:
            data['captcha'] = captcha or ''

        return self._submit(data)

    # -- 短信登录 ------------------------------------------------------------
    def send_sms_code(self, mobile: str, captcha: Optional[str] = None) -> Tuple[bool, str]:
        """
        发送短信验证码 (dynamicCode/getDynamicCode.htl)。

        手机号用页面的 frontBackKey 加密后提交；图形验证码必填。
        """
        page = self._page or self.load_login_page()
        key = page['front_back_key'] or DEFAULT_FRONT_BACK_KEY
        captcha = self._solve_captcha(captcha)

        response = self.session.post(
            BASE_URL + "/dynamicCode/getDynamicCode.htl",
            data={'mobile': encrypt_password(mobile, key), 'captcha': captcha},
            timeout=self.timeout,
        )
        response.raise_for_status()
        try:
            result = response.json()
        except ValueError:
            raise AuthError("getDynamicCode.htl 返回了非 JSON 内容，上游接口可能再次变更")

        code = result.get('code')
        message = result.get('message') or ''
        if code == 'success':
            self._last_captcha = captcha
            return True, message or "短信验证码已发送"
        if code == 'timeExpire':
            return False, message or f"发送过于频繁，请 {result.get('time', '')} 秒后重试"
        # error / captchaError：验证码已作废，调用方需重新取图
        return False, message or f"发送失败 ({code})"

    def login_with_sms(self, mobile: str, dynamic_code: str) -> Tuple[bool, str]:
        form = self._form(FORM_SMS)
        data = dict(form['fields'])
        data['username'] = mobile
        data['dynamicCode'] = dynamic_code
        data['captcha'] = self._last_captcha
        return self._submit(data)

    # -- 提交 ----------------------------------------------------------------
    def _submit(self, data: Dict[str, str]) -> Tuple[bool, str]:
        logger.debug("Submitting login form...")
        response = self.session.post(
            LOGIN_URL,
            data=data,
            allow_redirects=False,
            timeout=self.timeout,
        )
        # If successful, it redirects to the service URL (302) with a ticket
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            if urlparse(location).path.rstrip('/').endswith('/authserver/login'):
                return False, "Login failed: redirected back to login page"
            return True, "Login successful"
        return False, parse_error_message(_decode(response))


# --------------------------------------------------------------------------- #
# 对外便捷函数
# --------------------------------------------------------------------------- #
def _guard(func: Callable[[], Tuple[bool, str]]) -> Tuple[bool, str]:
    try:
        return func()
    except AuthError as e:
        return False, str(e)
    except requests.exceptions.SSLError as e:
        return False, f"SSL Error: {str(e)}"
    except requests.exceptions.Timeout:
        return False, "Request timed out. Please check your network connection."
    except requests.exceptions.RequestException as e:
        return False, f"Network error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def verify_login(
    username: str,
    password: str,
    timeout: int = 10,
    captcha_solver: Optional[CaptchaSolver] = None,
    verify_tls: bool = True,
) -> Tuple[bool, str]:
    """
    Verify login credentials for Yibin University auth server.

    若上游要求图形验证码，需通过 ``captcha_solver(image_bytes) -> str`` 提供答案；
    否则返回 ``(False, "需要图形验证码...")``。
    验证码绑定在会话上，若要自行管理验证码请直接使用 :class:`YibinuAuth`
    （先 ``fetch_captcha()`` 展示图片，再把答案传给 ``captcha=``）。
    """
    def run():
        client = YibinuAuth(timeout=timeout, verify_tls=verify_tls, captcha_solver=captcha_solver)
        client.load_login_page()
        return client.login_with_password(username, password)
    return _guard(run)


def verify_sms_login(
    mobile: str,
    code_provider: Callable[[], str],
    timeout: int = 10,
    captcha_solver: Optional[CaptchaSolver] = None,
    verify_tls: bool = True,
) -> Tuple[bool, str]:
    """
    短信登录：取图形验证码 → 发送短信 → 通过 ``code_provider()`` 取得短信验证码 → 登录。
    """
    def run():
        client = YibinuAuth(timeout=timeout, verify_tls=verify_tls, captcha_solver=captcha_solver)
        client.load_login_page()
        ok, message = client.send_sms_code(mobile)
        if not ok:
            return False, message
        logger.info(message)
        return client.login_with_sms(mobile, code_provider())
    return _guard(run)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _cli_captcha_solver(image: bytes) -> str:
    """把验证码图片存成临时文件，让用户查看后手动输入。"""
    fd, path = tempfile.mkstemp(prefix="yibinu_captcha_", suffix=".jpg")
    with os.fdopen(fd, 'wb') as f:
        f.write(image)
    print(f"图形验证码已保存到: {path}")
    return input("请输入图形验证码: ").strip()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="宜宾学院统一身份认证登录验证",
        epilog="兼容旧用法: python verify_yibinu.py <学号> '<密码>' 等价于 password 子命令",
    )
    parser.add_argument('--insecure', action='store_true', help="不校验服务器证书（不推荐）")
    parser.add_argument('--timeout', type=int, default=10)
    parser.add_argument('--debug', action='store_true')
    sub = parser.add_subparsers(dest='mode', required=True)

    p = sub.add_parser('password', help="账号密码登录")
    p.add_argument('username')
    p.add_argument('password', help="包含特殊字符（如 !）时请用单引号包裹")

    s = sub.add_parser('sms', help="短信验证码登录")
    s.add_argument('mobile', help="手机号（海外手机用 国家代码-手机号，如 1-888888）")
    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # 兼容旧 CLI：<username> <password>
    if len(argv) >= 2 and not argv[0].startswith('-') and argv[0] not in ('password', 'sms'):
        argv.insert(0, 'password')

    args = _build_parser().parse_args(argv)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    common = dict(timeout=args.timeout, verify_tls=not args.insecure, captcha_solver=_cli_captcha_solver)
    if args.mode == 'password':
        success, message = verify_login(args.username, args.password, **common)
    else:
        success, message = verify_sms_login(
            args.mobile,
            code_provider=lambda: getpass.getpass("请输入短信验证码: ").strip(),
            **common,
        )

    print(f"\nResult: {'Success' if success else 'Failed'}")
    print(f"Message: {message}")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
