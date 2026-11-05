"""命令行入口：``verify-yibinu`` / ``python -m verify_yibinu``，用法与旧版 verify_yibinu.py 一致。"""
import argparse
import getpass
import os
import sys
import tempfile

from . import verify_login, verify_sms_login


def _cli_captcha_solver(image: bytes) -> str:
    fd, path = tempfile.mkstemp(prefix="yibinu_captcha_", suffix=".jpg")
    with os.fdopen(fd, "wb") as f:
        f.write(image)
    print(f"图形验证码已保存到: {path}", file=sys.stderr)
    return input("请输入图形验证码: ").strip()


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="verify-yibinu",
        description="宜宾学院统一身份认证登录验证",
        epilog="兼容旧用法: verify-yibinu <学号> '<密码>' 等价于 password 子命令",
    )
    p.add_argument("--insecure", action="store_true", help="不校验服务器证书（不推荐）")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--base-url", default=None, help="authserver 地址，默认宜宾学院正式环境")
    sub = p.add_subparsers(dest="mode", required=True)
    pw = sub.add_parser("password", help="账号密码登录")
    pw.add_argument("username")
    pw.add_argument("password", help="包含特殊字符（如 !）时请用单引号包裹")
    sms = sub.add_parser("sms", help="短信验证码登录")
    sms.add_argument("mobile", help="手机号（海外手机用 国家代码-手机号，如 1-888888）")
    return p


_VALUE_OPTIONS = {"--timeout", "--base-url"}


def _insert_legacy_subcommand(argv):
    """兼容旧用法 ``<学号> <密码>``：在第一个位置参数前补上 ``password``（跳过选项及其取值）。"""
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in _VALUE_OPTIONS:
            i += 2
            continue
        if not a.startswith("-"):
            positional.append(i)
        i += 1
    if len(positional) >= 2 and argv[positional[0]] not in ("password", "sms"):
        argv.insert(positional[0], "password")
    return argv


def main(argv=None) -> int:
    argv = _insert_legacy_subcommand(list(sys.argv[1:] if argv is None else argv))
    args = _parser().parse_args(argv)
    common = dict(timeout=args.timeout, verify_tls=not args.insecure, captcha_solver=_cli_captcha_solver)
    if args.base_url:
        common["base_url"] = args.base_url
    if args.mode == "password":
        ok, msg = verify_login(args.username, args.password, **common)
    else:
        ok, msg = verify_sms_login(
            args.mobile, code_provider=lambda: getpass.getpass("请输入短信验证码: ").strip(), **common)
    print(f"\nResult: {'Success' if ok else 'Failed'}")
    print(f"Message: {msg}")
    return 0 if ok else 1
