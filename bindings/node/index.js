'use strict';
/**
 * 宜宾学院统一身份认证登录验证 —— Rust 核心库的 Node.js 绑定。
 * 所有网络操作返回 Promise，在 libuv 线程池中执行，不阻塞事件循环。
 */
const native = require('./yibinu_auth.node');

class YibinuError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'YibinuError';
    /** 稳定的错误类型标识 */
    this.code = code;
  }
}

const ERROR_CLASSES = {};
function defineError(className, code) {
  const C = class extends YibinuError {
    constructor(message) {
      super(code, message);
      this.name = className;
    }
  };
  Object.defineProperty(C, 'name', { value: className });
  ERROR_CLASSES[code] = C;
  return C;
}

const CaptchaRequiredError = defineError('CaptchaRequiredError', 'captcha_required');
const SliderCaptchaUnsupportedError = defineError('SliderCaptchaUnsupportedError', 'slider_captcha_unsupported');
const PageStructureError = defineError('PageStructureError', 'page_structure');
const UnexpectedResponseError = defineError('UnexpectedResponseError', 'unexpected_response');
const NetworkError = defineError('NetworkError', 'network');
const InvalidArgumentError = defineError('InvalidArgumentError', 'invalid_argument');

/** 把原生错误（reason 为 JSON）转换成对应的错误类；参数类型错误等非本库错误原样抛出。 */
function convert(err) {
  if (!(err instanceof Error)) return err;
  let info;
  try {
    info = JSON.parse(err.message);
  } catch {
    return err;
  }
  if (!info || typeof info.kind !== 'string') return err;
  const C = ERROR_CLASSES[info.kind];
  return C ? new C(info.message) : new YibinuError(info.kind, info.message);
}

function wrapSync(fn) {
  try {
    return fn();
  } catch (e) {
    throw convert(e);
  }
}

async function wrapAsync(fn) {
  try {
    return await fn();
  } catch (e) {
    throw convert(e);
  }
}

/**
 * 一次认证会话。验证码与短信验证码绑定在会话上，取图 / 发短信 / 登录必须使用同一个 Client。
 */
class Client {
  /** @param {import('./index').ClientOptions} [options] */
  constructor(options) {
    this._native = wrapSync(() => new native.NativeClient(options));
  }

  loadLoginPage() {
    return wrapAsync(() => this._native.loadLoginPage());
  }

  needCaptcha(username) {
    return wrapAsync(() => this._native.needCaptcha(username));
  }

  fetchCaptcha() {
    return wrapAsync(() => this._native.fetchCaptcha());
  }

  loginWithPassword(username, password, captcha) {
    return wrapAsync(() => this._native.loginWithPassword(username, password, captcha ?? undefined));
  }

  sendSmsCode(mobile, captcha) {
    return wrapAsync(() => this._native.sendSmsCode(mobile, captcha));
  }

  loginWithSms(mobile, dynamicCode) {
    return wrapAsync(() => this._native.loginWithSms(mobile, dynamicCode));
  }
}

/**
 * 便捷函数：账号密码登录；需要验证码时调用 `captchaSolver(imageBuffer)` 取得答案。
 * 没有 solver 时以 CaptchaRequiredError reject。
 */
async function verifyLogin(username, password, { captchaSolver, ...options } = {}) {
  const client = new Client(options);
  await client.loadLoginPage();
  try {
    return await client.loginWithPassword(username, password);
  } catch (e) {
    if (!(e instanceof CaptchaRequiredError) || !captchaSolver) throw e;
    const answer = await captchaSolver(await client.fetchCaptcha());
    return client.loginWithPassword(username, password, answer);
  }
}

/**
 * 便捷函数：短信登录。`captchaSolver(image)` 提供图形验证码，`codeProvider()` 提供短信验证码。
 * 短信发送失败时返回 `{ success: false, message }`。
 */
async function verifySmsLogin(mobile, { captchaSolver, codeProvider, ...options }) {
  if (typeof captchaSolver !== 'function' || typeof codeProvider !== 'function') {
    throw new TypeError('verifySmsLogin 需要 captchaSolver 和 codeProvider');
  }
  const client = new Client(options);
  await client.loadLoginPage();
  const captcha = await captchaSolver(await client.fetchCaptcha());
  const sent = await client.sendSmsCode(mobile, captcha);
  if (!sent.sent) return { success: false, message: sent.message, redirect: null };
  return client.loginWithSms(mobile, await codeProvider());
}

module.exports = {
  Client,
  verifyLogin,
  verifySmsLogin,
  encryptPassword: (plain, salt) => wrapSync(() => native.encryptPassword(plain, salt)),
  version: native.version,
  YibinuError,
  CaptchaRequiredError,
  SliderCaptchaUnsupportedError,
  PageStructureError,
  UnexpectedResponseError,
  NetworkError,
  InvalidArgumentError,
};
