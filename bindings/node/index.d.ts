/// <reference types="node" />

export interface ClientOptions {
  /** authserver 根地址，默认 https://authserver.yibinu.edu.cn/authserver */
  baseUrl?: string;
  /** 登录成功后跳转的 service */
  service?: string;
  /** 单次请求超时（秒），默认 10 */
  timeoutSecs?: number;
  /** 是否校验服务器证书，默认 true */
  verifyTls?: boolean;
  /** 是否读取 HTTPS_PROXY / NO_PROXY 环境变量，默认 true */
  useEnvProxy?: boolean;
}

export interface LoginForm {
  fields: Record<string, string>;
  salt: string;
}

export interface LoginPage {
  /** "1" = 图形验证码，"2" = 滑块验证码 */
  captchaSwitch: string;
  frontBackKey: string;
  passwordForm?: LoginForm | null;
  smsForm?: LoginForm | null;
}

/** 登录结果。凭据错误不会 reject，而是 success === false。 */
export interface LoginResult {
  success: boolean;
  message: string;
  /** 成功时上游 302 跳转的地址（含 ticket） */
  redirect?: string | null;
}

export interface SmsResult {
  sent: boolean;
  /** success / error / captchaError / timeExpire */
  code: string;
  message: string;
  /** 需要等待多少秒后才能再次发送 */
  retryAfter?: number | null;
}

/** 一次认证会话。取图 / 发短信 / 登录必须使用同一个 Client。 */
export declare class Client {
  constructor(options?: ClientOptions);
  loadLoginPage(): Promise<LoginPage>;
  needCaptcha(username: string): Promise<boolean>;
  /** 返回 JPEG 图片 */
  fetchCaptcha(): Promise<Buffer>;
  /** 上游要求验证码而 captcha 为空时以 CaptchaRequiredError reject */
  loginWithPassword(username: string, password: string, captcha?: string | null): Promise<LoginResult>;
  sendSmsCode(mobile: string, captcha: string): Promise<SmsResult>;
  loginWithSms(mobile: string, dynamicCode: string): Promise<LoginResult>;
}

export type CaptchaSolver = (image: Buffer) => string | Promise<string>;

export declare function verifyLogin(
  username: string,
  password: string,
  options?: ClientOptions & { captchaSolver?: CaptchaSolver },
): Promise<LoginResult>;

export declare function verifySmsLogin(
  mobile: string,
  options: ClientOptions & { captchaSolver: CaptchaSolver; codeProvider: () => string | Promise<string> },
): Promise<LoginResult>;

export declare function encryptPassword(plain: string, salt: string): string;
export declare function version(): string;

export type ErrorCode =
  | 'captcha_required'
  | 'slider_captcha_unsupported'
  | 'page_structure'
  | 'unexpected_response'
  | 'network'
  | 'invalid_argument';

export declare class YibinuError extends Error {
  readonly code: ErrorCode | string;
}
export declare class CaptchaRequiredError extends YibinuError {}
export declare class SliderCaptchaUnsupportedError extends YibinuError {}
export declare class PageStructureError extends YibinuError {}
export declare class UnexpectedResponseError extends YibinuError {}
export declare class NetworkError extends YibinuError {}
export declare class InvalidArgumentError extends YibinuError {}
