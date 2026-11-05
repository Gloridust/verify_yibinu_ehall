/*
 * yibinu_auth.h — 宜宾学院统一身份认证登录验证 C ABI
 *
 * 返回值约定
 *   除 yibinu_client_free / yibinu_string_free / yibinu_version 外，所有函数返回一个
 *   NUL 结尾的 UTF-8 JSON 字符串，调用方必须用 yibinu_string_free() 释放：
 *     成功: {"ok":true,"data":<见各函数说明>}
 *     失败: {"ok":false,"error":{"kind":"<kind>","message":"<可读信息>"}}
 *
 * error.kind 取值
 *   captcha_required            需要图形验证码：yibinu_fetch_captcha() 取图后带 captcha 重试
 *   slider_captcha_unsupported  上游启用了滑块验证码，无法自动完成
 *   page_structure              登录页结构变化，找不到需要的表单 / 字段
 *   unexpected_response         上游返回了意料之外的内容
 *   network                     网络 / TLS / 超时
 *   invalid_argument            参数非法（NULL、空字符串、非 UTF-8、配置 JSON 错误）
 *   internal                    内部错误（已捕获的 panic）
 *
 * 注意：凭据错误不是 error，而是 data.success == false 的 LoginResult。
 *
 * 线程安全：YibinuClient 可以在多个线程间共享；同一登录会话的步骤需按顺序调用。
 * 验证码与短信验证码绑定在会话 cookie 上，取图 / 发短信 / 登录必须使用同一个 client。
 */
#ifndef YIBINU_AUTH_H
#define YIBINU_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct YibinuClient YibinuClient;

/* config_json 可为 NULL，或如下 JSON（字段均可省略）：
 *   {"base_url":"https://authserver.yibinu.edu.cn/authserver",
 *    "service":"https://ehall.yibinu.edu.cn:443/login?service=...",
 *    "timeout_secs":10, "verify_tls":true, "use_env_proxy":true}
 * 成功时 *out 为新句柄（data 为 null），用 yibinu_client_free() 释放。 */
char *yibinu_client_new(const char *config_json, YibinuClient **out);
void yibinu_client_free(YibinuClient *client);
void yibinu_string_free(char *s);
const char *yibinu_version(void); /* 静态字符串，无需释放 */

/* data: {"captcha_switch":"1","front_back_key":"...","password_form":{...}|null,"sms_form":{...}|null} */
char *yibinu_load_login_page(const YibinuClient *client);

/* data: true / false */
char *yibinu_need_captcha(const YibinuClient *client, const char *username);

/* data: Base64 编码的验证码图片（JPEG） */
char *yibinu_fetch_captcha(const YibinuClient *client);

/* captcha 可为 NULL。data: {"success":bool,"message":"...","redirect":"..."|null} */
char *yibinu_login_with_password(const YibinuClient *client, const char *username,
                                 const char *password, const char *captcha);

/* data: {"sent":bool,"code":"success|error|captchaError|timeExpire","message":"...","retry_after":120|null} */
char *yibinu_send_sms_code(const YibinuClient *client, const char *mobile, const char *captcha);

/* data: LoginResult（同 yibinu_login_with_password） */
char *yibinu_login_with_sms(const YibinuClient *client, const char *mobile, const char *dynamic_code);

#ifdef __cplusplus
}
#endif

#endif /* YIBINU_AUTH_H */
