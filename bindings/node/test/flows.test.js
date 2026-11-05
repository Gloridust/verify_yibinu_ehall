'use strict';
// 端到端测试：Node → napi → Rust → 本地假 authserver（crates/mock-upstream），不访问外网。
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const y = require('..');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const CAPTCHA = 'abcd';
const SMS_CODE = '123456';
const JPEG = Buffer.from('\xff\xd8\xff\xe0fake-jpeg', 'latin1');

function mockBin() {
  const p = process.env.YIBINU_MOCK_BIN || path.join(ROOT, 'target', 'release', 'yibinu-mock-upstream');
  if (!fs.existsSync(p)) execFileSync('cargo', ['build', '--release', '-p', 'yibinu-mock-upstream'], { cwd: ROOT, stdio: 'inherit' });
  return p;
}

async function startMock(...args) {
  const proc = spawn(mockBin(), args, { stdio: ['pipe', 'pipe', 'inherit'] });
  const line = await new Promise((resolve, reject) => {
    readline.createInterface({ input: proc.stdout }).once('line', resolve);
    proc.once('error', reject);
  });
  assert.match(line, /^PORT=\d+$/);
  return { proc, opts: { baseUrl: `http://127.0.0.1:${line.slice(5)}/authserver`, useEnvProxy: false } };
}

const mocks = [];
let captchaMock, noCaptchaMock;
before(async () => {
  captchaMock = await startMock();
  noCaptchaMock = await startMock('--no-captcha');
  mocks.push(captchaMock, noCaptchaMock);
});
after(() => mocks.forEach((m) => m.proc.stdin.end()));

test('login page', async () => {
  const page = await new y.Client(captchaMock.opts).loadLoginPage();
  assert.equal(page.captchaSwitch, '1');
  assert.equal(page.passwordForm.salt, 'G9KhHtvLf0t2HKrD');
  assert.equal(page.smsForm.fields.cllt, 'dynamicLogin');
});

test('password login with captcha', async () => {
  const c = new y.Client(captchaMock.opts);
  await c.loadLoginPage();
  await assert.rejects(c.loginWithPassword('230110128', 'secret!'), (e) => {
    assert.ok(e instanceof y.CaptchaRequiredError);
    assert.ok(e instanceof y.YibinuError);
    assert.equal(e.code, 'captcha_required');
    assert.match(e.message, /验证码/);
    return true;
  });
  assert.deepEqual(await c.fetchCaptcha(), JPEG);
  const r = await c.loginWithPassword('230110128', 'secret!', CAPTCHA);
  assert.equal(r.success, true);
  assert.match(r.redirect, /ticket=/);
});

test('wrong password resolves with success=false', async () => {
  const r = await new y.Client(noCaptchaMock.opts).loginWithPassword('u', 'bad');
  assert.deepEqual([r.success, r.message], [false, '您提供的用户名或者密码有误']);
});

test('sms flow', async () => {
  const c = new y.Client(captchaMock.opts);
  await c.fetchCaptcha();
  const bad = await c.sendSmsCode('13800000000', 'zzzz');
  assert.deepEqual([bad.sent, bad.code], [false, 'captchaError']);
  const sent = await c.sendSmsCode('13800000000', CAPTCHA);
  assert.deepEqual([sent.sent, sent.retryAfter], [true, 120]);
  assert.equal((await c.loginWithSms('13800000000', '000000')).message, '动态码错误');
  assert.equal((await c.loginWithSms('13800000000', SMS_CODE)).success, true);
});

test('verifyLogin / verifySmsLogin helpers', async () => {
  let seen;
  const r = await y.verifyLogin('u', 'secret!', {
    ...captchaMock.opts,
    captchaSolver: async (img) => { seen = img; return CAPTCHA; },
  });
  assert.equal(r.success, true);
  assert.deepEqual(seen, JPEG);
  await assert.rejects(y.verifyLogin('u', 'secret!', captchaMock.opts), y.CaptchaRequiredError);

  const s = await y.verifySmsLogin('13800000000', {
    ...captchaMock.opts, captchaSolver: () => CAPTCHA, codeProvider: () => SMS_CODE,
  });
  assert.equal(s.success, true);
});

test('error classes', async () => {
  await assert.rejects(
    new y.Client({ baseUrl: 'http://127.0.0.1:1/authserver', useEnvProxy: false, timeoutSecs: 2 }).loadLoginPage(),
    y.NetworkError,
  );
  await assert.rejects(new y.Client(noCaptchaMock.opts).loginWithPassword('', 'p'), y.InvalidArgumentError);
  assert.throws(() => new y.Client({ baseUrl: '::bad' }), y.InvalidArgumentError);
  assert.throws(() => y.encryptPassword('x', 'short'), y.InvalidArgumentError);
  // 非本库错误（参数类型不对）保持原样
  await assert.rejects(new y.Client().needCaptcha(123), (e) => e instanceof TypeError || !(e instanceof y.YibinuError));
});

test('does not block the event loop', async () => {
  // 只接受连接、从不响应的服务：请求会挂到 1 秒超时。若阻塞事件循环，这期间定时器不会触发。
  const net = require('node:net');
  const sockets = [];
  const server = net.createServer((s) => sockets.push(s));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const c = new y.Client({ baseUrl: `http://127.0.0.1:${server.address().port}/authserver`, useEnvProxy: false, timeoutSecs: 1 });

  let ticks = 0;
  const timer = setInterval(() => ticks++, 10);
  const started = Date.now();
  await assert.rejects(c.loadLoginPage(), y.NetworkError);
  clearInterval(timer);
  sockets.forEach((s) => s.destroy());
  server.close();

  assert.ok(Date.now() - started >= 900, '请求应等待约 1 秒超时');
  assert.ok(ticks >= 30, `等待期间定时器应持续触发，实际 ${ticks} 次`);
});

test('version', () => {
  assert.match(y.version(), /^\d+\.\d+\.\d+/);
});
