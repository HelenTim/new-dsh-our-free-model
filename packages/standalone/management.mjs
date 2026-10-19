import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import { buildStats } from '../../src/core/stats.js'
import { generateKey } from '../../src/forward.js'
import { openLoginTerminal } from './login-terminal.mjs'
import { publicModelVisibility, validateModelVisibility, isModelHidden } from '../../src/store.js'

const PREFIX = '/api/management'
const BOOTSTRAP_MS = 10 * 60_000
const SESSION_MS = 8 * 60 * 60_000
const MAX_BODY_BYTES = 16 * 1024
const REMOTE_LOGIN_MS = 15 * 60_000
const REMOTE_PROXY_LIMIT = 1024 * 1024
const LOOPBACK_NAMES = new Set(['127.0.0.1', '[::1]', '::1', 'localhost'])
const ASSETS = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
])
const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
}

function fail(statusCode, message) {
  return Object.assign(new Error(message), { statusCode })
}

function matches(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string' || expected === '') return false
  const left = Buffer.from(actual)
  const right = Buffer.from(expected)
  return left.length === right.length && crypto.timingSafeEqual(left, right)
}

/** Split a Host/Origin/Referer value into {scheme, hostname, port}. */
function parseAuthority(value, defaultScheme = 'http') {
  if (typeof value !== 'string' || value.trim() === '') return null
  let url
  try {
    url = new URL(value.includes('://') ? value.trim() : `${defaultScheme}://${value.trim()}`)
  } catch {
    return null
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
  const scheme = url.protocol === 'https:' ? 'https' : 'http'
  const port = url.port === '' ? (scheme === 'https' ? '443' : '80') : url.port
  return { scheme, hostname: url.hostname.toLowerCase(), port }
}

function sameAuthority(left, right) {
  return left !== null && right !== null && left.scheme === right.scheme &&
    left.hostname === right.hostname && left.port === right.port
}

/** Behind a platform proxy the connection is plain HTTP but the page is HTTPS. */
function requestScheme(req) {
  const forwarded = String(req.headers['x-forwarded-proto'] ?? '').split(',')[0].trim().toLowerCase()
  return forwarded === 'https' ? 'https' : 'http'
}

function requestAuthority(req, { forwardedHost = false } = {}) {
  const forwarded = forwardedHost ? String(req.headers['x-forwarded-host'] ?? '').split(',')[0].trim() : ''
  const host = forwarded !== '' ? forwarded : req.headers.host
  return parseAuthority(host, requestScheme(req))
}

function isLoopbackName(hostname) {
  return LOOPBACK_NAMES.has(String(hostname ?? '').toLowerCase())
}

/**
 * Find the local callback/page target inside a provider login URL.
 *
 * Callback providers put their loopback redirect in different parameters
 * (`redirect_uri` for LobsterAI/Gemini, `auth_callback_url` for TRAE, a bare
 * `port` for CodeArts). Loomy/Raccoon return the local page itself. A device
 * code flow has no loopback target and needs no remote helper.
 */
function findLocalTarget(loginUrl) {
  let url
  try { url = new URL(loginUrl) } catch { return undefined }
  if (isLoopbackName(url.hostname) && url.port !== '') {
    return { kind: 'page', port: Number(url.port), path: url.pathname + url.search }
  }
  // LobsterAI keeps its login query inside the hash (`/portal#/login?...`),
  // so inspect both the search and the fragment.
  const hashQuery = url.hash.includes('?') ? url.hash.slice(url.hash.indexOf('?') + 1) : ''
  const params = [url.searchParams, new URLSearchParams(hashQuery)]
  for (const search of params) {
    for (const key of ['redirect_uri', 'redirect', 'auth_callback_url', 'callback', 'callback_url']) {
      const raw = search.get(key)
      if (raw === null) continue
      let candidate
      try { candidate = new URL(raw) } catch { continue }
      if (isLoopbackName(candidate.hostname) && candidate.port !== '') {
        return { kind: 'callback', port: Number(candidate.port), path: candidate.pathname + candidate.search }
      }
    }
    const port = search.get('port')
    if (port !== null && /^\d+$/.test(port) && Number(port) > 0 && Number(port) <= 65535) {
      return { kind: 'callback', port: Number(port), path: '/' }
    }
  }
  return undefined
}

/** The pasted callback URL must point at the exact loopback port we started. */
function localCallbackPath(value, expectedPort) {
  let url
  try { url = new URL(String(value ?? '').trim()) } catch { return undefined }
  if (url.protocol !== 'http:' || url.username !== '' || url.password !== '') return undefined
  if (!isLoopbackName(url.hostname) || url.port === '' || Number(url.port) !== expectedPort) return undefined
  return url.pathname + url.search
}

const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[character]))

async function readRawBody(req, limit = MAX_BODY_BYTES) {
  const chunks = []
  let bytes = 0
  for await (const chunk of req) {
    bytes += chunk.length
    if (bytes > limit) throw fail(413, '请求内容过大')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

/** Ask the worker's loopback callback server to process a pasted redirect. */
function replayLocalCallback(port, path) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1', port, path, method: 'GET', timeout: 30_000,
    }, response => {
      response.resume()
      response.once('end', () => resolve({ pending: false }))
    })
    request.once('timeout', () => {
      request.destroy()
      // The handler received the request but is still exchanging the code.
      resolve({ pending: true })
    })
    request.once('error', reject)
    request.end()
  })
}

function renderManualLoginPage(entry) {
  const provider = entry.provider === 'codearts' ? 'CodeArts'
    : entry.provider === 'lobsterai' ? 'LobsterAI'
      : entry.provider === 'trae' ? 'TRAE'
        : entry.provider === 'gemini' ? 'Gemini' : entry.provider
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(provider)} 授权</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
         background: #f5f6f8; color: #1f2329; }
  .card { background: #fff; border-radius: 12px; padding: 24px 28px; box-shadow: 0 4px 24px rgba(0,0,0,.08);
          width: min(520px, calc(100vw - 32px)); box-sizing: border-box; }
  h1 { font-size: 17px; margin: 0 0 12px; }
  p { font-size: 13px; line-height: 1.7; color: #4e5969; margin: 0 0 10px; }
  a { display: inline-block; margin: 4px 0 14px; padding: 9px 16px; border-radius: 8px;
      background: #07c160; color: #fff; text-decoration: none; font-size: 14px; }
  textarea { width: 100%; box-sizing: border-box; min-height: 84px; padding: 8px 10px; font-size: 13px;
             border: 1px solid #d9dde3; border-radius: 8px; font-family: ui-monospace, monospace; }
  button { margin-top: 10px; width: 100%; padding: 9px; font-size: 14px; border: 0; border-radius: 8px;
           background: #1f2329; color: #fff; cursor: pointer; }
  button:disabled { background: #c9cdd4; cursor: not-allowed; }
  #status { margin-top: 10px; font-size: 13px; color: #0f9d58; min-height: 20px; }
  #status[data-tone="err"] { color: #d93026; }
</style>
</head>
<body>
  <div class="card">
    <h1>完成 ${escapeHtml(provider)} 授权</h1>
    <p>1. 点击下面的按钮打开授权页（会在新标签页打开）。</p>
    <a href="${escapeHtml(entry.loginUrl)}" target="_blank" rel="noreferrer noopener">打开授权页</a>
    <p>2. 授权完成后，浏览器会跳转到 <code>127.0.0.1</code> 并提示无法访问。这是正常的。</p>
    <p>3. 复制地址栏中的完整地址，粘贴到这里并提交。</p>
    <textarea id="callback" placeholder="http://127.0.0.1:..."></textarea>
    <button id="submit" type="button">提交授权地址</button>
    <p id="status" role="status"></p>
    <p>提交后可以关闭本页，回到控制台等待账号出现。</p>
  </div>
<script>
(function () {
  var token = ${JSON.stringify(entry.token)};
  var status = document.getElementById('status');
  var submit = document.getElementById('submit');
  function setStatus(text, tone) {
    status.textContent = text;
    if (tone) status.setAttribute('data-tone', tone);
    else status.removeAttribute('data-tone');
  }
  submit.addEventListener('click', function () {
    var url = document.getElementById('callback').value.trim();
    if (url === '') { setStatus('请先粘贴授权后的地址', 'err'); return; }
    submit.disabled = true;
    setStatus('正在提交…');
    fetch('${PREFIX}/login/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token, url: url })
    }).then(function (response) {
      return response.json().then(function (value) { return { ok: response.ok, value: value }; });
    }).then(function (result) {
      if (!result.ok) { setStatus(result.value.error || '提交失败', 'err'); return; }
      setStatus(result.value.pending === true
        ? '已提交，服务端仍在等待渠道确认；稍后回到控制台查看。'
        : '已提交，正在等待渠道确认；稍后回到控制台查看。');
    }).catch(function (error) {
      setStatus('提交失败：' + (error && error.message ? error.message : error), 'err');
    }).finally(function () { submit.disabled = false; });
  });
})();
</script>
</body>
</html>`
}

/** Local login pages use root-absolute fetches; move them under the proxy token. */
function rewriteProxiedHtml(html, entry) {
  const prefix = `${PREFIX}/login/page/${entry.token}`
  const bases = entry.provider === 'loomy' ? ['/wechat/'] : entry.provider === 'raccoon' ? ['/raccoon/'] : []
  let output = html
  for (const base of bases) {
    output = output.split(`"${base}`).join(`"${prefix}${base}`)
    output = output.split(`'${base}`).join(`'${prefix}${base}`)
  }
  if (entry.provider === 'raccoon') {
    // The local page silently swallows fetch failures; surface an expired
    // management session instead of leaving the user on "等待扫码…".
    output = output.replace('<body>', `<body>
<div style="margin:0;padding:8px 12px;background:#eef6ff;color:#1d4f91;font-size:12px;text-align:center">扫码后请在微信中确认登录；若一直停留在“等待扫码”，可改用短信登录。</div>
<script>
(function () {
  document.addEventListener('securitypolicyviolation', function (event) {
    var target = document.getElementById('smsStatus');
    if (!target) return;
    target.textContent = '验证码组件被 CSP 拦截：' + (event.blockedURI || event.violatedDirective || 'unknown');
    target.setAttribute('data-tone', 'err');
  });
  var original = window.fetch;
  window.fetch = function (input, init) {
    return original(input, init).then(function (response) {
      if (response.status === 401 || response.status === 403) {
        var targets = [document.getElementById('qrStatus'), document.getElementById('smsStatus')];
        targets.forEach(function (target) {
          if (!target) return;
          target.textContent = '管理会话已失效，请关闭窗口并重新登录';
          target.setAttribute('data-tone', 'err');
        });
      }
      return response;
    });
  };
})();
</script>`)
  }
  return output
}

const LOGIN_PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
// Raccoon's SMS tab loads the Aliyun slider captcha. Its script, API calls and
// iframe all live on Alibaba's CDNs, so this one proxied page gets a wider CSP
// than the management console. The QR tab does not need any of it.
const RACCOON_LOGIN_PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline' https://*.alicdn.com https://o.alicdn.com; script-src 'unsafe-inline' 'unsafe-eval' https://*.alicdn.com https://o.alicdn.com; connect-src 'self' https://*.aliyuncs.com https://*.alicdn.com https://o.alicdn.com; img-src 'self' data: blob: https://*.aliyuncs.com https://*.alicdn.com https://o.alicdn.com; frame-src 'self' blob: https://*.aliyuncs.com https://*.alicdn.com https://o.alicdn.com; font-src 'self' data: https://*.alicdn.com https://o.alicdn.com; worker-src 'self' blob:; form-action 'self' https://*.aliyuncs.com https://*.alicdn.com https://o.alicdn.com; frame-ancestors 'none'; base-uri 'none'"

function loginPageHeaders(provider) {
  return {
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'content-security-policy': provider === 'raccoon' ? RACCOON_LOGIN_PAGE_CSP : LOGIN_PAGE_CSP,
  }
}

async function readBody(req, limit = MAX_BODY_BYTES) {
  if (!String(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
    throw fail(415, '请求必须使用 application/json')
  }
  let bytes = 0
  const chunks = []
  for await (const chunk of req) {
    bytes += chunk.length
    if (bytes > limit) throw fail(413, '请求内容过大')
    chunks.push(chunk)
  }
  let value
  try { value = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { throw fail(400, '请求不是有效 JSON') }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw fail(400, '请求必须是 JSON 对象')
  return value
}

function validateSettings(patch) {
  const visibility = validateModelVisibility(patch)
  const booleans = new Set(['enabled', 'exposeRegionModels', 'streamRecovery', 'standaloneProbe', 'standaloneLanEnabled'])
  const numbers = { probeIntervalMinutes: [1, 1440], defaultMaxTokens: [512, 131072], standaloneLanPort: [0, 65535] }
  const result = {}
  for (const [key, value] of Object.entries(patch)) {
    if (Object.hasOwn(visibility, key)) { result[key] = visibility[key]; continue }
    if (booleans.has(key)) {
      if (typeof value !== 'boolean') throw fail(400, `${key} 必须是布尔值`)
    } else if (Object.hasOwn(numbers, key)) {
      const [min, max] = numbers[key]
      if (!Number.isInteger(value) || value < min || value > max) throw fail(400, `${key} 必须是 ${min} 到 ${max} 的整数`)
    } else throw fail(400, `不支持的设置字段：${key}`)
    result[key] = value
  }
  return result
}

export function managementSettings(value) {
  return {
    ...publicModelVisibility(value),
    enabled: value.enabled !== false,
    exposeRegionModels: value.exposeRegionModels !== false,
    streamRecovery: value.streamRecovery !== false,
    standaloneProbe: value.standaloneProbe === true,
    standaloneLanEnabled: value.standaloneLanEnabled === true,
    standaloneLanPort: value.standaloneLanPort ?? 0,
    probeIntervalMinutes: value.probeIntervalMinutes ?? 15,
    defaultMaxTokens: value.defaultMaxTokens ?? 32768,
  }
}

/** 管理读写要求鉴权；登录恢复仅允许同源页面触发固定本机动作。 */
export function createManagement({ stores, runtime, channels, eac, info, onSettingsChanged, loginTerminal = openLoginTerminal, publicUrl, remoteAccess = false, keyFromEnv = false }) {
  let bootstrap = { token: crypto.randomBytes(32).toString('base64url'), until: Date.now() + BOOTSTRAP_MS }
  const sessions = new Map()
  // A public deployment names the one origin it is reachable at; the fence
  // then accepts that authority in addition to loopback. Without it, only
  // loopback hostnames are trusted, exactly as before.
  const publicAuthority = publicUrl === undefined ? null : parseAuthority(publicUrl, 'https')
  // Pending channel logins whose loopback callback/page lives on this host.
  // The public deployment cannot reach the user's own 127.0.0.1, so the
  // login URL is rewritten to a management route and the callback is either
  // proxied (local login pages) or replayed from a pasted URL (OAuth).
  const remoteLogins = new Map()
  const remoteLoginEnabled = publicUrl !== undefined
  const pruneRemoteLogins = () => {
    for (const [token, entry] of remoteLogins) if (entry.expiresAt <= Date.now()) remoteLogins.delete(token)
  }
  const findRemoteLogin = token => {
    pruneRemoteLogins()
    return remoteLogins.get(token)
  }
  const registerRemoteLogin = (result, payload) => {
    if (!remoteLoginEnabled || result?.ok !== true || result.value === undefined) return
    const loginUrl = result.value.loginUrl
    if (typeof loginUrl !== 'string' || loginUrl === '') return
    const target = findLocalTarget(loginUrl)
    if (target === undefined) return
    const token = crypto.randomBytes(24).toString('base64url')
    const entry = {
      token, provider: String(payload?.provider ?? ''), kind: target.kind,
      port: target.port, loginUrl, expiresAt: Date.now() + REMOTE_LOGIN_MS,
    }
    remoteLogins.set(token, entry)
    const base = info().baseUrl.replace(/\/+$/, '')
    if (target.kind === 'page') {
      const original = new URL(loginUrl)
      result.value.loginUrl = `${base}${PREFIX}/login/page/${token}${original.pathname}${original.search}`
    } else {
      result.value.loginUrl = `${base}${PREFIX}/login/manual/${token}`
    }
  }
  let cookieName
  let closed = false
  let terminalOpening = false
  let terminalOpenedAt = null
  const loginPlatform = process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'unsupported'
  const assets = new Map([...ASSETS].map(([url, [file, type]]) => [
    url, { type, body: file === 'index.html'
      ? Buffer.from(fs.readFileSync(new URL(`./web/${file}`, import.meta.url), 'utf8')
        .replace('data-login-platform="unsupported"', `data-login-platform="${loginPlatform}"`))
      : fs.readFileSync(new URL(`./web/${file}`, import.meta.url)) },
  ]))
  // 只公开构建清单中经过路径校验的 JS/CSS，绝不按请求路径读取磁盘。
  const manifest = JSON.parse(fs.readFileSync(new URL('./web/assets.json', import.meta.url), 'utf8'))
  if (!Array.isArray(manifest) || manifest.some(name => typeof name !== 'string' || !/^[\w-]+\.(js|css)$/.test(name))) {
    throw new Error('独立端资源清单无效')
  }
  for (const name of manifest) assets.set(`/assets/${name}`, {
    type: name.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8',
    body: fs.readFileSync(new URL(`./web/${name}`, import.meta.url)),
  })
  const json = (res, status, payload, headers = {}) => {
    res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'application/json; charset=utf-8', ...headers })
    res.end(JSON.stringify(payload))
  }
  const cookie = req => {
    const parts = String(req.headers.cookie ?? '').split(';')
    return parts.map(value => value.trim()).find(value => value.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1)
  }
  const clearCookie = req => `${cookieName}=; Path=${PREFIX}; HttpOnly; SameSite=Strict; Max-Age=0${requestScheme(req) === 'https' ? '; Secure' : ''}`
  const pruneSessions = () => {
    for (const [id, until] of sessions) if (until <= Date.now()) sessions.delete(id)
  }
  const authenticated = req => {
    const bearer = /^Bearer (.+)$/i.exec(String(req.headers.authorization ?? ''))?.[1]
    if (matches(bearer, stores.settings.get().forwardKey)) return true
    pruneSessions()
    return sessions.has(cookie(req))
  }
  const authorityRejection = req => {
    // Only a deployment that declared a public origin is assumed to sit behind
    // a proxy, so only then is `x-forwarded-host` allowed to name the authority.
    const authority = requestAuthority(req, { forwardedHost: publicAuthority !== null })
    if (authority === null) return 'host-invalid'
    const allowed = LOOPBACK_NAMES.has(authority.hostname) || sameAuthority(authority, publicAuthority)
    return allowed ? undefined : 'host-not-allowed'
  }
  /**
   * Host/Origin fence for the API surface. Loopback remains trusted for local
   * use; a configured public URL is the only additional authority accepted, so
   * a DNS-rebinding or cross-site caller cannot reach management data through
   * another Host. The scheme is read from `x-forwarded-proto` because a
   * platform proxy terminates TLS in front of this plain-HTTP listener.
   *
   * Static assets use only `authorityRejection`: a top-level navigation from
   * another site carries a cross-site `Sec-Fetch-Site` and an external
   * `Referer`, and serving the login page there changes no state.
   */
  const trustRejection = req => {
    const hostReason = authorityRejection(req)
    if (hostReason !== undefined) return hostReason
    if (String(req.headers['sec-fetch-site'] ?? '').toLowerCase() === 'cross-site') return 'cross-site'
    for (const header of ['origin', 'referer']) {
      const raw = req.headers[header]
      if (typeof raw !== 'string' || raw.trim() === '') continue
      const parsed = parseAuthority(raw, 'http')
      if (parsed === null) return `${header}-invalid`
      if (!sameAuthority(parsed, requestAuthority(req, { forwardedHost: publicAuthority !== null })) &&
          !sameAuthority(parsed, publicAuthority)) return `${header}-mismatch`
    }
    return undefined
  }
  const sameOrigin = req => sameAuthority(
    requestAuthority(req, { forwardedHost: publicAuthority !== null }),
    parseAuthority(req.headers.origin, 'http'),
  )
  const persist = patch => {
    const previous = stores.settings.get()
    stores.settings.update(patch)
    stores.settings.flush()
    if (stores.settings.writeFailed) {
      // 不向页面谎报保存成功；保留原运行配置并由后续写入重试落盘。
      stores.settings.value = previous
      throw fail(500, '无法保存设置，请检查数据目录权限和磁盘空间')
    }
  }
  const summary = () => {
    const state = runtime.state()
    const available = stores.availability.get()
    const routable = new Set(runtime.publicModelRows().map(entry => entry.id))
    return {
      ...info(),
      channels: channels?.state(),
      eacAuth: eac?.cached(),
      settings: managementSettings(stores.settings.get()),
      catalogSyncedAt: stores.settings.get().catalogSyncedAt ?? 0,
      probedAt: available.at ?? 0,
      catalog: state.catalog.map(entry => ({
        id: entry.id, name: entry.name, channel: entry.channel ?? 'anonymous',
        vision: entry.vision === true, reasoning: entry.reasoning === true || (entry.reasoning !== null && typeof entry.reasoning === 'object'),
        contextWindow: entry.contextWindow ?? entry.context_window, maxOutput: entry.maxOutput ?? entry.max_tokens,
        routable: routable.has(entry.id),
        hiddenByUser: isModelHidden(entry, state.settings),
        hiddenByGroup: isModelHidden(entry, { ...state.settings, hiddenModelIds: [] }),
        availability: entry.channel ? 'listed' : available.results?.[entry.id]?.state ?? 'unknown',
        ttftMs: available.results?.[entry.id]?.ttftMs ?? null,
      })),
    }
  }

  async function route(req, res, pathname) {
    const method = req.method ?? 'GET'
    if (method === 'POST' && pathname === `${PREFIX}/login/terminal`) {
      // 此入口发生在登录前，必须有浏览器的同源 Origin，拒绝跨站和无来源调用。
      // 远程部署没有可打开的本机终端，令牌只能来自启动日志中的一次性链接。
      if (remoteAccess) throw fail(400, '远程部署不支持自动获取令牌，请使用启动日志中的一次性登录链接')
      if (!sameOrigin(req) || req.headers['sec-fetch-site'] !== 'same-origin') {
        throw fail(403, '请从本机登录页面点击获取令牌')
      }
      const body = await readBody(req)
      if (Object.keys(body).length !== 0) throw fail(400, '获取令牌不接受路径或命令参数')
      if (terminalOpening || (terminalOpenedAt !== null && Date.now() - terminalOpenedAt < 30_000)) {
        throw fail(429, '已请求打开终端，请检查弹出的窗口，30 秒后可重试')
      }
      terminalOpening = true
      try {
        await loginTerminal(info().dataDir)
        terminalOpenedAt = Date.now()
        json(res, 200, { ok: true })
      } finally { terminalOpening = false }
      return
    }
    if (method === 'POST' && pathname === `${PREFIX}/session`) {
      const body = await readBody(req)
      const validBootstrap = bootstrap !== null && bootstrap.until > Date.now() && matches(body.bootstrapToken, bootstrap.token)
      if (!validBootstrap && !matches(body.key, stores.settings.get().forwardKey)) throw fail(401, '登录链接已失效或 API Key 不正确')
      pruneSessions()
      if (sessions.size >= 64) throw fail(429, '管理会话过多，请稍后重试')
      if (validBootstrap) bootstrap = null
      const id = crypto.randomBytes(32).toString('base64url')
      sessions.set(id, Date.now() + SESSION_MS)
      json(res, 200, { ok: true }, {
        'set-cookie': `${cookieName}=${id}; Path=${PREFIX}; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MS / 1000}${requestScheme(req) === 'https' ? '; Secure' : ''}`,
      })
      return
    }
    if (!authenticated(req)) throw fail(401, '请先登录管理页面')
    if (method === 'POST' && pathname === `${PREFIX}/logout`) {
      await readBody(req)
      sessions.delete(cookie(req))
      json(res, 200, { ok: true }, { 'set-cookie': clearCookie(req) })
    } else if (method === 'GET' && pathname === `${PREFIX}/summary`) {
      json(res, 200, summary())
    } else if (method === 'GET' && pathname === `${PREFIX}/stats`) {
      json(res, 200, buildStats(stores.stats.get(), runtime.catalog))
    } else if (method === 'POST' && pathname === `${PREFIX}/login/callback`) {
      const body = await readBody(req)
      const entry = findRemoteLogin(body.token)
      if (entry === undefined || entry.kind !== 'callback') throw fail(404, '授权会话不存在或已过期')
      const targetPath = localCallbackPath(body.url, entry.port)
      if (targetPath === undefined) throw fail(400, '地址不是本次授权流程的回调地址')
      const outcome = await replayLocalCallback(entry.port, targetPath)
        .catch(() => { throw fail(502, '无法连接本机回调服务，授权可能已超时') })
      remoteLogins.delete(entry.token)
      json(res, 200, { ok: true, pending: outcome.pending })
    } else if (method === 'GET' && pathname.startsWith(`${PREFIX}/login/manual/`)) {
      const entry = findRemoteLogin(pathname.slice(`${PREFIX}/login/manual/`.length))
      if (entry === undefined || entry.kind !== 'callback') throw fail(404, '授权会话不存在或已过期')
      res.writeHead(200, { ...loginPageHeaders(entry.provider), 'content-type': 'text/html; charset=utf-8' })
      res.end(renderManualLoginPage(entry))
    } else if (pathname.startsWith(`${PREFIX}/login/page/`)) {
      const rest = pathname.slice(`${PREFIX}/login/page/`.length)
      const slash = rest.indexOf('/')
      const token = slash === -1 ? rest : rest.slice(0, slash)
      const localPath = slash === -1 ? '/' : rest.slice(slash)
      const entry = findRemoteLogin(token)
      if (entry === undefined || entry.kind !== 'page') throw fail(404, '授权页面不存在或已过期')
      const allowed = entry.provider === 'loomy' ? '/wechat/' : entry.provider === 'raccoon' ? '/raccoon/' : '/'
      if (!localPath.startsWith(allowed) || /(^|\/)\.\.?(\/|$)|%2e/i.test(localPath)) throw fail(404, '授权页面路径无效')
      if (!['GET', 'POST', 'HEAD'].includes(method)) throw fail(405, '授权页面只支持 GET、POST 或 HEAD')
      const search = new URL(req.url ?? '/', 'http://localhost').search
      const body = method === 'POST' ? await readRawBody(req, 64 * 1024) : undefined
      const upstream = await new Promise((resolve, reject) => {
        const request = http.request({
          host: '127.0.0.1', port: entry.port, path: `${localPath}${search}`, method, timeout: 40_000,
          headers: {
            ...method === 'POST' && typeof req.headers['content-type'] === 'string'
              ? { 'content-type': req.headers['content-type'] } : {},
            ...body === undefined ? {} : { 'content-length': String(body.length) },
          },
        }, response => {
          const chunks = []
          let bytes = 0
          response.on('data', chunk => {
            bytes += chunk.length
            if (bytes <= REMOTE_PROXY_LIMIT) chunks.push(chunk)
          })
          response.once('end', () => resolve({
            status: response.statusCode ?? 502,
            type: String(response.headers['content-type'] ?? 'application/octet-stream'),
            body: Buffer.concat(chunks),
          }))
        })
        request.once('timeout', () => { request.destroy(new Error('timeout')) })
        request.once('error', reject)
        request.end(body)
      }).catch(() => { throw fail(502, '无法连接本机登录页，授权可能已超时') })
      if (upstream.type.toLowerCase().includes('text/html')) {
        res.writeHead(upstream.status, { ...loginPageHeaders(entry.provider), 'content-type': 'text/html; charset=utf-8' })
        res.end(rewriteProxiedHtml(upstream.body.toString('utf8'), entry))
      } else {
        res.writeHead(upstream.status, {
          'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer', 'content-type': upstream.type,
        })
        res.end(upstream.body)
      }
    } else if (method === 'POST' && pathname === `${PREFIX}/channels/rpc` && channels) {
      // 渠道备份导入包含多账号凭据，仍限制总大小，但不能套设置表单的 16KB。
      const body = await readBody(req, 8 * 1024 * 1024)
      if (body.method === 'gateway.getEnabled' || body.method === 'gateway.setEnabled') {
        if (body.method === 'gateway.setEnabled') {
          if (typeof body.payload?.enabled !== 'boolean') throw fail(400, 'enabled 必须是布尔值')
          persist({ enabled: body.payload.enabled })
          await onSettingsChanged()
        }
        const base = new URL(info().baseUrl)
        const port = base.port === '' ? (base.protocol === 'https:' ? 443 : 80) : Number(base.port)
        json(res, 200, { ok: true, value: {
          enabled: stores.settings.get().enabled !== false, running: stores.settings.get().enabled !== false,
          blockedByEnv: false, address: { host: base.hostname, port },
          apiKey: { value: stores.settings.get().forwardKey, path: `${info().dataDir}/settings.json`, fromEnv: keyFromEnv },
          models: runtime.publicModelRows(), modelsSource: 'catalog',
        } })
      } else {
        const controller = new AbortController()
        const abort = () => controller.abort()
        res.once('close', abort)
        try {
          const result = await channels.rpc(body, controller.signal)
          if (body.method === 'account.create') registerRemoteLogin(result, body.payload)
          json(res, 200, result)
        } finally { res.removeListener('close', abort) }
      }
    } else if (eac && pathname.startsWith(`${PREFIX}/eac/`)) {
      const params = new URL(req.url, 'http://localhost').searchParams
      const route = pathname.slice(PREFIX.length)
      let result
      if (method === 'GET' && route === '/eac/status') result = await eac.status()
      else if (method === 'GET' && route === '/eac/login/poll') result = await eac.poll(params.get('link') ?? '')
      else if (method === 'GET' && route === '/eac/pool') result = await eac.pool()
      else if (method === 'POST') {
        await readBody(req)
        if (route === '/eac/login/start') result = await eac.start()
        else if (route === '/eac/login/cancel') result = eac.cancel(params.get('link') ?? '')
        else if (route === '/eac/logout') result = await eac.logout()
      }
      if (result === undefined) throw fail(404, 'EAC 接口不存在')
      if (result.error) throw fail(502, result.error)
      if (result.ok === false) throw fail(500, '无法移除本地授权')
      json(res, 200, result)
    } else if (method === 'POST' && pathname === `${PREFIX}/settings`) {
      const patch = validateSettings(await readBody(req))
      persist(patch)
      await onSettingsChanged()
      json(res, 200, { settings: managementSettings(stores.settings.get()), lan: info().lan })
    } else if (method === 'GET' && pathname === `${PREFIX}/lan/key`) {
      json(res, 200, { key: stores.settings.get().standaloneLanKey ?? '' })
    } else if (method === 'POST' && pathname === `${PREFIX}/lan/key/rotate`) {
      const body = await readBody(req)
      if (body.confirm !== true || Object.keys(body).length !== 1) throw fail(400, 'LAN key rotation requires only confirm: true')
      persist({ standaloneLanKey: generateKey() })
      json(res, 200, { key: stores.settings.get().standaloneLanKey })
    } else if (method === 'GET' && pathname === `${PREFIX}/key`) {
      json(res, 200, { key: stores.settings.get().forwardKey })
    } else if (method === 'POST' && pathname === `${PREFIX}/key/rotate`) {
      // A platform-managed key is authoritative across restarts; rotating it in
      // memory would silently revert on the next deploy.
      if (keyFromEnv) throw fail(400, 'API Key 由环境变量管理，请在部署平台修改 OFM_FORWARD_KEY 后重新部署')
      const body = await readBody(req)
      if (body.confirm !== true) throw fail(400, '请确认轮换 API Key')
      const id = cookie(req)
      persist({ forwardKey: generateKey() })
      // 仅当前管理会话保留；旧密钥与其他会话立即失效。
      const until = sessions.get(id)
      sessions.clear()
      if (until) sessions.set(id, until)
      bootstrap = null
      json(res, 200, { key: stores.settings.get().forwardKey })
    } else if (method === 'POST' && pathname === `${PREFIX}/models/refresh`) {
      const body = await readBody(req)
      if (body.probe !== undefined && typeof body.probe !== 'boolean') throw fail(400, 'probe 必须是布尔值')
      await runtime.refreshCatalog({ probe: body.probe === true, force: body.probe === true })
      json(res, 200, summary())
    } else if (method === 'POST' && pathname === `${PREFIX}/models/test`) {
      const body = await readBody(req)
      if (stores.settings.get().enabled === false) throw fail(503, '推理服务已暂停，请先在服务设置中启用')
      if (typeof body.model !== 'string' || body.model.length > 300) throw fail(400, '请选择有效模型')
      const controller = new AbortController()
      const abort = () => controller.abort()
      res.once('close', abort)
      const deadline = setTimeout(abort, 60_000)
      deadline.unref?.()
      const started = Date.now()
      try {
        const outcome = await runtime.complete({
          model: body.model, signal: controller.signal,
          openAi: { messages: [{ role: 'user', content: 'Reply with OK.' }], max_tokens: 64 },
        })
        if (outcome.error) throw fail(502, outcome.error)
        json(res, 200, { ok: true, text: outcome.text.slice(0, 2000), latencyMs: Date.now() - started })
      } finally {
        clearTimeout(deadline)
        res.removeListener('close', abort)
      }
    } else throw fail(404, '管理接口不存在')
  }

  return {
    setPort(port) { cookieName = `ofm_management_${port}` },
    get bootstrapFragment() { return bootstrap === null ? '' : `#login=${bootstrap.token}` },
    async handleRequest(req, res) {
      const pathname = new URL(req.url ?? '/', 'http://localhost').pathname
      const asset = assets.get(pathname)
      const isApi = pathname === PREFIX || pathname.startsWith(`${PREFIX}/`)
      if (!asset && !isApi) return false
      if (closed || !cookieName) json(res, 503, { error: '服务正在停止或启动' })
      else if ((asset === undefined ? trustRejection(req) : authorityRejection(req)) !== undefined) {
        json(res, 403, { error: '管理接口仅允许同源访问' })
      }
      else if (asset) {
        if (req.method !== 'GET' && req.method !== 'HEAD') json(res, 405, { error: '资源仅支持 GET 或 HEAD' })
        else {
          res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': asset.type })
          res.end(req.method === 'HEAD' ? undefined : asset.body)
        }
      } else {
        try { await route(req, res, pathname) } catch (error) {
          if (!res.destroyed && !res.headersSent) json(res, error.statusCode ?? 500, {
            error: error.statusCode ? error.message : '管理操作失败，请查看服务日志',
          })
        }
      }
      return true
    },
    dispose() { closed = true; bootstrap = null; sessions.clear() },
  }
}
