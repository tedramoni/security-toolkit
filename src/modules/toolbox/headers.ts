import { evaluateCsp, getDirective, parseCsp } from './csp'
import type { Finding, Severity } from './types'
import { worstSeverity } from './types'

/*
 * HTTP response security header analyzer.
 * Primary reference: OWASP HTTP Headers Cheat Sheet
 *   https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
 * Cookies: RFC 6265bis (cookie prefixes, SameSite) and MDN Set-Cookie
 *   https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie
 */

const OWASP_HEADERS = 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'
const MDN_COOKIE = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie'
const MDN_HSTS = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security'

export interface ParsedHeaders {
  /** Lower-cased header name -> values (in order). */
  headers: Map<string, string[]>
  statusLine?: string
  /** Number of responses found (e.g. curl -L shows one block per redirect). Only the last is analysed. */
  responseCount: number
}

export function parseHeaders(raw: string): ParsedHeaders {
  const lines = raw.replace(/\r\n?/g, '\n').split('\n')
  let headers = new Map<string, string[]>()
  let statusLine: string | undefined
  let responseCount = 0
  let lastName: string | undefined
  for (let rawLine of lines) {
    // curl -v prefixes response headers with "< "
    rawLine = rawLine.replace(/^<\s?/, '')
    if (rawLine.trim() === '') continue
    if (/^HTTP\/\d(?:\.\d)?\s+\d{3}/i.test(rawLine.trim())) {
      // New response block: only keep the last one.
      responseCount++
      headers = new Map()
      statusLine = rawLine.trim()
      lastName = undefined
      continue
    }
    if (/^[ \t]/.test(rawLine) && lastName) {
      // obs-fold continuation line
      const vals = headers.get(lastName)!
      vals[vals.length - 1] += ' ' + rawLine.trim()
      continue
    }
    const idx = rawLine.indexOf(':')
    if (idx <= 0) continue
    const name = rawLine.slice(0, idx).trim().toLowerCase()
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) continue
    const value = rawLine.slice(idx + 1).trim()
    const list = headers.get(name) ?? []
    list.push(value)
    headers.set(name, list)
    lastName = name
  }
  return { headers, statusLine, responseCount: Math.max(responseCount, headers.size > 0 ? 1 : 0) }
}

/** Single combined value (comma-joined, as HTTP allows for list headers). */
function get(h: Map<string, string[]>, name: string): string | undefined {
  const v = h.get(name)
  return v === undefined ? undefined : v.join(', ')
}

/* ---------- cookies ---------- */

export interface ParsedCookie {
  name: string
  value: string
  /** Lower-cased attribute name -> value ('' for flags). */
  attributes: Map<string, string>
  raw: string
}

export function parseSetCookie(raw: string): ParsedCookie {
  const [pair, ...attrs] = raw.split(';')
  const eq = pair.indexOf('=')
  const name = (eq === -1 ? '' : pair.slice(0, eq)).trim()
  const value = (eq === -1 ? pair : pair.slice(eq + 1)).trim()
  const attributes = new Map<string, string>()
  for (const a of attrs) {
    const i = a.indexOf('=')
    const k = (i === -1 ? a : a.slice(0, i)).trim().toLowerCase()
    if (!k) continue
    attributes.set(k, i === -1 ? '' : a.slice(i + 1).trim())
  }
  return { name, value, attributes, raw }
}

const SESSION_NAME = /sess|sid$|^sid|auth|token|jwt|login|remember|identity|^id$|connect\.sid|jsessionid|phpsessid|asp\.net_sessionid/i

/** Anti-CSRF cookies (double-submit: csrftoken, XSRF-TOKEN…) must often be readable by JS — not session cookies. */
const CSRF_NAME = /csrf|xsrf/i

export function isSessionLikeCookie(name: string): boolean {
  return SESSION_NAME.test(name) && !CSRF_NAME.test(name)
}

/** Remaining lifetime in seconds, from Max-Age (takes precedence) or Expires. undefined = session cookie. */
export function cookieLifetime(c: ParsedCookie, now: number): number | undefined {
  const maxAge = c.attributes.get('max-age')
  if (maxAge !== undefined && /^-?\d+$/.test(maxAge)) return parseInt(maxAge, 10)
  const expires = c.attributes.get('expires')
  if (expires !== undefined) {
    const t = Date.parse(expires)
    if (!Number.isNaN(t)) return Math.round(t / 1000 - now)
  }
  return undefined
}

export interface CookieReport {
  name: string
  secure: boolean
  httpOnly: boolean
  sameSite?: string
  domain?: string
  path?: string
  lifetimeSeconds?: number
  sessionLike: boolean
  findings: Finding[]
}

const DAY = 86400

export function analyzeCookie(raw: string, now: number): CookieReport {
  const c = parseSetCookie(raw)
  const a = c.attributes
  const name = c.name || '(unnamed)'
  const secure = a.has('secure')
  const httpOnly = a.has('httponly')
  const sameSiteRaw = a.get('samesite')
  const sameSite = sameSiteRaw?.toLowerCase()
  const domain = a.get('domain')
  const path = a.get('path')
  const lifetime = cookieLifetime(c, now)
  const sessionLike = isSessionLikeCookie(c.name)
  const f: Finding[] = []
  const t = (s: string) => `Cookie ${name}: ${s}`

  if (lifetime !== undefined && lifetime <= 0) {
    f.push({ severity: 'info', title: t('deletion cookie'), detail: 'Max-Age/Expires is in the past: this response deletes the cookie. Attribute checks still apply.' })
  }

  if (!secure) {
    f.push({
      severity: sessionLike ? 'high' : 'medium',
      title: t('missing Secure'),
      detail: 'The cookie can be sent over plain HTTP and intercepted on the network.',
      fix: 'Add the Secure attribute (and serve the whole site over HTTPS with HSTS).',
      ref: MDN_COOKIE,
    })
  }
  if (!httpOnly) {
    f.push({
      severity: sessionLike ? 'medium' : 'low',
      title: t('missing HttpOnly'),
      detail: sessionLike
        ? 'This looks like a session/auth cookie and is readable by JavaScript — any XSS can steal it.'
        : 'Readable by JavaScript. Fine only if your front-end really needs to read it.',
      fix: 'Add HttpOnly unless client-side scripts must read the value.',
      ref: MDN_COOKIE,
    })
  }
  if (sameSite === undefined) {
    f.push({
      severity: 'low',
      title: t('no SameSite attribute'),
      detail: 'Chromium defaults to Lax, but other browsers may not apply that default, so cross-site requests (CSRF) may carry this cookie.',
      fix: 'Set SameSite=Lax (or Strict for sensitive cookies) explicitly.',
      ref: MDN_COOKIE,
    })
  } else if (!['strict', 'lax', 'none'].includes(sameSite)) {
    f.push({ severity: 'low', title: t(`invalid SameSite value "${sameSiteRaw}"`), detail: 'Unknown values are ignored by browsers.', fix: 'Use Strict, Lax or None.' })
  } else if (sameSite === 'none') {
    if (!secure) {
      f.push({
        severity: 'high',
        title: t('SameSite=None without Secure'),
        detail: 'Browsers reject SameSite=None cookies that are not Secure — the cookie will not be set at all.',
        fix: 'Add Secure, or use SameSite=Lax if cross-site sending is not required.',
        ref: MDN_COOKIE,
      })
    } else {
      f.push({
        severity: sessionLike ? 'medium' : 'info',
        title: t('SameSite=None'),
        detail: 'The cookie is sent on cross-site requests, so endpoints relying on it need explicit CSRF protection.',
        fix: 'Use Lax/Strict unless a cross-site use case (embedded iframe, third-party API) requires None.',
      })
    }
  }

  if (c.name.startsWith('__Host-')) {
    const problems: string[] = []
    if (!secure) problems.push('Secure is missing')
    if (path !== '/') problems.push('Path must be "/"')
    if (domain !== undefined) problems.push('Domain must not be set')
    if (problems.length > 0) {
      f.push({
        severity: 'high',
        title: t('invalid __Host- prefix'),
        detail: `Browsers reject this cookie: ${problems.join(', ')}.`,
        fix: '__Host- cookies need Secure, Path=/ and no Domain attribute.',
        ref: MDN_COOKIE,
      })
    }
  } else if (c.name.startsWith('__Secure-') && !secure) {
    f.push({ severity: 'high', title: t('invalid __Secure- prefix'), detail: 'Browsers reject __Secure- cookies without the Secure attribute.', fix: 'Add Secure.', ref: MDN_COOKIE })
  } else if (sessionLike && secure && domain === undefined && path === '/' && !c.name.startsWith('__')) {
    f.push({
      severity: 'info',
      title: t('could use the __Host- prefix'),
      detail: 'The __Host- prefix guarantees the cookie was set by this exact host over HTTPS and cannot be overwritten by a subdomain.',
      fix: `Rename to __Host-${c.name}.`,
      ref: MDN_COOKIE,
    })
  }

  if (domain !== undefined) {
    f.push({
      severity: sessionLike ? 'medium' : 'low',
      title: t(`Domain=${domain} shares it with all subdomains`),
      detail: 'Setting Domain makes the cookie available to every subdomain; a compromised or user-controlled subdomain can read or overwrite it.',
      fix: 'Omit the Domain attribute so the cookie is host-only, unless subdomains truly need it.',
      ref: MDN_COOKIE,
    })
  }

  if (sessionLike && lifetime !== undefined && lifetime > 30 * DAY) {
    f.push({
      severity: 'medium',
      title: t(`long lifetime (${Math.round(lifetime / DAY)} days)`),
      detail: 'A session/auth cookie that persists for a long time widens the window to use a stolen cookie (shared computers, backups, malware).',
      fix: 'Use a session cookie (no Expires/Max-Age) or a short lifetime with server-side idle and absolute timeouts.',
      ref: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
    })
  }

  if (f.every((x) => x.severity === 'info')) {
    f.push({ severity: 'pass', title: t('attributes look good'), detail: 'Secure, HttpOnly and SameSite are set.' })
  }

  return { name, secure, httpOnly, sameSite: sameSiteRaw, domain, path, lifetimeSeconds: lifetime, sessionLike, findings: f }
}

/* ---------- header checks ---------- */

export function checkHsts(value: string | undefined): Finding {
  if (value === undefined) {
    return {
      severity: 'high',
      title: 'Strict-Transport-Security missing',
      detail: 'Without HSTS, the first request (or any typed http:// URL) can be downgraded and intercepted (SSL stripping). Note: browsers only honour HSTS received over HTTPS.',
      fix: 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload (preload only after reading hstspreload.org requirements)',
      ref: OWASP_HEADERS,
    }
  }
  const lower = value.toLowerCase()
  const m = /max-age\s*=\s*"?(\d+)"?/.exec(lower)
  const sub = /(^|;)\s*includesubdomains\s*(;|$)/.test(lower)
  const preload = /(^|;)\s*preload\s*(;|$)/.test(lower)
  if (!m) return { severity: 'high', title: 'HSTS without a valid max-age', detail: 'max-age is required; browsers ignore the header.', fix: 'Strict-Transport-Security: max-age=63072000; includeSubDomains', ref: MDN_HSTS }
  const maxAge = parseInt(m[1], 10)
  if (maxAge === 0) return { severity: 'high', title: 'HSTS disabled (max-age=0)', detail: 'max-age=0 tells browsers to forget HSTS for this host.', fix: 'Set max-age to at least 31536000 (1 year).', ref: MDN_HSTS }
  if (maxAge < 31536000) {
    return {
      severity: 'medium',
      title: `HSTS max-age too short (${Math.round(maxAge / DAY)} days)`,
      detail: 'Short max-age values expire between visits, re-opening the downgrade window. One year is the recommended minimum (and required for preload).',
      fix: 'Set max-age=31536000 or more (63072000 = 2 years is common).',
      ref: OWASP_HEADERS,
    }
  }
  if (!sub) {
    return {
      severity: 'low',
      title: 'HSTS without includeSubDomains',
      detail: 'Subdomains are not protected; an attacker can use an http:// subdomain to set or read cookies scoped to the parent domain.',
      fix: 'Add includeSubDomains once every subdomain serves HTTPS.',
      ref: MDN_HSTS,
    }
  }
  return {
    severity: 'pass',
    title: 'Strict-Transport-Security is strong',
    detail: preload
      ? 'max-age ≥ 1 year with includeSubDomains and preload. Make sure the domain is actually submitted at https://hstspreload.org — removal from the preload list takes months.'
      : 'max-age ≥ 1 year with includeSubDomains. Optional: add preload and submit to https://hstspreload.org.',
    ref: MDN_HSTS,
  }
}

export function checkCsp(h: Map<string, string[]>): Finding[] {
  const csp = get(h, 'content-security-policy')
  const ro = get(h, 'content-security-policy-report-only')
  if (csp === undefined) {
    return [
      {
        severity: ro !== undefined ? 'medium' : 'high',
        title: ro !== undefined ? 'CSP is report-only' : 'Content-Security-Policy missing',
        detail: ro !== undefined
          ? 'A Report-Only policy is present but nothing is enforced.'
          : 'No CSP: injected scripts run freely. CSP is the main defence-in-depth control against XSS.',
        fix: "Start with: script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none' — use the CSP tab to build one.",
        ref: 'https://web.dev/articles/strict-csp',
      },
    ]
  }
  // Multiple CSP headers are all enforced; evaluate the first (most common case is one header).
  const findings = evaluateCsp(parseCsp(h.get('content-security-policy')![0]))
  // Clickjacking (frame-ancestors) is reported by its own check, which looks at every CSP header; don't count it twice.
  const issues = findings.filter((x) => x.severity !== 'pass' && x.severity !== 'info' && !x.title.includes('frame-ancestors'))
  const worst = worstSeverity(issues)
  const extra: Finding[] = []
  const policyCount = h.get('content-security-policy')!.flatMap((v) => v.split(',')).filter((p) => p.trim() !== '').length
  if (policyCount > 1) {
    extra.push({
      severity: 'info',
      title: `${policyCount} Content-Security-Policy policies sent`,
      detail: 'Browsers enforce every policy (a resource must pass all of them). Only the first policy is summarised here — paste the others in the CSP tab.',
    })
  }
  if (!worst) {
    return [{ severity: 'pass', title: 'Content-Security-Policy present and strong', detail: 'No significant issues found by the CSP evaluator.' }, ...extra]
  }
  return [
    ...extra,
    {
      severity: worst,
      title: `Content-Security-Policy present, ${issues.length} issue${issues.length > 1 ? 's' : ''}`,
      detail: issues.map((x) => `[${x.severity}] ${x.title}`).join(' · '),
      fix: 'Paste the policy in the CSP tab for details and fixes.',
    },
  ]
}

function checkClickjacking(h: Map<string, string[]>): Finding {
  // Repeated identical X-Frame-Options values ("DENY, DENY") are treated as one by browsers.
  const xfoValues = [...new Set((h.get('x-frame-options') ?? []).flatMap((v) => v.split(',')).map((v) => v.trim().toUpperCase()).filter(Boolean))]
  const xfo = h.has('x-frame-options') ? xfoValues.join(', ') : undefined
  // Every enforced CSP header (and comma-separated policy) applies; use the first one that sets frame-ancestors.
  const fa = (h.get('content-security-policy') ?? [])
    .flatMap((v) => v.split(','))
    .map((p) => getDirective(parseCsp(p), 'frame-ancestors'))
    .find((d) => d !== undefined)
  if (fa) {
    const open = fa.some((v) => v === '*' || /^https?:$/i.test(v))
    return open
      ? { severity: 'medium', title: 'frame-ancestors allows any site', detail: 'The page can be framed by any origin.', fix: "Use frame-ancestors 'none' or 'self'." }
      : { severity: 'pass', title: 'Framing restricted (CSP frame-ancestors)', detail: `frame-ancestors ${fa.join(' ')}${xfo ? ` (X-Frame-Options: ${xfo} also set for old browsers)` : ''}.` }
  }
  if (xfo === 'DENY' || xfo === 'SAMEORIGIN') {
    return { severity: 'pass', title: `X-Frame-Options: ${xfo}`, detail: 'Framing is restricted. CSP frame-ancestors is the modern equivalent and takes precedence when both are set.' }
  }
  if (xfo?.startsWith('ALLOW-FROM')) {
    return {
      severity: 'medium',
      title: 'X-Frame-Options ALLOW-FROM is obsolete',
      detail: 'Modern browsers ignore ALLOW-FROM — the page is effectively frameable by anyone.',
      fix: 'Use CSP frame-ancestors https://trusted.example instead.',
      ref: OWASP_HEADERS,
    }
  }
  return {
    severity: 'medium',
    title: 'No clickjacking protection',
    detail: xfo ? `Invalid X-Frame-Options value "${xfo}" and no CSP frame-ancestors.` : 'Neither X-Frame-Options nor CSP frame-ancestors is set: any site can frame this page.',
    fix: "Content-Security-Policy: frame-ancestors 'none' (and X-Frame-Options: DENY for legacy browsers).",
    ref: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
  }
}

const REFERRER_GOOD = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
const REFERRER_ALL = [...REFERRER_GOOD, 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'unsafe-url']

function checkReferrer(value: string | undefined): Finding {
  if (value === undefined) {
    return {
      severity: 'low',
      title: 'Referrer-Policy missing',
      detail: 'Modern browsers default to strict-origin-when-cross-origin, but setting it explicitly protects older clients and documents intent.',
      fix: 'Referrer-Policy: strict-origin-when-cross-origin',
      ref: OWASP_HEADERS,
    }
  }
  // The browser uses the last policy it understands.
  const tokens = value.split(',').map((t) => t.trim().toLowerCase()).filter((t) => REFERRER_ALL.includes(t))
  const eff = tokens[tokens.length - 1]
  if (!eff) return { severity: 'low', title: `Referrer-Policy has no valid value ("${value}")`, detail: 'Browsers fall back to their default.', fix: 'Referrer-Policy: strict-origin-when-cross-origin' }
  if (REFERRER_GOOD.includes(eff)) return { severity: 'pass', title: `Referrer-Policy: ${eff}`, detail: 'Full URLs (paths, query strings with tokens) are not leaked cross-origin.' }
  return {
    severity: eff === 'unsafe-url' || eff === 'no-referrer-when-downgrade' ? 'medium' : 'low',
    title: `Weak Referrer-Policy: ${eff}`,
    detail: eff === 'unsafe-url' || eff === 'no-referrer-when-downgrade'
      ? 'The full URL (including path and query string, which may contain tokens or IDs) is sent to other origins.'
      : 'The origin is sent even on HTTPS→HTTP downgrades.',
    fix: 'Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)',
    ref: OWASP_HEADERS,
  }
}

function infoDisclosure(h: Map<string, string[]>): Finding[] {
  const f: Finding[] = []
  const server = get(h, 'server')
  if (server !== undefined) {
    f.push(/\d/.test(server)
      ? { severity: 'low', title: `Server header discloses version ("${server}")`, detail: 'Version numbers let attackers match the server to known CVEs instantly.', fix: 'Remove the version (e.g. nginx: server_tokens off; Apache: ServerTokens Prod).', ref: OWASP_HEADERS }
      : { severity: 'info', title: `Server header: "${server}"`, detail: 'No version shown. Consider removing it or using a generic value.', ref: OWASP_HEADERS })
  }
  const leaky: [string, string, string][] = [
    ['x-powered-by', 'X-Powered-By', 'Remove it (Express: app.disable("x-powered-by"); PHP: expose_php = Off).'],
    ['x-aspnet-version', 'X-AspNet-Version', 'Set <httpRuntime enableVersionHeader="false" /> in web.config.'],
    ['x-aspnetmvc-version', 'X-AspNetMvc-Version', 'Set MvcHandler.DisableMvcResponseHeader = true at startup.'],
    ['x-generator', 'X-Generator', 'Remove it in the CMS / framework configuration.'],
  ]
  for (const [key, label, fix] of leaky) {
    const v = get(h, key)
    if (v !== undefined) f.push({ severity: 'low', title: `${label} discloses technology ("${v}")`, detail: 'Fingerprinting information helps attackers pick exploits.', fix, ref: OWASP_HEADERS })
  }
  return f
}

function checkCors(h: Map<string, string[]>): Finding[] {
  const acao = get(h, 'access-control-allow-origin')?.trim()
  if (acao === undefined) return []
  const creds = get(h, 'access-control-allow-credentials')?.trim().toLowerCase() === 'true'
  if (acao === '*' && creds) {
    return [{
      severity: 'critical',
      title: 'CORS: wildcard origin with credentials',
      detail: 'Access-Control-Allow-Origin: * together with Allow-Credentials: true. Browsers refuse this combination, but it shows the server intends credentialed cross-origin access — such servers often reflect the Origin header instead, letting any site read authenticated responses.',
      fix: 'Validate Origin against an exact allowlist and echo only allowed origins; never reflect arbitrary origins with credentials.',
      ref: 'https://portswigger.net/web-security/cors',
    }]
  }
  if (acao.toLowerCase() === 'null') {
    return [{
      severity: creds ? 'high' : 'medium',
      title: 'CORS: "null" origin allowed',
      detail: 'The "null" origin is sent by sandboxed iframes, file:// pages and some redirects — any attacker can produce it.',
      fix: 'Never allow "null"; use an explicit allowlist of origins.',
      ref: 'https://portswigger.net/web-security/cors',
    }]
  }
  if (acao === '*') {
    return [{ severity: 'info', title: 'CORS: Access-Control-Allow-Origin: *', detail: 'Any site can read this response (without cookies). Fine for genuinely public data/APIs only.' }]
  }
  const f: Finding[] = [{
    severity: 'info',
    title: `CORS allows ${acao}${creds ? ' with credentials' : ''}`,
    detail: 'If this value changes with the request Origin header, make sure it is checked against an exact allowlist (no suffix/regex matching like *.example.com.evil.com).',
    ref: 'https://portswigger.net/web-security/cors',
  }]
  const vary = get(h, 'vary')?.toLowerCase() ?? ''
  if (!vary.includes('origin') && !vary.includes('*')) {
    f.push({
      severity: 'low',
      title: 'CORS origin echoed without Vary: Origin',
      detail: 'Caches may serve a response with one origin\'s ACAO to another origin (cache poisoning / broken CORS).',
      fix: 'Add Vary: Origin to responses whose Access-Control-Allow-Origin depends on the request.',
    })
  }
  return f
}

/* ---------- full analysis ---------- */

export interface HeaderAnalysis {
  parsed: ParsedHeaders
  findings: Finding[]
  cookies: CookieReport[]
  score: number
  grade: string
}

const PENALTY: Record<Severity, number> = { critical: 30, high: 15, medium: 8, low: 3, info: 0, pass: 0 }

export function gradeFor(score: number): string {
  if (score >= 95) return 'A+'
  if (score >= 85) return 'A'
  if (score >= 70) return 'B'
  if (score >= 55) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

export function analyzeHeaders(raw: string, now: number = Date.now() / 1000): HeaderAnalysis {
  const parsed = parseHeaders(raw)
  const h = parsed.headers
  const f: Finding[] = []

  if (parsed.responseCount > 1) {
    f.push({ severity: 'info', title: `${parsed.responseCount} responses found`, detail: 'Only the last response block (after redirects) is analysed.' })
  }

  f.push(checkHsts(get(h, 'strict-transport-security')))
  f.push(...checkCsp(h))

  const xcto = get(h, 'x-content-type-options')
  f.push(xcto?.trim().toLowerCase() === 'nosniff'
    ? { severity: 'pass', title: 'X-Content-Type-Options: nosniff', detail: 'MIME sniffing disabled.' }
    : {
        severity: 'medium',
        title: xcto === undefined ? 'X-Content-Type-Options missing' : `Invalid X-Content-Type-Options "${xcto}"`,
        detail: 'Browsers may MIME-sniff responses, e.g. execute an uploaded text file as script or treat it as HTML.',
        fix: 'X-Content-Type-Options: nosniff',
        ref: OWASP_HEADERS,
      })

  f.push(checkClickjacking(h))
  f.push(checkReferrer(get(h, 'referrer-policy')))

  const pp = get(h, 'permissions-policy')
  if (pp !== undefined) {
    f.push({ severity: 'pass', title: 'Permissions-Policy present', detail: pp.length > 160 ? pp.slice(0, 160) + '…' : pp })
  } else {
    f.push({
      severity: 'low',
      title: get(h, 'feature-policy') !== undefined ? 'Only the deprecated Feature-Policy is set' : 'Permissions-Policy missing',
      detail: 'Restricting powerful features (camera, microphone, geolocation, payment…) limits what injected code or embedded third parties can use.',
      fix: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()',
      ref: OWASP_HEADERS,
    })
  }

  const coop = get(h, 'cross-origin-opener-policy')?.trim().toLowerCase()
  f.push(coop === 'same-origin' || coop === 'same-origin-allow-popups' || coop === 'noopener-allow-popups'
    ? { severity: 'pass', title: `Cross-Origin-Opener-Policy: ${coop}`, detail: 'The page is isolated from cross-origin windows it opens or that open it (XS-Leaks, tabnabbing).' }
    : {
        severity: 'low',
        title: coop === undefined ? 'Cross-Origin-Opener-Policy missing' : `Weak Cross-Origin-Opener-Policy: ${coop}`,
        detail: 'Cross-origin pages that open this page (or that it opens) keep a window reference, enabling XS-Leaks and opener-based attacks.',
        fix: 'Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if you rely on OAuth/payment popups)',
        ref: OWASP_HEADERS,
      })

  const corp = get(h, 'cross-origin-resource-policy')?.trim().toLowerCase()
  f.push(corp === 'same-origin' || corp === 'same-site'
    ? { severity: 'pass', title: `Cross-Origin-Resource-Policy: ${corp}`, detail: 'Other sites cannot embed this resource (mitigates Spectre-style side channels).' }
    : corp === 'cross-origin'
      ? { severity: 'info', title: 'Cross-Origin-Resource-Policy: cross-origin', detail: 'Any site may embed this resource. Fine for public CDN assets.' }
      : { severity: 'low', title: 'Cross-Origin-Resource-Policy missing', detail: 'Other sites can load this response as an image/script and attempt side-channel reads.', fix: 'Cross-Origin-Resource-Policy: same-site (or same-origin)', ref: OWASP_HEADERS })

  const coep = get(h, 'cross-origin-embedder-policy')?.trim().toLowerCase()
  f.push(coep === 'require-corp' || coep === 'credentialless'
    ? { severity: 'pass', title: `Cross-Origin-Embedder-Policy: ${coep}`, detail: 'Together with COOP same-origin this enables cross-origin isolation.' }
    : { severity: 'info', title: 'Cross-Origin-Embedder-Policy not set', detail: 'Only needed for cross-origin isolation (SharedArrayBuffer, high-resolution timers). Enabling it can break third-party embeds — test first.', fix: 'Cross-Origin-Embedder-Policy: require-corp', ref: OWASP_HEADERS })

  const xxss = get(h, 'x-xss-protection')?.trim()
  if (xxss !== undefined && xxss !== '0') {
    f.push({
      severity: 'low',
      title: `Deprecated X-XSS-Protection: ${xxss}`,
      detail: 'The XSS auditor has been removed from all modern browsers; in old browsers it introduced XS-Leak and filter-abuse vulnerabilities.',
      fix: 'Set X-XSS-Protection: 0 or remove the header, and rely on CSP.',
      ref: OWASP_HEADERS,
    })
  }

  f.push(...infoDisclosure(h))
  f.push(...checkCors(h))

  const cc = get(h, 'cache-control')?.toLowerCase()
  const hasCookies = h.has('set-cookie')
  if (cc?.includes('no-store')) {
    f.push({ severity: 'pass', title: 'Cache-Control: no-store', detail: 'The response will not be stored by browsers or shared caches.' })
  } else {
    f.push({
      severity: 'info',
      title: cc === undefined ? 'Cache-Control not set' : `Cache-Control: ${cc}`,
      detail: `${hasCookies ? 'This response sets cookies; if it' : 'If this response'} contains personal or authenticated data, it may be stored by the browser or by shared caches/proxies.`,
      fix: 'For sensitive responses: Cache-Control: no-store. For per-user but cacheable content: private.',
      ref: OWASP_HEADERS,
    })
  }

  const cookies = (h.get('set-cookie') ?? []).map((c) => analyzeCookie(c, now))
  const all = [...f, ...cookies.flatMap((c) => c.findings)]

  let score = 100
  for (const x of all) score -= PENALTY[x.severity]
  score = Math.max(0, score)
  return { parsed, findings: f, cookies, score, grade: gradeFor(score) }
}

export const SAMPLE_HEADERS = `HTTP/2 200
server: nginx/1.18.0
content-type: text/html; charset=utf-8
x-powered-by: Express
strict-transport-security: max-age=86400
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://ajax.googleapis.com
access-control-allow-origin: *
access-control-allow-credentials: true
set-cookie: sessionid=abc123; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT
set-cookie: __Host-csrf=xyz; Path=/; Secure; HttpOnly; SameSite=Strict
set-cookie: theme=dark; Path=/; SameSite=None`
