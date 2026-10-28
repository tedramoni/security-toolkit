import { describe, expect, it } from 'vitest'
import {
  SAMPLE_HEADERS,
  analyzeCookie,
  analyzeHeaders,
  checkCsp,
  checkHsts,
  cookieLifetime,
  gradeFor,
  isSessionLikeCookie,
  parseHeaders,
  parseSetCookie,
} from './headers'
import type { Finding } from './types'

const NOW = 1_700_000_000
const find = (f: Finding[], re: RegExp) => f.find((x) => re.test(x.title))

const GOOD = `HTTP/2 200
strict-transport-security: max-age=63072000; includeSubDomains; preload
content-security-policy: default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; report-to csp
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
cross-origin-embedder-policy: require-corp
cache-control: no-store
set-cookie: __Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax`

describe('parseHeaders', () => {
  it('parses case-insensitively and keeps multiple values', () => {
    const p = parseHeaders('HTTP/1.1 200 OK\r\nX-Test: a\r\nx-test: b\r\nSet-Cookie: a=1\r\nSET-COOKIE: b=2\r\n')
    expect(p.headers.get('x-test')).toEqual(['a', 'b'])
    expect(p.headers.get('set-cookie')).toEqual(['a=1', 'b=2'])
    expect(p.statusLine).toBe('HTTP/1.1 200 OK')
  })
  it('keeps colons inside values and trims whitespace', () => {
    expect(parseHeaders('Location:  https://x.example:8443/a  ').headers.get('location')).toEqual(['https://x.example:8443/a'])
  })
  it('handles curl -v prefixes and folded lines', () => {
    const p = parseHeaders('< HTTP/2 200\n< server: nginx\n< x-long: part1\n\tpart2\n')
    expect(p.headers.get('server')).toEqual(['nginx'])
    expect(p.headers.get('x-long')).toEqual(['part1 part2'])
  })
  it('only keeps the last response of a redirect chain', () => {
    const p = parseHeaders('HTTP/1.1 301 Moved\nLocation: /b\n\nHTTP/1.1 200 OK\nServer: final\n')
    expect(p.responseCount).toBe(2)
    expect(p.headers.has('location')).toBe(false)
    expect(p.headers.get('server')).toEqual(['final'])
  })
  it('ignores junk lines and empty input', () => {
    expect(parseHeaders('not a header\n: novalue\nbad name: x').headers.size).toBe(0)
    expect(parseHeaders('').responseCount).toBe(0)
  })
})

describe('checkHsts', () => {
  it.each([
    [undefined, 'high', /missing/],
    ['includeSubDomains', 'high', /without a valid max-age/],
    ['max-age=0', 'high', /disabled/],
    ['max-age=86400; includeSubDomains', 'medium', /too short/],
    ['max-age=31536000', 'low', /without includeSubDomains/],
    ['max-age=31536000; includeSubDomains', 'pass', /strong/],
    ['MAX-AGE="63072000"; INCLUDESUBDOMAINS; PRELOAD', 'pass', /strong/],
  ] as const)('%s -> %s', (value, sev, title) => {
    const f = checkHsts(value)
    expect(f.severity).toBe(sev)
    expect(f.title).toMatch(title)
  })
  it('mentions preload submission', () => {
    expect(checkHsts('max-age=31536000; includeSubDomains; preload').detail).toMatch(/hstspreload\.org/)
  })
})

describe('checkCsp', () => {
  it('missing / report-only', () => {
    expect(checkCsp(new Map())[0].severity).toBe('high')
    expect(checkCsp(new Map([['content-security-policy-report-only', ["default-src 'self'"]]]))[0].severity).toBe('medium')
  })
  it('summarises evaluator issues with the worst severity', () => {
    const [f] = checkCsp(new Map([['content-security-policy', ["default-src 'self'; script-src 'self' 'unsafe-inline'"]]]))
    expect(f.severity).toBe('high')
    expect(f.detail).toMatch(/unsafe-inline/)
    expect(f.detail).not.toMatch(/frame-ancestors/)
  })
})

describe('analyzeHeaders', () => {
  it('a hardened response gets A+', () => {
    const a = analyzeHeaders(GOOD, NOW)
    const bad = [...a.findings, ...a.cookies.flatMap((c) => c.findings)].filter((x) => !['pass', 'info'].includes(x.severity))
    expect(bad).toEqual([])
    expect(a.score).toBe(100)
    expect(a.grade).toBe('A+')
  })
  it('an empty response fails the core checks', () => {
    const a = analyzeHeaders('HTTP/1.1 200 OK\ncontent-type: text/html', NOW)
    expect(find(a.findings, /Strict-Transport-Security missing/)?.severity).toBe('high')
    expect(find(a.findings, /Content-Security-Policy missing/)?.severity).toBe('high')
    expect(find(a.findings, /X-Content-Type-Options missing/)?.severity).toBe('medium')
    expect(find(a.findings, /No clickjacking protection/)?.severity).toBe('medium')
    expect(find(a.findings, /Referrer-Policy missing/)?.severity).toBe('low')
    expect(find(a.findings, /Permissions-Policy missing/)?.severity).toBe('low')
    expect(find(a.findings, /Cross-Origin-Opener-Policy missing/)?.severity).toBe('low')
    expect(find(a.findings, /Cross-Origin-Resource-Policy missing/)?.severity).toBe('low')
    expect(find(a.findings, /Cross-Origin-Embedder-Policy not set/)?.severity).toBe('info')
    expect(find(a.findings, /Cache-Control not set/)?.severity).toBe('info')
    expect(a.grade).toBe('D')
  })
  it('clickjacking: XFO, CSP frame-ancestors, ALLOW-FROM', () => {
    expect(find(analyzeHeaders('X-Frame-Options: deny').findings, /X-Frame-Options: DENY/)?.severity).toBe('pass')
    expect(find(analyzeHeaders("Content-Security-Policy: frame-ancestors 'self'").findings, /Framing restricted/)?.severity).toBe('pass')
    expect(find(analyzeHeaders('X-Frame-Options: ALLOW-FROM https://a').findings, /ALLOW-FROM/)?.severity).toBe('medium')
    expect(find(analyzeHeaders('Content-Security-Policy: frame-ancestors *').findings, /frame-ancestors allows any/)?.severity).toBe('medium')
  })
  it('referrer policy: uses the last valid token', () => {
    expect(find(analyzeHeaders('Referrer-Policy: unsafe-url').findings, /Weak Referrer-Policy/)?.severity).toBe('medium')
    expect(find(analyzeHeaders('Referrer-Policy: origin').findings, /Weak Referrer-Policy/)?.severity).toBe('low')
    expect(find(analyzeHeaders('Referrer-Policy: unsafe-url, no-referrer').findings, /Referrer-Policy: no-referrer/)?.severity).toBe('pass')
    expect(find(analyzeHeaders('Referrer-Policy: bogus').findings, /no valid value/)).toBeDefined()
  })
  it('flags Feature-Policy only, weak COOP and cross-origin CORP', () => {
    const a = analyzeHeaders('Feature-Policy: camera none\nCross-Origin-Opener-Policy: unsafe-none\nCross-Origin-Resource-Policy: cross-origin')
    expect(find(a.findings, /deprecated Feature-Policy/)).toBeDefined()
    expect(find(a.findings, /Weak Cross-Origin-Opener-Policy/)?.severity).toBe('low')
    expect(find(a.findings, /CORP|Cross-Origin-Resource-Policy: cross-origin/)?.severity).toBe('info')
  })
  it('flags information disclosure headers', () => {
    const a = analyzeHeaders('Server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4\nX-AspNet-Version: 4.0.30319\nX-AspNetMvc-Version: 5.2')
    expect(find(a.findings, /Server header discloses version/)?.severity).toBe('low')
    expect(find(a.findings, /X-Powered-By/)?.severity).toBe('low')
    expect(find(a.findings, /X-AspNet-Version/)?.fix).toMatch(/enableVersionHeader/)
    expect(find(a.findings, /X-AspNetMvc-Version/)).toBeDefined()
    expect(find(analyzeHeaders('Server: cloudflare').findings, /Server header/)?.severity).toBe('info')
  })
  it('X-XSS-Protection: recommends 0 or removal', () => {
    expect(find(analyzeHeaders('X-XSS-Protection: 1; mode=block').findings, /X-XSS-Protection/)?.severity).toBe('low')
    expect(find(analyzeHeaders('X-XSS-Protection: 0').findings, /X-XSS-Protection/)).toBeUndefined()
  })
  it('CORS checks', () => {
    expect(find(analyzeHeaders('Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true').findings, /wildcard origin with credentials/)?.severity).toBe('critical')
    expect(find(analyzeHeaders('Access-Control-Allow-Origin: null').findings, /"null" origin/)?.severity).toBe('medium')
    expect(find(analyzeHeaders('Access-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true').findings, /"null" origin/)?.severity).toBe('high')
    expect(find(analyzeHeaders('Access-Control-Allow-Origin: *').findings, /CORS/)?.severity).toBe('info')
    const echoed = analyzeHeaders('Access-Control-Allow-Origin: https://app.example\nAccess-Control-Allow-Credentials: true')
    expect(find(echoed.findings, /with credentials/)?.severity).toBe('info')
    expect(find(echoed.findings, /Vary: Origin/)?.severity).toBe('low')
    expect(find(analyzeHeaders('Access-Control-Allow-Origin: https://a\nVary: Accept, Origin').findings, /Vary: Origin/)).toBeUndefined()
  })
  it('Cache-Control no-store passes', () => {
    expect(find(analyzeHeaders('Cache-Control: no-store, max-age=0').findings, /no-store/)?.severity).toBe('pass')
  })
  it('analyses the sample with several issues and a low grade', () => {
    const a = analyzeHeaders(SAMPLE_HEADERS, NOW)
    expect(a.cookies).toHaveLength(3)
    expect(find(a.findings, /HSTS max-age too short/)).toBeDefined()
    expect(find(a.findings, /wildcard origin with credentials/)).toBeDefined()
    expect(a.grade).toBe('F')
  })
})

describe('cookies', () => {
  it('parses name, value and attributes', () => {
    const c = parseSetCookie('id=a=b; Path=/; secure; HttpOnly; SameSite=Lax; Max-Age=60')
    expect(c.name).toBe('id')
    expect(c.value).toBe('a=b')
    expect(c.attributes.get('samesite')).toBe('Lax')
    expect(c.attributes.has('secure')).toBe(true)
    expect(c.attributes.get('max-age')).toBe('60')
  })
  it('detects session-looking names', () => {
    for (const n of ['JSESSIONID', 'PHPSESSID', 'connect.sid', 'auth_token', 'sid', 'remember_me', '__Host-session']) expect(isSessionLikeCookie(n)).toBe(true)
    for (const n of ['theme', 'lang', '_ga', 'csrftoken_ui_pref'.replace('token', '')]) expect(isSessionLikeCookie(n)).toBe(false)
  })
  it('computes lifetime from Max-Age (priority) or Expires', () => {
    expect(cookieLifetime(parseSetCookie('a=1; Max-Age=100; Expires=Wed, 21 Oct 2099 07:28:00 GMT'), NOW)).toBe(100)
    expect(cookieLifetime(parseSetCookie('a=1; Expires=Tue, 14 Nov 2023 22:13:20 GMT'), NOW)).toBe(0)
    expect(cookieLifetime(parseSetCookie('a=1'), NOW)).toBeUndefined()
    expect(cookieLifetime(parseSetCookie('a=1; Expires=garbage'), NOW)).toBeUndefined()
  })
  it('flags missing Secure / HttpOnly with higher severity for session cookies', () => {
    const s = analyzeCookie('sessionid=x; SameSite=Lax', NOW)
    expect(find(s.findings, /missing Secure/)?.severity).toBe('high')
    expect(find(s.findings, /missing HttpOnly/)?.severity).toBe('medium')
    const t = analyzeCookie('theme=dark; SameSite=Lax', NOW)
    expect(find(t.findings, /missing Secure/)?.severity).toBe('medium')
    expect(find(t.findings, /missing HttpOnly/)?.severity).toBe('low')
  })
  it('SameSite checks', () => {
    expect(find(analyzeCookie('a=1; Secure; HttpOnly', NOW).findings, /no SameSite/)?.severity).toBe('low')
    expect(find(analyzeCookie('a=1; HttpOnly; SameSite=None', NOW).findings, /SameSite=None without Secure/)?.severity).toBe('high')
    expect(find(analyzeCookie('sid=1; Secure; HttpOnly; SameSite=None', NOW).findings, /SameSite=None/)?.severity).toBe('medium')
    expect(find(analyzeCookie('a=1; Secure; HttpOnly; SameSite=Bogus', NOW).findings, /invalid SameSite/)).toBeDefined()
  })
  it('prefix rules', () => {
    expect(find(analyzeCookie('__Host-a=1; Secure; HttpOnly; SameSite=Lax; Path=/', NOW).findings, /prefix/)).toBeUndefined()
    const bad = find(analyzeCookie('__Host-a=1; HttpOnly; SameSite=Lax; Domain=example.com; Path=/app', NOW).findings, /invalid __Host-/)
    expect(bad?.severity).toBe('high')
    expect(bad?.detail).toMatch(/Secure is missing.*Path.*Domain/)
    expect(find(analyzeCookie('__Secure-a=1; HttpOnly; SameSite=Lax', NOW).findings, /invalid __Secure-/)?.severity).toBe('high')
    expect(find(analyzeCookie('__Secure-a=1; Secure; HttpOnly; SameSite=Lax', NOW).findings, /invalid __Secure-/)).toBeUndefined()
    expect(find(analyzeCookie('session=1; Secure; HttpOnly; SameSite=Lax; Path=/', NOW).findings, /could use the __Host- prefix/)?.severity).toBe('info')
  })
  it('flags Domain attribute', () => {
    expect(find(analyzeCookie('sid=1; Secure; HttpOnly; SameSite=Lax; Domain=.example.com', NOW).findings, /Domain=/)?.severity).toBe('medium')
    expect(find(analyzeCookie('pref=1; Secure; HttpOnly; SameSite=Lax; Domain=example.com', NOW).findings, /Domain=/)?.severity).toBe('low')
  })
  it('flags long-lived session cookies only', () => {
    expect(find(analyzeCookie(`sid=1; Secure; HttpOnly; SameSite=Lax; Max-Age=${86400 * 365}`, NOW).findings, /long lifetime \(365 days\)/)?.severity).toBe('medium')
    expect(find(analyzeCookie(`sid=1; Secure; HttpOnly; SameSite=Lax; Max-Age=3600`, NOW).findings, /long lifetime/)).toBeUndefined()
    expect(find(analyzeCookie(`theme=1; Secure; HttpOnly; SameSite=Lax; Max-Age=${86400 * 365}`, NOW).findings, /long lifetime/)).toBeUndefined()
  })
  it('notes deletion cookies and passes good cookies', () => {
    expect(find(analyzeCookie('a=; Max-Age=0; Secure; HttpOnly; SameSite=Lax', NOW).findings, /deletion/)).toBeDefined()
    const ok = analyzeCookie('pref=1; Secure; HttpOnly; SameSite=Strict', NOW)
    expect(ok.findings.map((x) => x.severity)).toEqual(['pass'])
  })
})

describe('gradeFor', () => {
  it('maps scores to grades', () => {
    expect([100, 95, 90, 75, 60, 45, 10, 0].map(gradeFor)).toEqual(['A+', 'A+', 'A', 'B', 'C', 'D', 'F', 'F'])
  })
})

describe('review regressions', () => {
  it('does not treat CSRF cookies as session cookies (they must often be JS-readable)', () => {
    for (const n of ['csrftoken', 'XSRF-TOKEN', '_csrf_token', 'csrf_session']) expect(isSessionLikeCookie(n)).toBe(false)
    const r = analyzeCookie('XSRF-TOKEN=abc; Path=/; Secure; SameSite=Strict', 0)
    expect(r.sessionLike).toBe(false)
    expect(r.findings.find((f) => f.title.includes('HttpOnly'))?.severity).toBe('low')
  })
  it('finds frame-ancestors in a second CSP header', () => {
    const a = analyzeHeaders("HTTP/2 200\ncontent-security-policy: script-src 'self'\ncontent-security-policy: frame-ancestors 'none'")
    expect(a.findings.some((f) => f.severity === 'pass' && f.title.includes('frame-ancestors'))).toBe(true)
    expect(a.findings.some((f) => f.title.includes('2 Content-Security-Policy policies'))).toBe(true)
  })
  it('accepts a repeated identical X-Frame-Options value', () => {
    const a = analyzeHeaders('HTTP/2 200\nx-frame-options: DENY\nx-frame-options: deny')
    expect(a.findings.some((f) => f.severity === 'pass' && f.title === 'X-Frame-Options: DENY')).toBe(true)
  })
})
