import { describe, expect, it } from 'vitest'
import {
  DEFAULT_BUILDER_OPTIONS,
  buildCsp,
  evaluateCspString,
  getDirective,
  matchBypassHosts,
  parseCsp,
  sampleNonce,
  sourceHost,
} from './csp'
import type { Finding } from './types'

const find = (f: Finding[], re: RegExp) => f.find((x) => re.test(x.title))
const STRICT = "script-src 'nonce-abc123' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; report-to csp"

describe('parseCsp', () => {
  it('parses directives, lower-cases names and keeps value case', () => {
    const p = parseCsp("Default-Src 'self';  script-src 'nonce-AbC' https://CDN.example ;;")
    expect(p.directives).toEqual([
      { name: 'default-src', values: ["'self'"] },
      { name: 'script-src', values: ["'nonce-AbC'", 'https://CDN.example'] },
    ])
  })
  it('strips a header name prefix and detects report-only', () => {
    expect(parseCsp("Content-Security-Policy: default-src 'none'").reportOnly).toBe(false)
    const ro = parseCsp("content-security-policy-report-only:default-src 'none'")
    expect(ro.reportOnly).toBe(true)
    expect(getDirective(ro, 'default-src')).toEqual(["'none'"])
  })
  it('keeps the first of duplicate directives', () => {
    const p = parseCsp("script-src 'self'; script-src *")
    expect(getDirective(p, 'script-src')).toEqual(["'self'"])
    expect(p.duplicates).toEqual(['script-src'])
  })
  it('splits comma-separated policies', () => {
    const p = parseCsp("default-src 'self', script-src 'none'")
    expect(p.directives).toHaveLength(1)
    expect(p.extraPolicies).toEqual(["script-src 'none'"])
  })
  it('handles empty input and valueless directives', () => {
    expect(parseCsp('').directives).toEqual([])
    expect(getDirective(parseCsp('upgrade-insecure-requests'), 'upgrade-insecure-requests')).toEqual([])
  })
})

describe('sourceHost / matchBypassHosts', () => {
  it('extracts hosts', () => {
    expect(sourceHost('https://*.Example.com:443/path/')).toBe('*.example.com')
    expect(sourceHost('cdn.example.com')).toBe('cdn.example.com')
    expect(sourceHost("'self'")).toBeUndefined()
    expect(sourceHost('https:')).toBeUndefined()
    expect(sourceHost('*')).toBe('*')
  })
  it('matches exact bypass hosts', () => {
    expect(matchBypassHosts('https://ajax.googleapis.com').map((b) => b.host)).toContain('ajax.googleapis.com')
    expect(matchBypassHosts('cdnjs.cloudflare.com')[0].kind).toMatch(/Angular/)
    expect(matchBypassHosts('https://www.google.com/recaptcha/')).toHaveLength(1)
  })
  it('matches wildcard sources covering bypass hosts', () => {
    const hosts = matchBypassHosts('*.googleapis.com').map((b) => b.host)
    expect(hosts).toEqual(expect.arrayContaining(['ajax.googleapis.com', 'storage.googleapis.com']))
  })
  it('matches subdomains of user-content domains', () => {
    expect(matchBypassHosts('https://mybucket.s3.amazonaws.com')).toHaveLength(1)
    expect(matchBypassHosts('d111111abcdef8.cloudfront.net')).toHaveLength(1)
    expect(matchBypassHosts('*.cloudfront.net')).toHaveLength(1)
  })
  it('does not match unrelated or look-alike hosts', () => {
    expect(matchBypassHosts('https://cdn.example.com')).toEqual([])
    expect(matchBypassHosts('evilcloudfront.net')).toEqual([])
    expect(matchBypassHosts('cloudfront.net')).toEqual([])
    expect(matchBypassHosts("'self'")).toEqual([])
    expect(matchBypassHosts('*')).toEqual([])
  })
})

describe('evaluateCsp', () => {
  it('reports an empty policy', () => {
    expect(evaluateCspString('')[0].severity).toBe('high')
  })
  it('accepts a strict nonce-based policy without medium+ findings', () => {
    const f = evaluateCspString(STRICT)
    expect(f.filter((x) => ['critical', 'high', 'medium'].includes(x.severity))).toEqual([])
    expect(find(f, /Missing default-src/)?.severity).toBe('low')
    expect(find(f, /Strict script-src/)?.severity).toBe('pass')
    expect(find(f, /unsafe-inline' is ignored/)?.severity).toBe('info')
    expect(find(f, /Scheme-only source "https:"/)?.severity).toBe('info')
  })
  it('flags missing default-src and script-src', () => {
    const f = evaluateCspString("object-src 'none'")
    expect(find(f, /Missing default-src/)?.severity).toBe('high')
    expect(find(f, /Scripts are not restricted/)?.severity).toBe('high')
  })
  it('missing default-src is low when script-src exists', () => {
    expect(find(evaluateCspString("script-src 'self'"), /Missing default-src/)?.severity).toBe('low')
  })
  it("flags 'unsafe-inline' without nonce as high, and via default-src fallback", () => {
    expect(find(evaluateCspString("script-src 'self' 'unsafe-inline'"), /'unsafe-inline' in script-src/)?.severity).toBe('high')
    expect(find(evaluateCspString("default-src 'self' 'unsafe-inline'"), /'unsafe-inline' in default-src/)?.severity).toBe('high')
  })
  it("treats 'unsafe-inline' as ignored with a hash", () => {
    const f = evaluateCspString("script-src 'sha256-abc=' 'unsafe-inline'")
    expect(find(f, /ignored/)?.severity).toBe('info')
    expect(find(f, /without 'strict-dynamic'/)?.severity).toBe('low')
  })
  it("flags 'unsafe-eval' and 'unsafe-hashes'", () => {
    const f = evaluateCspString("default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-hashes'")
    expect(find(f, /unsafe-eval/)?.severity).toBe('medium')
    expect(find(f, /unsafe-hashes/)?.severity).toBe('low')
  })
  it("does not confuse 'wasm-unsafe-eval' with 'unsafe-eval'", () => {
    expect(find(evaluateCspString("script-src 'self' 'wasm-unsafe-eval'"), /unsafe-eval/)).toBeUndefined()
  })
  it('flags wildcard and scheme-only script sources', () => {
    const f = evaluateCspString("script-src * https: data: blob:")
    expect(find(f, /Wildcard source "\*"/)?.severity).toBe('high')
    expect(find(f, /Scheme-only source "https:"/)?.severity).toBe('high')
    expect(find(f, /Scheme-only source "data:"/)?.severity).toBe('high')
    expect(find(f, /Scheme-only source "blob:"/)?.severity).toBe('medium')
  })
  it("flags 'strict-dynamic' without nonce", () => {
    expect(find(evaluateCspString("script-src 'strict-dynamic' 'self'"), /without a nonce/)?.severity).toBe('medium')
  })
  it('flags bypassable hosts (high) unless strict-dynamic with nonce', () => {
    expect(find(evaluateCspString("script-src 'self' https://ajax.googleapis.com"), /Bypassable host/)?.severity).toBe('high')
    expect(find(evaluateCspString("script-src 'nonce-x' 'strict-dynamic' *.amazonaws.com"), /Bypassable host/)?.severity).toBe('info')
  })
  it('flags http: sources in any directive', () => {
    expect(find(evaluateCspString("default-src 'self'; img-src http://img.example"), /Plain HTTP/)?.severity).toBe('medium')
  })
  it('flags unquoted keywords', () => {
    const f = evaluateCspString('default-src self; script-src nonce-abc')
    expect(find(f, /Unquoted keyword "self"/)).toBeDefined()
    expect(find(f, /Unquoted keyword "nonce-abc"/)).toBeDefined()
  })
  it("flags 'none' mixed with sources", () => {
    expect(find(evaluateCspString("default-src 'none' 'self'"), /'none' combined/)?.severity).toBe('low')
  })
  it("object-src: required unless default-src 'none'", () => {
    expect(find(evaluateCspString("script-src 'self'"), /object-src/)?.severity).toBe('medium')
    expect(find(evaluateCspString("default-src 'self'"), /object-src/)).toBeDefined()
    expect(find(evaluateCspString("default-src 'none'"), /object-src/)).toBeUndefined()
    expect(find(evaluateCspString("default-src 'self'; object-src 'none'"), /object-src/)).toBeUndefined()
    expect(find(evaluateCspString("default-src 'none'; object-src *"), /object-src/)).toBeDefined()
  })
  it('flags missing base-uri, frame-ancestors, form-action (no default-src fallback)', () => {
    const f = evaluateCspString("default-src 'none'")
    expect(find(f, /Missing base-uri/)?.severity).toBe('medium')
    expect(find(f, /Missing frame-ancestors/)?.severity).toBe('medium')
    expect(find(f, /Missing form-action/)?.severity).toBe('low')
  })
  it('flags permissive base-uri and frame-ancestors', () => {
    const f = evaluateCspString("default-src 'none'; base-uri *; frame-ancestors https:")
    expect(find(f, /base-uri allows any host/)).toBeDefined()
    expect(find(f, /frame-ancestors allows any site/)).toBeDefined()
  })
  it('reports reporting configuration', () => {
    expect(find(evaluateCspString("default-src 'none'"), /No violation reporting/)?.severity).toBe('info')
    expect(find(evaluateCspString("default-src 'none'; report-uri /r"), /Only report-uri/)).toBeDefined()
    const both = evaluateCspString("default-src 'none'; report-uri /r; report-to g")
    expect(find(both, /report/i)).toBeUndefined()
  })
  it('flags deprecated and unknown directives', () => {
    const f = evaluateCspString("default-src 'none'; plugin-types application/pdf; block-all-mixed-content; prefetch-src 'self'; script-scr 'self'")
    expect(find(f, /Deprecated directive "plugin-types"/)?.severity).toBe('low')
    expect(find(f, /Deprecated directive "block-all-mixed-content"/)).toBeDefined()
    expect(find(f, /Deprecated directive "prefetch-src"/)).toBeDefined()
    expect(find(f, /Unknown directive "script-scr"/)?.severity).toBe('info')
  })
  it('reports duplicates, report-only and extra policies', () => {
    const f = evaluateCspString("Content-Security-Policy-Report-Only: default-src 'none'; default-src *, script-src 'none'")
    expect(find(f, /Duplicate directive/)).toBeDefined()
    expect(find(f, /Report-Only/)).toBeDefined()
    expect(find(f, /additional comma-separated/)).toBeDefined()
  })
  it('recognises trusted types', () => {
    expect(find(evaluateCspString("default-src 'none'; require-trusted-types-for 'script'"), /Trusted Types/)?.severity).toBe('pass')
  })
})

describe('buildCsp', () => {
  it('builds the strict policy and it evaluates clean', () => {
    const csp = buildCsp(DEFAULT_BUILDER_OPTIONS)
    expect(csp).toContain("script-src 'nonce-{RANDOM_NONCE}' 'strict-dynamic' https: 'unsafe-inline'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).toContain("base-uri 'none'")
    expect(csp).toContain('upgrade-insecure-requests')
    const issues = evaluateCspString(csp).filter((x) => ['critical', 'high', 'medium'].includes(x.severity))
    expect(issues).toEqual([])
  })
  it('builds an allowlist policy with hosts and sanitises separators', () => {
    const csp = buildCsp({
      ...DEFAULT_BUILDER_OPTIONS,
      mode: 'allowlist',
      scriptHosts: 'https://cdn.example.com, https://evil.com;script-src',
      connectHosts: 'https://api.example.com',
      frameAncestors: 'self',
      trustedTypes: true,
      reportTo: 'csp-endpoint',
      reportUri: 'https://r.example/csp',
    })
    expect(csp).toContain("script-src 'self' https://cdn.example.com")
    expect(csp).not.toContain('evil')
    expect(csp).toContain("connect-src 'self' https://api.example.com")
    expect(csp).toContain("frame-src 'none'")
    expect(csp).toContain("frame-ancestors 'self'")
    expect(csp).toContain("require-trusted-types-for 'script'")
    expect(csp).toContain('report-to csp-endpoint; report-uri https://r.example/csp')
    const issues = evaluateCspString(csp).filter((x) => ['critical', 'high', 'medium'].includes(x.severity))
    expect(issues).toEqual([])
  })
  it('omits optional parts', () => {
    const csp = buildCsp({ ...DEFAULT_BUILDER_OPTIONS, formActionSelf: false, upgradeInsecureRequests: false })
    expect(csp).not.toContain('form-action')
    expect(csp).not.toContain('upgrade-insecure-requests')
  })
  it('generates random base64 nonces', () => {
    const a = sampleNonce()
    expect(a).toMatch(/^[A-Za-z0-9+/]{22}==$/)
    expect(sampleNonce()).not.toBe(a)
  })
})

describe('review regressions', () => {
  it('matches wildcard sources that cover wildcard bypass entries', () => {
    expect(matchBypassHosts('*.com').some((b) => b.host === '*.amazonaws.com')).toBe(true)
    expect(matchBypassHosts('https://*.net').some((b) => b.host === '*.cloudfront.net')).toBe(true)
    expect(matchBypassHosts('*.example.com')).toEqual([])
  })
  it('only lists hosts verified against csp-evaluator (code.jquery.com is not there)', () => {
    expect(matchBypassHosts('code.jquery.com')).toEqual([])
    expect(matchBypassHosts('unpkg.com')[0]?.kind).toBe('user-uploaded content')
  })
})
