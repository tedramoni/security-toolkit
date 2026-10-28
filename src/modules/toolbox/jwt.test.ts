import { describe, expect, it } from 'vitest'
import { base64UrlEncode } from './encoders'
import { JwtError, SAMPLE_JWT, decodeJwt, describeTimeClaims, findSensitiveClaims, formatRelative, lintJwt } from './jwt'
import type { Finding } from './types'

const NOW = 1_700_000_000

function make(header: unknown, payload: unknown, sig = 'c2lnbmF0dXJl'): string {
  const p = typeof payload === 'string' ? payload : JSON.stringify(payload)
  return `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(p)}.${sig}`
}

const good = { iss: 'https://idp.example', aud: 'api', sub: 'u1', iat: NOW - 60, exp: NOW + 600 }

function lint(header: unknown, payload: unknown, sig?: string): Finding[] {
  return lintJwt(decodeJwt(make(header, payload, sig)), NOW)
}
const titles = (f: Finding[]) => f.map((x) => x.title)
const find = (f: Finding[], re: RegExp) => f.find((x) => re.test(x.title))

describe('decodeJwt', () => {
  it('decodes the jwt.io sample', () => {
    const d = decodeJwt(SAMPLE_JWT)
    expect(d.kind).toBe('JWS')
    expect(d.header).toEqual({ alg: 'HS256', typ: 'JWT' })
    expect(d.payload).toEqual({ sub: '1234567890', name: 'John Doe', iat: 1516239022 })
    expect(d.signaturePresent).toBe(true)
    expect(d.signatureBytes).toBe(32)
  })
  it('strips Bearer prefix, whitespace and padding', () => {
    const t = make({ alg: 'RS256' }, good)
    expect(decodeJwt(`Authorization: Bearer ${t}\n`).header.alg).toBe('RS256')
    expect(decodeJwt(`  bearer ${t.slice(0, 10)}\n${t.slice(10)}`).header.alg).toBe('RS256')
    const [h, p, s] = t.split('.')
    expect(decodeJwt(`${h}==.${p}=.${s}`).header.alg).toBe('RS256')
  })
  it('decodes unicode payloads', () => {
    const d = decodeJwt(make({ alg: 'HS256' }, { name: 'Zoë 🔐' }))
    expect(d.payload).toEqual({ name: 'Zoë 🔐' })
  })
  it('keeps non-JSON payloads as text', () => {
    const d = decodeJwt(make({ alg: 'HS256' }, 'plain text'))
    expect(d.payload).toBeUndefined()
    expect(d.payloadText).toBe('plain text')
  })
  it('detects JWE (5 parts)', () => {
    const t = `${base64UrlEncode(JSON.stringify({ alg: 'RSA-OAEP-256', enc: 'A256GCM' }))}.a.b.c.d`
    const d = decodeJwt(t)
    expect(d.kind).toBe('JWE')
    expect(d.header.enc).toBe('A256GCM')
  })
  it.each([
    ['', /Paste a token/],
    ['abc', /3 dot-separated parts.*has 1/],
    ['a.b', /has 2/],
    ['a.b.c.d', /has 4/],
    ['.b.c', /header segment is empty/],
    ['a$b.c.d', /not valid Base64URL/],
    [`${base64UrlEncode('not json')}.e30.`, /Header is not valid JSON/],
    [`${base64UrlEncode('[1]')}.e30.`, /must be a JSON object/],
    [`${base64UrlEncode('{"alg":"HS256"}')}.e30.a`, /impossible Base64URL length/],
  ])('rejects malformed token %#', (input, msg) => {
    expect(() => decodeJwt(input)).toThrow(JwtError)
    expect(() => decodeJwt(input)).toThrow(msg)
  })
  it('reports invalid UTF-8 in a segment', () => {
    expect(() => decodeJwt(`_w.e30.`)).toThrow(/Header could not be decoded/)
  })
})

describe('lintJwt — algorithm', () => {
  it('flags alg none as critical (any case)', () => {
    for (const alg of ['none', 'None', 'NONE', 'nOnE']) {
      const f = lint({ alg }, good, '')
      expect(find(f, /alg is "none"/)?.severity).toBe('critical')
    }
  })
  it('notes alg none with a signature', () => {
    expect(find(lint({ alg: 'none' }, good), /non-empty signature/)).toBeDefined()
  })
  it('flags HS* as info with strong-secret advice', () => {
    const f = find(lint({ alg: 'HS256' }, good), /Symmetric/)
    expect(f?.severity).toBe('info')
    expect(f?.fix).toMatch(/256 bits/)
  })
  it('passes asymmetric algorithms', () => {
    for (const alg of ['RS256', 'PS384', 'ES512', 'EdDSA']) {
      expect(find(lint({ alg }, good), /Asymmetric/)?.severity).toBe('pass')
    }
  })
  it('flags missing alg, unknown alg and empty signature', () => {
    expect(find(lint({ typ: 'JWT' }, good), /Missing alg/)?.severity).toBe('high')
    expect(find(lint({ alg: 'XYZ' }, good), /Unusual algorithm/)?.severity).toBe('medium')
    expect(find(lint({ alg: 'RS256' }, good, ''), /Signature is empty/)?.severity).toBe('high')
  })
})

describe('lintJwt — header parameters', () => {
  it('flags jku / x5u as info', () => {
    expect(find(lint({ alg: 'RS256', jku: 'https://evil' }, good), /jku/)?.severity).toBe('info')
    expect(find(lint({ alg: 'RS256', x5u: 'https://evil' }, good), /x5u/)?.severity).toBe('info')
  })
  it('flags embedded jwk as high', () => {
    expect(find(lint({ alg: 'RS256', jwk: { kty: 'RSA' } }, good), /jwk/)?.severity).toBe('high')
  })
  it('notes kid and x5c', () => {
    const f = lint({ alg: 'RS256', kid: '../../dev/null', x5c: ['MII'] }, good)
    expect(find(f, /Key ID/)?.severity).toBe('info')
    expect(find(f, /x5c/)?.severity).toBe('info')
  })
  it('does not report header parameters that are absent', () => {
    const t = titles(lint({ alg: 'RS256' }, good))
    expect(t.some((x) => /jku|jwk|kid|x5c/.test(x))).toBe(false)
  })
})

describe('lintJwt — claims', () => {
  it('a well-formed short-lived token has no issues above info', () => {
    const f = lint({ alg: 'ES256', typ: 'JWT' }, good)
    expect(f.filter((x) => !['pass', 'info'].includes(x.severity))).toEqual([])
  })
  it('flags missing exp as high', () => {
    const { exp: _e, ...p } = good
    expect(find(lint({ alg: 'RS256' }, p), /No expiration/)?.severity).toBe('high')
  })
  it('flags expired tokens as medium', () => {
    const f = find(lint({ alg: 'RS256' }, { ...good, iat: NOW - 7200, exp: NOW - 3600 }), /expired/)
    expect(f?.severity).toBe('medium')
    expect(f?.title).toMatch(/1 hour ago/)
  })
  it('flags non-numeric exp', () => {
    expect(find(lint({ alg: 'RS256' }, { ...good, exp: '2030-01-01' }), /not a valid NumericDate/)?.severity).toBe('medium')
  })
  it('flags nbf in the future and iat in the future', () => {
    const f = lint({ alg: 'RS256' }, { ...good, nbf: NOW + 3600, iat: NOW + 3600, exp: NOW + 7200 })
    expect(find(f, /Not valid yet/)?.severity).toBe('low')
    expect(find(f, /Issued in the future/)?.severity).toBe('low')
  })
  it('flags lifetime > 24h as medium, using nbf when iat is absent', () => {
    expect(find(lint({ alg: 'RS256' }, { ...good, exp: NOW - 60 + 86400 * 30 }), /Long lifetime/)?.severity).toBe('medium')
    const { iat: _i, ...noIat } = good
    expect(find(lint({ alg: 'RS256' }, { ...noIat, nbf: NOW, exp: NOW + 2 * 86400 }), /Long lifetime/)).toBeDefined()
    expect(find(lint({ alg: 'RS256' }, { ...good, exp: NOW - 60 + 86400 }), /Long lifetime/)).toBeUndefined()
  })
  it('flags missing iss and aud as low', () => {
    const f = lint({ alg: 'RS256' }, { sub: 'x', exp: NOW + 60 })
    expect(find(f, /No issuer/)?.severity).toBe('low')
    expect(find(f, /No audience/)?.severity).toBe('low')
  })
  it('flags sensitive claims as high', () => {
    const f = find(lint({ alg: 'RS256' }, { ...good, password: 'hunter2', profile: { ssn: '123-45-6789' } }), /Sensitive/)
    expect(f?.severity).toBe('high')
    expect(f?.detail).toMatch(/password/)
    expect(f?.detail).toMatch(/profile\.ssn/)
  })
  it('lints the jwt.io sample: HS256, no exp, no iss/aud', () => {
    const t = titles(lintJwt(decodeJwt(SAMPLE_JWT), NOW))
    expect(t).toEqual(expect.arrayContaining([expect.stringMatching(/Symmetric/), expect.stringMatching(/No expiration/), expect.stringMatching(/No issuer/), expect.stringMatching(/No audience/)]))
  })
  it('skips claim checks for non-object payloads', () => {
    const f = lint({ alg: 'RS256' }, 'text')
    expect(find(f, /not a JSON claims object/)).toBeDefined()
    expect(find(f, /No expiration/)).toBeUndefined()
  })
  it('handles JWE: header checks only, RSA1_5 flagged', () => {
    const t = `${base64UrlEncode(JSON.stringify({ alg: 'RSA1_5', enc: 'A128CBC-HS256', jku: 'https://x' }))}.a.b.c.d`
    const f = lintJwt(decodeJwt(t), NOW)
    expect(find(f, /Encrypted token/)).toBeDefined()
    expect(find(f, /RSA1_5/)?.severity).toBe('medium')
    expect(find(f, /jku/)).toBeDefined()
    expect(find(f, /No expiration/)).toBeUndefined()
  })
})

describe('findSensitiveClaims', () => {
  it('detects key names', () => {
    const r = findSensitiveClaims({ api_key: 'x', clientSecret: 'y', creditCard: '4111', user: { password: 'p' } })
    expect(r.map((x) => x.path).sort()).toEqual(['api_key', 'clientSecret', 'creditCard', 'user.password'])
  })
  it('detects values: SSN, Luhn-valid card, tokens', () => {
    const r = findSensitiveClaims({ a: '123-45-6789', b: '4111 1111 1111 1111', c: ['ghp_' + 'a'.repeat(36)] })
    expect(r.map((x) => x.path)).toEqual(['a', 'b', 'c[0]'])
  })
  it('ignores non-Luhn numbers, booleans/timestamps on sensitive names, and benign claims', () => {
    expect(findSensitiveClaims({ n: '4111 1111 1111 1112', password_changed_at: 1700000000, mfa_password: false })).toEqual([])
    expect(findSensitiveClaims({ sub: 'u', name: 'Bob', roles: ['admin'] })).toEqual([])
    expect(findSensitiveClaims({ password: '' })).toEqual([])
  })
})

describe('time helpers', () => {
  it('formats relative times', () => {
    expect(formatRelative(0)).toBe('now')
    expect(formatRelative(30)).toBe('in 30 seconds')
    expect(formatRelative(-1)).toBe('1 second ago')
    expect(formatRelative(-3600)).toBe('1 hour ago')
    expect(formatRelative(86400 * 3)).toBe('in 3 days')
    expect(formatRelative(-86400 * 400)).toBe('1 year ago')
  })
  it('describes time claims with ISO dates and flags invalid values', () => {
    const r = describeTimeClaims({ iat: 0, exp: 'soon', nbf: 1e15 }, NOW)
    expect(r[0]).toMatchObject({ claim: 'iat', iso: '1970-01-01T00:00:00.000Z', valid: true })
    expect(r.find((x) => x.claim === 'exp')?.valid).toBe(false)
    expect(r.find((x) => x.claim === 'nbf')?.valid).toBe(false)
    expect(describeTimeClaims('x', NOW)).toEqual([])
  })
})

describe('review regressions', () => {
  it('rejects deeply nested JSON instead of overflowing the stack', () => {
    const deep = '['.repeat(20_000) + ']'.repeat(20_000)
    expect(() => decodeJwt(make({ alg: 'HS256' }, deep))).toThrow(/nested/)
    expect(() => decodeJwt(`${base64UrlEncode('{"a":' + deep + '}')}.e30.c2ln`)).toThrow(JwtError)
  })
  it('accepts normal nesting and ignores brackets inside strings', () => {
    expect(() => decodeJwt(make({ alg: 'HS256' }, { s: '[[[[[[[[[[[[[[[[[[[[' .repeat(10), a: { b: [1] } }))).not.toThrow()
  })
  it('flags numeric sensitive claims but not timestamps', () => {
    expect(findSensitiveClaims({ pin: 1234 }).length).toBe(1)
    expect(findSensitiveClaims({ card: 4111111111111111 }).length).toBe(1)
    expect(findSensitiveClaims({ ts_ms: 1700000000000, ts_us: 1700000000000003 })).toEqual([])
  })
})
