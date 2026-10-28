import { describe, expect, it } from 'vitest'
import type { GeneralNameInfo } from './extensions'
import { dnsIdMatches, matchHostname, normalizeHostname, parseIPv4, parseIPv6 } from './hostname'
import { escapeSubjValue, opensslReqCommand, opensslSubj, parseSanList, shellQuote, validateSubject, EMPTY_SUBJECT, encodeSubject } from './generate'
import { decodeName, formatName } from './names'

const dns = (...v: string[]): GeneralNameInfo[] => v.map((value) => ({ type: 'DNS', value }))

describe('RFC 6125 / RFC 9525 hostname matching', () => {
  it('exact and case-insensitive matches, trailing dot', () => {
    expect(matchHostname('www.example.com', dns('www.example.com')).match).toBe(true)
    expect(matchHostname('WWW.Example.COM', dns('www.example.com')).match).toBe(true)
    expect(matchHostname('www.example.com.', dns('www.example.com')).match).toBe(true)
    expect(matchHostname('example.com', dns('www.example.com')).match).toBe(false)
  })
  it('wildcard matches exactly one left-most label', () => {
    expect(dnsIdMatches('*.example.com', 'foo.example.com').match).toBe(true)
    expect(dnsIdMatches('*.example.com', 'example.com').match).toBe(false)
    expect(dnsIdMatches('*.example.com', 'a.b.example.com').match).toBe(false)
    expect(dnsIdMatches('*.example.com', 'foo.example.org').match).toBe(false)
    expect(matchHostname('API.Example.com', dns('*.example.com')).matchedBy).toBe('DNS:*.example.com')
  })
  it('rejects partial, inner, multiple and TLD wildcards', () => {
    expect(dnsIdMatches('f*.example.com', 'foo.example.com').match).toBe(false)
    expect(dnsIdMatches('*oo.example.com', 'foo.example.com').match).toBe(false)
    expect(dnsIdMatches('www.*.example.com', 'www.foo.example.com').match).toBe(false)
    expect(dnsIdMatches('*.*.example.com', 'a.b.example.com').match).toBe(false)
    expect(dnsIdMatches('*.com', 'example.com').match).toBe(false)
    expect(matchHostname('foo.example.com', dns('f*.example.com')).match).toBe(false)
  })
  it('IP addresses only match iPAddress SANs', () => {
    const sans: GeneralNameInfo[] = [{ type: 'DNS', value: '192.0.2.1' }, { type: 'IP', value: '2001:db8::1' }]
    expect(matchHostname('192.0.2.1', sans).match).toBe(false)
    expect(matchHostname('2001:DB8:0:0:0:0:0:1', sans).match).toBe(true)
    expect(matchHostname('[2001:db8::1]', sans).match).toBe(true)
    expect(matchHostname('10.0.0.1', [{ type: 'IP', value: '10.0.0.1' }]).match).toBe(true)
  })
  it('ignores CN when there are no DNS SANs (browser behaviour) but reports it', () => {
    const r = matchHostname('legacy.example.com', [], ['legacy.example.com'])
    expect(r.match).toBe(false)
    expect(r.cnOnlyMatch).toBe(true)
  })
  it('IDNs are compared as A-labels', () => {
    expect(normalizeHostname('bücher.example')).toBe('xn--bcher-kva.example')
    expect(matchHostname('bücher.example', dns('xn--bcher-kva.example')).match).toBe(true)
  })
  it('IP parsing', () => {
    expect(parseIPv4('192.168.001.1')).toBeUndefined()
    expect(parseIPv4('256.1.1.1')).toBeUndefined()
    expect(parseIPv6('::ffff:192.0.2.1')?.slice(10)).toEqual([0xff, 0xff, 192, 0, 2, 1])
    expect(parseIPv6('1::2::3')).toBeUndefined()
    expect(parseIPv6('::')).toEqual(new Array(16).fill(0))
  })
})

describe('CSR generator helpers', () => {
  it('escapes -subj values (/, +, backslash) and shell-quotes', () => {
    expect(escapeSubjValue('Acme/Sub + Co\\x')).toBe('Acme\\/Sub \\+ Co\\\\x')
    expect(shellQuote("O'Brien")).toBe(`'O'\\''Brien'`)
    const subj = opensslSubj({ ...EMPTY_SUBJECT, C: 'FR', O: "O'Brien/Partners", CN: 'www.example.com' })
    expect(subj).toBe("/C=FR/O=O'Brien\\/Partners/CN=www.example.com")
    const cmd = opensslReqCommand({ keyType: 'P-256', hash: 'SHA-256', subject: { ...EMPTY_SUBJECT, CN: 'www.example.com', O: "O'Brien" }, sans: [{ type: 'dns', value: 'www.example.com' }, { type: 'ip', value: '10.0.0.1' }] })
    expect(cmd).toContain("-newkey ec -pkeyopt ec_paramgen_curve:P-256")
    expect(cmd).toContain(`-subj '/O=O'\\''Brien/CN=www.example.com'`)
    expect(cmd).toContain("-addext 'subjectAltName=DNS:www.example.com,IP:10.0.0.1'")
    expect(cmd).toContain('-sha256')
    const ed = opensslReqCommand({ keyType: 'Ed25519', hash: 'SHA-256', subject: { ...EMPTY_SUBJECT, CN: 'x' }, sans: [], selfSigned: true, days: 7 })
    expect(ed).toContain('-x509 -newkey ed25519')
    expect(ed).not.toContain('-sha256')
    expect(ed).toContain('-days 7')
    expect(opensslReqCommand({ keyType: 'RSA-3072', hash: 'SHA-384', subject: { ...EMPTY_SUBJECT, CN: 'x' }, sans: [] })).toContain('-newkey rsa:3072')
  })
  it('validates subject fields', () => {
    expect(validateSubject({ ...EMPTY_SUBJECT, CN: 'a', C: 'fr' }).C).toBeDefined()
    expect(validateSubject({ ...EMPTY_SUBJECT, CN: 'a', C: 'FRA' }).C).toBeDefined()
    expect(validateSubject({ ...EMPTY_SUBJECT, CN: 'a', C: 'FR' })).toEqual({})
    expect(validateSubject({ ...EMPTY_SUBJECT, CN: 'x'.repeat(65) }).CN).toContain('64')
    expect(validateSubject({ ...EMPTY_SUBJECT, CN: 'a\nb' }).CN).toContain('Control')
    expect(validateSubject({ ...EMPTY_SUBJECT, E: 'not-an-email' }).E).toBeDefined()
    expect(validateSubject(EMPTY_SUBJECT).CN).toBeDefined()
  })
  it('encodes subjects exactly (quotes, backslashes, unicode survive)', () => {
    const s = { ...EMPTY_SUBJECT, C: 'DE', O: 'Müller "&" Söhne \\ GmbH', CN: 'a+b=c, d' , E: 'pki@example.com' }
    const rdns = decodeName(encodeSubject(s))
    expect(rdns.map((r) => r[0].value)).toEqual(['DE', 'Müller "&" Söhne \\ GmbH', 'a+b=c, d', 'pki@example.com'])
    expect(formatName(rdns)).toContain('CN=a\\+b\\=c\\, d')
  })
  it('parses SAN lists with type inference and validation', () => {
    const r = parseSanList('www.example.com, *.api.example.com\n10.0.0.1 IP:2001:db8::1 email:me@example.com bücher.example DNS:www.example.com')
    expect(r.errors).toEqual([])
    expect(r.sans).toEqual([
      { type: 'dns', value: 'www.example.com' },
      { type: 'dns', value: '*.api.example.com' },
      { type: 'ip', value: '10.0.0.1' },
      { type: 'ip', value: '2001:db8::1' },
      { type: 'email', value: 'me@example.com' },
      { type: 'dns', value: 'xn--bcher-kva.example' },
    ])
    const bad = parseSanList('bad_host.example.com IP:300.1.1.1 *.com foo..bar email:x')
    expect(bad.errors).toHaveLength(5)
  })
})
