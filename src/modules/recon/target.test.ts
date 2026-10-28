import { describe, expect, it } from 'vitest'
import { domainChain, guessRegistrable, isValidHostname, normalizeTarget, reverseName } from './target'

function ok(input: string) {
  const r = normalizeTarget(input)
  if (!r.ok) throw new Error(`expected ok for ${input}: ${r.error}`)
  return r.target
}

function err(input: string) {
  const r = normalizeTarget(input)
  if (r.ok) throw new Error(`expected error for ${input}, got ${r.target.host}`)
  return r.error
}

describe('normalizeTarget', () => {
  it('strips scheme, path, port, credentials, trailing dot and lower-cases', () => {
    expect(ok('https://User:pw@WWW.Example.COM:8443/path?q=1#x').host).toBe('www.example.com')
    expect(ok('Example.com.').host).toBe('example.com')
    expect(ok('  example.com/some/path ').host).toBe('example.com')
    expect(ok('*.example.com').host).toBe('example.com')
  })

  it('converts IDN to punycode and keeps the Unicode form for display', () => {
    const t = ok('https://bücher.fr/')
    expect(t.host).toBe('xn--bcher-kva.fr')
    expect(t.display).toBe('bücher.fr')
    expect(ok('münchen.de').host).toBe('xn--mnchen-3ya.de')
  })

  it('computes a registrable-domain guess', () => {
    expect(ok('a.b.example.com').registrable).toBe('example.com')
    expect(ok('www.bbc.co.uk').registrable).toBe('bbc.co.uk')
    expect(ok('www.service-public.gouv.fr').registrable).toBe('service-public.gouv.fr')
    expect(guessRegistrable('example.com')).toBe('example.com')
  })

  it('accepts public IPv4 / IPv6 targets', () => {
    expect(ok('140.82.121.4')).toEqual({ kind: 'ip', host: '140.82.121.4', ipVersion: 4 })
    expect(ok('2606:4700:4700::1111')).toMatchObject({ kind: 'ip', host: '2606:4700:4700::1111', ipVersion: 6 })
    expect(ok('http://[2606:4700:4700::1111]/')).toMatchObject({ kind: 'ip', ipVersion: 6 })
  })

  it('rejects private, loopback, metadata and special-use targets', () => {
    expect(err('localhost')).toMatch(/not a valid public host/)
    expect(err('foo.localhost')).toMatch(/special-use/)
    expect(err('127.0.0.1')).toMatch(/loopback/)
    expect(err('http://2130706433/')).toMatch(/loopback/) // decimal IPv4 canonicalised by the URL parser
    expect(err('0x7f.1')).toMatch(/loopback/)
    expect(err('10.1.2.3')).toMatch(/private/)
    expect(err('169.254.169.254')).toMatch(/metadata/)
    expect(err('[::1]')).toMatch(/loopback/)
    expect(err('::ffff:192.168.1.1')).toMatch(/private/)
    expect(err('printer.local')).toMatch(/special-use/)
    expect(err('metadata.google.internal')).toMatch(/metadata|special/)
    expect(err('intranet')).toMatch(/single-label|valid/)
  })

  it('rejects malformed input', () => {
    expect(err('')).toMatch(/Enter/)
    expect(err('ftp://example.com')).toMatch(/http/)
    expect(err('exa mple.com')).toBeTruthy()
    expect(err('-bad-.com')).toMatch(/valid/)
    expect(err('example.123')).toMatch(/valid/)
    expect(err('a'.repeat(64) + '.com')).toMatch(/valid/)
    expect(err('javascript:alert(1)')).toBeTruthy()
  })

  it('isValidHostname enforces label rules', () => {
    expect(isValidHostname('xn--bcher-kva.example')).toBe(true)
    expect(isValidHostname('a-b.c-d.com')).toBe(true)
    expect(isValidHostname('a_b.com')).toBe(false)
    expect(isValidHostname('com')).toBe(false)
  })

  it('is fast on adversarial input', () => {
    const t0 = performance.now()
    normalizeTarget('a-'.repeat(5000) + '!')
    normalizeTarget('a.'.repeat(1000) + '-')
    isValidHostname(('a'.repeat(62) + '-.').repeat(4) + 'com')
    expect(performance.now() - t0).toBeLessThan(200)
  })
})

describe('domainChain / reverseName', () => {
  it('walks up to the registrable domain', () => {
    expect(domainChain('a.b.example.com')).toEqual(['a.b.example.com', 'b.example.com', 'example.com'])
    expect(domainChain('example.com')).toEqual(['example.com'])
  })

  it('builds PTR names', () => {
    expect(reverseName('140.82.121.4')).toBe('4.121.82.140.in-addr.arpa')
    expect(reverseName('2001:db8::1')).toBe('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
    expect(reverseName('nope')).toBeUndefined()
  })
})
