import { describe, expect, it } from 'vitest'
import { createResolver, parseDohJson, resolveDns, unquoteTxt } from './doh'
import { fakeFetch } from './test-helpers'

// Real responses captured from dns.google / cloudflare-dns.com (2026-10).
const GOOGLE_WWW_GITHUB = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: 'www.github.com.', type: 1 }], Answer: [{ name: 'www.github.com.', type: 5, TTL: 3187, data: 'github.com.' }, { name: 'github.com.', type: 1, TTL: 60, data: '20.250.119.67' }], Comment: 'Response from 198.51.44.8.' }
const GOOGLE_NX = { Status: 3, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: 'nonexistent-zz9.github.com.', type: 1 }], Authority: [{ name: 'github.com.', type: 6, TTL: 1800, data: 'dns1.p08.nsone.net. hostmaster.nsone.net. 1656468023 43200 7200 1209600 3600' }] }
const CF_AFNIC_SIGNED = { Status: 0, TC: false, RD: true, RA: true, AD: true, CD: false, Question: [{ name: 'afnic.fr', type: 1 }], Answer: [{ name: 'afnic.fr', type: 1, TTL: 600, data: '51.178.83.21' }, { name: 'afnic.fr', type: 46, TTL: 600, data: 'A 13 2 600 1795595605 1793011595 30609 afnic.fr. bPcBUsUAvQnFgPMxdq64vLTJFHFN/38cvKA2z4yl9rHlZ3oNdK0MnX2YWwRnSHqPA59zoEukJ863QXY8Ejk8cg==' }] }
const CF_TXT = { Status: 0, AD: false, Answer: [{ name: 'github.com', type: 16, TTL: 122, data: '"MS=ms44452932"' }, { name: 'github.com', type: 16, TTL: 122, data: '"v=spf1 ip4:192.30.252.0/22 " "include:_spf.google.com ~all"' }] }

describe('unquoteTxt', () => {
  it('handles both resolver formats', () => {
    expect(unquoteTxt('v=spf1 -all')).toBe('v=spf1 -all') // Google: unquoted
    expect(unquoteTxt('"v=spf1 -all"')).toBe('v=spf1 -all') // Cloudflare: quoted
    expect(unquoteTxt('"part one " "part two"')).toBe('part one part two')
    expect(unquoteTxt('"say \\"hi\\"" "\\059x"')).toBe('say "hi";x')
  })

  it('is linear on adversarial input', () => {
    const t0 = performance.now()
    unquoteTxt('"' + '\\'.repeat(200000))
    unquoteTxt('" "'.repeat(50000))
    expect(performance.now() - t0).toBeLessThan(500)
  })
})

describe('parseDohJson', () => {
  it('separates the CNAME chain from requested records', () => {
    const r = parseDohJson(GOOGLE_WWW_GITHUB, 'www.github.com', 'A', 'google')
    expect(r.cnames).toEqual(['github.com'])
    expect(r.records).toEqual([{ name: 'github.com', type: 1, typeName: 'A', ttl: 60, data: '20.250.119.67' }])
    expect(r.statusText).toBe('NOERROR')
  })

  it('reports NXDOMAIN and the AD flag', () => {
    expect(parseDohJson(GOOGLE_NX, 'x', 'A', 'google')).toMatchObject({ status: 3, statusText: 'NXDOMAIN', records: [] })
    const signed = parseDohJson(CF_AFNIC_SIGNED, 'afnic.fr', 'A', 'cloudflare')
    expect(signed.ad).toBe(true)
    expect(signed.records).toHaveLength(1) // RRSIG filtered
    expect(signed.answers).toHaveLength(2)
  })

  it('unquotes TXT data and rejects malformed bodies', () => {
    const r = parseDohJson(CF_TXT, 'github.com', 'TXT', 'cloudflare')
    expect(r.records.map((x) => x.data)).toEqual(['MS=ms44452932', 'v=spf1 ip4:192.30.252.0/22 include:_spf.google.com ~all'])
    expect(() => parseDohJson({ nope: 1 }, 'x', 'A', 'google')).toThrow(/Malformed/)
    expect(() => parseDohJson(null, 'x', 'A', 'google')).toThrow()
  })
})

describe('resolveDns', () => {
  it('falls back to Cloudflare when Google fails, with the dns-json Accept header', async () => {
    const calls: string[] = []
    let accept: string | null = null
    const fetch = fakeFetch((url, init) => {
      if (url.startsWith('https://dns.google/')) return { fail: true, body: '' }
      accept = new Headers(init?.headers).get('accept')
      return { body: CF_AFNIC_SIGNED }
    }, calls)
    const r = await resolveDns('afnic.fr', 'A', { fetch, backoffMs: 0 })
    expect(r.resolver).toBe('cloudflare')
    expect(accept).toBe('application/dns-json')
    expect(calls[0]).toBe('https://dns.google/resolve?name=afnic.fr&type=A&do=1')
    expect(calls[1]).toContain('https://cloudflare-dns.com/dns-query?name=afnic.fr&type=A')
  })

  it('does not retry NXDOMAIN on the second resolver', async () => {
    const calls: string[] = []
    const fetch = fakeFetch(() => ({ body: GOOGLE_NX }), calls)
    const r = await resolveDns('nonexistent-zz9.github.com', 'A', { fetch })
    expect(r.status).toBe(3)
    expect(calls).toHaveLength(1)
  })

  it('throws when every resolver fails', async () => {
    const fetch = fakeFetch(() => ({ status: 500, body: 'oops' }))
    await expect(resolveDns('x.com', 'A', { fetch, backoffMs: 0 })).rejects.toThrow(/HTTP 500/)
  })

  it('memoises identical queries', async () => {
    const calls: string[] = []
    const resolve = createResolver({ fetch: fakeFetch(() => ({ body: GOOGLE_WWW_GITHUB }), calls) })
    await Promise.all([resolve('www.github.com', 'A'), resolve('WWW.github.com', 'A'), resolve('www.github.com', 'A')])
    expect(calls).toHaveLength(1)
    expect(resolve.queries()).toBe(1)
  })
})
