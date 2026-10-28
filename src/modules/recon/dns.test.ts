import { describe, expect, it } from 'vitest'
import { caaIssuer, isNullMx, parseCaa, parseDs, parseMx, parseSoa, runDnsCheck, sortMx, txtServices } from './dns'
import { fakeResolver } from './test-helpers'

describe('record parsers', () => {
  it('parses and sorts MX', () => {
    const mx = ['20 alt.example.com.', '10 mx1.example.com.', '10 aa.example.com.'].map((x) => parseMx(x)!)
    expect(sortMx(mx).map((m) => m.exchange)).toEqual(['aa.example.com', 'mx1.example.com', 'alt.example.com'])
    expect(parseMx('garbage')).toBeUndefined()
    expect(isNullMx([parseMx('0 .')!])).toBe(true)
    expect(isNullMx([parseMx('0 mx.example.com.')!])).toBe(false)
  })

  it('parses SOA (real github.com answer)', () => {
    expect(parseSoa('dns1.p08.nsone.net. hostmaster.nsone.net. 1656468023 43200 7200 1209600 3600')).toEqual({
      mname: 'dns1.p08.nsone.net',
      rname: 'hostmaster.nsone.net',
      serial: 1656468023,
      refresh: 43200,
      retry: 7200,
      expire: 1209600,
      minimum: 3600,
    })
    expect(parseSoa('a b c')).toBeUndefined()
  })

  it('parses CAA', () => {
    expect(parseCaa('0 issue "pki.goog"')).toEqual({ flags: 0, critical: false, tag: 'issue', value: 'pki.goog' })
    expect(parseCaa('128 issuewild ";"')).toEqual({ flags: 128, critical: true, tag: 'issuewild', value: ';' })
    expect(parseCaa('0 iodef "mailto:security@example.com"')?.value).toBe('mailto:security@example.com')
    expect(parseCaa('0 issue letsencrypt.org')?.value).toBe('letsencrypt.org')
    expect(parseCaa('999 issue "x"')).toBeUndefined()
    expect(parseCaa('nonsense')).toBeUndefined()
    expect(caaIssuer('letsencrypt.org; validationmethods=dns-01')).toBe('letsencrypt.org')
    expect(caaIssuer(';')).toBe('')
  })

  it('parses DS (real afnic.fr answer)', () => {
    expect(parseDs('30098 13 2 DEA3DF8F5147EF21A6BC35F497BE6369DAD5C988CA6895317D1FE1FDFD24DB1D')).toMatchObject({ keyTag: 30098, algorithm: 13, digestType: 2 })
  })

  it('maps TXT verification tokens to services', () => {
    expect(txtServices(['MS=ms44452932', 'google-site-verification=abc', 'v=spf1 -all', 'TAILSCALE-xyz'])).toEqual(['Google (Search Console / Workspace)', 'Microsoft 365', 'Tailscale'])
  })

  it('parsers are linear on adversarial input', () => {
    const t0 = performance.now()
    parseCaa('0 issue ' + '"'.repeat(100000))
    parseMx('1'.repeat(100000) + ' x')
    parseDs('1 2 3 ' + 'a '.repeat(50000) + '!')
    // regression: long whitespace run after the digest type used to backtrack quadratically (~0.8 s for 30k)
    expect(parseDs('1 2 3' + ' '.repeat(100000) + '!')).toBeUndefined()
    expect(performance.now() - t0).toBeLessThan(300)
    expect(parseDs('2371 13 2 1F987CC6583E92DF0890718C42 98 2F3E2E0')).toEqual({ keyTag: 2371, algorithm: 13, digestType: 2, digest: '1f987cc6583e92df0890718c42982f3e2e0' })
  })
})

describe('runDnsCheck', () => {
  it('reports DNSSEC, CAA inheritance, NS count and services', async () => {
    const resolve = fakeResolver({
      'www.example.com|A': { data: ['93.184.215.14'], ad: true },
      'www.example.com|NS': { data: [] },
      'www.example.com|TXT': ['google-site-verification=x'],
      'example.com|CAA': ['0 issue "letsencrypt.org"'],
      'example.com|DS': ['1 13 2 ABCD'],
    })
    const { data, findings } = await runDnsCheck('www.example.com', resolve, 'zz-random')
    expect(data.dnssec).toBe('validated')
    expect(data.caaFrom).toBe('example.com')
    expect(findings.find((f) => f.title.startsWith('CAA restricts'))?.title).toContain('inherited from example.com')
    expect(findings.some((f) => f.title === 'No IPv6 (AAAA) records')).toBe(true)
    expect(findings.some((f) => /third-party service/.test(f.title))).toBe(true)
    expect(data.wildcard).toBe(false)
  })

  it('flags missing CAA, unsigned zone, single NS and wildcard', async () => {
    const resolve = fakeResolver({
      'example.org|A': ['1.2.3.4'],
      'example.org|AAAA': ['2001:4860::1'],
      'example.org|NS': ['ns1.example.net.'],
      'zz-random.example.org|A': ['1.2.3.4'],
    })
    const { data, findings } = await runDnsCheck('example.org', resolve, 'zz-random')
    expect(data.dnssec).toBe('unsigned')
    const titles = findings.map((f) => `${f.severity}:${f.title}`)
    expect(titles).toContain('info:No CAA record')
    expect(titles).toContain('low:DNSSEC not enabled')
    expect(titles).toContain('medium:Single authoritative name server')
    expect(titles).toContain('info:Wildcard DNS')
  })

  it('flags a DS without validation and fails only when every query fails', async () => {
    const resolve = fakeResolver({ 'example.net|A': ['1.2.3.4'], 'example.net|DS': ['1 8 2 AB'] })
    const { data } = await runDnsCheck('example.net', resolve, 'r')
    expect(data.dnssec).toBe('ds-present-not-validated')
    const broken = async () => {
      throw new Error('offline')
    }
    await expect(runDnsCheck('example.net', broken, 'r')).rejects.toThrow(/All DNS queries failed/)
  })
})
