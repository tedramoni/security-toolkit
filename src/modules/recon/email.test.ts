import { describe, expect, it } from 'vitest'
import { concat, derNull, derOid, derSeq, tlv } from '../pki/der'
import { toBase64 } from '../pki/bytes'
import { OID } from '../pki/oids'
import {
  analyzeSpf,
  dkimFindings,
  dmarcFindings,
  isDmarcRecord,
  parseDkim,
  parseDmarc,
  parseSpf,
  parseStsPolicy,
  parseTags,
  runEmailCheck,
  spfFindings,
  stsMxMatches,
} from './email'
import { fakeResolver } from './test-helpers'

// Real records (github.com, 2026-10)
const GITHUB_SPF = 'v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all'
const GITHUB_DKIM_1024 = 'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxZC/z2cK+2s1f/ktzSDSeFzkfIHrjwtGFsfKMAYvKaXjPVNzKykpbXBkX5nB7dVUTFttda7aROr2iSrIseQ27Ui+4rUZVzgFanE8RaXhYM9n5wPKNv8GtLJk7JgcsYZ7ErgID4uW2sEYyV/dnRYw6rDzOaeRKkKELTUfJI5ebLQIDAQAB;'
const GITHUB_DKIM_2048 = 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj6T5sl/RwdSqGoYWaWaFbS2UAeyPrEmd0gogocmRfS441qwR8/0KB81Hw89P0l4YiFRrXYk7NVIGfyCRHAYYZUzCkGeOysI2EjgzLFhd/NEsbRzOEc/kWkK/RO6JFq/5lOn6M9AZw/ap9tds4JG9ApgNNdSpPxp9DmvpsOSgNMVflRxQFrk3kdS4RNAPKu/OPoA7dlR/A/pECryjRoYgENtDXzdnK70HgCekems6UDzxDj61cjyoKoXtEMF/QsaHEQ1Gjfv014rDJBsubk/kT5VqHkWHa/ia68Z5r228Ety/wFfQNjXTx/J7KGZ9GkZlKED659eiJcLnWcKDSiQlhwIDAQAB'
const AFNIC_DMARC = 'v=DMARC1; p=quarantine; pct=100; ruf=mailto:dmarc-feedback@afnic.fr; rua=mailto:dmarc-feedback@afnic.fr; fo=1'

function rsaKey(bits: number, pkcs1Only = false): string {
  const n = new Uint8Array(bits / 8 + 1)
  n[1] = 0x80 // top bit set → exact bit length
  n[n.length - 1] = 1
  const pkcs1 = derSeq(tlv(0x02, n), tlv(0x02, new Uint8Array([1, 0, 1])))
  if (pkcs1Only) return toBase64(pkcs1)
  return toBase64(derSeq(derSeq(derOid(OID.rsaEncryption), derNull()), tlv(0x03, concat(new Uint8Array([0]), pkcs1))))
}

describe('parseSpf', () => {
  it('parses github.com mechanisms and counts lookup terms', () => {
    const p = parseSpf(GITHUB_SPF)
    expect(p.errors).toEqual([])
    expect(p.all).toBe('~')
    expect(p.includes).toHaveLength(8)
    expect(p.lookupTerms).toBe(8)
    expect(p.terms[0]).toMatchObject({ kind: 'mechanism', qualifier: '+', name: 'ip4', value: '192.30.252.0/22' })
  })

  it('handles qualifiers, modifiers, a/mx with cidr and unknown mechanisms', () => {
    const p = parseSpf('v=spf1 a/24 mx:mail.example.com -ptr ?exists:%{i}.x.example redirect=_spf.example.com exp=explain.example.com foo=bar')
    expect(p.lookupTerms).toBe(5)
    expect(p.redirect).toBe('_spf.example.com')
    expect(p.usesPtr).toBe(true)
    expect(p.terms.find((t) => t.name === 'a')?.value).toBe('/24')
    expect(parseSpf('v=spf1 bogus -all').errors[0]).toMatch(/Unknown mechanism/)
    expect(parseSpf('v=spf2 -all').errors[0]).toMatch(/v=spf1/)
    expect(parseSpf('v=spf1 redirect=a.com redirect=b.com').errors[0]).toMatch(/Duplicate "redirect"/)
    expect(parseSpf('v=spf1 -all include:x.com').termsAfterAll).toBe(1)
  })

  it('does not count lookups that are never evaluated (regression)', () => {
    // terms after "all" are ignored (RFC 7208 §5.1)
    const after = parseSpf('v=spf1 ip4:192.0.2.1 -all include:x.com a mx ptr')
    expect(after.lookupTerms).toBe(0)
    expect(after.includes).toEqual([])
    expect(after.usesPtr).toBe(false)
    // redirect is ignored when "all" is present (RFC 7208 §6.1)
    expect(parseSpf('v=spf1 redirect=_spf.x.com -all').lookupTerms).toBe(0)
    expect(parseSpf('v=spf1 include:a.com redirect=_spf.x.com').lookupTerms).toBe(2)
    // ip4 / ip6 / all / exp never cost a lookup
    expect(parseSpf('v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 exp=explain.x.com -all').lookupTerms).toBe(0)
    expect(parseSpf('v=spf1 a mx ptr exists:%{i}.x.com include:y.com -all').lookupTerms).toBe(5)
  })

  it('is linear on huge adversarial records', () => {
    const t0 = performance.now()
    parseSpf('v=spf1 ' + 'include:a.b '.repeat(20000) + '=:/'.repeat(20000))
    parseTags('a=b;'.repeat(50000))
    parseDmarc('v=DMARC1;' + ' ;'.repeat(50000))
    expect(performance.now() - t0).toBeLessThan(800)
  })
})

describe('analyzeSpf (recursive lookup counting)', () => {
  it('counts nested includes and flags > 10 lookups', async () => {
    const zone: Record<string, string[]> = { 'example.com|TXT': ['v=spf1 include:a.example include:b.example mx a -all'] }
    zone['a.example|TXT'] = ['v=spf1 include:c.example include:d.example include:e.example ~all']
    zone['b.example|TXT'] = ['v=spf1 a mx exists:x.example include:f.example ~all']
    for (const d of ['c', 'd', 'e', 'f']) zone[`${d}.example|TXT`] = ['v=spf1 ip4:1.2.3.4 ~all']
    const a = await analyzeSpf('example.com', fakeResolver(zone))
    // root 4 (2 include + mx + a), a.example 3, b.example 4 = 11
    expect(a.totalLookups).toBe(11)
    const f = spfFindings(a, true)
    expect(f.find((x) => x.severity === 'high')?.title).toBe('SPF needs 11 DNS lookups (limit 10)')
    expect(f.some((x) => x.title === 'SPF ends with "-all"')).toBe(true)
  })

  it('detects include loops without hanging', async () => {
    const zone = { 'loop.example|TXT': ['v=spf1 include:l2.example -all'], 'l2.example|TXT': ['v=spf1 include:loop.example -all'] }
    const a = await analyzeSpf('loop.example', fakeResolver(zone))
    expect(a.loops).toEqual(['loop.example → l2.example → loop.example'])
    expect(spfFindings(a, true).some((f) => f.title === 'SPF include loop')).toBe(true)
  })

  it('caps the expansion of hostile wide trees', async () => {
    const calls: string[] = []
    // every domain includes 5 fresh ones: exponential without a cap
    const resolve = fakeResolver(
      new Proxy({} as Record<string, string[]>, {
        get: (_t, key: string) => {
          const d = key.split('|')[0]
          return [`v=spf1 ${[1, 2, 3, 4, 5].map((i) => `include:${i}.${d}`).join(' ')} -all`]
        },
      }),
      calls,
    )
    const a = await analyzeSpf('hostile.example', resolve, { maxNodes: 30 })
    expect(a.capped).toBe(true)
    expect(calls.length).toBeLessThanOrEqual(30)
  })

  it('flags void includes, multiple records, +all and missing SPF', async () => {
    const a = await analyzeSpf('x.example', fakeResolver({ 'x.example|TXT': ['v=spf1 include:gone.example +all'] }))
    expect(a.voidLookups).toBe(1)
    const f = spfFindings(a, true)
    expect(f.some((x) => x.severity === 'high' && x.title === 'SPF includes a domain without SPF')).toBe(true)
    expect(f.some((x) => x.severity === 'critical' && /\+all/.test(x.title))).toBe(true)

    const multi = await analyzeSpf('m.example', fakeResolver({ 'm.example|TXT': ['v=spf1 -all', 'v=spf1 ~all'] }))
    expect(spfFindings(multi, true)[0].title).toBe('2 SPF records (permerror)')

    const none = await analyzeSpf('n.example', fakeResolver({ 'n.example|TXT': ['hello'] }))
    expect(spfFindings(none, true)[0]).toMatchObject({ severity: 'medium', title: 'No SPF record' })
    expect(spfFindings(none, false)[0].severity).toBe('low')
  })

  it('ignores redirect when all is present and does not expand macros', async () => {
    const calls: string[] = []
    const a = await analyzeSpf('r.example', fakeResolver({ 'r.example|TXT': ['v=spf1 include:%{d}.spf.example redirect=other.example -all'] }, calls))
    expect(calls).toEqual(['r.example|TXT'])
    expect(a.root.children[0].notExpanded).toMatch(/macros/)
  })
})

describe('DMARC', () => {
  it('parses a real record', () => {
    const d = parseDmarc(AFNIC_DMARC)
    expect(d).toMatchObject({ valid: true, p: 'quarantine', pct: 100, adkim: 'r', aspf: 'r', rua: ['mailto:dmarc-feedback@afnic.fr'] })
    expect(isDmarcRecord(AFNIC_DMARC)).toBe(true)
    expect(isDmarcRecord('v=spf1 -all')).toBe(false)
  })

  it('flags missing record, p=none, no rua, sp=none and invalid values', () => {
    expect(dmarcFindings([], 'example.com', false)[0]).toMatchObject({ severity: 'high', title: 'No DMARC record' })
    const none = dmarcFindings(['v=DMARC1; p=none'], 'example.com', false).map((f) => f.title)
    expect(none).toContain('DMARC policy p=none (monitoring only)')
    expect(none).toContain('No DMARC aggregate reports (rua)')
    expect(dmarcFindings(['v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c'], 'example.com', false).map((f) => f.title)).toContain('Subdomains not protected (sp=none)')
    expect(parseDmarc('v=DMARC1; p=maybe; pct=200').errors).toHaveLength(2)
    expect(dmarcFindings(['v=DMARC1; p=reject', 'v=DMARC1; p=none'], 'x', false)[0].title).toBe('2 DMARC records')
  })

  it('uses sp= when inherited from the organisational domain', () => {
    const f = dmarcFindings(['v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c'], 'example.com', true)
    expect(f.map((x) => x.title)).toContain('DMARC policy p=none (monitoring only)')
  })
})

describe('DKIM', () => {
  it('measures real RSA key sizes', () => {
    expect(parseDkim('selector1', GITHUB_DKIM_1024)).toMatchObject({ keyType: 'rsa', bits: 1024, revoked: false })
    expect(parseDkim('google', GITHUB_DKIM_2048).bits).toBe(2048)
  })

  it('accepts PKCS#1-only keys, Ed25519 and revoked keys', () => {
    expect(parseDkim('s', `v=DKIM1; p=${rsaKey(2048, true)}`).bits).toBe(2048)
    expect(parseDkim('s', `v=DKIM1; k=ed25519; p=${toBase64(new Uint8Array(32))}`)).toMatchObject({ bits: 256, keyType: 'ed25519' })
    expect(parseDkim('s', 'v=DKIM1; p=')).toMatchObject({ revoked: true })
    expect(parseDkim('s', 'v=DKIM1; p=!!!').error).toMatch(/base64/)
  })

  it('grades key sizes', () => {
    const keys = [parseDkim('a', `p=${rsaKey(512)}`), parseDkim('b', `p=${rsaKey(1024)}`), parseDkim('c', `p=${rsaKey(2048)}`)]
    expect(keys.map((k) => k.bits)).toEqual([512, 1024, 2048])
    expect(dkimFindings(keys, 3, true).map((f) => f.severity)).toEqual(['critical', 'medium', 'pass'])
    expect(dkimFindings([], 30, true)[0].severity).toBe('info')
  })
})

describe('MTA-STS', () => {
  it('parses a policy and matches MX patterns', () => {
    const p = parseStsPolicy('version: STSv1\nmode: enforce\nmx: *.mail.protection.outlook.com\nmax_age: 604800\n')
    expect(p).toEqual({ version: 'STSv1', mode: 'enforce', mx: ['*.mail.protection.outlook.com'], maxAge: 604800, errors: [] })
    expect(stsMxMatches('*.mail.protection.outlook.com', 'github-com.mail.protection.outlook.com')).toBe(true)
    expect(stsMxMatches('*.example.com', 'a.b.example.com')).toBe(false)
    expect(stsMxMatches('mx.example.com', 'MX.example.com')).toBe(true)
    expect(parseStsPolicy('mode: weird').errors.length).toBeGreaterThan(1)
  })
})

describe('runEmailCheck', () => {
  it('builds a full picture from DNS', async () => {
    const resolve = fakeResolver({
      'github.com|MX': ['0 github-com.mail.protection.outlook.com.'],
      'github.com|TXT': ['MS=ms44452932', 'v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com ~all'],
      'spf.protection.outlook.com|TXT': ['v=spf1 ip4:40.92.0.0/15 -all'],
      '_dmarc.github.com|TXT': ['v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@github.com'],
      'selector1._domainkey.github.com|TXT': [GITHUB_DKIM_1024],
      'google._domainkey.github.com|TXT': [GITHUB_DKIM_2048],
      '_mta-sts.github.com|TXT': { data: [] },
      '_smtp._tls.github.com|TXT': ['v=TLSRPTv1; rua=mailto:tls@github.com'],
    })
    const { data, findings } = await runEmailCheck('github.com', 'github.com', resolve)
    expect(data.mx).toEqual([{ priority: 0, exchange: 'github-com.mail.protection.outlook.com' }])
    expect(data.spf?.totalLookups).toBe(1)
    expect(data.dmarc?.parsed?.p).toBe('reject')
    expect(data.dkim.map((k) => `${k.selector}:${k.bits}`)).toEqual(['google:2048', 'selector1:1024'])
    expect(data.tlsRpt?.rua).toEqual(['mailto:tls@github.com'])
    const titles = findings.map((f) => f.title)
    expect(titles).toContain('DMARC enforced (p=reject)')
    expect(titles).toContain('DKIM selector1: RSA 1024-bit key')
    expect(titles).toContain('No MTA-STS')
  })

  it('falls back to the organisational DMARC record and handles null MX', async () => {
    const resolve = fakeResolver({
      'www.example.com|MX': ['0 .'],
      'www.example.com|TXT': ['v=spf1 ~all'],
      '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:x@example.com'],
    })
    const { data, findings } = await runEmailCheck('www.example.com', 'example.com', resolve)
    expect(data.nullMx).toBe(true)
    expect(data.dmarc).toMatchObject({ name: '_dmarc.example.com', fallback: true })
    const titles = findings.map((f) => f.title)
    expect(titles).toContain('Null MX: domain accepts no email')
    expect(titles).toContain('Null MX but SPF is not "-all"')
    expect(titles).toContain('DMARC inherited from example.com')
  })
})
