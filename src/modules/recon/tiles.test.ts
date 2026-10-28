import { describe, expect, it } from 'vitest'
import { ctFindings, processCrtsh } from './crtsh'
import { runDnsCheck } from './dns'
import { runEmailCheck } from './email'
import { fakeResolver } from './test-helpers'
import { CHECK_TILES, splitFindings, tileOf, tileStatus } from './tiles'

describe('tile routing', () => {
  it('routes DNS findings to records / DNSSEC / CAA / NS tiles', async () => {
    const resolve = fakeResolver({
      'example.com|A': ['192.0.2.10'],
      'example.com|NS': ['ns1.example.net.'],
      'example.com|SOA': ['ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 300'],
      'example.com|TXT': ['google-site-verification=x'],
    })
    const { findings } = await runDnsCheck('example.com', resolve, 'rnd')
    const by = splitFindings('dns', findings)
    expect(by.get('dns-caa')!.map((f) => f.title)).toEqual(['No CAA record'])
    expect(by.get('dns-dnssec')!.map((f) => f.title)).toEqual(['DNSSEC not enabled'])
    expect(by.get('dns-ns')!.map((f) => f.title)).toEqual(['Single authoritative name server'])
    expect(by.get('dns-records')!.some((f) => f.title.startsWith('No IPv6'))).toBe(true)
    expect([...by.values()].flat()).toHaveLength(findings.length)
  })

  it('routes email findings to SPF / DMARC / DKIM / transport tiles', async () => {
    const resolve = fakeResolver({
      'example.com|MX': ['10 mx.example.com.'],
      'example.com|TXT': ['v=spf1 mx ~all'],
      '_dmarc.example.com|TXT': ['v=DMARC1; p=none'],
      'selector1._domainkey.example.com|TXT': ['v=DKIM1; k=rsa; p='],
    })
    const { findings } = await runEmailCheck('example.com', 'example.com', resolve)
    const by = splitFindings('email', findings)
    expect(by.get('email-dmarc')!.some((f) => f.title.includes('p=none'))).toBe(true)
    expect(by.get('email-dkim')!.some((f) => f.title.startsWith('DKIM selector1'))).toBe(true)
    expect(by.get('email-transport')!.some((f) => f.title === 'No MTA-STS')).toBe(true)
    expect(by.get('email-spf')!.some((f) => f.title.includes('~all'))).toBe(true)
    // Nothing about SPF leaks into DMARC and vice versa.
    expect(by.get('email-spf')!.some((f) => /DMARC|DKIM|MTA-STS/.test(f.title))).toBe(false)
    expect([...by.values()].flat()).toHaveLength(findings.length)
  })

  it('routes CT findings and web findings', () => {
    const s = processCrtsh([], 'example.com', 0)
    for (const f of ctFindings(s, 'example.com')) expect(tileOf('ct', f)).toBe('ct-hosts')
    expect(tileOf('ct', { title: '2 certificates expire within 14 days without a logged renewal' })).toBe('ct-certs')
    expect(tileOf('web', { title: 'Headers: Missing Content-Security-Policy' })).toBe('web-headers')
    expect(tileOf('web', { title: 'security.txt: No Policy link' })).toBe('web-securitytxt')
    expect(tileOf('web', { title: 'No security.txt' })).toBe('web-securitytxt')
    expect(tileOf('web', { title: 'robots.txt lists 3 potentially sensitive path(s)' })).toBe('web-robots')
    expect(tileOf('web', { title: 'HTTP is not redirected to HTTPS' })).toBe('web-https')
  })

  it('unknown titles fall back to the first tile of the check', () => {
    for (const [check, tiles] of Object.entries(CHECK_TILES)) expect(tileOf(check as keyof typeof CHECK_TILES, { title: 'zzz' })).toBe(tiles[0])
  })
})

describe('tileStatus', () => {
  it('maps check state and worst severity', () => {
    expect(tileStatus('running', [])).toBe('loading')
    expect(tileStatus('error', [])).toBe('error')
    expect(tileStatus('needs-proxy', [])).toBe('needs-proxy')
    expect(tileStatus('done', [{ severity: 'pass' }, { severity: 'high' }])).toBe('fail')
    expect(tileStatus('done', [{ severity: 'pass' }, { severity: 'low' }])).toBe('warn')
    expect(tileStatus('done', [{ severity: 'pass' }, { severity: 'info' }])).toBe('ok')
    expect(tileStatus('done', [{ severity: 'info' }])).toBe('info')
  })
})
