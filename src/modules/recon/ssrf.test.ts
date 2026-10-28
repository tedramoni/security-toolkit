import { describe, expect, it } from 'vitest'
import workerSource from './proxy-worker.js.txt?raw'
import { blockedIPv4Reason, blockedIPv6Reason, checkHost, checkProxyTarget, parseIPv4, parseIPv6 } from './ssrf'

describe('IP parsing', () => {
  it('parses dotted quads strictly', () => {
    expect(parseIPv4('192.168.0.1')).toEqual([192, 168, 0, 1])
    expect(parseIPv4('256.1.1.1')).toBeUndefined()
    expect(parseIPv4('01.1.1.1')).toBeUndefined()
    expect(parseIPv4('1.1.1')).toBeUndefined()
  })

  it('parses IPv6 with compression and embedded IPv4', () => {
    expect(parseIPv6('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 1])
    expect(parseIPv6('[fe80::1%eth0]')).toEqual([0xfe80, 0, 0, 0, 0, 0, 0, 1])
    expect(parseIPv6('::ffff:10.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001])
    expect(parseIPv6('1::2::3')).toBeUndefined()
    expect(parseIPv6('1:2:3:4:5:6:7:8:9')).toBeUndefined()
    expect(parseIPv6('12345::')).toBeUndefined()
  })
})

describe('blocked ranges', () => {
  it.each([
    ['0.0.0.0'], ['10.0.0.1'], ['100.64.0.1'], ['127.1.2.3'], ['169.254.169.254'], ['172.16.0.1'], ['172.31.255.255'],
    ['192.0.0.1'], ['192.0.2.1'], ['192.168.1.1'], ['198.18.0.1'], ['198.51.100.7'], ['203.0.113.9'], ['224.0.0.1'], ['255.255.255.255'],
  ])('blocks IPv4 %s', (ip) => {
    expect(blockedIPv4Reason(parseIPv4(ip)!)).toBeTruthy()
  })

  it.each([['8.8.8.8'], ['1.1.1.1'], ['172.32.0.1'], ['100.128.0.1'], ['140.82.121.4']])('allows public IPv4 %s', (ip) => {
    expect(blockedIPv4Reason(parseIPv4(ip)!)).toBeUndefined()
  })

  it.each([['::'], ['::1'], ['::ffff:127.0.0.1'], ['::ffff:169.254.169.254'], ['64:ff9b::10.0.0.1'], ['fc00::1'], ['fd12:3456::1'], ['fe80::1'], ['ff02::1'], ['2001:db8::1'], ['2002:c0a8:0101::1'], ['::127.0.0.1'], ['::ffff:0:127.0.0.1'], ['::ffff:0:a9fe:a9fe']])(
    'blocks IPv6 %s',
    (ip) => {
      expect(blockedIPv6Reason(parseIPv6(ip)!)).toBeTruthy()
    },
  )

  it.each([['2606:4700:4700::1111'], ['2a00:1450:4007:80e::200e'], ['::ffff:8.8.8.8'], ['64:ff9b::8.8.8.8']])('allows public IPv6 %s', (ip) => {
    expect(blockedIPv6Reason(parseIPv6(ip)!)).toBeUndefined()
  })
})

describe('checkHost / checkProxyTarget', () => {
  it('blocks special names', () => {
    for (const h of ['localhost', 'a.localhost', 'nas.local', 'db.internal', 'metadata.google.internal', 'metadata', 'router.lan', 'x.home.arpa', '10.0.0.1.nip.io', 'app.lvh.me', 'intranet', '0x7f000001', '1.2.3']) {
      expect(checkHost(h).blocked, h).toBeTruthy()
    }
    expect(checkHost('example.com').blocked).toBeUndefined()
    expect(checkHost('[2606:4700::1]')).toEqual({ kind: 'ipv6' })
  })

  it('validates proxy targets', () => {
    expect(checkProxyTarget('https://example.com/robots.txt').ok).toBe(true)
    expect(checkProxyTarget('http://example.com:8080/').ok).toBe(true)
    const bad = ['file:///etc/passwd', 'gopher://example.com/', 'https://user:pw@example.com/', 'https://example.com:22/', 'http://127.0.0.1/', 'http://2130706433/', 'http://0x7f.0.0.1/', 'http://[::1]/', 'http://[::ffff:7f00:1]/', 'http://[::ffff:0:a9fe:a9fe]/', 'http://0177.0.0.1/', 'http://017700000001/', 'http://169.254.169.254/latest/meta-data/', 'http://metadata.google.internal/', 'http://localhost:8080/', 'not a url', 'https://' + 'a'.repeat(3000) + '.com/']
    for (const u of bad) expect(checkProxyTarget(u).ok, u).toBe(false)
  })
})

describe('worker template', () => {
  it('ships the hardening controls', () => {
    expect(workerSource).toContain("request.method !== 'GET'")
    expect(workerSource).toContain('ALLOWED_ORIGIN')
    expect(workerSource).toContain("redirect: 'manual'")
    expect(workerSource).toContain('AbortSignal.timeout(TIMEOUT_MS)')
    expect(workerSource).toContain('MAX_BYTES')
    expect(workerSource).toContain('redactCookie')
    expect(workerSource).not.toMatch(/request\.headers\.get\(['"]cookie/i)
    expect(workerSource).not.toMatch(/Access-Control-Allow-Origin['"]?:\s*['"]\*/)
  })

  it('duplicates the SSRF guard of ssrf.ts verbatim (logic kept in sync)', () => {
    // Every blocked range / name string in ssrf.ts must appear in the worker as well.
    for (const ip of ['127.0.0.1', '169.254.169.254', '10.0.0.1', '172.16.0.1', '192.168.1.1', '100.64.0.1', '224.0.0.1']) {
      const reason = blockedIPv4Reason(parseIPv4(ip)!)!
      expect(workerSource).toContain(reason)
    }
    for (const ip of ['::1', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1']) {
      expect(workerSource).toContain(blockedIPv6Reason(parseIPv6(ip)!)!)
    }
    for (const s of ['nip.io', 'metadata.google.internal', "'home.arpa'", "['', '80', '443', '8080', '8443']"]) expect(workerSource).toContain(s)
  })
})
