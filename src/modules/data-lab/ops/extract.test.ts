import { describe, expect, it } from 'vitest'
import { runOp } from '../testUtil'
import {
  defang,
  extractBitcoin,
  extractDomains,
  extractEmails,
  extractHashes,
  extractIPv4,
  extractIPv6,
  extractPaths,
  extractUrls,
  isIPv6,
  refang,
} from './extract'

const SAMPLE = `Contact admin@example.com or sec-team+ir@corp.example.co.uk.
Beacon: https://evil.example.com/gate.php?id=1&x=y, fallback (http://203.0.113.9:8080/a).
Hosts 10.0.0.1 and 256.1.1.1 and 1.2.3.4.5 and v1.2.3.
IPv6 fe80::1 and 2001:db8::8a2e:370:7334 and ::ffff:192.0.2.1 not 1:2:3.
Files C:\\Windows\\System32\\evil.dll and /etc/passwd and ~/.ssh/id_rsa.
Hash 44d88612fea8a8f36de82e1278abb02f and da39a3ee5e6b4b0d3255bfef95601890afd80709.`

describe('extractors', () => {
  it('URLs (trailing punctuation dropped, balanced parens kept)', () => {
    expect(extractUrls(SAMPLE)).toEqual(['https://evil.example.com/gate.php?id=1&x=y', 'http://203.0.113.9:8080/a'])
    expect(extractUrls('see https://en.wikipedia.org/wiki/Foo_(bar).')).toEqual(['https://en.wikipedia.org/wiki/Foo_(bar)'])
  })
  it('emails', () => {
    expect(extractEmails(SAMPLE)).toEqual(['admin@example.com', 'sec-team+ir@corp.example.co.uk'])
    expect(extractEmails('not@valid and x@y.z1')).toEqual([])
  })
  it('IPv4 (octets validated, no partial matches)', () => {
    expect(extractIPv4(SAMPLE)).toEqual(['203.0.113.9', '10.0.0.1', '192.0.2.1']) // last one is embedded in an IPv6 address
    expect(extractIPv4('1.2.3.04 0.0.0.0 255.255.255.255')).toEqual(['0.0.0.0', '255.255.255.255'])
  })
  it('IPv6 validation', () => {
    for (const ok of ['::', '::1', 'fe80::1', '2001:db8::8a2e:370:7334', '1:2:3:4:5:6:7:8', '::ffff:192.0.2.1', '1:2:3:4:5:6:1.2.3.4', '1::']) {
      expect(isIPv6(ok), ok).toBe(true)
    }
    for (const bad of ['1:2:3', '1:::2', '1::2::3', '1:2:3:4:5:6:7:8:9', '12345::', 'g::1', '::1.2.3', '1:2:3:4:5:6:7:1.2.3.4', ':1:2:3:4:5:6:7']) {
      expect(isIPv6(bad), bad).toBe(false)
    }
    expect(extractIPv6(SAMPLE)).toEqual(['fe80::1', '2001:db8::8a2e:370:7334', '::ffff:192.0.2.1'])
  })
  it('domains', () => {
    const d = extractDomains('Visit evil.example.com, api.v2.example.org and 1.2.3.4 or xn--bcher-kva.example')
    expect(d).toEqual(['evil.example.com', 'api.v2.example.org', 'xn--bcher-kva.example'])
  })
  it('paths', () => {
    expect(extractPaths(SAMPLE, 'both')).toEqual(['C:\\Windows\\System32\\evil.dll', '/etc/passwd', '~/.ssh/id_rsa'])
    expect(extractPaths('\\\\fileserver\\share\\doc.txt', 'windows')).toEqual(['\\\\fileserver\\share\\doc.txt'])
    expect(extractPaths('https://example.com/a/b', 'unix')).toEqual([])
  })
  it('hashes by length', () => {
    expect(extractHashes(SAMPLE, true)).toEqual(['MD5/NTLM\t44d88612fea8a8f36de82e1278abb02f', 'SHA-1\tda39a3ee5e6b4b0d3255bfef95601890afd80709'])
    expect(extractHashes('12345678901234567890123456789012', false)).toEqual([])
  })
  it('bitcoin-like addresses', () => {
    expect(extractBitcoin('pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq now')).toEqual([
      '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
      'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
    ])
  })
  it('op options: unique, sort, count', async () => {
    expect(await runOp('extract-ipv4', '9.9.9.9 1.1.1.1 9.9.9.9', { sort: true })).toBe('1.1.1.1\n9.9.9.9')
    expect(await runOp('extract-ipv4', '9.9.9.9 9.9.9.9', { unique: false, showCount: true })).toBe('Total found: 2\n\n9.9.9.9\n9.9.9.9')
  })
})

describe('defang / refang', () => {
  const opts = { dots: true, scheme: true, separator: false, at: false }
  it('defangs URLs (host only), IPs, domains and emails', () => {
    expect(defang('Go to https://evil.example.com/a.php now', opts)).toBe('Go to hxxps://evil[.]example[.]com/a.php now')
    expect(defang('ip 203.0.113.9 and bad.example.org', opts)).toBe('ip 203[.]0[.]113[.]9 and bad[.]example[.]org')
    expect(defang('mail x@evil.example', { ...opts, at: true })).toBe('mail x[@]evil[.]example')
    expect(defang('HTTP://A.B', { ...opts, separator: true })).toBe('HXXP[://]A[.]B')
  })
  it('refang reverses common styles', () => {
    expect(refang('hxxps://evil[.]example(.)com/x hXXp[://]a{.}b 1[dot]2[.]3[.]4 x[@]y[.]z fxp://f[.]g')).toBe(
      'https://evil.example.com/x http://a.b 1.2.3.4 x@y.z ftp://f.g',
    )
    const text = 'Beacon https://evil.example.com/gate.php from 203.0.113.45 by a@b.example'
    expect(refang(defang(text, { dots: true, scheme: true, separator: true, at: true }))).toBe(text)
  })
})

describe('ReDoS regression: extractors are linear on adversarial input', () => {
  const N = 200_000
  const adversarial = [
    'a'.repeat(N),
    'a.'.repeat(N / 2),
    'a-'.repeat(N / 2),
    '1.'.repeat(N / 2),
    'a@'.repeat(N / 2),
    ('a'.repeat(63) + '.').repeat(N / 64),
    'http://' + 'a'.repeat(N),
    ':'.repeat(N),
    'f:'.repeat(N / 2),
    'C:\\' + 'a\\'.repeat(N / 2),
    '/' + 'a/'.repeat(N / 2),
    '\\\\' + 'a'.repeat(N),
    '0'.repeat(N),
    '&#'.repeat(N / 2),
    'hxxp[.]'.repeat(N / 7),
  ]
  const ops = ['extract-urls', 'extract-emails', 'extract-ipv4', 'extract-ipv6', 'extract-domains', 'extract-paths', 'extract-hashes', 'extract-bitcoin', 'defang', 'refang']
  it.each(ops)('%s stays fast', async (op) => {
    for (const input of adversarial) {
      const t0 = performance.now()
      await runOp(op, input)
      const ms = performance.now() - t0
      expect(ms, `${op} on ${JSON.stringify(input.slice(0, 12))}…`).toBeLessThan(1500)
    }
  })
})
