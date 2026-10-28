import { describe, expect, it } from 'vitest'
import fixture from './fixtures/crtsh-afnic.fr.json?raw'
import { compareHosts, crtDate, ctFindings, fetchCrtsh, issuerLabel, processCrtsh, sanitizeCrtsh } from './crtsh'
import type { CrtshEntry } from './crtsh'
import { fakeFetch } from './test-helpers'

const entries = sanitizeCrtsh(JSON.parse(fixture))
const NOW = Date.parse('2026-10-28T12:00:00Z')

describe('crt.sh processing (real afnic.fr sample)', () => {
  it('dedupes subdomains, keeps them in scope and sorted by label', () => {
    const s = processCrtsh(entries, 'afnic.fr', NOW)
    expect(new Set(s.subdomains).size).toBe(s.subdomains.length)
    expect(s.subdomains.every((h) => h === 'afnic.fr' || h.endsWith('.afnic.fr'))).toBe(true)
    expect(s.subdomains).toContain('visio.afnic.fr')
    expect(s.subdomains).toContain('autodiscover.afnic.fr')
    expect([...s.subdomains].sort(compareHosts)).toEqual(s.subdomains)
    expect(s.certs.length).toBeLessThanOrEqual(entries.length)
    expect(s.issuers[0].count).toBeGreaterThan(0)
  })

  it('merges precertificate/certificate pairs and strips wildcards', () => {
    const base = { issuer_ca_id: 1, issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11', common_name: '*.example.com', not_before: '2026-10-01T00:00:00', not_after: '2026-11-05T00:00:00', serial_number: 'abc' }
    const s = processCrtsh(
      sanitizeCrtsh([
        { ...base, id: 1, name_value: '*.example.com\nexample.com' },
        { ...base, id: 2, name_value: '*.example.com\nexample.com' },
        { ...base, id: 3, serial_number: 'def', common_name: 'evil.com', name_value: 'evil.com\nWWW.Example.com.\nuser@example.com\nbad_host!.example.com' },
      ]),
      'example.com',
      NOW,
    )
    expect(s.subdomains).toEqual(['example.com', 'www.example.com'])
    expect(s.wildcards).toEqual(['*.example.com'])
    expect(s.certs).toHaveLength(2)
    expect(s.foreignNames).toBe(1)
    expect(s.certs[0].issuer).toBe("Let's Encrypt (R11)")
    const f = ctFindings(s, 'example.com')
    expect(f.some((x) => x.title.startsWith('Wildcard certificates'))).toBe(true)
    expect(f.some((x) => /expire within 14 days/.test(x.title))).toBe(true)
  })

  it('validates external JSON', () => {
    expect(() => sanitizeCrtsh({})).toThrow(/array/)
    expect(sanitizeCrtsh([null, 1, { name_value: 5 }, { name_value: 'a.com', not_before: 'x', not_after: 'y' }])).toHaveLength(1)
    expect(crtDate('2026-10-05T23:33:49')).toBe(Date.parse('2026-10-05T23:33:49Z'))
    expect(issuerLabel('C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1')).toBe('DigiCert Inc (DigiCert Global G2 TLS RSA SHA256 2020 CA1)')
  })

  it('is fast on adversarial names', () => {
    const t0 = performance.now()
    const evil = [{ name_value: ('a-'.repeat(100) + '.').repeat(200) + '\n' + 'a.'.repeat(5000) + 'example.com', not_before: '', not_after: '', issuer_name: ', '.repeat(10000) + 'O' }]
    processCrtsh(sanitizeCrtsh(evil), 'example.com', NOW)
    issuerLabel(', a'.repeat(30000))
    expect(performance.now() - t0).toBeLessThan(500)
  })
})

describe('fetchCrtsh', () => {
  it('falls back to exclude=expired when the full query fails', async () => {
    const calls: string[] = []
    const fetch = fakeFetch((url) => (url.includes('exclude=expired') ? { body: JSON.parse(fixture) } : { status: 502, body: '<html>Bad gateway</html>' }), calls)
    const r = await fetchCrtsh('afnic.fr', { fetch, backoffMs: 0 })
    expect(r.unexpiredOnly).toBe(true)
    expect(r.entries.length).toBe(entries.length)
    expect(calls[0]).toBe('https://crt.sh/?q=afnic.fr&output=json')
    expect(calls).toHaveLength(3) // full (502), retry (502), exclude=expired
  })

  it('reports HTML error pages clearly', async () => {
    const fetch = fakeFetch(() => ({ body: '<html>busy</html>' }))
    await expect(fetchCrtsh('example.com', { fetch, backoffMs: 0 })).rejects.toThrow(/error page instead of JSON/)
  })
})

describe('ctFindings renewal check (regression: was quadratic)', () => {
  const entry = (id: number, name: string, notAfter: string): CrtshEntry => ({
    issuer_ca_id: 1, issuer_name: 'O=CA, CN=X', common_name: name, name_value: name, id, not_before: '2026-01-01T00:00:00', not_after: notAfter, serial_number: `s${id}`,
  })
  const now = Date.parse('2026-10-28T00:00:00Z')

  it('flags only certificates without a later-expiring certificate for the same names', () => {
    const s = processCrtsh([entry(1, 'a.example.com', '2026-11-02T00:00:00'), entry(2, 'a.example.com', '2027-01-20T00:00:00'), entry(3, 'b.example.com', '2026-11-03T00:00:00')], 'example.com', now)
    const f = ctFindings(s, 'example.com').find((x) => x.title.includes('expire within 14 days'))
    expect(f?.title).toMatch(/^1 certificate /)
    expect(f?.detail).toContain('b.example.com')
    expect(f?.detail).not.toContain('a.example.com')
  })

  it('stays fast with 20 000 certificates expiring soon', () => {
    const many = Array.from({ length: 20000 }, (_, i) => entry(i + 10, `h${i}.example.com`, '2026-11-01T00:00:00'))
    const s = processCrtsh(many, 'example.com', now)
    const t0 = performance.now()
    ctFindings(s, 'example.com')
    expect(performance.now() - t0).toBeLessThan(500)
  })
})
