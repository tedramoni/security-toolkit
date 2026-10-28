import { describe, expect, it } from 'vitest'
import afnic from './fixtures/rdap-afnic.fr.json?raw'
import github from './fixtures/rdap-github.com.json?raw'
import arin from './fixtures/rdap-ip-arin.json?raw'
import ripe from './fixtures/rdap-ip-ripe.json?raw'
import wikipedia from './fixtures/rdap-wikipedia.org.json?raw'
import { fetchRdapDomain, fetchRdapIp, normalizeStatus, parseRdapDomain, parseRdapIp, rdapDomainFindings } from './rdap'
import { fakeFetch } from './test-helpers'

const NOW = Date.parse('2026-10-28T12:00:00Z')

describe('RDAP domain parsing (real responses)', () => {
  it('Verisign (.com)', () => {
    const d = parseRdapDomain(JSON.parse(github))
    expect(d.name).toBe('github.com')
    expect(d.registrar).toMatchObject({ name: 'MarkMonitor Inc.', ianaId: '292' })
    expect(d.abuse?.email).toBe('abusecomplaints@markmonitor.com')
    expect(d.registration).toBe('2007-10-09T18:20:50Z')
    expect(d.expiration).toBe('2028-10-09T18:20:50Z')
    expect(d.status.map((s) => s.code)).toEqual(['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited'])
    expect(d.status[1].help).toMatch(/transfers/)
    expect(d.nameservers).toContain('dns1.p08.nsone.net')
    expect(d.delegationSigned).toBe(false)
    expect(rdapDomainFindings(d, NOW).map((f) => f.severity)).toEqual(['pass', 'pass'])
  })

  it('PIR (.org) and AFNIC (.fr)', () => {
    const w = parseRdapDomain(JSON.parse(wikipedia))
    expect(w.registrar?.name).toBe('MarkMonitor Inc.')
    expect(w.nameservers).toEqual(['ns0.wikimedia.org', 'ns1.wikimedia.org', 'ns2.wikimedia.org'])
    const a = parseRdapDomain(JSON.parse(afnic))
    expect(a.name).toBe('afnic.fr')
    expect(a.status.map((s) => s.code)).toEqual(['active'])
    expect(a.registrar?.name).toBe('Registry Operations')
    expect(a.expiration).toBe('2029-07-18T08:26:59Z')
    // ccTLD without client*/server* statuses: no "no transfer lock" false positive
    expect(rdapDomainFindings(a, NOW).some((f) => f.title === 'No transfer lock')).toBe(false)
  })

  it('flags expiry, holds and missing locks', () => {
    const d = parseRdapDomain(JSON.parse(github))
    const soon = rdapDomainFindings({ ...d, expiration: '2026-11-10T00:00:00Z' }, NOW)
    expect(soon[0]).toMatchObject({ severity: 'high', title: 'Domain expires in 12 days' })
    expect(rdapDomainFindings({ ...d, expiration: '2026-10-01T00:00:00Z' }, NOW)[0].severity).toBe('critical')
    const unlocked = rdapDomainFindings({ ...d, status: [{ code: 'clientUpdateProhibited' }, { code: 'clientHold' }] }, NOW).map((f) => f.title)
    expect(unlocked).toContain('No transfer lock')
    expect(unlocked).toContain('Domain status clientHold')
  })

  it('normalises status spellings and rejects other objects', () => {
    expect(normalizeStatus('client transfer prohibited')).toBe('clientTransferProhibited')
    expect(normalizeStatus('clientTransferProhibited')).toBe('clientTransferProhibited')
    expect(normalizeStatus('redemption period')).toBe('redemptionPeriod')
    expect(() => parseRdapDomain({ objectClassName: 'entity' })).toThrow()
  })
})

describe('RDAP IP parsing (real responses)', () => {
  it('ARIN', () => {
    const ip = parseRdapIp(JSON.parse(arin))
    expect(ip).toMatchObject({ handle: 'NET-140-82-112-0-1', name: 'GITHU', cidrs: ['140.82.112.0/20'], org: 'GitHub, Inc.' })
    expect(ip.abuse?.email).toBeTruthy()
  })

  it('RIPE', () => {
    const ip = parseRdapIp(JSON.parse(ripe))
    expect(ip).toMatchObject({ name: 'NIC-FR-SITES-SQY-TH3', country: 'FR', cidrs: ['192.134.4.0/22'] })
    expect(ip.org).toMatch(/AFNIC/)
  })
})

describe('fetchRdapDomain', () => {
  it('follows rdap.org and reports the registry server', async () => {
    const fetch = fakeFetch((url) => (url === 'https://rdap.org/domain/github.com' ? { body: JSON.parse(github), url: 'https://rdap.verisign.com/com/v1/domain/github.com' } : undefined))
    const r = await fetchRdapDomain('www.github.com', 'github.com', { fetch })
    expect(r).toMatchObject({ kind: 'ok', queried: 'github.com', server: 'rdap.verisign.com' })
  })

  it('stops on "no RDAP service" for the TLD (.io)', async () => {
    const calls: string[] = []
    const fetch = fakeFetch(() => ({ status: 404, body: { rdapConformance: ['rdap_level_0'], errorCode: 404, title: 'No RDAP service is available for this resource' }, url: 'https://rdap.org/domain/github.io' }), calls)
    const r = await fetchRdapDomain('pages.github.io', 'github.io', { fetch })
    expect(r.kind).toBe('unavailable')
    expect(calls).toHaveLength(1)
  })

  it('tries other candidates on a registry 404', async () => {
    const calls: string[] = []
    const fetch = fakeFetch((url) => (url.endsWith('/domain/bbc.co.uk') ? { body: JSON.parse(github) } : { status: 404, body: { errorCode: 404 }, url: 'https://rdap.nominet.uk/uk/domain/x' }), calls)
    const r = await fetchRdapDomain('www.bbc.co.uk', 'co.uk', { fetch })
    expect(r.kind).toBe('ok')
    expect(calls.map((c) => c.split('/').pop())).toEqual(['co.uk', 'bbc.co.uk'])
  })

  it('IP lookups surface HTTP errors', async () => {
    const fetch = fakeFetch(() => ({ status: 400, body: '{}' }))
    await expect(fetchRdapIp('1.2.3.4', { fetch })).rejects.toThrow(/HTTP 400/)
    const ok = fakeFetch(() => ({ body: JSON.parse(arin), url: 'https://rdap.arin.net/registry/ip/140.82.121.4' }))
    expect((await fetchRdapIp('140.82.121.4', { fetch: ok })).server).toBe('rdap.arin.net')
  })
})
