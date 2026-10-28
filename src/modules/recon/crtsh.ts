/**
 * Certificate Transparency via crt.sh (https://crt.sh/?q=<domain>&output=json, Access-Control-Allow-Origin: *).
 * crt.sh is slow and sometimes answers 502/timeouts on large domains: generous timeout, one retry, then a lighter
 * "exclude=expired" query as fallback.
 */
import type { FetchLike } from './net'
import { SourceError, fetchText } from './net'
import type { Finding } from './types'

export interface CrtshEntry {
  issuer_ca_id: number
  issuer_name: string
  common_name: string
  name_value: string
  id: number
  entry_timestamp?: string
  not_before: string
  not_after: string
  serial_number: string
}

/** Keep only well-formed entries (crt.sh JSON is external data). */
export function sanitizeCrtsh(json: unknown): CrtshEntry[] {
  if (!Array.isArray(json)) throw new Error('crt.sh did not return a JSON array')
  const out: CrtshEntry[] = []
  for (const e of json as Record<string, unknown>[]) {
    if (typeof e !== 'object' || e === null) continue
    if (typeof e.name_value !== 'string' || typeof e.not_before !== 'string' || typeof e.not_after !== 'string') continue
    out.push({
      issuer_ca_id: typeof e.issuer_ca_id === 'number' ? e.issuer_ca_id : 0,
      issuer_name: typeof e.issuer_name === 'string' ? e.issuer_name : '',
      common_name: typeof e.common_name === 'string' ? e.common_name : '',
      name_value: e.name_value,
      id: typeof e.id === 'number' ? e.id : 0,
      entry_timestamp: typeof e.entry_timestamp === 'string' ? e.entry_timestamp : undefined,
      not_before: e.not_before,
      not_after: e.not_after,
      serial_number: typeof e.serial_number === 'string' ? e.serial_number : '',
    })
  }
  return out
}

/** crt.sh timestamps have no zone and are UTC. */
export function crtDate(s: string): number {
  const t = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`)
  return Number.isNaN(t) ? NaN : t
}

const HOSTNAME = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$/

/** Organisation / CN of an issuer DN like "C=US, O=Let's Encrypt, CN=R11". */
export function issuerLabel(dn: string): string {
  let o: string | undefined
  let cn: string | undefined
  for (const part of dn.split(/,\s*(?=[A-Za-z]+=)/)) {
    const i = part.indexOf('=')
    if (i === -1) continue
    const k = part.slice(0, i).trim().toUpperCase()
    const v = part.slice(i + 1).trim().replace(/^"|"$/g, '')
    if (k === 'O' && o === undefined) o = v
    if (k === 'CN' && cn === undefined) cn = v
  }
  if (o && cn) return `${o} (${cn})`
  return o ?? cn ?? (dn || 'unknown issuer')
}

export interface CertSummary {
  id: number
  issuer: string
  issuerDn: string
  commonName: string
  names: string[]
  notBefore: string
  notAfter: string
  serial: string
  wildcard: boolean
  expired: boolean
  daysLeft: number
}

export interface CtSummary {
  /** Unique host names under the target domain (wildcards stripped), sorted. */
  subdomains: string[]
  /** Wildcard names seen (e.g. *.example.com). */
  wildcards: string[]
  /** Unique certificates (precertificate + certificate entries merged), newest first. */
  certs: CertSummary[]
  issuers: { issuer: string; count: number }[]
  totalEntries: number
  /** Names in certificates that are outside the target domain (SANs shared with other domains). */
  foreignNames: number
}

export function processCrtsh(entries: readonly CrtshEntry[], domain: string, now: number): CtSummary {
  const d = domain.toLowerCase()
  const inScope = (h: string) => h === d || h.endsWith('.' + d)
  const subs = new Set<string>()
  const wild = new Set<string>()
  let foreign = 0
  const byCert = new Map<string, CertSummary>()
  for (const e of entries) {
    const names = e.name_value
      .split('\n')
      .map((x) => x.trim().toLowerCase().replace(/\.$/, ''))
      .filter((x) => x !== '' && x.length <= 253)
    const isWildcard = names.some((n) => n.startsWith('*.'))
    for (const raw of names) {
      if (raw.includes('@')) continue // e-mail SANs (S/MIME)
      const host = raw.startsWith('*.') ? raw.slice(2) : raw
      if (!HOSTNAME.test(host)) continue
      if (!inScope(host)) {
        foreign++
        continue
      }
      if (raw.startsWith('*.')) wild.add(raw)
      subs.add(host)
    }
    const key = `${e.issuer_ca_id}:${e.serial_number || e.id}`
    const notAfter = crtDate(e.not_after)
    const existing = byCert.get(key)
    if (existing) {
      for (const n of names) if (!existing.names.includes(n)) existing.names.push(n)
      existing.id = Math.max(existing.id, e.id)
      continue
    }
    byCert.set(key, {
      id: e.id,
      issuer: issuerLabel(e.issuer_name),
      issuerDn: e.issuer_name,
      commonName: e.common_name.toLowerCase(),
      names: [...names],
      notBefore: e.not_before,
      notAfter: e.not_after,
      serial: e.serial_number,
      wildcard: isWildcard,
      expired: Number.isFinite(notAfter) ? notAfter < now : false,
      daysLeft: Number.isFinite(notAfter) ? Math.floor((notAfter - now) / 86400000) : NaN,
    })
  }
  const certs = [...byCert.values()].sort((a, b) => crtDate(b.notBefore) - crtDate(a.notBefore) || b.id - a.id)
  const issuerCount = new Map<string, number>()
  // Group by organisation: one CA operates many intermediates (Let's Encrypt R10, R11, E5…).
  for (const c of certs) {
    const paren = c.issuer.indexOf(' (')
    const org = paren > 0 && c.issuer.endsWith(')') ? c.issuer.slice(0, paren) : c.issuer
    issuerCount.set(org, (issuerCount.get(org) ?? 0) + 1)
  }
  const issuers = [...issuerCount.entries()].map(([issuer, count]) => ({ issuer, count })).sort((a, b) => b.count - a.count || a.issuer.localeCompare(b.issuer))
  const subdomains = [...subs].sort(compareHosts)
  return { subdomains, wildcards: [...wild].sort(), certs, issuers, totalEntries: entries.length, foreignNames: foreign }
}

/** Sort host names by their labels from the right (groups siblings together). */
export function compareHosts(a: string, b: string): number {
  const ra = a.split('.').reverse()
  const rb = b.split('.').reverse()
  for (let i = 0; i < Math.min(ra.length, rb.length); i++) {
    if (ra[i] !== rb[i]) return ra[i] < rb[i] ? -1 : 1
  }
  return ra.length - rb.length
}

export function ctFindings(s: CtSummary, domain: string): Finding[] {
  const f: Finding[] = []
  const valid = s.certs.filter((c) => !c.expired)
  f.push({
    severity: 'info',
    title: `${s.subdomains.length} host name${s.subdomains.length === 1 ? '' : 's'} in certificate transparency logs`,
    detail: `Every publicly trusted certificate is logged, so these names under ${domain} are public — including staging, admin or internal names. Review the list for hosts that should not be exposed.`,
    ref: 'https://certificate.transparency.dev/',
  })
  // Expiring soon: a valid cert for a name with no newer certificate covering it.
  const soon = valid.filter((c) => c.daysLeft <= 14)
  // Linear in the number of names (crt.sh can return 10k+ certificates): a certificate counts as renewed when every
  // one of its names is also covered by a certificate that expires later.
  const latest = new Map<string, number>()
  for (const c of valid) for (const n of c.names) latest.set(n, Math.max(latest.get(n) ?? -Infinity, c.daysLeft))
  const notRenewed = soon.filter((c) => c.names.some((n) => (latest.get(n) ?? -Infinity) <= c.daysLeft))
  if (notRenewed.length > 0) {
    f.push({
      severity: 'medium',
      title: `${notRenewed.length} certificate${notRenewed.length > 1 ? 's' : ''} expire within 14 days without a logged renewal`,
      detail: notRenewed.slice(0, 8).map((c) => `${c.commonName || c.names[0]} (${c.daysLeft} d)`).join(', '),
      fix: 'Check automated renewal (ACME) for these hosts.',
    })
  }
  if (s.wildcards.length > 0) {
    f.push({
      severity: 'info',
      title: `Wildcard certificates in use (${s.wildcards.join(', ').slice(0, 200)})`,
      detail: 'A wildcard key compromised on one server can impersonate every subdomain. Prefer per-host certificates where practical, and keep wildcard keys on few, well-protected hosts.',
    })
  }
  if (s.issuers.length > 3) {
    f.push({ severity: 'info', title: `${s.issuers.length} different CA organisations issue certificates`, detail: 'Several teams or vendors obtain certificates. A CAA record lets you restrict this list.' })
  }
  return f
}

export interface CrtshOptions {
  fetch?: FetchLike
  signal?: AbortSignal
  timeoutMs?: number
  backoffMs?: number
}

export interface CrtshFetchResult {
  entries: CrtshEntry[]
  /** True when the full query failed and only unexpired certificates were retrieved. */
  unexpiredOnly: boolean
  url: string
}

export function crtshUrl(domain: string, excludeExpired = false): string {
  return `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json${excludeExpired ? '&exclude=expired' : ''}`
}

export async function fetchCrtsh(domain: string, opts: CrtshOptions = {}): Promise<CrtshFetchResult> {
  const attempt = async (excludeExpired: boolean) => {
    const url = crtshUrl(domain, excludeExpired)
    const res = await fetchText(url, { source: 'crt.sh', fetch: opts.fetch, signal: opts.signal, timeoutMs: opts.timeoutMs ?? 60000, retries: 1, backoffMs: opts.backoffMs ?? 2000 })
    if (!res.ok) throw new SourceError('crt.sh', 'http', `crt.sh returned HTTP ${res.status} (the service is often overloaded — try again later)`, res.status)
    let json: unknown
    try {
      json = JSON.parse(res.text)
    } catch {
      throw new SourceError('crt.sh', 'parse', 'crt.sh returned an error page instead of JSON (overloaded or query too large)')
    }
    return { entries: sanitizeCrtsh(json), unexpiredOnly: excludeExpired, url }
  }
  try {
    return await attempt(false)
  } catch (e) {
    if (e instanceof SourceError && e.kind === 'aborted') throw e
    try {
      return await attempt(true)
    } catch (e2) {
      if (e2 instanceof SourceError && e2.kind === 'aborted') throw e2
      throw e
    }
  }
}
