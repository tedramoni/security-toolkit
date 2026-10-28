/**
 * DNS-over-HTTPS JSON client.
 *  - Google Public DNS: https://dns.google/resolve?name=…&type=…   (docs: https://developers.google.com/speed/public-dns/docs/doh/json)
 *  - Cloudflare:        https://cloudflare-dns.com/dns-query?name=…&type=…  with "accept: application/dns-json"
 *    (Accept is a CORS-safelisted header, so no preflight is needed.)
 * Both send Access-Control-Allow-Origin: *. Google is tried first, Cloudflare on network/HTTP/parse failure.
 * NXDOMAIN / NODATA are answers, not failures, and are not retried on the other resolver.
 */
import type { FetchLike } from './net'
import { SourceError, fetchText } from './net'

export const RR: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  RRSIG: 46,
  DNSKEY: 48,
  SVCB: 64,
  HTTPS: 65,
  CAA: 257,
}

const RR_NAME: Record<number, string> = Object.fromEntries(Object.entries(RR).map(([k, v]) => [v, k]))

export function rrName(type: number): string {
  return RR_NAME[type] ?? `TYPE${type}`
}

export const RCODE: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
}

export type ResolverId = 'google' | 'cloudflare'

export const RESOLVERS: Record<ResolverId, { label: string; url: (name: string, type: string) => string; headers?: Record<string, string> }> = {
  google: {
    label: 'Google Public DNS (dns.google)',
    url: (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${encodeURIComponent(t)}&do=1`,
  },
  cloudflare: {
    label: 'Cloudflare (cloudflare-dns.com)',
    url: (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${encodeURIComponent(t)}&do=1`,
    headers: { accept: 'application/dns-json' },
  },
}

export interface DnsRecord {
  /** Owner name without the trailing dot, lower-cased. */
  name: string
  type: number
  typeName: string
  ttl: number
  /** RDATA in presentation format. TXT is unquoted and its character-strings concatenated. */
  data: string
}

export interface DnsResult {
  name: string
  type: string
  status: number
  statusText: string
  /** DNSSEC "Authenticated Data": the resolver validated the answer. */
  ad: boolean
  /** Records of the requested type (CNAME chain and RRSIGs removed). */
  records: DnsRecord[]
  /** CNAME chain followed by the resolver, in order. */
  cnames: string[]
  /** Every answer record as returned (for the raw view). */
  answers: DnsRecord[]
  resolver: ResolverId
}

function stripDot(s: string): string {
  return s.endsWith('.') && s.length > 1 ? s.slice(0, -1) : s
}

/**
 * Unquote TXT RDATA. Cloudflare returns `"part one" "part two"` (quoted, with \" escapes); Google returns the
 * concatenated text unquoted. Character-strings are concatenated without separator (RFC 7208 §3.3).
 */
export function unquoteTxt(data: string): string {
  const s = data.trim()
  if (!s.startsWith('"')) return data
  let out = ''
  let i = 0
  while (i < s.length) {
    while (i < s.length && s[i] === ' ') i++
    if (i >= s.length) break
    if (s[i] !== '"') return data // not the quoted format after all
    i++
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\' && i + 1 < s.length) {
        // \DDD decimal escape or \X
        const m = /^\d{3}/.exec(s.slice(i + 1, i + 4))
        if (m) {
          out += String.fromCharCode(Number(m[0]))
          i += 4
        } else {
          out += s[i + 1]
          i += 2
        }
        continue
      }
      out += s[i]
      i++
    }
    i++ // closing quote
  }
  return out
}

interface RawAnswer {
  name?: unknown
  type?: unknown
  TTL?: unknown
  data?: unknown
}

/** Parse a DoH JSON body (Google/Cloudflare share the format). Throws on a malformed body. */
export function parseDohJson(json: unknown, qname: string, qtype: string, resolver: ResolverId): DnsResult {
  if (typeof json !== 'object' || json === null || typeof (json as { Status?: unknown }).Status !== 'number') {
    throw new Error('Malformed DoH response (no Status)')
  }
  const j = json as { Status: number; AD?: unknown; Answer?: unknown }
  const answers: DnsRecord[] = []
  if (Array.isArray(j.Answer)) {
    for (const a of j.Answer as RawAnswer[]) {
      if (typeof a !== 'object' || a === null || typeof a.type !== 'number' || typeof a.data !== 'string') continue
      const type = a.type
      answers.push({
        name: stripDot(String(a.name ?? '').toLowerCase()),
        type,
        typeName: rrName(type),
        ttl: typeof a.TTL === 'number' ? a.TTL : 0,
        data: type === RR.TXT ? unquoteTxt(a.data) : a.data,
      })
    }
  }
  const wanted = RR[qtype] ?? Number(qtype.replace(/^TYPE/, ''))
  return {
    name: qname,
    type: qtype,
    status: j.Status,
    statusText: RCODE[j.Status] ?? `RCODE ${j.Status}`,
    ad: j.AD === true,
    records: answers.filter((a) => a.type === wanted),
    cnames: wanted === RR.CNAME ? [] : answers.filter((a) => a.type === RR.CNAME).map((a) => stripDot(a.data.toLowerCase())),
    answers,
    resolver,
  }
}

export interface DohOptions {
  fetch?: FetchLike
  signal?: AbortSignal
  timeoutMs?: number
  /** Resolver order (default google, then cloudflare). */
  resolvers?: ResolverId[]
  backoffMs?: number
}

export async function resolveDns(name: string, type: string, opts: DohOptions = {}): Promise<DnsResult> {
  const order = opts.resolvers ?? ['google', 'cloudflare']
  let lastErr: unknown
  for (const id of order) {
    const r = RESOLVERS[id]
    try {
      const res = await fetchText(r.url(name, type), {
        source: r.label,
        fetch: opts.fetch,
        signal: opts.signal,
        headers: r.headers,
        timeoutMs: opts.timeoutMs ?? 8000,
        retries: 0,
        backoffMs: opts.backoffMs,
      })
      if (!res.ok) throw new SourceError(r.label, 'http', `${r.label} returned HTTP ${res.status}`, res.status)
      let json: unknown
      try {
        json = JSON.parse(res.text)
      } catch {
        throw new SourceError(r.label, 'parse', `${r.label} returned invalid JSON`)
      }
      return parseDohJson(json, name, type, id)
    } catch (e) {
      if (e instanceof SourceError && e.kind === 'aborted') throw e
      lastErr = e
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error('DNS resolution failed')
}

export type Resolve = (name: string, type: string) => Promise<DnsResult>

/** Memoising resolver for one scan: identical (name, type) queries share one request (SPF recursion, DKIM, subdomains). */
export function createResolver(opts: DohOptions = {}): Resolve & { queries: () => number } {
  const cache = new Map<string, Promise<DnsResult>>()
  const fn = (name: string, type: string) => {
    const key = `${name.toLowerCase()}|${type}`
    let p = cache.get(key)
    if (!p) {
      p = resolveDns(name, type, opts)
      // Do not cache failures: a retry (re-run of a check) should hit the network again.
      p.catch(() => cache.delete(key))
      cache.set(key, p)
    }
    return p
  }
  return Object.assign(fn, { queries: () => cache.size })
}

/** TXT strings of a name (empty on NXDOMAIN / NODATA). */
export async function txtRecords(resolve: Resolve, name: string): Promise<{ texts: string[]; result: DnsResult }> {
  const result = await resolve(name, 'TXT')
  return { texts: result.records.map((r) => r.data), result }
}

export function isNxdomain(r: DnsResult): boolean {
  return r.status === 3
}
