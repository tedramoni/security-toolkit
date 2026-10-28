/**
 * Turn whatever the user typed (domain, URL, IDN, IP) into a scan target.
 * The WHATWG URL parser does the heavy lifting: lower-casing, IDNA/punycode (UTS #46), IPv4 shorthand canonicalisation.
 */
import { checkHost } from './ssrf'

export interface ReconTarget {
  kind: 'domain' | 'ip'
  /** ASCII form (punycode for IDNs, no trailing dot; IPv6 without brackets). */
  host: string
  /** What the user typed for the host when it differs from `host` (e.g. the Unicode IDN). */
  display?: string
  /** Best-effort registrable domain (no Public Suffix List in the bundle — heuristic). Domains only. */
  registrable?: string
  ipVersion?: 4 | 6
}

export type TargetResult = { ok: true; target: ReconTarget } | { ok: false; error: string }

/**
 * Common multi-label public suffixes where the registrable domain has three labels. Not exhaustive (the full Public
 * Suffix List is ~200 KB); used only to pick the RDAP / DMARC organisational domain, with fallbacks.
 */
const SECOND_LEVEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'org.nz', 'net.nz', 'govt.nz', 'ac.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'co.kr', 'or.kr', 'go.kr', 'ac.kr',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.tw', 'org.tw', 'gov.tw', 'edu.tw',
  'com.hk', 'org.hk', 'gov.hk',
  'com.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
  'co.za', 'org.za', 'gov.za',
  'com.mx', 'org.mx', 'gob.mx',
  'com.ar', 'com.tr', 'gov.tr', 'com.pl', 'com.es', 'co.il', 'org.il', 'ac.il',
  'gouv.fr', 'asso.fr', 'nom.fr', 'com.fr', 'tm.fr',
  'co.at', 'or.at', 'gv.at',
  'com.ua', 'co.ua', 'com.ru', 'com.my', 'com.ph', 'com.vn', 'co.th', 'ac.th', 'co.id', 'or.id', 'ac.id',
])

export function guessRegistrable(host: string): string {
  const labels = host.split('.')
  if (labels.length <= 2) return host
  const last2 = labels.slice(-2).join('.')
  if (SECOND_LEVEL_SUFFIXES.has(last2)) return labels.slice(-3).join('.')
  return last2
}

/** Parent domains from the host up to (and including) the registrable guess: a.b.example.com → [a.b.example.com, b.example.com, example.com]. */
export function domainChain(host: string, stopAt: string = guessRegistrable(host)): string[] {
  const out: string[] = []
  let cur = host
  for (let i = 0; i < 10; i++) {
    out.push(cur)
    if (cur === stopAt || !cur.includes('.')) break
    cur = cur.slice(cur.indexOf('.') + 1)
  }
  return out
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/

export function isValidHostname(h: string): boolean {
  if (h.length < 1 || h.length > 253) return false
  const labels = h.split('.')
  if (labels.length < 2) return false
  if (!labels.every((l) => LABEL.test(l))) return false
  // TLDs are never all-numeric
  return !/^\d+$/.test(labels[labels.length - 1])
}

export function normalizeTarget(input: string): TargetResult {
  let s = input.trim()
  if (s === '') return { ok: false, error: 'Enter a domain (example.com), a URL or an IP address.' }
  if (s.length > 2048) return { ok: false, error: 'Input is too long.' }
  // "*.example.com" (copied from a certificate) → example.com
  s = s.replace(/^\*\./, '')
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s)
  if (hasScheme && !/^https?:\/\//i.test(s)) return { ok: false, error: 'Only http(s) URLs or bare domains are supported.' }
  // Bare IPv6 (not bracketed) cannot go through the URL parser as-is.
  if (!hasScheme && /^[0-9a-f:.]+$/i.test(s) && s.split(':').length > 2) s = `[${s}]`
  let url: URL
  try {
    url = new URL(hasScheme ? s : `http://${s}`)
  } catch {
    return { ok: false, error: 'Not a valid domain name or URL.' }
  }
  let host = url.hostname.replace(/\.$/, '')
  const check = checkHost(host)
  if (check.kind === 'ipv4' || check.kind === 'ipv6') {
    if (check.blocked) return { ok: false, error: `Not a public address: ${check.blocked}.` }
    host = host.replace(/^\[|\]$/g, '')
    return { ok: true, target: { kind: 'ip', host, ipVersion: check.kind === 'ipv4' ? 4 : 6 } }
  }
  if (!isValidHostname(host)) return { ok: false, error: `"${host}" is not a valid public host name.` }
  if (check.blocked) return { ok: false, error: `Not a public domain: ${check.blocked}.` }
  const typedHost = hostPart(s)
  const display = typedHost && typedHost.toLowerCase() !== host && /[^ -~]/.test(typedHost) ? typedHost : undefined
  return { ok: true, target: { kind: 'domain', host, display, registrable: guessRegistrable(host) } }
}

/** The host as typed (for showing the Unicode form of an IDN next to its punycode). */
function hostPart(s: string): string {
  let rest = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
  const cut = rest.search(/[/?#]/)
  if (cut !== -1) rest = rest.slice(0, cut)
  const at = rest.lastIndexOf('@')
  if (at !== -1) rest = rest.slice(at + 1)
  const colon = rest.lastIndexOf(':')
  if (colon !== -1 && !rest.includes(']')) rest = rest.slice(0, colon)
  return rest.replace(/\.$/, '')
}

/** Reverse-DNS name for PTR lookups. */
export function reverseName(ip: string): string | undefined {
  const v4 = ip.split('.')
  if (v4.length === 4 && v4.every((p) => /^\d{1,3}$/.test(p))) return `${v4.reverse().join('.')}.in-addr.arpa`
  if (!ip.includes(':')) return undefined
  // Expand IPv6 to 32 nibbles
  const [head, tail = ''] = ip.split('::')
  const h = head ? head.split(':') : []
  const t = tail ? tail.split(':') : []
  if (!ip.includes('::') && h.length !== 8) return undefined
  const groups = [...h, ...new Array<string>(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t]
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return undefined
  const nibbles = groups.map((g) => g.padStart(4, '0')).join('').toLowerCase().split('')
  return `${nibbles.reverse().join('.')}.ip6.arpa`
}
