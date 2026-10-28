/**
 * Hostname verification against a certificate's identities, following RFC 9525 (which obsoletes RFC 6125) and
 * browser practice:
 *  - DNS-IDs (SAN dNSName) only; the subject CN is NOT used (Chrome/Firefox/Safari ignore it). We still report a
 *    CN-only match as informational.
 *  - Wildcard only as the complete left-most label ("*.example.com"), matching exactly one label; partial
 *    wildcards ("f*.example.com") are rejected (RFC 9525 §6.3, CA/B BR).
 *  - IP addresses match only SAN iPAddress entries (byte comparison), never DNS names.
 *  - Comparison is case-insensitive; a trailing dot is ignored; IDNs are compared as A-labels (punycode).
 */
import type { GeneralNameInfo } from './extensions'

export interface HostnameResult {
  match: boolean
  /** The SAN entry that matched. */
  matchedBy?: string
  /** Human explanation. */
  reason: string
  cnOnlyMatch?: boolean
}

/** Parse dotted-quad IPv4 (strict: 4 decimal octets, no leading zeros beyond "0"). */
export function parseIPv4(s: string): number[] | undefined {
  const parts = s.split('.')
  if (parts.length !== 4) return undefined
  const out: number[] = []
  for (const p of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return undefined
    const n = Number(p)
    if (n > 255) return undefined
    out.push(n)
  }
  return out
}

/** Parse IPv6 (with optional embedded IPv4 and "::") to 16 bytes. Zone IDs are not accepted. */
export function parseIPv6(input: string): number[] | undefined {
  let s = input
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  if (s.length > 45 || !/^[0-9a-fA-F:.]+$/.test(s)) return undefined
  const dbl = s.indexOf('::')
  if (dbl !== s.lastIndexOf('::')) return undefined
  const parsePart = (part: string): number[] | undefined => {
    if (part === '') return []
    const groups = part.split(':')
    const out: number[] = []
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i]
      if (i === groups.length - 1 && g.includes('.')) {
        const v4 = parseIPv4(g)
        if (!v4) return undefined
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3])
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return undefined
        out.push(parseInt(g, 16))
      }
    }
    return out
  }
  let words: number[]
  if (dbl >= 0) {
    const left = parsePart(s.slice(0, dbl))
    const right = parsePart(s.slice(dbl + 2))
    if (!left || !right || left.length + right.length > 7) return undefined
    words = [...left, ...new Array(8 - left.length - right.length).fill(0), ...right]
  } else {
    const all = parsePart(s)
    if (!all || all.length !== 8) return undefined
    words = all
  }
  return words.flatMap((w) => [w >> 8, w & 0xff])
}

export function parseIp(s: string): number[] | undefined {
  return parseIPv4(s) ?? (s.includes(':') ? parseIPv6(s) : undefined)
}

/** Lower-case, strip one trailing dot, convert IDN U-labels to A-labels. Returns undefined if not a valid hostname. */
export function normalizeHostname(input: string): string | undefined {
  let h = input.trim()
  if (h.endsWith('.')) h = h.slice(0, -1)
  if (h === '' || h.length > 253) return undefined
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(h)) {
    try {
      h = new URL(`http://${h}/`).hostname
    } catch {
      return undefined
    }
  }
  h = h.toLowerCase()
  if (!/^[a-z0-9_*-]{1,63}(\.[a-z0-9_-]{1,63}){0,126}$/.test(h)) return undefined
  return h
}

/** Does a presented DNS-ID (possibly with a wildcard) match a reference hostname? Both already normalized. */
export function dnsIdMatches(presented: string, host: string): { match: boolean; note?: string } {
  if (!presented.includes('*')) return { match: presented === host }
  const pl = presented.split('.')
  if (pl[0] !== '*') return { match: false, note: `partial or misplaced wildcard "${presented}" is not accepted` }
  if (pl.slice(1).some((l) => l.includes('*'))) return { match: false, note: `"${presented}" has more than one wildcard` }
  if (pl.length < 3) return { match: false, note: `"${presented}" wildcard covers a top-level domain and is rejected` }
  const hl = host.split('.')
  if (hl.length !== pl.length) return { match: false }
  if (hl[0] === '') return { match: false }
  for (let i = 1; i < pl.length; i++) if (pl[i] !== hl[i]) return { match: false }
  return { match: true }
}

export function matchHostname(hostname: string, sans: readonly GeneralNameInfo[], commonNames: readonly string[] = []): HostnameResult {
  const raw = hostname.trim()
  if (raw === '') return { match: false, reason: 'Enter a hostname or IP address.' }
  const ip = parseIp(raw.replace(/^\[|\]$/g, ''))
  if (ip) {
    for (const s of sans) {
      if (s.type !== 'IP') continue
      const sip = parseIp(s.value)
      if (sip && sip.length === ip.length && sip.every((v, i) => v === ip[i])) {
        return { match: true, matchedBy: `IP:${s.value}`, reason: `IP address matches SAN IP:${s.value}.` }
      }
    }
    return { match: false, reason: 'IP addresses only match SAN iPAddress entries — none matches.' }
  }
  const host = normalizeHostname(raw)
  if (!host || host.includes('*')) return { match: false, reason: `"${raw}" is not a valid hostname.` }
  const dns = sans.filter((s) => s.type === 'DNS')
  const notes: string[] = []
  for (const s of dns) {
    const p = normalizeHostname(s.value.replace(/^\*\./, 'x.'))
    if (!p) {
      notes.push(`ignored malformed SAN "${s.value}"`)
      continue
    }
    const presented = s.value.startsWith('*.') ? `*.${p.slice(2)}` : (normalizeHostname(s.value) ?? s.value.toLowerCase())
    const r = dnsIdMatches(presented, host)
    if (r.note) notes.push(r.note)
    if (r.match) {
      return { match: true, matchedBy: `DNS:${s.value}`, reason: `Matches SAN DNS:${s.value}${presented.startsWith('*.') ? ' (wildcard, one label)' : ''}.` }
    }
  }
  const cnMatch = commonNames.some((cn) => {
    const n = normalizeHostname(cn.replace(/^\*\./, 'x.'))
    if (!n) return false
    return dnsIdMatches(cn.startsWith('*.') ? `*.${n.slice(2)}` : n, host).match
  })
  const extra = notes.length ? ` Notes: ${notes.join('; ')}.` : ''
  if (dns.length === 0) {
    return {
      match: false,
      cnOnlyMatch: cnMatch,
      reason: cnMatch
        ? 'Only the subject CN matches. Browsers ignore the CN and require a SAN DNS entry, so this certificate is NOT valid for this name.'
        : `The certificate has no SAN DNS names.${extra}`,
    }
  }
  return { match: false, cnOnlyMatch: cnMatch, reason: `No SAN DNS name matches "${host}".${extra}` }
}
