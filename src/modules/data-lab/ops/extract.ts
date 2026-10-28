/*
 * IOC extractors. Every regex here is linear-time: bounded quantifiers, no nested quantifiers over overlapping
 * classes, and anchored starts via fixed-width lookbehinds. See extract.test.ts for the timing regression tests.
 */
import { argBool, argStr } from '../engine/bytes'
import type { ArgValues, OpDef } from '../engine/types'
import { sel, textFn } from './helpers'

const C = 'Extractors' as const

export const URL_RE = /\b(?:https?|ftp|wss?|file):\/\/[^\s<>"'`{}|\\^]{1,2048}/gi
export const EMAIL_RE = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}/g
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
export const IPV4_RE = new RegExp(`(?<![\\d.])(?:${OCTET}\\.){3}${OCTET}(?!\\.?\\d)`, 'g')
export const DOMAIN_RE = /(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,10}[A-Za-z][A-Za-z0-9-]{0,22}[A-Za-z](?![A-Za-z0-9-]|\.[A-Za-z0-9])/g
const WIN_PATH_RE = /(?<![A-Za-z0-9])(?:[A-Za-z]:\\|\\\\[A-Za-z0-9._$-]{1,255}\\)(?:[^\\/:*?"<>|\s]{1,255}\\){0,64}[^\\/:*?"<>|\s]{0,255}/g
const UNIX_PATH_RE = /(?<![A-Za-z0-9_.~:/-])(?:~|\.{1,2})?\/(?:[A-Za-z0-9._@+-]{1,255}\/){0,64}[A-Za-z0-9._@+-]{1,255}/g
const TOKEN_RE = /[A-Za-z0-9]+/g
const HEXRUN_RE = /[0-9A-Fa-f:.]+/g

function trimUrl(u: string): string {
  // Drop trailing punctuation that is more likely sentence than URL; keep balanced closing parens.
  let end = u.length
  while (end > 0 && '.,;:!?\'")]}>'.includes(u[end - 1])) {
    if (u[end - 1] === ')' && countChar(u.slice(0, end), '(') >= countChar(u.slice(0, end), ')')) break
    end--
  }
  return u.slice(0, end)
}

function countChar(s: string, c: string): number {
  let n = 0
  for (let i = 0; i < s.length; i++) if (s[i] === c) n++
  return n
}

export function extractUrls(text: string): string[] {
  return Array.from(text.matchAll(URL_RE), (m) => trimUrl(m[0])).filter((u) => /:\/\/./.test(u))
}

export function extractEmails(text: string): string[] {
  return Array.from(text.matchAll(EMAIL_RE), (m) => m[0].replace(/\.+$/, '')).filter((e) => {
    const tld = e.slice(e.lastIndexOf('.') + 1)
    return /^[A-Za-z]{2,}$/.test(tld) && !e.startsWith('.')
  })
}

export function extractIPv4(text: string): string[] {
  return Array.from(text.matchAll(IPV4_RE), (m) => m[0])
}

const IPV4_FULL_RE = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`)
const HEX_GROUP_RE = /^[0-9A-Fa-f]{1,4}$/

/** Strict IPv6 text validation (RFC 4291 §2.2), including embedded IPv4 and '::' compression. */
export function isIPv6(s: string): boolean {
  if (s.length < 2 || s.length > 45) return false
  let body = s
  let extra = 0
  const lastColon = s.lastIndexOf(':')
  if (lastColon < 0) return false
  const tail = s.slice(lastColon + 1)
  if (tail.includes('.')) {
    if (!IPV4_FULL_RE.test(tail)) return false
    body = s.slice(0, lastColon + 1)
    if (!body.endsWith('::')) body = body.slice(0, -1)
    extra = 2
  }
  const dbl = body.indexOf('::')
  if (dbl !== body.lastIndexOf('::')) return false
  if (dbl >= 0) {
    const l = body.slice(0, dbl)
    const r = body.slice(dbl + 2)
    const groups = [...(l ? l.split(':') : []), ...(r ? r.split(':') : [])]
    return groups.every((g) => HEX_GROUP_RE.test(g)) && groups.length + extra <= 7
  }
  const groups = body.split(':')
  return groups.every((g) => HEX_GROUP_RE.test(g)) && groups.length + extra === 8
}

export function extractIPv6(text: string): string[] {
  const out: string[] = []
  for (const m of text.matchAll(HEXRUN_RE)) {
    let cand = m[0]
    const prev = m.index > 0 ? text[m.index - 1] : ''
    if (/[A-Za-z0-9_]/.test(prev)) continue
    if (!cand.includes(':')) continue
    cand = cand.replace(/\.+$/, '')
    if (cand.endsWith(':') && !cand.endsWith('::')) cand = cand.slice(0, -1)
    if (isIPv6(cand)) out.push(cand)
  }
  return out
}

export function extractDomains(text: string): string[] {
  return Array.from(text.matchAll(DOMAIN_RE), (m) => m[0])
}

export function extractPaths(text: string, kind: string): string[] {
  const out: string[] = []
  if (kind !== 'unix') out.push(...Array.from(text.matchAll(WIN_PATH_RE), (m) => m[0].replace(/[.,;:]+$/, '')))
  if (kind !== 'windows') out.push(...Array.from(text.matchAll(UNIX_PATH_RE), (m) => m[0].replace(/[.,;:]+$/, '')))
  return out
}

const HASH_TYPES: Record<number, string> = { 32: 'MD5/NTLM', 40: 'SHA-1', 56: 'SHA-224', 64: 'SHA-256', 96: 'SHA-384', 128: 'SHA-512' }

export function extractHashes(text: string, label: boolean): string[] {
  const out: string[] = []
  for (const m of text.matchAll(TOKEN_RE)) {
    const t = m[0]
    const type = HASH_TYPES[t.length]
    if (!type || !/^[0-9A-Fa-f]+$/.test(t)) continue
    // Skip all-digit or all-letter runs: real digests mix both with overwhelming probability.
    if (/^[0-9]+$/.test(t) || /^[A-Fa-f]+$/.test(t)) continue
    out.push(label ? `${type}\t${t}` : t)
  }
  return out
}

export function extractBitcoin(text: string): string[] {
  const out: string[] = []
  for (const m of text.matchAll(TOKEN_RE)) {
    const t = m[0]
    if (/^[13][1-9A-HJ-NP-Za-km-z]{25,33}$/.test(t)) out.push(t)
    else if (/^bc1[02-9ac-hj-np-z]{11,71}$/.test(t)) out.push(t)
  }
  return out
}

function finish(items: string[], a: ArgValues): string {
  let list = items
  if (argBool(a, 'unique')) list = [...new Set(list)]
  if (argBool(a, 'sort')) list = [...list].sort()
  const body = list.join('\n')
  return argBool(a, 'showCount') ? `Total found: ${list.length}\n\n${body}` : body
}

const listArgs = [
  { key: 'unique', label: 'Unique', type: 'boolean', default: true },
  { key: 'sort', label: 'Sort', type: 'boolean', default: false },
  { key: 'showCount', label: 'Show total', type: 'boolean', default: false },
] as const

function extractor(id: string, name: string, description: string, fn: (s: string, a: ArgValues) => string[], extra: OpDef['args'] = []): OpDef {
  return { id, name, category: C, description, args: [...extra, ...listArgs], run: textFn((s, a) => finish(fn(s, a), a)) }
}

/* ---------- defang / refang ---------- */

const IOC_RE = new RegExp(`${URL_RE.source}|${EMAIL_RE.source}|${IPV4_RE.source}|${DOMAIN_RE.source}`, 'gi')

export interface DefangOptions {
  dots: boolean
  scheme: boolean
  separator: boolean
  at: boolean
}

export function defang(text: string, o: DefangOptions): string {
  return text.replace(IOC_RE, (m) => {
    let s = m
    if (o.scheme) s = s.replace(/^http/i, (h) => (h[0] === 'H' ? 'HXXP' : 'hxxp')).replace(/^ftp/i, 'fxp')
    if (o.separator) s = s.replace('://', '[://]')
    if (o.at) s = s.replace(/@/g, '[@]')
    if (o.dots) {
      // In URLs only the host part is defanged; the path keeps its dots.
      const sep = s.indexOf('://')
      if (sep >= 0) {
        const hostStart = s.indexOf('/', sep + 3) === -1 ? s.length : s.indexOf('/', sep + 3)
        s = s.slice(0, sep + 3) + s.slice(sep + 3, hostStart).replace(/\./g, '[.]') + s.slice(hostStart)
      } else s = s.replace(/\./g, '[.]')
    }
    return s
  })
}

export function refang(text: string): string {
  return text
    .replace(/\bhxxp(s?)(?![A-Za-z0-9])/gi, (_m, s: string) => `http${s}`)
    .replace(/\bfxp(?=\[?:)/gi, 'ftp')
    .replace(/\[:\/\/\]|\[:\]\/\/|\(:\/\/\)/g, '://')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}/gi, '.')
    .replace(/\[@\]|\(@\)|\[at\]|\(at\)/gi, '@')
    .replace(/\[:\]/g, ':')
}

export const extractOps: OpDef[] = [
  extractor('extract-urls', 'Extract URLs', 'Find http(s), ftp, ws(s) and file URLs. Trailing sentence punctuation is dropped.', (s) => extractUrls(s)),
  extractor('extract-emails', 'Extract Email Addresses', 'Find email addresses (pragmatic pattern, not full RFC 5322).', (s) => extractEmails(s)),
  extractor('extract-ipv4', 'Extract IPv4 Addresses', 'Find dotted-quad IPv4 addresses (each octet 0–255, no leading-zero octets).', (s) => extractIPv4(s)),
  extractor('extract-ipv6', 'Extract IPv6 Addresses', 'Find IPv6 addresses, including :: compression and embedded IPv4 (validated per RFC 4291).', (s) => extractIPv6(s)),
  extractor(
    'extract-domains',
    'Extract Domains',
    'Find domain names (labels + alphabetic TLD). Note: file names like "report.pdf" also look like domains.',
    (s) => extractDomains(s),
  ),
  extractor(
    'extract-paths',
    'Extract File Paths',
    'Find Windows (C:\\…, \\\\server\\share\\…) and Unix (/…, ~/…, ./…) paths. Paths containing spaces are cut at the first space.',
    (s, a) => extractPaths(s, argStr(a, 'kind')),
    [sel('kind', 'Kind', 'both', [['both', 'Windows and Unix'], ['windows', 'Windows'], ['unix', 'Unix']])],
  ),
  extractor(
    'extract-hashes',
    'Extract Hashes',
    'Find hex digests by length: 32 (MD5/NTLM), 40 (SHA-1), 56 (SHA-224), 64 (SHA-256), 96 (SHA-384), 128 (SHA-512).',
    (s, a) => extractHashes(s, argBool(a, 'label')),
    [{ key: 'label', label: 'Label with likely algorithm', type: 'boolean', default: true }],
  ),
  extractor(
    'extract-bitcoin',
    'Extract Bitcoin Addresses',
    'Find Bitcoin-like addresses (legacy 1…/3… Base58 and bech32 bc1…). Checksums are not verified.',
    (s) => extractBitcoin(s),
  ),
  {
    id: 'defang',
    name: 'Defang IOCs',
    category: C,
    description: 'Make URLs, domains, IPs and emails non-clickable for reports: hxxp, example[.]com, 1[.]2[.]3[.]4.',
    args: [
      { key: 'dots', label: 'Dots → [.]', type: 'boolean', default: true },
      { key: 'scheme', label: 'http → hxxp', type: 'boolean', default: true },
      { key: 'separator', label: ':// → [://]', type: 'boolean', default: false },
      { key: 'at', label: '@ → [@]', type: 'boolean', default: false },
    ],
    run: textFn((s, a) => defang(s, { dots: argBool(a, 'dots'), scheme: argBool(a, 'scheme'), separator: argBool(a, 'separator'), at: argBool(a, 'at') })),
  },
  {
    id: 'refang',
    name: 'Refang IOCs',
    category: C,
    description: 'Undo common defanging: hxxp → http, [.] (.) [dot] → ., [://] → ://, [@] [at] → @.',
    args: [],
    run: textFn((s) => refang(s)),
  },
]
