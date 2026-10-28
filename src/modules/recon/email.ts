/**
 * Email authentication posture from public DNS: MX, SPF (RFC 7208), DMARC (RFC 7489), DKIM (RFC 6376) key probing,
 * MTA-STS (RFC 8461), SMTP TLS reporting (RFC 8460) and BIMI.
 *
 * All parsers are single-pass splits on ';' / whitespace (no backtracking regexes on record text).
 */
import { fromBase64 } from '../pki/bytes'
import { concat, derNull, derOid, derSeq, tlv } from '../pki/der'
import { OID } from '../pki/oids'
import { describeSpki } from '../pki/spki'
import type { Resolve } from './doh'
import type { MxRecord } from './dns'
import { isNullMx, parseMx, sortMx } from './dns'
import { mapPool } from './net'
import type { Finding } from './types'

const RFC7208 = 'https://www.rfc-editor.org/rfc/rfc7208'
const RFC7489 = 'https://www.rfc-editor.org/rfc/rfc7489'

/* ------------------------------------------------------------------ SPF */

export type SpfQualifier = '+' | '-' | '~' | '?'

export interface SpfTerm {
  raw: string
  kind: 'mechanism' | 'modifier'
  qualifier?: SpfQualifier
  /** Lower-cased mechanism / modifier name. */
  name: string
  /** Domain-spec / address (without the leading ':' or '='), if any. */
  value?: string
}

export interface ParsedSpf {
  terms: SpfTerm[]
  errors: string[]
  /** Qualifier of the `all` mechanism, if present. */
  all?: SpfQualifier
  redirect?: string
  includes: string[]
  /** Mechanisms / modifiers that cost a DNS lookup in this record (include, a, mx, ptr, exists, redirect). */
  lookupTerms: number
  usesPtr: boolean
  /** Terms after `all` are never evaluated. */
  termsAfterAll: number
}

const MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'])
const LOOKUP_MECHANISMS = new Set(['include', 'a', 'mx', 'ptr', 'exists'])

export function isSpfRecord(txt: string): boolean {
  const t = txt.trimStart().toLowerCase()
  return t === 'v=spf1' || t.startsWith('v=spf1 ')
}

export function parseSpf(record: string): ParsedSpf {
  const out: ParsedSpf = { terms: [], errors: [], includes: [], lookupTerms: 0, usesPtr: false, termsAfterAll: 0 }
  const tokens = record.trim().split(/\s+/)
  if (tokens[0]?.toLowerCase() !== 'v=spf1') {
    out.errors.push('Record does not start with "v=spf1".')
    return out
  }
  let seenAll = false
  for (const raw of tokens.slice(1)) {
    if (raw === '') continue
    if (seenAll) out.termsAfterAll++
    const eq = raw.indexOf('=')
    const colon = raw.indexOf(':')
    const slash = raw.indexOf('/')
    // A modifier is name=value where '=' comes before any ':' or '/'.
    if (eq > 0 && (colon === -1 || eq < colon) && (slash === -1 || eq < slash) && /^[A-Za-z][A-Za-z0-9._-]*$/.test(raw.slice(0, eq))) {
      const name = raw.slice(0, eq).toLowerCase()
      const value = raw.slice(eq + 1)
      if ((name === 'redirect' || name === 'exp') && out.terms.some((t) => t.kind === 'modifier' && t.name === name)) {
        out.errors.push(`Duplicate "${name}" modifier (permerror).`)
      }
      out.terms.push({ raw, kind: 'modifier', name, value })
      if (name === 'redirect' && out.redirect === undefined) out.redirect = value.toLowerCase()
      continue
    }
    let q: SpfQualifier | undefined
    let body = raw
    if ('+-~?'.includes(body[0])) {
      q = body[0] as SpfQualifier
      body = body.slice(1)
    }
    const sep = body.search(/[:/]/)
    const name = (sep === -1 ? body : body.slice(0, sep)).toLowerCase()
    const value = sep === -1 ? undefined : body[sep] === ':' ? body.slice(sep + 1) : body.slice(sep)
    if (!MECHANISMS.has(name)) {
      out.errors.push(`Unknown mechanism "${raw}" (permerror).`)
      out.terms.push({ raw, kind: 'mechanism', qualifier: q ?? '+', name, value })
      continue
    }
    out.terms.push({ raw, kind: 'mechanism', qualifier: q ?? '+', name, value })
    // Mechanisms after "all" are never evaluated (RFC 7208 §5.1): they cost no lookup and are not expanded.
    if (!seenAll) {
      if (LOOKUP_MECHANISMS.has(name)) out.lookupTerms++
      if (name === 'ptr') out.usesPtr = true
      if (name === 'include' && value) out.includes.push(value.toLowerCase())
    }
    if (name === 'include' && !value) out.errors.push('"include" without a domain (permerror).')
    if ((name === 'ip4' || name === 'ip6' || name === 'exists') && !value) out.errors.push(`"${name}" requires a value (permerror).`)
    if (name === 'all') {
      if (value !== undefined) out.errors.push('"all" takes no argument.')
      if (!seenAll) out.all = q ?? '+'
      seenAll = true
    }
  }
  // "redirect" costs a lookup only when evaluated: it is ignored when the record has an "all" mechanism (RFC 7208 §6.1).
  if (out.redirect !== undefined && out.all === undefined) out.lookupTerms++
  return out
}

export interface SpfNode {
  domain: string
  /** How this domain was reached. */
  via: 'root' | 'include' | 'redirect'
  record?: string
  parsed?: ParsedSpf
  /** DNS-lookup terms in this record (include, a, mx, ptr, exists, redirect). */
  lookups: number
  children: SpfNode[]
  error?: string
  /** The TXT query found no SPF (void lookup when reached via include/redirect). */
  missing?: boolean
  loop?: boolean
  /** Not expanded because the depth / node cap was reached, or the domain contains macros. */
  notExpanded?: string
}

export interface SpfAnalysis {
  root: SpfNode
  /** Total DNS-lookup terms across the evaluated tree (limit 10, RFC 7208 §4.6.4). */
  totalLookups: number
  voidLookups: number
  loops: string[]
  capped: boolean
  records: string[]
}

export interface SpfOptions {
  maxDepth?: number
  maxNodes?: number
}

/**
 * Fetch the SPF record of `domain` and recursively expand include/redirect to count DNS lookups.
 * Loop detection uses the current include path; the node cap bounds total work on hostile records.
 */
export async function analyzeSpf(domain: string, resolve: Resolve, opts: SpfOptions = {}): Promise<SpfAnalysis> {
  const maxDepth = opts.maxDepth ?? 10
  const maxNodes = opts.maxNodes ?? 60
  let nodes = 0
  let total = 0
  let voids = 0
  let capped = false
  const loops: string[] = []
  let rootRecords: string[] = []

  const visit = async (d: string, via: SpfNode['via'], path: readonly string[]): Promise<SpfNode> => {
    nodes++
    const node: SpfNode = { domain: d, via, lookups: 0, children: [] }
    let texts: string[]
    let voidLookup = false
    try {
      const r = await resolve(d, 'TXT')
      texts = r.records.map((x) => x.data)
      // RFC 7208 §4.6.4: a void lookup is one that returns NXDOMAIN or no answer at all.
      voidLookup = r.status === 3 || (r.status === 0 && r.records.length === 0)
      if (r.status !== 0 && r.status !== 3) {
        node.error = `DNS error ${r.statusText} (temperror)`
        return node
      }
    } catch (e) {
      node.error = `Lookup failed: ${e instanceof Error ? e.message : String(e)}`
      return node
    }
    const spf = texts.filter(isSpfRecord)
    if (via === 'root') rootRecords = spf
    if (spf.length === 0) {
      node.missing = true
      if (via !== 'root') {
        if (voidLookup) voids++
        node.error = `No SPF record at ${d} (permerror for ${via})`
      }
      return node
    }
    if (spf.length > 1) {
      node.error = `${spf.length} SPF records (permerror: exactly one is allowed)`
    }
    node.record = spf[0]
    const parsed = parseSpf(spf[0])
    node.parsed = parsed
    node.lookups = parsed.lookupTerms
    total += parsed.lookupTerms
    const targets: { domain: string; via: 'include' | 'redirect' }[] = parsed.includes.map((x) => ({ domain: x, via: 'include' }))
    // redirect is ignored when an "all" mechanism is present (RFC 7208 §6.1)
    if (parsed.redirect && parsed.all === undefined) targets.push({ domain: parsed.redirect, via: 'redirect' })
    for (const t of targets) {
      if (t.domain.includes('%')) {
        node.children.push({ domain: t.domain, via: t.via, lookups: 0, children: [], notExpanded: 'contains SPF macros (expanded per message)' })
        continue
      }
      if (path.includes(t.domain) || t.domain === d) {
        loops.push([...path, d, t.domain].join(' → '))
        node.children.push({ domain: t.domain, via: t.via, lookups: 0, children: [], loop: true, error: 'Include loop (permerror)' })
        continue
      }
      if (path.length + 1 >= maxDepth || nodes >= maxNodes) {
        capped = true
        node.children.push({ domain: t.domain, via: t.via, lookups: 0, children: [], notExpanded: 'recursion cap reached' })
        continue
      }
      node.children.push(await visit(t.domain, t.via, [...path, d]))
    }
    return node
  }

  const root = await visit(domain.toLowerCase(), 'root', [])
  return { root, totalLookups: total, voidLookups: voids, loops, capped, records: rootRecords }
}

export function spfFindings(a: SpfAnalysis, hasMail: boolean): Finding[] {
  const f: Finding[] = []
  const n = a.records.length
  if (n === 0) {
    if (a.root.error) {
      f.push({ severity: 'info', title: 'SPF lookup failed', detail: a.root.error })
      return f
    }
    f.push(
      hasMail
        ? { severity: 'medium', title: 'No SPF record', detail: 'Receivers cannot tell which servers may send mail for this domain; spoofed mail is more likely to be delivered.', fix: 'Publish a TXT record such as "v=spf1 include:<your provider> -all".', ref: RFC7208 }
        : { severity: 'low', title: 'No SPF record on a domain without mail', detail: 'Domains that never send mail should say so, otherwise they can be spoofed.', fix: 'Publish "v=spf1 -all" (and a DMARC p=reject record).', ref: 'https://www.m3aawg.org/sites/default/files/m3aawg_parked_domains_bp-2015-12.pdf' },
    )
    return f
  }
  if (n > 1) {
    f.push({ severity: 'high', title: `${n} SPF records (permerror)`, detail: 'RFC 7208 §4.5: more than one "v=spf1" record makes SPF evaluation fail — receivers treat it as a permanent error.', fix: 'Merge them into a single record.', ref: `${RFC7208}#section-4.5` })
  }
  const p = a.root.parsed
  if (!p) return f
  for (const e of p.errors) f.push({ severity: 'medium', title: 'SPF syntax problem', detail: e, ref: RFC7208 })
  if (p.all === '+') {
    f.push({ severity: 'critical', title: 'SPF "+all": anyone may send as this domain', detail: 'The record authorises every IP address on the Internet.', fix: 'Replace "+all" with "-all" (or "~all" while rolling out).', ref: `${RFC7208}#section-5.1` })
  } else if (p.all === '?') {
    f.push({ severity: 'medium', title: 'SPF "?all" (neutral)', detail: 'Unlisted senders get a neutral result, which gives receivers no signal against spoofing.', fix: 'Use "-all" once all legitimate senders are listed.', ref: `${RFC7208}#section-2.6` })
  } else if (p.all === '~') {
    f.push({ severity: 'low', title: 'SPF "~all" (softfail)', detail: 'Unlisted senders are only marked suspicious. Acceptable with an enforcing DMARC policy; "-all" is stricter.', ref: `${RFC7208}#section-2.6` })
  } else if (p.all === '-') {
    f.push({ severity: 'pass', title: 'SPF ends with "-all"', detail: 'Mail from unlisted servers fails SPF.' })
  } else if (!p.redirect) {
    f.push({ severity: 'medium', title: 'SPF has no "all" mechanism', detail: 'Without "all" or "redirect", unmatched senders default to neutral.', fix: 'End the record with "-all".', ref: RFC7208 })
  }
  if (a.totalLookups > 10) {
    f.push({ severity: 'high', title: `SPF needs ${a.totalLookups} DNS lookups (limit 10)`, detail: 'RFC 7208 §4.6.4 caps include/a/mx/ptr/exists/redirect at 10 lookups; beyond that evaluation returns permerror and legitimate mail may fail SPF.', fix: 'Flatten includes, remove unused senders or move some senders to a subdomain.', ref: `${RFC7208}#section-4.6.4` })
  } else {
    f.push({ severity: a.totalLookups >= 9 ? 'low' : 'pass', title: `SPF uses ${a.totalLookups}/10 DNS lookups`, detail: a.totalLookups >= 9 ? 'Close to the limit: adding one more include will break SPF.' : 'Within the RFC 7208 lookup limit.' })
  }
  if (a.voidLookups > 2) {
    f.push({ severity: 'medium', title: `${a.voidLookups} void lookups`, detail: 'More than 2 lookups returning no data cause permerror (RFC 7208 §4.6.4).', ref: `${RFC7208}#section-4.6.4` })
  }
  for (const l of a.loops) f.push({ severity: 'high', title: 'SPF include loop', detail: l })
  const missingIncludes = collect(a.root, (x) => x !== a.root && x.missing === true).map((x) => x.domain)
  if (missingIncludes.length > 0) {
    f.push({ severity: 'high', title: 'SPF includes a domain without SPF', detail: `${missingIncludes.join(', ')}: evaluation returns permerror. If the included domain expired, an attacker could register it and authorise their own servers.`, ref: `${RFC7208}#section-5.2` })
  }
  if (p.usesPtr) f.push({ severity: 'low', title: 'SPF uses the deprecated "ptr" mechanism', detail: 'RFC 7208 §5.5: "ptr" is slow, unreliable and should not be used.', ref: `${RFC7208}#section-5.5` })
  if (p.termsAfterAll > 0) f.push({ severity: 'info', title: 'Terms after "all" are ignored', detail: `${p.termsAfterAll} term(s) follow "all" and are never evaluated.` })
  if (a.capped) f.push({ severity: 'info', title: 'SPF expansion capped', detail: 'The include tree is very deep or wide; counting stopped at the safety cap, so the real total is higher.' })
  return f
}

function collect(n: SpfNode, pred: (x: SpfNode) => boolean, out: SpfNode[] = []): SpfNode[] {
  if (pred(n)) out.push(n)
  for (const c of n.children) collect(c, pred, out)
  return out
}

/* ------------------------------------------------------------------ tag=value records (DMARC, DKIM, STS…) */

/** `k=v; k2=v2` → Map (lower-cased keys, first occurrence wins). */
export function parseTags(record: string): Map<string, string> {
  const m = new Map<string, string>()
  for (const part of record.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const k = part.slice(0, eq).trim().toLowerCase()
    if (k && !m.has(k)) m.set(k, part.slice(eq + 1).trim())
  }
  return m
}

/* ------------------------------------------------------------------ DMARC */

export interface DmarcRecord {
  raw: string
  valid: boolean
  errors: string[]
  p?: string
  sp?: string
  pct: number
  rua: string[]
  ruf: string[]
  adkim: 'r' | 's'
  aspf: 'r' | 's'
  fo?: string
  tags: Record<string, string>
}

export function parseDmarc(raw: string): DmarcRecord {
  const tags = parseTags(raw)
  const errors: string[] = []
  const first = raw.split(';')[0].trim().replace(/\s+/g, '')
  if (first !== 'v=DMARC1') errors.push('Record must start with "v=DMARC1".')
  const p = tags.get('p')?.toLowerCase()
  if (p === undefined) errors.push('Missing required "p" tag.')
  else if (!['none', 'quarantine', 'reject'].includes(p)) errors.push(`Invalid policy p=${p}.`)
  const sp = tags.get('sp')?.toLowerCase()
  if (sp !== undefined && !['none', 'quarantine', 'reject'].includes(sp)) errors.push(`Invalid subdomain policy sp=${sp}.`)
  const pctRaw = tags.get('pct')
  let pct = 100
  if (pctRaw !== undefined) {
    if (/^\d{1,3}$/.test(pctRaw) && Number(pctRaw) <= 100) pct = Number(pctRaw)
    else errors.push(`Invalid pct=${pctRaw}.`)
  }
  const uris = (v?: string) => (v ? v.split(',').map((x) => x.trim()).filter(Boolean) : [])
  const align = (v?: string): 'r' | 's' => (v?.toLowerCase() === 's' ? 's' : 'r')
  return {
    raw,
    valid: errors.length === 0,
    errors,
    p,
    sp,
    pct,
    rua: uris(tags.get('rua')),
    ruf: uris(tags.get('ruf')),
    adkim: align(tags.get('adkim')),
    aspf: align(tags.get('aspf')),
    fo: tags.get('fo'),
    tags: Object.fromEntries(tags),
  }
}

export function isDmarcRecord(txt: string): boolean {
  return /^v\s*=\s*DMARC1\s*(;|$)/i.test(txt.trimStart())
}

export function dmarcFindings(records: string[], from: string, fallback: boolean): Finding[] {
  const f: Finding[] = []
  const dm = records.filter(isDmarcRecord)
  if (dm.length === 0) {
    f.push({ severity: 'high', title: 'No DMARC record', detail: 'Without DMARC, receivers apply no policy to mail that fails SPF/DKIM alignment, so the domain can be spoofed in the From: header, and you get no reports.', fix: `Start with _dmarc.${from} TXT "v=DMARC1; p=none; rua=mailto:dmarc@${from}", then move to quarantine/reject.`, ref: RFC7489 })
    return f
  }
  if (dm.length > 1) {
    f.push({ severity: 'high', title: `${dm.length} DMARC records`, detail: 'RFC 7489 §6.6.3: with more than one record, receivers ignore DMARC entirely.', fix: 'Keep a single record.', ref: `${RFC7489}#section-6.6.3` })
    return f
  }
  const d = parseDmarc(dm[0])
  if (fallback) f.push({ severity: 'info', title: `DMARC inherited from ${from}`, detail: 'No record at the host itself; receivers use the organisational domain\'s policy (its sp= tag applies).' })
  for (const e of d.errors) f.push({ severity: 'high', title: 'Invalid DMARC record', detail: e, ref: RFC7489 })
  const policy = fallback ? (d.sp ?? d.p) : d.p
  if (policy === 'none') {
    f.push({ severity: 'medium', title: 'DMARC policy p=none (monitoring only)', detail: 'Spoofed mail is still delivered; the record only produces reports.', fix: 'Once reports show legitimate senders aligned, move to p=quarantine then p=reject.', ref: RFC7489 })
  } else if (policy === 'quarantine' || policy === 'reject') {
    f.push({ severity: 'pass', title: `DMARC enforced (p=${policy})`, detail: 'Unaligned mail is quarantined or rejected by receivers.' })
  }
  if (!fallback && d.sp === 'none' && (d.p === 'quarantine' || d.p === 'reject')) {
    f.push({ severity: 'medium', title: 'Subdomains not protected (sp=none)', detail: 'Attackers can spoof any subdomain (e.g. billing.example.com) even though the main domain is enforced.', fix: 'Remove sp=none or set sp=reject.' })
  }
  if (d.pct < 100 && policy !== 'none') {
    f.push({ severity: 'low', title: `DMARC applies to ${d.pct}% of mail`, detail: 'The policy is only applied to a sample of failing messages.', fix: 'Raise pct to 100.' })
  }
  if (d.rua.length === 0) {
    f.push({ severity: 'low', title: 'No DMARC aggregate reports (rua)', detail: 'You will not see who sends mail as your domain, nor detect spoofing or misconfigured senders.', fix: `Add rua=mailto:dmarc-reports@${from}.` })
  }
  return f
}

/* ------------------------------------------------------------------ DKIM */

export const DKIM_SELECTORS = [
  'default', 'dkim', 'mail', 'smtp', 'k1', 'k2', 'k3', 's1', 's2', 'selector1', 'selector2', 'google',
  'mandrill', 'mxvault', 'everlytickey1', 'everlytickey2', 'sig1', 'mailjet', 'zendesk1', 'zendesk2',
  'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3', 'key1', 'key2', 'dkim1', 'mx',
] as const

export interface DkimKey {
  selector: string
  raw: string
  keyType: string
  bits?: number
  revoked: boolean
  testing: boolean
  error?: string
}

/** Wrap a PKCS#1 RSAPublicKey in a SubjectPublicKeyInfo (some DNS providers publish the bare PKCS#1 form). */
function pkcs1ToSpki(pkcs1: Uint8Array): Uint8Array {
  return derSeq(derSeq(derOid(OID.rsaEncryption), derNull()), tlv(0x03, concat(new Uint8Array([0]), pkcs1)))
}

export function parseDkim(selector: string, raw: string): DkimKey {
  const tags = parseTags(raw)
  const keyType = (tags.get('k') ?? 'rsa').toLowerCase()
  const p = (tags.get('p') ?? '').replace(/\s+/g, '')
  const testing = (tags.get('t') ?? '').split(':').some((x) => x.trim().toLowerCase() === 'y')
  const key: DkimKey = { selector, raw, keyType, revoked: p === '', testing }
  if (!tags.has('p')) {
    key.error = 'No "p=" tag'
    return key
  }
  if (p === '') return key
  let der: Uint8Array
  try {
    der = fromBase64(p)
  } catch {
    key.error = 'Public key is not valid base64'
    return key
  }
  if (keyType === 'ed25519') {
    if (der.length === 32) key.bits = 256
    else key.error = `Ed25519 key must be 32 bytes, got ${der.length}`
    return key
  }
  for (const candidate of [der, pkcs1ToSpki(der)]) {
    try {
      const info = describeSpki(candidate)
      if (info.bits !== undefined) {
        key.bits = info.bits
        if (info.type !== 'RSA' && keyType === 'rsa') key.keyType = info.type
        return key
      }
    } catch {
      /* try next form */
    }
  }
  key.error = 'Could not decode the public key'
  return key
}

export function isDkimRecord(txt: string): boolean {
  const t = parseTags(txt)
  return t.get('v')?.toUpperCase() === 'DKIM1' || t.has('p')
}

export function dkimFindings(keys: DkimKey[], probed: number, hasMail: boolean): Finding[] {
  const f: Finding[] = []
  if (keys.length === 0) {
    if (hasMail) {
      f.push({ severity: 'info', title: 'No DKIM key found on common selectors', detail: `${probed} usual selectors were probed. DKIM selectors cannot be listed via DNS, so this does not prove DKIM is absent — check a received email's DKIM-Signature "s=" tag.` })
    }
    return f
  }
  for (const k of keys) {
    const name = `DKIM ${k.selector}`
    if (k.revoked) {
      f.push({ severity: 'info', title: `${name}: revoked key`, detail: 'Empty p= tag: the key has been revoked (normal after a rotation).' })
      continue
    }
    if (k.error) {
      f.push({ severity: 'medium', title: `${name}: unparseable key`, detail: k.error })
      continue
    }
    if (k.keyType === 'rsa' && k.bits !== undefined) {
      if (k.bits < 1024) f.push({ severity: 'critical', title: `${name}: RSA ${k.bits}-bit key`, detail: 'Keys under 1024 bits can be factored; signatures can be forged. RFC 8301 requires at least 1024 bits and receivers ignore smaller keys.', fix: 'Rotate to a 2048-bit RSA key.', ref: 'https://www.rfc-editor.org/rfc/rfc8301' })
      else if (k.bits < 2048) f.push({ severity: 'medium', title: `${name}: RSA ${k.bits}-bit key`, detail: '1024-bit RSA is below current recommendations (NIST, RFC 8301 recommends 2048).', fix: 'Rotate to a 2048-bit key.', ref: 'https://www.rfc-editor.org/rfc/rfc8301' })
      else f.push({ severity: 'pass', title: `${name}: RSA ${k.bits}-bit key`, detail: 'Key size is adequate.' })
    } else {
      f.push({ severity: 'pass', title: `${name}: ${k.keyType}${k.bits ? ` ${k.bits}-bit` : ''} key`, detail: 'Modern key type.' })
    }
    if (k.testing) f.push({ severity: 'low', title: `${name}: testing mode (t=y)`, detail: 'Receivers may treat failures as non-fatal.' })
  }
  return f
}

/* ------------------------------------------------------------------ MTA-STS / TLS-RPT / BIMI */

export interface StsPolicy {
  version?: string
  mode?: string
  mx: string[]
  maxAge?: number
  errors: string[]
}

/** RFC 8461 §3.2 policy file: "key: value" lines. */
export function parseStsPolicy(text: string): StsPolicy {
  const out: StsPolicy = { mx: [], errors: [] }
  for (const line of text.slice(0, 65536).split(/\r?\n/)) {
    const i = line.indexOf(':')
    if (i === -1) continue
    const k = line.slice(0, i).trim().toLowerCase()
    const v = line.slice(i + 1).trim()
    if (k === 'version') out.version = v
    else if (k === 'mode') out.mode = v.toLowerCase()
    else if (k === 'mx') out.mx.push(v.toLowerCase())
    else if (k === 'max_age') out.maxAge = /^\d{1,10}$/.test(v) ? Number(v) : undefined
  }
  if (out.version !== 'STSv1') out.errors.push('version must be STSv1')
  if (!out.mode || !['enforce', 'testing', 'none'].includes(out.mode)) out.errors.push('mode must be enforce, testing or none')
  if (out.maxAge === undefined) out.errors.push('max_age missing or invalid')
  if (out.mode !== 'none' && out.mx.length === 0) out.errors.push('no mx patterns')
  return out
}

/** Does an MTA-STS mx pattern (exact or "*.example.net") cover a host? */
export function stsMxMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase()
  const h = host.toLowerCase()
  if (p.startsWith('*.')) {
    const suffix = p.slice(1)
    return h.endsWith(suffix) && !h.slice(0, -suffix.length).includes('.') && h.length > suffix.length
  }
  return p === h
}

/* ------------------------------------------------------------------ check orchestration */

export interface EmailCheckData {
  mx: MxRecord[]
  nullMx: boolean
  spf?: SpfAnalysis
  dmarc?: { name: string; records: string[]; fallback: boolean; parsed?: DmarcRecord }
  dkim: DkimKey[]
  dkimProbed: string[]
  mtaSts?: { record?: string; id?: string; policy?: StsPolicy; policyError?: string }
  tlsRpt?: { record?: string; rua: string[] }
  bimi?: { record?: string; logo?: string; vmc?: string }
  errors: string[]
}

export interface EmailOptions {
  /** Fetch the MTA-STS policy file (needs the CORS proxy). */
  fetchStsPolicy?: (url: string) => Promise<string>
  signal?: AbortSignal
}

export async function runEmailCheck(host: string, orgDomain: string, resolve: Resolve, opts: EmailOptions = {}): Promise<{ data: EmailCheckData; findings: Finding[] }> {
  const errors: string[] = []
  const safeTxt = async (name: string): Promise<string[] | undefined> => {
    try {
      const r = await resolve(name, 'TXT')
      if (r.status !== 0 && r.status !== 3) {
        errors.push(`${name}: ${r.statusText}`)
        return undefined
      }
      return r.records.map((x) => x.data)
    } catch (e) {
      errors.push(`${name}: ${e instanceof Error ? e.message : String(e)}`)
      return undefined
    }
  }

  const [mxRes, spf, dmarcHost, mtaTxt, tlsTxt, bimiTxt] = await Promise.all([
    resolve(host, 'MX').catch((e: unknown) => {
      errors.push(`MX: ${e instanceof Error ? e.message : String(e)}`)
      return undefined
    }),
    analyzeSpf(host, resolve),
    safeTxt(`_dmarc.${host}`),
    safeTxt(`_mta-sts.${host}`),
    safeTxt(`_smtp._tls.${host}`),
    safeTxt(`default._bimi.${host}`),
  ])

  const mx = sortMx((mxRes?.records ?? []).map((r) => parseMx(r.data)).filter((x): x is MxRecord => x !== undefined))
  const nullMx = isNullMx(mx)
  const hasMail = mx.length > 0 && !nullMx

  // DMARC: host first, then the organisational domain (RFC 7489 §6.6.3).
  let dmarc: EmailCheckData['dmarc']
  if (dmarcHost !== undefined) {
    const own = dmarcHost.filter(isDmarcRecord)
    if (own.length === 0 && orgDomain !== host) {
      const org = await safeTxt(`_dmarc.${orgDomain}`)
      const orgRecs = (org ?? []).filter(isDmarcRecord)
      dmarc = orgRecs.length > 0 ? { name: `_dmarc.${orgDomain}`, records: orgRecs, fallback: true } : { name: `_dmarc.${host}`, records: [], fallback: false }
    } else {
      dmarc = { name: `_dmarc.${host}`, records: own, fallback: false }
    }
    if (dmarc.records.length === 1) dmarc.parsed = parseDmarc(dmarc.records[0])
  }

  // DKIM selector probing (bounded concurrency; the resolver dedupes).
  const dkim: DkimKey[] = []
  await mapPool(
    DKIM_SELECTORS,
    6,
    async (sel) => {
      try {
        const r = await resolve(`${sel}._domainkey.${host}`, 'TXT')
        const rec = r.records.map((x) => x.data).find(isDkimRecord)
        if (rec) dkim.push(parseDkim(sel, rec))
      } catch {
        /* individual selector failures are not interesting */
      }
    },
    opts.signal,
  )
  dkim.sort((a, b) => a.selector.localeCompare(b.selector))

  // MTA-STS
  let mtaSts: EmailCheckData['mtaSts']
  const stsRec = mtaTxt?.find((t) => /^v=STSv1\b/i.test(t.trim()))
  if (mtaTxt !== undefined) {
    mtaSts = { record: stsRec, id: stsRec ? parseTags(stsRec).get('id') : undefined }
    if (stsRec && opts.fetchStsPolicy) {
      try {
        mtaSts.policy = parseStsPolicy(await opts.fetchStsPolicy(`https://mta-sts.${host}/.well-known/mta-sts.txt`))
      } catch (e) {
        mtaSts.policyError = e instanceof Error ? e.message : String(e)
      }
    }
  }
  const tlsRec = tlsTxt?.find((t) => /^v=TLSRPTv1\b/i.test(t.trim()))
  const tlsRpt = tlsTxt !== undefined ? { record: tlsRec, rua: tlsRec ? (parseTags(tlsRec).get('rua') ?? '').split(',').map((x) => x.trim()).filter(Boolean) : [] } : undefined
  const bimiRec = bimiTxt?.find((t) => /^v=BIMI1\b/i.test(t.trim()))
  const bimiTags = bimiRec ? parseTags(bimiRec) : undefined
  const bimi = bimiTxt !== undefined ? { record: bimiRec, logo: bimiTags?.get('l') || undefined, vmc: bimiTags?.get('a') || undefined } : undefined

  /* ---- findings ---- */
  const f: Finding[] = []
  if (mxRes) {
    if (nullMx) f.push({ severity: 'info', title: 'Null MX: domain accepts no email', detail: 'RFC 7505 "0 ." record. Make sure SPF is "v=spf1 -all" and DMARC p=reject so the domain cannot be spoofed either.', ref: 'https://www.rfc-editor.org/rfc/rfc7505' })
    else if (mx.length === 0) f.push({ severity: 'info', title: 'No MX record', detail: 'Mail falls back to the A/AAAA record (RFC 5321 §5.1). If the domain should not receive mail, publish a null MX ("0 .").' })
    else f.push({ severity: 'info', title: `${mx.length} MX record${mx.length > 1 ? 's' : ''}`, detail: mx.map((m) => `${m.priority} ${m.exchange}`).join(', ') })
  }
  if (nullMx && spf.root.parsed && spf.root.parsed.all !== '-') {
    f.push({ severity: 'medium', title: 'Null MX but SPF is not "-all"', detail: 'A domain that sends no mail should publish "v=spf1 -all".' })
  }
  f.push(...spfFindings(spf, hasMail || !nullMx))
  if (dmarc) f.push(...dmarcFindings(dmarc.records, dmarc.fallback ? orgDomain : host, dmarc.fallback))
  f.push(...dkimFindings(dkim, DKIM_SELECTORS.length, hasMail))

  if (hasMail) {
    if (mtaSts && !mtaSts.record) {
      f.push({ severity: 'low', title: 'No MTA-STS', detail: 'Sending servers may deliver mail to you over unencrypted or unauthenticated SMTP if an attacker strips STARTTLS.', fix: `Publish _mta-sts.${host} TXT "v=STSv1; id=<date>" and a policy at https://mta-sts.${host}/.well-known/mta-sts.txt`, ref: 'https://www.rfc-editor.org/rfc/rfc8461' })
    } else if (mtaSts?.policy) {
      const pol = mtaSts.policy
      for (const e of pol.errors) f.push({ severity: 'medium', title: 'Invalid MTA-STS policy', detail: e, ref: 'https://www.rfc-editor.org/rfc/rfc8461#section-3.2' })
      if (pol.mode === 'enforce') f.push({ severity: 'pass', title: 'MTA-STS enforced', detail: `Policy mode enforce, max_age ${pol.maxAge ?? '?'} s.` })
      else if (pol.mode) f.push({ severity: 'low', title: `MTA-STS mode ${pol.mode}`, detail: 'Senders report but still deliver over insecure connections.', fix: 'Switch to mode: enforce once TLS reports are clean.' })
      const uncovered = mx.filter((m) => !pol.mx.some((p) => stsMxMatches(p, m.exchange)))
      if (pol.mode && pol.mode !== 'none' && uncovered.length > 0) {
        f.push({ severity: 'high', title: 'MX hosts not covered by the MTA-STS policy', detail: `${uncovered.map((m) => m.exchange).join(', ')}: senders enforcing the policy will refuse to deliver to them.` })
      }
    } else if (mtaSts?.record && mtaSts.policyError) {
      f.push({ severity: 'info', title: 'MTA-STS record present; policy not checked', detail: mtaSts.policyError })
    } else if (mtaSts?.record) {
      f.push({ severity: 'info', title: 'MTA-STS record present', detail: 'Fetching the policy file needs the optional CORS proxy (see the Proxy tab).' })
    }
    if (tlsRpt && !tlsRpt.record) {
      f.push({ severity: 'info', title: 'No SMTP TLS reporting (TLS-RPT)', detail: 'You will not be told when senders fail to establish TLS with your MX.', fix: `_smtp._tls.${host} TXT "v=TLSRPTv1; rua=mailto:tls-reports@${host}"`, ref: 'https://www.rfc-editor.org/rfc/rfc8460' })
    }
  }
  if (bimi?.record) f.push({ severity: 'info', title: 'BIMI record present', detail: `Brand logo published${bimi.vmc ? ' with a Verified Mark Certificate' : ''}.` })
  if (errors.length > 0) f.push({ severity: 'info', title: 'Some DNS lookups failed', detail: errors.slice(0, 5).join('; ') })

  return { data: { mx, nullMx, spf, dmarc, dkim, dkimProbed: [...DKIM_SELECTORS], mtaSts, tlsRpt, bimi, errors }, findings: f }
}
