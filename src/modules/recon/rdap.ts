/**
 * RDAP (RFC 9083) — the structured successor of WHOIS — through the rdap.org bootstrap redirector.
 * rdap.org answers with a 302 to the authoritative registry (Verisign for .com/.net, PIR for .org, AFNIC for .fr,
 * Google Registry for .dev, ARIN/RIPE/APNIC/LACNIC/AFRINIC for IPs). Those servers send
 * Access-Control-Allow-Origin: * so the browser follows the redirect transparently.
 * Some ccTLDs (.io, .de, .ch, …) have no RDAP service in the IANA bootstrap: rdap.org returns 404 and we say so.
 */
import type { FetchLike } from './net'
import { SourceError, fetchText, safeHref } from './net'
import { domainChain } from './target'
import type { Finding } from './types'

const DAY = 86400000

/** EPP status codes (RFC 5731 / ICANN "EPP Status Codes: What do they mean"). */
export const STATUS_HELP: Record<string, string> = {
  ok: 'Standard status: no pending operation or restriction.',
  active: 'Domain is active (RDAP equivalent of EPP "ok").',
  inactive: 'No name servers delegated: the domain does not resolve.',
  clientTransferProhibited: 'Registrar lock: transfers to another registrar are refused (protects against domain hijacking).',
  clientUpdateProhibited: 'Registrar lock: changes (e.g. name servers) are refused unless the lock is removed.',
  clientDeleteProhibited: 'Registrar lock: the domain cannot be deleted.',
  clientRenewProhibited: 'The registrar blocks renewal — often a dispute or unpaid domain.',
  clientHold: 'Registrar hold: the domain is removed from DNS (typically unpaid, abuse or legal dispute).',
  serverTransferProhibited: 'Registry lock: transfers are refused at the registry level.',
  serverUpdateProhibited: 'Registry lock: updates are refused at the registry level (strongest anti-hijacking protection).',
  serverDeleteProhibited: 'Registry lock: the domain cannot be deleted.',
  serverRenewProhibited: 'The registry blocks renewal.',
  serverHold: 'Registry hold: the domain is removed from DNS.',
  pendingCreate: 'Registration is being processed.',
  pendingDelete: 'The domain is about to be deleted and released.',
  pendingRenew: 'A renewal is being processed.',
  pendingRestore: 'A restore from redemption is being processed.',
  pendingTransfer: 'A transfer to another registrar is in progress.',
  pendingUpdate: 'An update is being processed.',
  redemptionPeriod: 'Expired and deleted by the registrar: can only be restored (at a cost) before final release.',
  autoRenewPeriod: 'Grace period after automatic renewal by the registry.',
  addPeriod: 'Grace period right after registration.',
  renewPeriod: 'Grace period after an explicit renewal.',
  transferPeriod: 'Grace period after a transfer.',
  transferProhibited: 'Transfers are refused.',
  updateProhibited: 'Updates are refused.',
  deleteProhibited: 'Deletion is refused.',
  renewProhibited: 'Renewal is refused.',
  locked: 'Object is locked against changes.',
  associated: 'Object is in use by another object (e.g. a host used by a domain).',
  validated: 'Registrant data has been validated.',
  removed: 'Some data has been removed from the response.',
  obscured: 'Some data has been obscured (privacy).',
  private: 'Some data is private.',
  proxy: 'A privacy/proxy service is used.',
}

/** "client transfer prohibited" (RDAP) → "clientTransferProhibited" (EPP). */
export function normalizeStatus(s: string): string {
  const words = s.trim().split(/[\s_-]+/).filter(Boolean)
  if (words.length <= 1) return words[0] ?? s
  return words[0].toLowerCase() + words.slice(1).map((w) => w[0].toUpperCase() + w.slice(1).toLowerCase()).join('')
}

/* ---- jCard (RFC 7095) helpers ---- */

type Json = Record<string, unknown>

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : []
}

function asObj(v: unknown): Json | undefined {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Json) : undefined
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined
}

export function vcardProps(entity: Json | undefined, prop: string): unknown[][] {
  const vc = asArray(entity?.vcardArray)
  const props = asArray(vc[1])
  return props.filter((p): p is unknown[] => Array.isArray(p) && p[0] === prop)
}

export function vcardText(entity: Json | undefined, prop: string): string | undefined {
  for (const p of vcardProps(entity, prop)) {
    const v = p[3]
    if (typeof v === 'string' && v.trim()) return v.trim()
    if (Array.isArray(v)) {
      const joined = v.flat().filter((x) => typeof x === 'string' && x.trim()).join(' ')
      if (joined) return joined
    }
  }
  return undefined
}

function vcardCountry(entity: Json | undefined): string | undefined {
  for (const p of vcardProps(entity, 'adr')) {
    const params = asObj(p[1])
    const cc = str(params?.cc)
    if (cc) return cc.toUpperCase()
    const v = p[3]
    if (Array.isArray(v) && typeof v[6] === 'string' && v[6].trim()) return v[6].trim()
  }
  return undefined
}

function roles(e: Json): string[] {
  return asArray(e.roles).filter((r): r is string => typeof r === 'string').map((r) => r.toLowerCase())
}

/** Depth-first walk over nested entities (bounded). */
function allEntities(root: Json, max = 50): Json[] {
  const out: Json[] = []
  const stack: Json[] = asArray(root.entities).map(asObj).filter((x): x is Json => !!x)
  while (stack.length > 0 && out.length < max) {
    const e = stack.shift()!
    out.push(e)
    for (const c of asArray(e.entities)) {
      const o = asObj(c)
      if (o) stack.push(o)
    }
  }
  return out
}

function eventDate(root: Json, action: string): string | undefined {
  for (const ev of asArray(root.events)) {
    const o = asObj(ev)
    if (o && typeof o.eventAction === 'string' && o.eventAction.toLowerCase() === action) return str(o.eventDate)
  }
  return undefined
}

function abuseContact(root: Json): { email?: string; phone?: string } | undefined {
  for (const e of allEntities(root)) {
    if (!roles(e).includes('abuse')) continue
    const email = vcardText(e, 'email')
    const tel = vcardText(e, 'tel')
    if (email || tel) return { email, phone: tel?.replace(/^tel:/i, '') }
  }
  return undefined
}

function selfLink(root: Json): string | undefined {
  for (const l of asArray(root.links)) {
    const o = asObj(l)
    if (o && o.rel === 'self') return safeHref(o.href)
  }
  return undefined
}

/* ---- domain ---- */

export interface RdapDomain {
  name: string
  unicodeName?: string
  handle?: string
  registrar?: { name: string; ianaId?: string; url?: string }
  abuse?: { email?: string; phone?: string }
  registration?: string
  expiration?: string
  lastChanged?: string
  status: { code: string; help?: string }[]
  nameservers: string[]
  delegationSigned?: boolean
  self?: string
}

export function parseRdapDomain(json: unknown): RdapDomain {
  const root = asObj(json)
  if (!root || root.objectClassName !== 'domain') throw new Error('Not an RDAP domain object')
  const registrarEnt = allEntities(root).find((e) => roles(e).includes('registrar'))
  let registrar: RdapDomain['registrar']
  if (registrarEnt) {
    const ianaId = asArray(registrarEnt.publicIds)
      .map(asObj)
      .find((p) => typeof p?.type === 'string' && /iana/i.test(p.type as string))?.identifier
    const name = vcardText(registrarEnt, 'fn') ?? vcardText(registrarEnt, 'org') ?? str(registrarEnt.handle) ?? 'unknown'
    registrar = { name, ianaId: typeof ianaId === 'string' || typeof ianaId === 'number' ? String(ianaId) : undefined, url: safeHref(vcardText(registrarEnt, 'url')) }
  }
  const status = asArray(root.status)
    .filter((s): s is string => typeof s === 'string')
    .map((s) => {
      const code = normalizeStatus(s)
      return { code, help: STATUS_HELP[code] }
    })
  const nameservers = asArray(root.nameservers)
    .map((n) => str(asObj(n)?.ldhName)?.toLowerCase())
    .filter((x): x is string => !!x)
  const secure = asObj(root.secureDNS)
  return {
    name: (str(root.ldhName) ?? '').toLowerCase(),
    unicodeName: str(root.unicodeName),
    handle: str(root.handle),
    registrar,
    abuse: abuseContact(root),
    registration: eventDate(root, 'registration'),
    expiration: eventDate(root, 'expiration'),
    lastChanged: eventDate(root, 'last changed'),
    status,
    nameservers,
    delegationSigned: typeof secure?.delegationSigned === 'boolean' ? secure.delegationSigned : undefined,
    self: selfLink(root),
  }
}

/** ccTLD registries often omit the registrar lock statuses entirely; only flag it for gTLD-style responses. */
export function rdapDomainFindings(d: RdapDomain, now: number): Finding[] {
  const f: Finding[] = []
  const codes = new Set(d.status.map((s) => s.code))
  if (d.expiration) {
    const exp = Date.parse(d.expiration)
    if (!Number.isNaN(exp)) {
      const days = Math.floor((exp - now) / DAY)
      if (days < 0) f.push({ severity: 'critical', title: 'Domain registration expired', detail: `Expired ${-days} day(s) ago (${d.expiration.slice(0, 10)}). Renew immediately before it is released and re-registered by someone else.` })
      else if (days < 30) f.push({ severity: 'high', title: `Domain expires in ${days} day${days === 1 ? '' : 's'}`, detail: `Expiration date ${d.expiration.slice(0, 10)}. An expired domain takes down web and mail, and can be re-registered by an attacker.`, fix: 'Renew now and enable auto-renewal.' })
      else if (days < 90) f.push({ severity: 'low', title: `Domain expires in ${days} days`, detail: `Expiration date ${d.expiration.slice(0, 10)}. Make sure auto-renewal is on.` })
      else f.push({ severity: 'pass', title: `Domain registered until ${d.expiration.slice(0, 10)}`, detail: `${days} days left.` })
    }
  }
  for (const c of ['clientHold', 'serverHold', 'redemptionPeriod', 'pendingDelete', 'inactive']) {
    if (codes.has(c)) f.push({ severity: 'high', title: `Domain status ${c}`, detail: STATUS_HELP[c] })
  }
  const gtldStyle = [...codes].some((c) => c.startsWith('client') || c.startsWith('server'))
  if (gtldStyle && !codes.has('clientTransferProhibited') && !codes.has('serverTransferProhibited')) {
    f.push({ severity: 'low', title: 'No transfer lock', detail: 'Neither clientTransferProhibited nor serverTransferProhibited is set: a compromised registrar account (or social engineering) can move the domain away more easily.', fix: 'Enable the registrar lock (and a registry lock for critical domains).' })
  } else if (codes.has('serverUpdateProhibited') && codes.has('serverTransferProhibited')) {
    f.push({ severity: 'pass', title: 'Registry lock in place', detail: 'serverUpdateProhibited + serverTransferProhibited: changes require an out-of-band procedure with the registry.' })
  } else if (codes.has('clientTransferProhibited')) {
    f.push({ severity: 'pass', title: 'Registrar transfer lock enabled', detail: STATUS_HELP.clientTransferProhibited })
  }
  return f
}

/* ---- IP network ---- */

export interface RdapIp {
  handle?: string
  name?: string
  type?: string
  startAddress?: string
  endAddress?: string
  cidrs: string[]
  country?: string
  org?: string
  asns: string[]
  abuse?: { email?: string; phone?: string }
  parentHandle?: string
  self?: string
}

export function parseRdapIp(json: unknown): RdapIp {
  const root = asObj(json)
  if (!root || root.objectClassName !== 'ip network') throw new Error('Not an RDAP ip network object')
  const cidrs = asArray(root.cidr0_cidrs)
    .map(asObj)
    .map((c) => {
      const prefix = str(c?.v4prefix) ?? str(c?.v6prefix)
      return prefix && typeof c?.length === 'number' ? `${prefix}/${c.length}` : undefined
    })
    .filter((x): x is string => !!x)
  const ents = allEntities(root)
  const registrants = ents.filter((e) => roles(e).includes('registrant'))
  // RIPE lists maintainer objects as registrants too: prefer the organisation entity.
  const registrant = registrants.find((e) => vcardText(e, 'kind') === 'org') ?? registrants.find((e) => vcardText(e, 'org') !== undefined) ?? registrants[0]
  const asns = asArray(root.arin_originas0_originautnums).map((x) => (typeof x === 'number' || typeof x === 'string' ? `AS${String(x).replace(/^AS/i, '')}` : undefined)).filter((x): x is string => !!x)
  return {
    handle: str(root.handle),
    name: str(root.name),
    type: str(root.type),
    startAddress: str(root.startAddress),
    endAddress: str(root.endAddress),
    cidrs,
    country: str(root.country) ?? vcardCountry(registrant),
    org: registrant ? (vcardText(registrant, 'fn') ?? vcardText(registrant, 'org')) : undefined,
    asns,
    abuse: abuseContact(root),
    parentHandle: str(root.parentHandle),
    self: selfLink(root),
  }
}

/* ---- fetching ---- */

export interface RdapOptions {
  fetch?: FetchLike
  signal?: AbortSignal
  timeoutMs?: number
  backoffMs?: number
  base?: string
}

export type RdapDomainResult =
  | { kind: 'ok'; domain: RdapDomain; queried: string; server: string; raw: unknown }
  | { kind: 'unavailable'; queried: string[]; reason: string }

function serverOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return 'rdap.org'
  }
}

/** Query the registrable domain first, then parents/children from the chain, until one RDAP answer is found. */
export async function fetchRdapDomain(host: string, registrable: string, opts: RdapOptions = {}): Promise<RdapDomainResult> {
  const base = opts.base ?? 'https://rdap.org'
  const chain = domainChain(host, registrable)
  const candidates = [registrable, ...chain.filter((c) => c !== registrable).reverse()]
  const tried: string[] = []
  let lastStatus = 0
  for (const c of candidates) {
    tried.push(c)
    const res = await fetchText(`${base}/domain/${encodeURIComponent(c)}`, { source: 'RDAP', fetch: opts.fetch, signal: opts.signal, timeoutMs: opts.timeoutMs ?? 15000, retries: 1, backoffMs: opts.backoffMs, headers: { accept: 'application/rdap+json, application/json' } })
    lastStatus = res.status
    if (res.status === 404) {
      // rdap.org's own 404 ("No RDAP service is available") means the TLD has no RDAP at all: stop.
      if (serverOf(res.url || base) === serverOf(base) && /no rdap service/i.test(res.text)) {
        return { kind: 'unavailable', queried: tried, reason: 'This TLD publishes no RDAP service in the IANA bootstrap registry (common for some ccTLDs such as .io, .de, .ch). Use the registry\'s WHOIS instead.' }
      }
      continue
    }
    if (!res.ok) throw new SourceError('RDAP', 'http', `RDAP server ${serverOf(res.url || base)} returned HTTP ${res.status}`, res.status)
    let json: unknown
    try {
      json = JSON.parse(res.text)
    } catch {
      throw new SourceError('RDAP', 'parse', 'RDAP server returned invalid JSON')
    }
    return { kind: 'ok', domain: parseRdapDomain(json), queried: c, server: serverOf(res.url || base), raw: json }
  }
  return { kind: 'unavailable', queried: tried, reason: `The registry has no record for ${tried.join(', ')} (HTTP ${lastStatus}).` }
}

export async function fetchRdapIp(ip: string, opts: RdapOptions = {}): Promise<{ ip: RdapIp; server: string; raw: unknown }> {
  const base = opts.base ?? 'https://rdap.org'
  const res = await fetchText(`${base}/ip/${encodeURIComponent(ip)}`, { source: 'RDAP', fetch: opts.fetch, signal: opts.signal, timeoutMs: opts.timeoutMs ?? 15000, retries: 1, backoffMs: opts.backoffMs, headers: { accept: 'application/rdap+json, application/json' } })
  if (!res.ok) throw new SourceError('RDAP', 'http', `RDAP (${serverOf(res.url || base)}) returned HTTP ${res.status}`, res.status)
  let json: unknown
  try {
    json = JSON.parse(res.text)
  } catch {
    throw new SourceError('RDAP', 'parse', 'RDAP server returned invalid JSON')
  }
  return { ip: parseRdapIp(json), server: serverOf(res.url || base), raw: json }
}
