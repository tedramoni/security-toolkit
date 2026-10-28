/** DNS records overview: record parsers (MX, SOA, CAA, DS) and the "DNS records" check. */
import type { DnsResult, Resolve } from './doh'
import { RESOLVERS } from './doh'
import type { Finding } from './types'
import { domainChain } from './target'

export interface MxRecord {
  priority: number
  exchange: string
}

export function parseMx(data: string): MxRecord | undefined {
  const m = /^\s*(\d{1,5})\s+(\S+)\s*$/.exec(data)
  if (!m) return undefined
  const ex = m[2].toLowerCase()
  return { priority: Number(m[1]), exchange: ex === '.' ? '.' : ex.replace(/\.$/, '') }
}

export function sortMx(records: readonly MxRecord[]): MxRecord[] {
  return [...records].sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange))
}

/** RFC 7505 null MX: a single "0 ." record — the domain accepts no mail. */
export function isNullMx(records: readonly MxRecord[]): boolean {
  return records.length === 1 && records[0].exchange === '.' && records[0].priority === 0
}

export interface SoaRecord {
  mname: string
  rname: string
  serial: number
  refresh: number
  retry: number
  expire: number
  minimum: number
}

export function parseSoa(data: string): SoaRecord | undefined {
  const p = data.trim().split(/\s+/)
  if (p.length !== 7 || !p.slice(2).every((x) => /^\d+$/.test(x))) return undefined
  const [serial, refresh, retry, expire, minimum] = p.slice(2).map(Number)
  return { mname: p[0].replace(/\.$/, ''), rname: p[1].replace(/\.$/, ''), serial, refresh, retry, expire, minimum }
}

export interface CaaRecord {
  flags: number
  critical: boolean
  tag: string
  value: string
}

/** RFC 8659 presentation format: `<flags> <tag> "<value>"` (value may be unquoted on some resolvers). */
export function parseCaa(data: string): CaaRecord | undefined {
  const m = /^\s*(\d{1,3})\s+([A-Za-z0-9]{1,15})\s+(.*)$/.exec(data)
  if (!m) return undefined
  const flags = Number(m[1])
  if (flags > 255) return undefined
  let value = m[3].trim()
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1).replace(/\\"/g, '"')
  return { flags, critical: (flags & 128) !== 0, tag: m[2].toLowerCase(), value }
}

/** CA domain of an issue/issuewild value: `letsencrypt.org; validationmethods=dns-01` → letsencrypt.org; `;` → '' (deny). */
export function caaIssuer(value: string): string {
  return value.split(';')[0].trim().toLowerCase()
}

export interface DsRecord {
  keyTag: number
  algorithm: number
  digestType: number
  digest: string
}

/** Split-based (the former `\s+([0-9A-Fa-f\s]+)$` regex backtracked quadratically on long runs of spaces). */
export function parseDs(data: string): DsRecord | undefined {
  const p = data.trim().split(/\s+/)
  if (p.length < 4 || !p.slice(0, 3).every((x) => /^\d{1,5}$/.test(x))) return undefined
  const digest = p.slice(3).join('')
  if (!/^[0-9A-Fa-f]+$/.test(digest)) return undefined
  return { keyTag: Number(p[0]), algorithm: Number(p[1]), digestType: Number(p[2]), digest: digest.toLowerCase() }
}

/** IANA DNSSEC algorithm numbers. */
export const DNSSEC_ALGS: Record<number, string> = {
  1: 'RSA/MD5 (deprecated)',
  3: 'DSA/SHA-1 (deprecated)',
  5: 'RSA/SHA-1',
  6: 'DSA-NSEC3-SHA1 (deprecated)',
  7: 'RSASHA1-NSEC3-SHA1',
  8: 'RSA/SHA-256',
  10: 'RSA/SHA-512',
  12: 'GOST R 34.10-2001 (deprecated)',
  13: 'ECDSA P-256/SHA-256',
  14: 'ECDSA P-384/SHA-384',
  15: 'Ed25519',
  16: 'Ed448',
}

/** TXT verification tokens reveal SaaS in use — useful passive recon (and phishing-pretext material for attackers). */
const TXT_SERVICES: readonly [RegExp, string][] = [
  [/^google-site-verification=/i, 'Google (Search Console / Workspace)'],
  [/^MS=/, 'Microsoft 365'],
  [/^facebook-domain-verification=/i, 'Meta / Facebook'],
  [/^apple-domain-verification=/i, 'Apple'],
  [/^atlassian-domain-verification=/i, 'Atlassian'],
  [/^docusign=/i, 'DocuSign'],
  [/^adobe-idp-site-verification=/i, 'Adobe'],
  [/^stripe-verification=/i, 'Stripe'],
  [/^zoom-domain-verification/i, 'Zoom'],
  [/^openai-domain-verification=/i, 'OpenAI'],
  [/^anthropic-domain-verification/i, 'Anthropic'],
  [/^slack-domain-verification=/i, 'Slack'],
  [/^dropbox-domain-verification=/i, 'Dropbox'],
  [/^hubspot-developer-verification=|^hubspot-domain-verification/i, 'HubSpot'],
  [/^globalsign-domain-verification=/i, 'GlobalSign'],
  [/^_?globalsign-smime-dv=/i, 'GlobalSign S/MIME'],
  [/^cisco-ci-domain-verification=/i, 'Cisco Webex'],
  [/^jamf-site-verification=/i, 'Jamf'],
  [/^krisp-domain-verification=/i, 'Krisp'],
  [/^TAILSCALE-/, 'Tailscale'],
  [/^miro-verification=/i, 'Miro'],
  [/^onetrust-domain-verification=/i, 'OneTrust'],
  [/^yandex-verification:/i, 'Yandex'],
  [/^have-i-been-pwned-verification=/i, 'Have I Been Pwned'],
  [/^brevo-code:|^Sendinblue-code:/i, 'Brevo (Sendinblue)'],
  [/^mailru-verification:/i, 'Mail.ru'],
  [/^teamviewer-sso-verification=/i, 'TeamViewer'],
  [/^canva-site-verification=/i, 'Canva'],
  [/^citrix-verification-code=/i, 'Citrix'],
  [/^webexdomainverification/i, 'Webex'],
  [/^github-verification|^_github-challenge/i, 'GitHub'],
]

export function txtServices(texts: readonly string[]): string[] {
  const found = new Set<string>()
  for (const t of texts) for (const [re, name] of TXT_SERVICES) if (re.test(t)) found.add(name)
  return [...found].sort()
}

export const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'DS', 'DNSKEY', 'HTTPS'] as const

export interface DnsCheckData {
  host: string
  resolvers: string[]
  results: Record<string, DnsResult | { error: string }>
  mx: MxRecord[]
  soa?: SoaRecord
  caa: CaaRecord[]
  /** Domain the effective CAA set was found at (RFC 8659 tree climbing), if not the host itself. */
  caaFrom?: string
  ds: DsRecord[]
  dnssec: 'validated' | 'unsigned' | 'ds-present-not-validated' | 'unknown'
  services: string[]
  wildcard?: boolean
}

function ok(r: DnsResult | { error: string } | undefined): r is DnsResult {
  return r !== undefined && !('error' in r)
}

export async function runDnsCheck(host: string, resolve: Resolve, randomLabel: string): Promise<{ data: DnsCheckData; findings: Finding[] }> {
  const results: Record<string, DnsResult | { error: string }> = {}
  await Promise.all(
    DNS_TYPES.map(async (t) => {
      try {
        results[t] = await resolve(host, t)
      } catch (e) {
        results[t] = { error: e instanceof Error ? e.message : String(e) }
      }
    }),
  )
  const errors = DNS_TYPES.filter((t) => !ok(results[t]))
  if (errors.length === DNS_TYPES.length) {
    throw new Error(`All DNS queries failed: ${(results.A as { error: string }).error}`)
  }

  const f: Finding[] = []
  const a = results.A
  if (ok(a) && a.status === 3) {
    f.push({ severity: 'high', title: 'Domain does not exist (NXDOMAIN)', detail: `${host} does not resolve. Check the spelling, or whether the domain expired.` })
  }
  const records = (t: string) => (ok(results[t]) ? (results[t] as DnsResult).records : [])

  const mx = sortMx(records('MX').map((r) => parseMx(r.data)).filter((x): x is MxRecord => x !== undefined))
  const soaRec = records('SOA')[0]
  const soa = soaRec ? parseSoa(soaRec.data) : undefined
  const ds = records('DS').map((r) => parseDs(r.data)).filter((x): x is DsRecord => x !== undefined)

  // CAA tree climbing: the relevant set is the first non-empty one walking up from the host.
  let caa = records('CAA').map((r) => parseCaa(r.data)).filter((x): x is CaaRecord => x !== undefined)
  let caaFrom: string | undefined
  if (caa.length === 0) {
    for (const parent of domainChain(host).slice(1)) {
      try {
        const r = await resolve(parent, 'CAA')
        const parsed = r.records.map((x) => parseCaa(x.data)).filter((x): x is CaaRecord => x !== undefined)
        if (parsed.length > 0) {
          caa = parsed
          caaFrom = parent
          break
        }
      } catch {
        break
      }
    }
  }

  // Wildcard detection: a random label that resolves means *.host exists (subdomain enumeration via DNS is noisy).
  let wildcard: boolean | undefined
  try {
    const w = await resolve(`${randomLabel}.${host}`, 'A')
    wildcard = w.status === 0 && w.records.length > 0
  } catch {
    wildcard = undefined
  }

  const hasAddr = records('A').length + records('AAAA').length > 0
  if (ok(a) && a.status === 0 && !hasAddr) {
    f.push({ severity: 'info', title: 'No A/AAAA records', detail: 'The name has no address records (it may only be used for mail or as a zone apex without a website).' })
  } else if (records('A').length > 0 && records('AAAA').length === 0) {
    f.push({ severity: 'info', title: 'No IPv6 (AAAA) records', detail: 'The host is reachable over IPv4 only.' })
  }

  const ns = records('NS')
  if (ok(results.NS) && ns.length === 1) {
    f.push({
      severity: 'medium',
      title: 'Single authoritative name server',
      detail: 'RFC 1034/2182 require at least two name servers, ideally on separate networks; one outage takes the whole domain down.',
      ref: 'https://www.rfc-editor.org/rfc/rfc2182#section-5',
    })
  }

  if (caa.length === 0) {
    f.push({
      severity: 'info',
      title: 'No CAA record',
      detail: 'Any public CA may issue certificates for this domain. A CAA record restricts issuance to the CAs you use.',
      fix: `${host}. CAA 0 issue "letsencrypt.org"  (list each CA you use; add an iodef for violation reports)`,
      ref: 'https://www.rfc-editor.org/rfc/rfc8659',
    })
  } else {
    const issuers = [...new Set(caa.filter((c) => c.tag === 'issue').map((c) => caaIssuer(c.value) || '(none — issuance forbidden)'))]
    f.push({
      severity: 'pass',
      title: `CAA restricts issuance${caaFrom ? ` (inherited from ${caaFrom})` : ''}`,
      detail: `Authorised CAs: ${issuers.join(', ') || 'see issuewild records'}.`,
    })
    const unknownCritical = caa.filter((c) => c.critical && !['issue', 'issuewild', 'iodef', 'issuemail', 'issuevmc', 'contactemail', 'contactphone'].includes(c.tag))
    if (unknownCritical.length > 0) {
      f.push({ severity: 'medium', title: 'Critical CAA property with an unknown tag', detail: `CAs must refuse issuance when they do not understand a critical tag: ${unknownCritical.map((c) => c.tag).join(', ')}.` })
    }
  }

  const ad = ok(a) ? a.ad : false
  let dnssec: DnsCheckData['dnssec'] = 'unknown'
  if (ok(a) || ok(results.DS)) {
    if (ad) dnssec = 'validated'
    else if (ds.length > 0) dnssec = 'ds-present-not-validated'
    else dnssec = 'unsigned'
  }
  if (dnssec === 'validated') {
    f.push({ severity: 'pass', title: 'DNSSEC validated', detail: 'The resolver authenticated the answers (AD flag set): the zone is signed with a valid chain of trust.' })
  } else if (dnssec === 'ds-present-not-validated') {
    f.push({
      severity: 'medium',
      title: 'DS record present but answers not validated',
      detail: 'The parent publishes a DS record, yet the resolver did not set the AD flag: the signatures may be broken or expired, which can make the domain unreachable for validating resolvers.',
      ref: 'https://dnsviz.net/',
    })
  } else if (dnssec === 'unsigned') {
    f.push({
      severity: 'low',
      title: 'DNSSEC not enabled',
      detail: 'Answers for this domain are not signed, so resolvers cannot detect spoofed or tampered records (cache poisoning, on-path attacks).',
      fix: 'Enable DNSSEC at your DNS provider and publish the DS record at your registrar.',
      ref: 'https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en',
    })
  }

  const services = txtServices(records('TXT').map((r) => r.data))
  if (services.length > 0) {
    f.push({
      severity: 'info',
      title: `TXT records reveal ${services.length} third-party service${services.length > 1 ? 's' : ''}`,
      detail: `${services.join(', ')}. Verification tokens are public by design, but they map your SaaS footprint for attackers (phishing pretexts). Remove tokens of services you no longer use.`,
    })
  }
  if (wildcard) {
    f.push({ severity: 'info', title: 'Wildcard DNS', detail: `Random names under ${host} resolve (*.${host} exists): any subdomain appears to exist.` })
  }

  const resolvers = [...new Set(Object.values(results).filter(ok).map((r) => RESOLVERS[r.resolver].label))]
  return { data: { host, resolvers, results, mx, soa, caa, caaFrom, ds, dnssec, services, wildcard }, findings: f }
}
