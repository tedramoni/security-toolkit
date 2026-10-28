/**
 * Dashboard tiles: each check is split into several small tiles (e.g. DNS → records, DNSSEC, CAA, NS/SOA). The checks
 * produce one finding list each; these pure helpers route every finding to exactly one tile of its check (the first
 * tile is the catch-all, so nothing is ever dropped) and derive a compact tile status.
 */
import type { CheckId, CheckStatus, Finding } from './types'

export type TileId =
  | 'dns-records'
  | 'dns-dnssec'
  | 'dns-caa'
  | 'dns-ns'
  | 'email-spf'
  | 'email-dmarc'
  | 'email-dkim'
  | 'email-transport'
  | 'ct-hosts'
  | 'ct-certs'
  | 'rdap'
  | 'ip'
  | 'wayback'
  | 'web-headers'
  | 'web-https'
  | 'web-robots'
  | 'web-securitytxt'

/** Tiles of each check, catch-all first. */
export const CHECK_TILES: Record<CheckId, readonly TileId[]> = {
  dns: ['dns-records', 'dns-dnssec', 'dns-caa', 'dns-ns'],
  email: ['email-spf', 'email-dmarc', 'email-dkim', 'email-transport'],
  ct: ['ct-hosts', 'ct-certs'],
  rdap: ['rdap'],
  ip: ['ip'],
  wayback: ['wayback'],
  web: ['web-https', 'web-headers', 'web-robots', 'web-securitytxt'],
}

/** Ordered [tile, test] rules per check; titles are produced by this module's own checks. Linear regexes only. */
const RULES: Partial<Record<CheckId, readonly [TileId, RegExp][]>> = {
  dns: [
    ['dns-caa', /\bCAA\b/],
    ['dns-dnssec', /DNSSEC|\bDS record/],
    ['dns-ns', /name server|Wildcard DNS/i],
  ],
  email: [
    ['email-dkim', /^(No )?DKIM\b/],
    ['email-dmarc', /DMARC|\bsp=none|Subdomains not protected/],
    ['email-transport', /MTA-STS|TLS|BIMI|not covered by the MTA/],
  ],
  ct: [['ct-certs', /certificate.*expire|expire within|CA organisations|unexpired certificates/i]],
  web: [
    ['web-securitytxt', /security\.txt/i],
    ['web-robots', /robots\.txt|sitemap/i],
    ['web-headers', /^Headers:|cookie/i],
  ],
}

export function tileOf(check: CheckId, f: Pick<Finding, 'title'>): TileId {
  for (const [tile, re] of RULES[check] ?? []) if (re.test(f.title)) return tile
  return CHECK_TILES[check][0]
}

export function splitFindings(check: CheckId, findings: readonly Finding[]): Map<TileId, Finding[]> {
  const out = new Map<TileId, Finding[]>(CHECK_TILES[check].map((t) => [t, []]))
  for (const f of findings) out.get(tileOf(check, f))!.push(f)
  return out
}

export type TileStatus = 'loading' | 'ok' | 'warn' | 'fail' | 'info' | 'error' | 'needs-proxy' | 'skipped'

/** Compact status for a tile: the check's state, then the worst finding routed to the tile. */
export function tileStatus(check: CheckStatus, findings: readonly Pick<Finding, 'severity'>[]): TileStatus {
  if (check === 'idle' || check === 'running') return 'loading'
  if (check === 'error') return 'error'
  if (check === 'needs-proxy') return 'needs-proxy'
  if (check === 'skipped') return 'skipped'
  const sev = new Set(findings.map((f) => f.severity))
  if (sev.has('critical') || sev.has('high')) return 'fail'
  if (sev.has('medium') || sev.has('low')) return 'warn'
  if (sev.has('pass')) return 'ok'
  return 'info'
}

export const TILE_STATUS_LABEL: Record<TileStatus, { text: string; cls: string }> = {
  loading: { text: 'Loading…', cls: 'sev-info' },
  ok: { text: 'OK', cls: 'sev-ok' },
  warn: { text: 'Warning', cls: 'sev-medium' },
  fail: { text: 'Fail', cls: 'sev-high' },
  info: { text: 'Info', cls: 'sev-info' },
  error: { text: 'Error', cls: 'sev-critical' },
  'needs-proxy': { text: 'Needs proxy', cls: 'sev-low' },
  skipped: { text: 'N/A', cls: 'sev-info' },
}
