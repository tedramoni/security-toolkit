import { mdTable } from '../../lib/markdown.ts'
import type { OsvVuln } from './osv.ts'
import type { SeverityInfo, SeverityLevel } from './severity.ts'
import { SEVERITY_LEVELS, SEVERITY_RANK, deriveSeverity, fixedVersions, maxSeverity } from './severity.ts'
import type { Dependency } from './types.ts'
import { depKey } from './types.ts'

export interface Finding {
  dep: Dependency
  /** OSV ids of the records describing this issue (records that alias each other are merged). */
  ids: string[]
  /** Preferred id to display (GHSA first, then CVE-free ids in OSV order). */
  primaryId: string
  /** CVE / GHSA / other aliases not already in ids. */
  aliases: string[]
  summary: string
  severity: SeverityInfo
  fixed: string[]
  /** Set when the vulnerability details could not be downloaded. */
  detailsMissing?: boolean
}

export function osvUrl(id: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`
}

function preferId(ids: string[]): string {
  return ids.find((i) => i.startsWith('GHSA-')) ?? ids.find((i) => !i.startsWith('CVE-')) ?? ids[0]
}

/**
 * Group OSV records for one package that describe the same issue: OSV often returns both the
 * GitHub advisory (GHSA-…) and the ecosystem record (PYSEC-…, GO-…, RUSTSEC-…) for one CVE.
 */
function groupIds(ids: string[], vulns: Map<string, OsvVuln>): string[][] {
  const parent = new Map<string, string>()
  const find = (x: string): string => {
    let r = x
    while (parent.get(r) !== r) r = parent.get(r)!
    parent.set(x, r)
    return r
  }
  const union = (a: string, b: string) => parent.set(find(a), find(b))
  for (const id of ids) parent.set(id, id)
  const owner = new Map<string, string>() // alias -> first id claiming it
  for (const id of ids) {
    const v = vulns.get(id)
    for (const alias of [id, ...(v?.aliases ?? [])]) {
      if (parent.has(alias) && alias !== id) union(id, alias)
      const o = owner.get(alias)
      if (o) union(id, o)
      else owner.set(alias, id)
    }
  }
  const groups = new Map<string, string[]>()
  for (const id of ids) {
    const r = find(id)
    groups.set(r, [...(groups.get(r) ?? []), id])
  }
  return [...groups.values()]
}

/**
 * Severity of a group of records. Some databases (e.g. the Go vulnerability database) never
 * score their records; when the group is unscored, fall back to aliased GitHub advisories that
 * were fetched separately (see aliasesToEnrich).
 */
function groupSeverity(records: OsvVuln[], vulns: Map<string, OsvVuln>): SeverityInfo {
  const own = maxSeverity(records.map(deriveSeverity))
  if (own.level !== 'unknown') return own
  const aliasRecords = records
    .flatMap((r) => r.aliases ?? [])
    .map((a) => vulns.get(a))
    .filter((v): v is OsvVuln => v !== undefined && !v.withdrawn)
  const fromAliases = maxSeverity(aliasRecords.map(deriveSeverity))
  return fromAliases.level !== 'unknown' ? fromAliases : own
}

/**
 * GHSA aliases worth fetching to score otherwise unscored records (GO-…, RUSTSEC-…, PYSEC-… without
 * CVSS). Returns ids not already downloaded.
 */
export function aliasesToEnrich(vulns: Map<string, OsvVuln>): string[] {
  const out = new Set<string>()
  for (const v of vulns.values()) {
    if (deriveSeverity(v).level !== 'unknown') continue
    const aliases = v.aliases ?? []
    if (aliases.some((a) => vulns.has(a) && deriveSeverity(vulns.get(a)!).level !== 'unknown')) continue
    for (const a of aliases) if (a.startsWith('GHSA-') && !vulns.has(a)) out.add(a)
  }
  return [...out]
}

export function buildFindings(
  deps: Dependency[],
  idsByDep: Map<string, string[]>,
  vulns: Map<string, OsvVuln>,
): Finding[] {
  const findings: Finding[] = []
  for (const dep of deps) {
    const ids = (idsByDep.get(depKey(dep)) ?? []).filter((id) => !vulns.get(id)?.withdrawn)
    for (const group of groupIds(ids, vulns)) {
      const records = group.map((id) => vulns.get(id)).filter((v): v is OsvVuln => v !== undefined)
      const aliasSet = new Set<string>()
      for (const r of records) for (const a of r.aliases ?? []) if (!group.includes(a)) aliasSet.add(a)
      const primaryId = preferId(group)
      const primary = vulns.get(primaryId) ?? records[0]
      const summary =
        primary?.summary?.trim() ||
        records.find((r) => r.summary)?.summary?.trim() ||
        (primary?.details ?? '').trim().split(/\r?\n/)[0].slice(0, 200)
      findings.push({
        dep,
        ids: group,
        primaryId,
        aliases: [...aliasSet].sort((a, b) => (a.startsWith('CVE-') === b.startsWith('CVE-') ? a.localeCompare(b) : a.startsWith('CVE-') ? -1 : 1)),
        summary,
        severity: groupSeverity(records, vulns),
        fixed: [...new Set(records.flatMap((r) => fixedVersions(r, dep)))],
        ...(records.length < group.length ? { detailsMissing: true } : {}),
      })
    }
  }
  return sortFindings(findings)
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity.level] - SEVERITY_RANK[a.severity.level] ||
      (b.severity.score ?? -1) - (a.severity.score ?? -1) ||
      a.dep.name.localeCompare(b.dep.name) ||
      a.primaryId.localeCompare(b.primaryId),
  )
}

export function countBySeverity(findings: Finding[]): Record<SeverityLevel, number> {
  const counts = Object.fromEntries(SEVERITY_LEVELS.map((l) => [l, 0])) as Record<SeverityLevel, number>
  for (const f of findings) counts[f.severity.level]++
  return counts
}

export interface FindingFilter {
  minLevel: SeverityLevel | 'all'
  hideDev: boolean
  text: string
}

export function filterFindings(findings: Finding[], f: FindingFilter): Finding[] {
  const q = f.text.trim().toLowerCase()
  return findings.filter((x) => {
    if (f.hideDev && x.dep.dev) return false
    // "unknown" (e.g. CVSS v4-only records) may well be critical: never hide it behind a severity threshold
    if (f.minLevel !== 'all' && x.severity.level !== 'unknown' && SEVERITY_RANK[x.severity.level] < SEVERITY_RANK[f.minLevel]) {
      return false
    }
    if (q) {
      const hay = [x.dep.name, x.dep.version, x.summary, ...x.ids, ...x.aliases].join(' ').toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
}

export function severityLabel(s: SeverityInfo): string {
  return s.score !== undefined ? `${s.level} (${s.score.toFixed(1)})` : s.level
}

const CSV_HEADERS = ['Severity', 'CVSS', 'Package', 'Version', 'Ecosystem', 'Dev', 'ID', 'Aliases', 'Summary', 'Fixed in', 'Link']

/**
 * RFC 4180 field escaping, plus protection against CSV/formula injection: advisory text is
 * untrusted, and a cell starting with = + - @ (or tab/CR) would be evaluated by spreadsheets.
 */
export function csvField(value: string): string {
  let v = value
  if (/^[=+\-@\t\r]/.test(v)) v = `'${v}`
  return /[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v
}

export function toCsv(findings: Finding[]): string {
  const rows = findings.map((f) => [
    f.severity.level,
    f.severity.score !== undefined ? f.severity.score.toFixed(1) : '',
    f.dep.name,
    f.dep.version,
    f.dep.ecosystem,
    f.dep.dev ? 'yes' : 'no',
    f.ids.join(' '),
    f.aliases.join(' '),
    f.summary,
    f.fixed.join(' '),
    osvUrl(f.primaryId),
  ])
  return [CSV_HEADERS, ...rows].map((r) => r.map(csvField).join(',')).join('\r\n') + '\r\n'
}

export interface ReportMeta {
  scannedPackages: number
  sources: string[]
  date: string
  failedPackages: number
}

const SAFE_ID = /^[A-Za-z0-9._:-]+$/

/** Advisory text is untrusted: neutralise raw HTML so it cannot inject markup into a PR comment or wiki page. */
export function mdText(s: string): string {
  // Brackets are entity-encoded (not backslash-escaped: mdCell doubles backslashes) so advisory
  // text cannot form [phishing](links) or ![tracking](images) in the rendered report.
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\[/g, '&#91;')
    .replace(/\]/g, '&#93;')
}

export function toMarkdown(findings: Finding[], meta: ReportMeta): string {
  const counts = countBySeverity(findings)
  const lines: string[] = [
    '# Dependency vulnerability report',
    '',
    `- Date: ${meta.date}`,
    `- Sources: ${meta.sources.join(', ') || 'n/a'}`,
    `- Packages checked: ${meta.scannedPackages}`,
    `- Vulnerabilities: ${findings.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, unknown ${counts.unknown})`,
    `- Data: [OSV.dev](https://osv.dev)`,
  ]
  if (meta.failedPackages > 0) lines.push(`- ⚠️ ${meta.failedPackages} packages could not be checked (network/API error)`)
  lines.push('')
  if (findings.length === 0) {
    lines.push('No known vulnerabilities found.')
    return lines.join('\n') + '\n'
  }
  const table = mdTable(
    ['Severity', 'Package', 'Version', 'ID', 'Aliases', 'Summary', 'Fixed in'],
    findings.map((f) => [
      severityLabel(f.severity),
      mdText(f.dep.name) + (f.dep.dev ? ' (dev)' : ''),
      mdText(f.dep.version),
      SAFE_ID.test(f.primaryId) ? `[${f.primaryId}](${osvUrl(f.primaryId)})` : mdText(f.primaryId),
      mdText(f.aliases.join(', ')),
      mdText(f.summary),
      mdText(f.fixed.join(', ')) || 'no fix available',
    ]),
  )
  lines.push(table)
  return lines.join('\n') + '\n'
}
