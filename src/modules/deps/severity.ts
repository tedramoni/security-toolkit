import { cvssRating, parseCvss3 } from './cvss.ts'
import type { OsvVuln } from './osv.ts'
import type { Dependency } from './types.ts'
import { normalizePyName } from './parsers/pypi.ts'

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'

/** Higher = worse. "unknown" ranks above "none"/"low" handling-wise only in sorting after low. */
export const SEVERITY_RANK: Record<SeverityLevel, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 1,
  none: 0,
}

export const SEVERITY_LEVELS: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'unknown', 'none']

export interface SeverityInfo {
  level: SeverityLevel
  /** CVSS v3 base score when a vector was available. */
  score?: number
  vector?: string
  /** Where the level came from. */
  source: 'advisory' | 'cvss3' | 'none'
}

function fromLabel(label: unknown): SeverityLevel | null {
  if (typeof label !== 'string') return null
  switch (label.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'critical'
    case 'HIGH':
      return 'high'
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium'
    case 'LOW':
      return 'low'
    default:
      return null
  }
}

/**
 * Severity of an OSV record:
 * 1. database_specific.severity (GitHub advisories: LOW / MODERATE / HIGH / CRITICAL),
 * 2. otherwise the CVSS v3.x base score computed from a vector in severity[] (top level or affected[]),
 * 3. otherwise "unknown" (e.g. only a CVSS v4 vector, or no scoring at all).
 */
export function deriveSeverity(vuln: OsvVuln): SeverityInfo {
  const vectors = [...(vuln.severity ?? []), ...(vuln.affected ?? []).flatMap((a) => a.severity ?? [])]
  let cvss: { score: number; vector: string } | undefined
  for (const s of vectors) {
    if (s.type !== 'CVSS_V3' || typeof s.score !== 'string') continue
    const parsed = parseCvss3(s.score)
    if (parsed && (!cvss || parsed.baseScore > cvss.score)) cvss = { score: parsed.baseScore, vector: s.score }
  }
  const label = fromLabel(vuln.database_specific?.severity)
  if (label) return { level: label, score: cvss?.score, vector: cvss?.vector, source: 'advisory' }
  if (cvss) return { level: cvssRating(cvss.score), score: cvss.score, vector: cvss.vector, source: 'cvss3' }
  return { level: 'unknown', source: 'none' }
}

export function maxSeverity(items: SeverityInfo[]): SeverityInfo {
  let best: SeverityInfo = { level: 'unknown', source: 'none' }
  let first = true
  for (const s of items) {
    if (
      first ||
      SEVERITY_RANK[s.level] > SEVERITY_RANK[best.level] ||
      (s.level === best.level && (s.score ?? -1) > (best.score ?? -1))
    ) {
      best = s
      first = false
    }
  }
  return best
}

/**
 * Loose version comparison: splits on non-alphanumerics, compares numeric parts numerically and
 * treats a pre-release suffix as lower than the release. Good enough to place a version within
 * introduced/fixed intervals for npm, PyPI, Maven, Go, RubyGems, Packagist and crates.io.
 */
export function compareLoose(a: string, b: string): number {
  const norm = (v: string) => v.replace(/^v(?=\d)/, '').split(/[^0-9A-Za-z]+|(?<=\d)(?=[A-Za-z])|(?<=[A-Za-z])(?=\d)/).filter(Boolean)
  const pa = norm(a)
  const pb = norm(b)
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    // a missing numeric part counts as 0 (1.0 == 1.0.0 < 1.0.1); a missing part before a
    // pre-release label makes the shorter version the release (1.0 > 1.0-rc1)
    let x = pa[i]
    let y = pb[i]
    if (x === undefined) {
      if (!/^\d+$/.test(y)) return 1
      x = '0'
    }
    if (y === undefined) {
      if (!/^\d+$/.test(x)) return -1
      y = '0'
    }
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) {
      const d = Number(x) - Number(y)
      if (d !== 0) return d
    } else if (xn !== yn) {
      return xn ? 1 : -1 // numbers sort after pre-release labels
    } else if (x !== y) {
      return x.toLowerCase() < y.toLowerCase() ? -1 : 1
    }
  }
  return 0
}

function samePackage(dep: Dependency, pkg: { name?: string; ecosystem?: string } | undefined): boolean {
  if (!pkg?.name || !pkg.ecosystem) return false
  if (pkg.ecosystem.split(':')[0] !== dep.ecosystem) return false
  if (dep.ecosystem === 'PyPI') return normalizePyName(pkg.name) === normalizePyName(dep.name)
  if (dep.ecosystem === 'Packagist') return pkg.name.toLowerCase() === dep.name.toLowerCase()
  return pkg.name === dep.name
}

/**
 * Fixed versions for this package. Prefers the fix of the range that contains the installed
 * version (e.g. 3.10.2 for a 3.x install, not 4.17.21); falls back to every fix listed.
 */
export function fixedVersions(vuln: OsvVuln, dep: Dependency): string[] {
  const all = new Set<string>()
  const relevant = new Set<string>()
  for (const aff of vuln.affected ?? []) {
    if (!samePackage(dep, aff.package)) continue
    for (const range of aff.ranges ?? []) {
      if (range.type === 'GIT') continue
      let introduced: string | undefined
      for (const ev of range.events ?? []) {
        if (ev.introduced !== undefined) introduced = ev.introduced
        if (ev.fixed !== undefined) {
          all.add(ev.fixed)
          const afterIntro = introduced === undefined || introduced === '0' || compareLoose(dep.version, introduced) >= 0
          if (afterIntro && compareLoose(dep.version, ev.fixed) < 0) relevant.add(ev.fixed)
          introduced = undefined
        }
      }
    }
  }
  const pick = relevant.size > 0 ? relevant : all
  return [...pick].sort(compareLoose)
}
