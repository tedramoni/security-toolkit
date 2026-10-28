/** Filtering and grouping of threats for the Threats step. Pure functions. */
import type { StrideCategory, Threat, ThreatModel, ThreatStatus } from './model.ts'
import { displayName, ELEMENT_TYPE_LABELS, STRIDE, STRIDE_NAMES } from './model.ts'
import type { RiskLevel } from './risk.ts'
import { compareRisk, riskOf } from './risk.ts'

export interface ThreatFilter {
  status: ThreatStatus | 'all'
  risk: RiskLevel | 'all' | 'high+'
  includeStale: boolean
  text: string
}

export const DEFAULT_FILTER: ThreatFilter = { status: 'all', risk: 'all', includeStale: true, text: '' }

export function matchesFilter(t: Threat, f: ThreatFilter): boolean {
  if (!f.includeStale && t.stale) return false
  if (f.status !== 'all' && t.status !== f.status) return false
  const risk = riskOf(t)
  if (f.risk === 'high+' ? risk !== 'high' && risk !== 'critical' : f.risk !== 'all' && risk !== f.risk) return false
  const q = f.text.trim().toLowerCase()
  if (q && !`${t.title}\n${t.description}\n${t.mitigation}\n${t.owner ?? ''}\n${t.ticket ?? ''}`.toLowerCase().includes(q)) return false
  return true
}

export interface ThreatGroup {
  key: string
  title: string
  subtitle: string
  threats: Threat[]
}

/** Within a group: highest risk first, then STRIDE order, then title — stable and predictable. */
function sortThreats(list: Threat[]): Threat[] {
  return [...list].sort(
    (a, b) => compareRisk(a, b) || STRIDE.indexOf(a.category) - STRIDE.indexOf(b.category) || a.title.localeCompare(b.title),
  )
}

export function groupThreats(model: ThreatModel, threats: Threat[], by: 'element' | 'category'): ThreatGroup[] {
  if (by === 'category') {
    return STRIDE.map((c: StrideCategory) => ({
      key: c,
      title: `${c} — ${STRIDE_NAMES[c]}`,
      subtitle: '',
      threats: sortThreats(threats.filter((t) => t.category === c)),
    })).filter((g) => g.threats.length > 0)
  }
  const groups: ThreatGroup[] = model.elements
    .map((el) => ({
      key: el.id,
      title: displayName(model, el),
      subtitle: ELEMENT_TYPE_LABELS[el.type],
      threats: sortThreats(threats.filter((t) => t.elementId === el.id)),
    }))
    .filter((g) => g.threats.length > 0)
  // Threats pointing at missing elements (should not happen after validation, but never hide data).
  const known = new Set(model.elements.map((e) => e.id))
  const orphans = threats.filter((t) => !known.has(t.elementId))
  if (orphans.length) groups.push({ key: '__orphans', title: 'Unknown element', subtitle: '', threats: sortThreats(orphans) })
  return groups
}
