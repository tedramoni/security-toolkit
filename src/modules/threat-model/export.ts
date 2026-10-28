/** Summaries, textual DFD, Mermaid diagram and Markdown report for a threat model. */
import { mdTable } from '../../lib/markdown.ts'
import type { ModelElement, StrideCategory, Threat, ThreatModel, ThreatStatus } from './model.ts'
import {
  displayName,
  ELEMENT_TYPE_LABELS,
  flowsOf,
  nodesOf,
  STATUS_LABELS,
  STRIDE,
  STRIDE_NAMES,
  TAGS,
  THREAT_STATUSES,
} from './model.ts'
import type { RiskLevel } from './risk.ts'
import { compareRisk, RISK_LABELS, RISK_LEVELS, riskOf, riskScore } from './risk.ts'

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export interface Summary {
  total: number
  /** Threats still needing a decision (status open). Stale threats are excluded from every count. */
  open: number
  /** Not open: mitigated, accepted, transferred or not applicable. */
  addressed: number
  stale: number
  byCategory: Record<StrideCategory, { total: number; open: number }>
  byRisk: Record<RiskLevel, { total: number; open: number }>
  byStatus: Record<ThreatStatus, number>
  /** Open high/critical threats, highest risk first. */
  openHighCritical: Threat[]
}

export function summarize(model: ThreatModel): Summary {
  const byCategory = Object.fromEntries(STRIDE.map((c) => [c, { total: 0, open: 0 }])) as Summary['byCategory']
  const byRisk = Object.fromEntries(RISK_LEVELS.map((r) => [r, { total: 0, open: 0 }])) as Summary['byRisk']
  const byStatus = Object.fromEntries(THREAT_STATUSES.map((s) => [s, 0])) as Summary['byStatus']
  let total = 0
  let open = 0
  let stale = 0
  const openHighCritical: Threat[] = []
  for (const t of model.threats) {
    if (t.stale) {
      stale++
      continue
    }
    total++
    const isOpen = t.status === 'open'
    const risk = riskOf(t)
    byCategory[t.category].total++
    byRisk[risk].total++
    byStatus[t.status]++
    if (isOpen) {
      open++
      byCategory[t.category].open++
      byRisk[risk].open++
      if (risk === 'high' || risk === 'critical') openHighCritical.push(t)
    }
  }
  openHighCritical.sort(compareRisk)
  return { total, open, addressed: total - open, stale, byCategory, byRisk, byStatus, openHighCritical }
}

// ---------------------------------------------------------------------------
// Textual DFD
// ---------------------------------------------------------------------------

/** "HTTPS, confidential, crosses trust boundary" */
export function flowAttributes(flow: ModelElement): string {
  const parts = [flow.protocol?.trim() || 'protocol?', flow.dataClassification ?? 'internal']
  if (flow.crossesTrustBoundary) parts.push('crosses trust boundary')
  return parts.join(', ')
}

function nameOf(model: ThreatModel, id: string | undefined): string {
  const el = model.elements.find((e) => e.id === id)
  return el ? displayName(model, el) : '?'
}

/** One line per flow: `A —[HTTPS, confidential, crosses trust boundary]→ B (label)` */
export function textualDfd(model: ThreatModel): string[] {
  return flowsOf(model).map((f) => {
    const label = f.name.trim() ? ` (${f.name.trim()})` : ''
    return `${nameOf(model, f.fromId)} —[${flowAttributes(f)}]→ ${nameOf(model, f.toId)}${label}`
  })
}

// ---------------------------------------------------------------------------
// Mermaid
// ---------------------------------------------------------------------------

/**
 * Make arbitrary text safe inside a quoted Mermaid label.
 * Characters with syntactic meaning (quotes, brackets, pipes, #, <, >, &, backticks, ;) are replaced by
 * Mermaid entity codes (`#<decimal>;`) in a single pass, so the `#` of an emitted code is never re-escaped.
 * Line breaks and other control characters collapse to a single space.
 */
export function mermaidEscape(text: string): string {
  const flat = text
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return flat.replace(/[#"'`<>&|[\](){};\\]/g, (ch) => `#${ch.charCodeAt(0)};`)
}

const SHAPES: Record<string, [string, string]> = {
  process: ['((', '))'],
  datastore: ['[(', ')]'],
  external: ['[', ']'],
}

/**
 * Mermaid flowchart text. Node ids are generated (n1, n2…) so user-controlled ids never reach the syntax.
 * Processes are circles, data stores cylinders, external entities rectangles;
 * flows crossing a trust boundary are drawn dashed.
 */
export function toMermaid(model: ThreatModel): string {
  const lines = ['flowchart LR']
  const ids = new Map<string, string>()
  nodesOf(model).forEach((n, i) => {
    const nid = `n${i + 1}`
    ids.set(n.id, nid)
    const [open, close] = SHAPES[n.type]
    lines.push(`  ${nid}${open}"${mermaidEscape(displayName(model, n)) || 'unnamed'}"${close}`)
  })
  const boundaryEdges: number[] = []
  let edgeIndex = 0
  for (const f of flowsOf(model)) {
    const from = ids.get(f.fromId ?? '')
    const to = ids.get(f.toId ?? '')
    if (!from || !to) continue
    const parts = [f.name.trim(), flowAttributes(f)].filter(Boolean).join(': ')
    const arrow = f.crossesTrustBoundary ? '-.->' : '-->'
    lines.push(`  ${from} ${arrow}|"${mermaidEscape(parts)}"| ${to}`)
    if (f.crossesTrustBoundary) boundaryEdges.push(edgeIndex)
    edgeIndex++
  }
  if (boundaryEdges.length) lines.push(`  linkStyle ${boundaryEdges.join(',')} stroke:#f97316,stroke-width:2px`)
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

/** Escape text used inline in Markdown paragraphs / list items (not in tables). */
export function mdInline(text: string): string {
  return text.replace(/([\\`*_[\]<>#|])/g, '\\$1').replace(/\r\n?|\n/g, ' ')
}

/**
 * Neutralise raw HTML, links/images and code spans in untrusted table-cell text. Uses HTML entities rather than
 * backslashes because the shared mdCell() escapes backslashes (pipes and newlines are handled by mdCell).
 */
export function mdCellSafe(text: string): string {
  return text.replace(/[&<>[\]`]/g, (ch) => `&#${ch.charCodeAt(0)};`)
}

function table(headers: string[], rows: string[][]): string {
  return mdTable(headers, rows.map((r) => r.map(mdCellSafe)))
}

function tagLabels(el: ModelElement): string {
  return el.tags.map((t) => TAGS.find((d) => d.id === t)?.label ?? t).join(', ')
}

function riskText(t: Threat): string {
  return `${RISK_LABELS[riskOf(t)]} (${riskScore(t.likelihood, t.impact)})`
}

export function toMarkdown(model: ThreatModel, now: string = new Date().toISOString()): string {
  const s = summarize(model)
  const out: string[] = []
  const elName = (id: string) => nameOf(model, id)

  out.push(`# Threat model: ${mdInline(model.name || 'Untitled')}`, '')
  out.push(`- **Owner:** ${mdInline(model.owner || '—')}`)
  out.push(`- **Last updated:** ${model.updatedAt.slice(0, 10)}`)
  out.push(`- **Report generated:** ${now.slice(0, 10)}`)
  out.push('- **Method:** STRIDE per element', '')
  if (model.description.trim()) out.push(mdInline(model.description.trim()), '')

  out.push('## Assumptions', '')
  if (model.assumptions.length) model.assumptions.forEach((a) => out.push(`- ${mdInline(a)}`))
  else out.push('_None recorded._')
  out.push('')

  out.push('## Summary', '')
  out.push(`${s.total} threats: **${s.open} open**, ${s.addressed} addressed${s.stale ? `, ${s.stale} stale (excluded)` : ''}.`, '')
  out.push(
    table(
      ['STRIDE category', 'Total', 'Open'],
      STRIDE.map((c) => [`${c} – ${STRIDE_NAMES[c]}`, String(s.byCategory[c].total), String(s.byCategory[c].open)]),
    ),
    '',
  )
  out.push(
    table(
      ['Risk', 'Total', 'Open'],
      [...RISK_LEVELS].reverse().map((r) => [RISK_LABELS[r], String(s.byRisk[r].total), String(s.byRisk[r].open)]),
    ),
    '',
  )

  out.push('### Open high and critical threats', '')
  if (s.openHighCritical.length) {
    out.push(
      table(
        ['Risk', 'Element', 'STRIDE', 'Threat', 'Owner', 'Ticket'],
        s.openHighCritical.map((t) => [riskText(t), elName(t.elementId), t.category, t.title, t.owner ?? '', t.ticket ?? '']),
      ),
    )
  } else out.push('_None._')
  out.push('')

  out.push('## System elements', '')
  const nodes = nodesOf(model)
  if (nodes.length) {
    out.push(
      table(
        ['Name', 'Type', 'Tags', 'Description'],
        nodes.map((n) => [displayName(model, n), ELEMENT_TYPE_LABELS[n.type], tagLabels(n), n.description]),
      ),
    )
  } else out.push('_No elements._')
  out.push('')

  out.push('## Data flows', '')
  const dfd = textualDfd(model)
  if (dfd.length) dfd.forEach((l) => out.push(`- ${mdInline(l)}`))
  else out.push('_No data flows._')
  out.push('')
  if (nodes.length) {
    out.push('### Diagram', '', '```mermaid', toMermaid(model), '```', '')
    out.push('_Dashed arrows cross a trust boundary._', '')
  }

  out.push('## Threats', '')
  const active = model.threats.filter((t) => !t.stale)
  const elementsWithThreats = model.elements.filter((e) => active.some((t) => t.elementId === e.id))
  if (!elementsWithThreats.length) out.push('_No threats recorded._', '')
  for (const el of elementsWithThreats) {
    out.push(`### ${mdInline(displayName(model, el))} (${ELEMENT_TYPE_LABELS[el.type]})`, '')
    const rows = active
      .filter((t) => t.elementId === el.id)
      .sort((a, b) => compareRisk(a, b) || STRIDE.indexOf(a.category) - STRIDE.indexOf(b.category))
      .map((t) => [
        t.category,
        t.title,
        riskText(t),
        STATUS_LABELS[t.status],
        t.mitigation.trim(),
        [t.owner, t.ticket].filter(Boolean).join(' / '),
      ])
    out.push(table(['STRIDE', 'Threat', 'Risk', 'Status', 'Mitigation / decision', 'Owner / ticket'], rows), '')
  }

  const staleList = model.threats.filter((t) => t.stale)
  if (staleList.length) {
    out.push('## Stale threats', '', '_Generated threats whose rule no longer applies to the current model. Review and delete if obsolete._', '')
    out.push(table(['Element', 'Threat', 'Status'], staleList.map((t) => [elName(t.elementId), t.title, STATUS_LABELS[t.status]])), '')
  }

  out.push('---', '_Generated with Security Champion Toolkit — risk = likelihood (1-3) × impact (1-3): 1-2 low, 3-4 medium, 6 high, 9 critical._', '')
  return out.join('\n')
}

