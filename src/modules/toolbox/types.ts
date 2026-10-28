import { mdTable } from '../../lib/markdown'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass'

export interface Finding {
  severity: Severity
  title: string
  detail: string
  fix?: string
  /** Reference URL (standard, cheat sheet, spec). */
  ref?: string
}

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'pass']

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s)
}

/** Stable sort, most severe first. Does not mutate the input. */
export function sortFindings<T extends { severity: Severity }>(findings: readonly T[]): T[] {
  return findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => severityRank(a.f.severity) - severityRank(b.f.severity) || a.i - b.i)
    .map(({ f }) => f)
}

export function countBySeverity(findings: readonly { severity: Severity }[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, pass: 0 }
  for (const f of findings) out[f.severity]++
  return out
}

/** Most severe level present, or undefined for an empty list. */
export function worstSeverity(findings: readonly { severity: Severity }[]): Severity | undefined {
  let best: Severity | undefined
  for (const f of findings) {
    if (best === undefined || severityRank(f.severity) < severityRank(best)) best = f.severity
  }
  return best
}

/** Markdown report suitable for pasting in a PR / issue comment. */
/**
 * Neutralise HTML and backticks in text that may contain pasted (untrusted) values, so the exported Markdown
 * cannot inject markup / break code spans when rendered by a less strict viewer than GitHub.
 */
export function mdText(s: string): string {
  // Backticks become an entity rather than "\`": a pasted backslash could otherwise cancel the escape.
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/`/g, '&#96;')
}

export function findingsToMarkdown(title: string, findings: readonly Finding[]): string {
  const rows = sortFindings(findings).map((f) => [f.severity.toUpperCase(), f.title, f.detail, f.fix ?? ''].map(mdText))
  return `### ${title}\n\n${findings.length === 0 ? '_No findings._' : mdTable(['Severity', 'Finding', 'Detail', 'Fix'], rows)}\n`
}
