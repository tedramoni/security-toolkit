/** Summary + Markdown / JSON report. All external text is entity-encoded (mdText) before it reaches Markdown. */
import { mdTable } from '../../lib/markdown'
import type { CheckId, CheckStatus, Finding } from './types'
import { mdText, sortFindings } from './types'
import { RESOLVERS } from './doh'

export const CHECK_LABELS: Record<CheckId, string> = {
  dns: 'DNS records',
  email: 'Email security',
  ct: 'Certificate transparency',
  rdap: 'Domain registration (RDAP)',
  ip: 'IP address',
  wayback: 'Web archive',
  web: 'Website (via proxy)',
}

/** Third parties contacted by each check (shown on every card). */
export const SOURCES = {
  dns: `${RESOLVERS.google.label}, fallback ${RESOLVERS.cloudflare.label}`,
  email: 'DNS over HTTPS (TXT/MX), MTA-STS policy via your proxy if set',
  ct: 'crt.sh (Certificate Transparency search)',
  rdap: 'rdap.org → the registry\'s RDAP server',
  ip: 'rdap.org → regional Internet registry (ARIN, RIPE NCC, APNIC…), PTR via DoH',
  wayback: 'archive.org Wayback Machine availability API',
  web: 'your CORS proxy → the site itself, hstspreload.org',
} as const

export interface CheckSnapshot {
  id: CheckId
  status: CheckStatus
  findings: Finding[]
  error?: string
  data?: unknown
  ms?: number
}

export interface ReportFinding extends Finding {
  check: CheckId
}

/** All non-pass findings across checks, most severe first. */
export function summaryFindings(checks: readonly CheckSnapshot[], includePass = false): ReportFinding[] {
  const all: ReportFinding[] = []
  for (const c of checks) for (const f of c.findings) if (includePass || f.severity !== 'pass') all.push({ ...f, check: c.id })
  return sortFindings(all)
}

export function reportMarkdown(target: string, checks: readonly CheckSnapshot[], generatedAt: Date): string {
  const lines: string[] = []
  lines.push(`# Website recon report — ${mdText(target)}`)
  lines.push('')
  lines.push(`Generated ${generatedAt.toISOString()} with Security Toolkit (passive, public data only).`)
  lines.push('')
  lines.push('## Checks')
  lines.push('')
  lines.push(mdTable(['Check', 'Status', 'Findings'], checks.map((c) => [CHECK_LABELS[c.id], c.status + (c.error ? `: ${mdText(c.error)}` : ''), String(c.findings.filter((f) => f.severity !== 'pass').length)])))
  lines.push('')
  lines.push('## Findings')
  lines.push('')
  const fs = summaryFindings(checks)
  if (fs.length === 0) lines.push('_No findings._')
  else lines.push(mdTable(['Severity', 'Check', 'Finding', 'Detail', 'Fix'], fs.map((f) => [f.severity.toUpperCase(), CHECK_LABELS[f.check], mdText(f.title), mdText(f.detail), mdText(f.fix ?? '')])))
  lines.push('')
  const passes = checks.flatMap((c) => c.findings.filter((f) => f.severity === 'pass').map((f) => ({ ...f, check: c.id })))
  if (passes.length > 0) {
    lines.push('## Passed')
    lines.push('')
    for (const p of passes) lines.push(`- **${CHECK_LABELS[p.check]}**: ${mdText(p.title)}`)
    lines.push('')
  }
  return lines.join('\n')
}

export function reportJson(target: string, checks: readonly CheckSnapshot[], generatedAt: Date): unknown {
  return {
    tool: 'Security Toolkit — Website Recon',
    target,
    generatedAt: generatedAt.toISOString(),
    checks: checks.map((c) => ({ id: c.id, label: CHECK_LABELS[c.id], status: c.status, error: c.error, durationMs: c.ms, findings: c.findings, data: c.data })),
  }
}
