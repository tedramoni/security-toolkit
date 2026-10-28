import { mdTable } from '../../lib/markdown'
import { mdText } from '../toolbox/types'
import type { FileReport } from './engine'
import { RULES_BY_ID } from './rules'
import type { ScoreResult } from './score'
import type { Finding, Sev, Suppression } from './types'
import { CATEGORIES, SEVERITIES } from './types'

export const TOOL_NAME = 'AI Skill Scanner (Security Toolkit)'
export const TOOL_VERSION = '1.0.0'
export const BASELINE_FILENAME = '.skill-scanner-baseline.json'
export const FINGERPRINT_KEY = 'skillScanner/v1'

/* ---------- SARIF 2.1.0 ---------- */

export function sarifLevel(s: Sev): 'error' | 'warning' | 'note' {
  return s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'note'
}

/** GitHub code scanning maps security-severity: ≥9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low. */
export const SECURITY_SEVERITY: Record<Sev, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '2.0', info: '0.0' }

function sarifUri(path: string, prefix: string): string {
  const p = (prefix ? prefix.replace(/\/+$/, '') + '/' : '') + path.replace(/\\/g, '/').replace(/^\/+/, '')
  return p.split('/').map(encodeURIComponent).join('/')
}

function pascal(s: string): string {
  return s
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim()
    .split(' ')
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join('')
}

export interface SarifOptions {
  /** Prepended to every artifact path so they match repository-relative paths. */
  pathPrefix?: string
  informationUri?: string
}

export function toSarif(findings: readonly Finding[], opts: SarifOptions = {}): object {
  const ruleIds = [...new Set(findings.map((f) => f.ruleId))].sort()
  const index = new Map(ruleIds.map((id, i) => [id, i]))
  const rules = ruleIds.map((id) => {
    const r = RULES_BY_ID.get(id)
    if (!r) throw new Error(`Unknown rule ${id}`)
    return {
      id,
      name: pascal(r.title),
      shortDescription: { text: r.title },
      fullDescription: { text: r.description },
      help: { text: `${r.description}\n\nRemediation: ${r.remediation}`, markdown: `${r.description}\n\n**Remediation:** ${r.remediation}` },
      helpUri: CATEGORIES[r.category].ref,
      defaultConfiguration: { level: sarifLevel(r.severity) },
      properties: { tags: ['security', 'ai-agent', r.category], precision: 'medium', 'security-severity': SECURITY_SEVERITY[r.severity] },
    }
  })
  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: index.get(f.ruleId),
    level: sarifLevel(f.severity),
    message: { text: f.possibleFalsePositive ? `${f.message} [possible false positive: ${f.possibleFalsePositive}]` : f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: sarifUri(f.path, opts.pathPrefix ?? '') },
          region: f.line > 0 ? { startLine: f.line, startColumn: f.column, endColumn: Math.max(f.endColumn, f.column + 1) } : { startLine: 1 },
        },
      },
    ],
    partialFingerprints: { [FINGERPRINT_KEY]: f.fingerprint },
    properties: { severity: f.severity, category: f.category, ...(f.possibleFalsePositive ? { possibleFalsePositive: true } : {}) },
  }))
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            semanticVersion: TOOL_VERSION,
            ...(opts.informationUri ? { informationUri: opts.informationUri } : {}),
            rules,
          },
        },
        automationDetails: { id: 'ai-skill-scanner/' },
        columnKind: 'utf16CodeUnits',
        results,
      },
    ],
  }
}

/* ---------- JSON ---------- */

export interface ReportInput {
  source: string
  files: readonly FileReport[]
  findings: readonly Finding[]
  suppressed: readonly { finding: Finding; reason: string }[]
  score: ScoreResult
  generatedAt?: Date
}

export function toJsonReport(r: ReportInput): object {
  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    generatedAt: (r.generatedAt ?? new Date()).toISOString(),
    source: r.source,
    verdict: r.score.verdict,
    score: r.score.score,
    reasons: r.score.reasons,
    files: r.files.map((f) => ({ path: f.path, kind: f.kind, size: f.size, lines: f.lineCount, truncated: f.truncated ?? false })),
    findings: r.findings.map(stripFinding),
    suppressed: r.suppressed.map((s) => ({ ...stripFinding(s.finding), suppressionReason: s.reason })),
  }
}

function stripFinding(f: Finding) {
  return {
    ruleId: f.ruleId,
    category: f.category,
    severity: f.severity,
    baseSeverity: f.baseSeverity,
    title: f.title,
    message: f.message,
    path: f.path,
    line: f.line,
    column: f.column,
    possibleFalsePositive: f.possibleFalsePositive ?? null,
    fingerprint: f.fingerprint,
  }
}

/* ---------- Markdown ---------- */

/**
 * Untrusted text (decoded hidden payloads, URLs from the scanned files) for a Markdown report that may be
 * posted as a PR comment: entity-encode HTML, neutralise link/image syntax and defang URL schemes so a
 * malicious skill cannot plant clickable links or tracking images in the report.
 */
export function mdSafe(s: string): string {
  return mdText(s)
    // Entities, not backslashes: mdCell() doubles backslashes inside table cells, which would re-enable the syntax.
    .replace(/[[\]!()]/g, (c) => `&#${c.charCodeAt(0)};`)
    .replace(/\b(https?|ftp|wss?|file):\/\//gi, '$1[:]//')
    .replace(/\bwww\./gi, 'www[.]')
}

export function toMarkdown(r: ReportInput): string {
  const counts = SEVERITIES.map((s) => [s, r.findings.filter((f) => f.severity === s).length] as const)
  const out: string[] = []
  out.push(`## AI Skill Scanner report`)
  out.push('')
  out.push(`**Source:** ${mdSafe(r.source)}  `)
  out.push(`**Verdict:** ${r.score.verdict} — risk score ${r.score.score}/100 (${mdText(r.score.reasons.join('; '))})  `)
  out.push(`**Files scanned:** ${r.files.length} · **Findings:** ${r.findings.length} · **Suppressed:** ${r.suppressed.length}`)
  out.push('')
  out.push(mdTable(['Severity', 'Count'], counts.map(([s, n]) => [s, String(n)])))
  out.push('')
  if (r.score.byCategory.length > 0) {
    out.push('### By category')
    out.push('')
    out.push(mdTable(['Category', 'Findings', 'Points'], r.score.byCategory.map((c) => [CATEGORIES[c.category].label, String(c.count), c.points.toFixed(1)])))
    out.push('')
  }
  out.push('### Findings')
  out.push('')
  if (r.findings.length === 0) out.push('_No findings._')
  else {
    const sorted = [...r.findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.path.localeCompare(b.path) || a.line - b.line)
    out.push(
      mdTable(
        ['Severity', 'Rule', 'Location', 'Finding'],
        sorted.map((f) => [
          f.severity.toUpperCase() + (f.possibleFalsePositive ? ' (possible FP)' : ''),
          `${f.ruleId} ${mdText(f.title)}`,
          mdSafe(`${f.path}${f.line > 0 ? `:${f.line}` : ''}`),
          mdSafe(f.message),
        ]),
      ),
    )
  }
  if (r.suppressed.length > 0) {
    out.push('')
    out.push('### Suppressed')
    out.push('')
    out.push(mdTable(['Rule', 'Location', 'Reason'], r.suppressed.map((s) => [s.finding.ruleId, mdSafe(`${s.finding.path}:${s.finding.line}`), mdSafe(s.reason)])))
  }
  out.push('')
  out.push('_Static, pattern-based analysis: findings need human review; a PASS is not a guarantee of safety._')
  return out.join('\n') + '\n'
}

/* ---------- Baseline (suppressions) ---------- */

export interface BaselineFile {
  tool: 'ai-skill-scanner'
  version: 1
  suppressions: Suppression[]
}

export function toBaseline(suppressions: readonly Suppression[]): BaselineFile {
  return { tool: 'ai-skill-scanner', version: 1, suppressions: [...suppressions] }
}

const FP_RE = /^[0-9a-f]{16}:\d{1,6}$/
const RULE_RE = /^SS-[A-Z]{2}-\d{3}$/

/** Validate an imported baseline; invalid entries are dropped. Throws on a wrong file shape. */
export function parseBaseline(data: unknown): Suppression[] {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) throw new Error('Baseline must be a JSON object.')
  const d = data as Record<string, unknown>
  if (d.tool !== 'ai-skill-scanner' || !Array.isArray(d.suppressions)) throw new Error(`Not a ${BASELINE_FILENAME} file.`)
  const out: Suppression[] = []
  for (const s of d.suppressions as unknown[]) {
    if (typeof s !== 'object' || s === null) continue
    const x = s as Record<string, unknown>
    if (typeof x.fingerprint !== 'string' || !FP_RE.test(x.fingerprint)) continue
    if (typeof x.ruleId !== 'string' || !RULE_RE.test(x.ruleId)) continue
    out.push({
      fingerprint: x.fingerprint,
      ruleId: x.ruleId,
      path: typeof x.path === 'string' ? x.path.slice(0, 1000) : '',
      line: typeof x.line === 'number' && Number.isInteger(x.line) && x.line >= 0 ? x.line : 0,
      reason: typeof x.reason === 'string' ? x.reason.slice(0, 1000) : '',
      createdAt: typeof x.createdAt === 'string' && !Number.isNaN(Date.parse(x.createdAt)) ? x.createdAt : new Date(0).toISOString(),
    })
  }
  return out
}

export function mergeSuppressions(existing: readonly Suppression[], incoming: readonly Suppression[]): Suppression[] {
  const map = new Map(existing.map((s) => [s.fingerprint, s]))
  for (const s of incoming) map.set(s.fingerprint, s)
  return [...map.values()]
}

/** Split findings into active and suppressed. */
export function applySuppressions(findings: readonly Finding[], suppressions: readonly Suppression[]): { active: Finding[]; suppressed: { finding: Finding; reason: string }[] } {
  const map = new Map(suppressions.map((s) => [s.fingerprint, s]))
  const active: Finding[] = []
  const suppressed: { finding: Finding; reason: string }[] = []
  for (const f of findings) {
    const s = map.get(f.fingerprint)
    if (s && s.ruleId === f.ruleId) suppressed.push({ finding: f, reason: s.reason })
    else active.push(f)
  }
  return { active, suppressed }
}
