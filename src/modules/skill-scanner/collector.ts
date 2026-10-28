import type { LineInfo } from './classify'
import { RULES_BY_ID } from './rules'
import type { Ctx, FileKind, Finding, Sev } from './types'
import { downgrade } from './types'

/** Per-file scan state shared by the regex engine and structured checks. */
export interface FileScan {
  path: string
  kind: FileKind
  lines: string[]
  infos: LineInfo[]
  findings: Finding[]
  disabled: ReadonlySet<string>
}

export interface AddOptions {
  /** 0-based line index (-1 = whole file). */
  line: number
  /** 0-based column. */
  col?: number
  len?: number
  message?: string
  ctx?: Ctx
  severity?: Sev
  possibleFalsePositive?: string
  redactMatch?: boolean
}

export const MAX_FINDINGS_PER_RULE_PER_FILE = 100

const ruleCounts = new WeakMap<FileScan, Map<string, number>>()

export function addFinding(s: FileScan, ruleId: string, o: AddOptions): boolean {
  if (s.disabled.has(ruleId)) return false
  const meta = RULES_BY_ID.get(ruleId)
  if (!meta) throw new Error(`Unknown rule ${ruleId}`)
  // O(1) per call: counting by scanning s.findings made large files quadratic.
  let counts = ruleCounts.get(s)
  if (!counts) {
    counts = new Map()
    for (const f of s.findings) counts.set(f.ruleId, (counts.get(f.ruleId) ?? 0) + 1)
    ruleCounts.set(s, counts)
  }
  const count = counts.get(ruleId) ?? 0
  if (count >= MAX_FINDINGS_PER_RULE_PER_FILE) return false
  counts.set(ruleId, count + 1)
  const base = o.severity ?? meta.severity
  const col = o.col ?? 0
  s.findings.push({
    ruleId,
    category: meta.category,
    baseSeverity: base,
    severity: o.possibleFalsePositive ? downgrade(base) : base,
    title: meta.title,
    message: o.message ?? meta.description,
    path: s.path,
    line: o.line + 1,
    column: col + 1,
    endColumn: col + 1 + (o.len ?? 0),
    ctx: o.ctx,
    possibleFalsePositive: o.possibleFalsePositive,
    redactMatch: o.redactMatch,
    fingerprint: '',
  })
  return true
}

export function hasFindingAt(s: FileScan, line0: number, predicate: (ruleId: string) => boolean): boolean {
  return s.findings.some((f) => f.line === line0 + 1 && predicate(f.ruleId))
}

/* ---------- fingerprints ---------- */

function fnv1a(str: string, seed: number): number {
  let h = seed >>> 0
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h >>> 0
}

export function hash64(str: string): string {
  return fnv1a(str, 0x811c9dc5).toString(16).padStart(8, '0') + fnv1a(str, 0x01234567).toString(16).padStart(8, '0')
}

/**
 * Stable fingerprints: hash(rule | path | whitespace-normalised line text) plus an occurrence counter,
 * so suppressions survive unrelated edits that move lines.
 */
export function assignFingerprints(findings: Finding[], lines: readonly string[]): void {
  const seen = new Map<string, number>()
  for (const f of findings) {
    const text = f.line > 0 ? (lines[f.line - 1] ?? '').trim().replace(/\s+/g, ' ').slice(0, 2000) : ''
    const h = hash64(`${f.ruleId}|${f.path}|${text}|${f.line > 0 ? '' : f.message}`)
    const n = seen.get(h) ?? 0
    seen.set(h, n + 1)
    f.fingerprint = `${h}:${n}`
  }
}
