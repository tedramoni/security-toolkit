import { checkFrontmatter, checkHiddenContent, checkJsonConfig, checkSecrets, checkUnicode } from './checks'
import type { LineInfo } from './classify'
import { badExampleComment, baseName, classifyLines, ctxAt, defensiveCue, detectKind, isExecutablePath, isImperative, sentencePrefix, splitLines } from './classify'
import type { FileScan } from './collector'
import { addFinding, assignFingerprints } from './collector'
import type { RegexRule } from './rules'
import { REGEX_RULES } from './rules'
import type { Ctx, FileKind, Finding, ScanFile } from './types'
import { CONFIG_KINDS, sevRank } from './types'

export const MAX_SCAN_CHARS = 2_000_000

export interface ArchiveIssue {
  /** Archive the entry came from. */
  archive: string
  entry: string
  kind: 'traversal' | 'symlink' | 'skipped'
  detail: string
}

export interface FileReport {
  path: string
  kind: FileKind
  size: number
  lineCount: number
  truncated?: boolean
  /** Text content (in memory only) for the viewer. */
  content?: string
}

export interface ScanResult {
  files: FileReport[]
  findings: Finding[]
}

export interface ScanOptions {
  disabledRules?: ReadonlySet<string>
  archiveIssues?: readonly ArchiveIssue[]
}

const compiled = new Map<RegExp, RegExp>()
function global(re: RegExp): RegExp {
  let g = compiled.get(re)
  if (!g) {
    g = new RegExp(re.source, [...new Set(re.flags.replace('g', '') + 'g')].join(''))
    compiled.set(re, g)
  }
  return g
}

const PROSE_LIKE: readonly Ctx[] = ['prose', 'hidden-comment', 'frontmatter', 'inline', 'code-comment']

function applies(rule: RegexRule, kind: FileKind, path: string): boolean {
  if (kind === 'binary') return false
  if (rule.fileName && !rule.fileName.test(baseName(path))) return false
  return rule.appliesTo === 'any' || rule.appliesTo.includes(kind)
}

/** Run the regex ruleset over one file. */
export function runRegexRules(s: FileScan, rules: readonly RegexRule[] = REGEX_RULES): void {
  const active = rules.filter((r) => !s.disabled.has(r.id) && applies(r, s.kind, s.path))
  for (let i = 0; i < s.lines.length; i++) {
    const line = s.lines[i]
    if (line.length < 3) continue
    const info: LineInfo = s.infos[i]
    for (const rule of active) {
      let reported = false
      for (const p of rule.patterns) {
        if (reported) break
        // exec() on a cached global regex: String.prototype.matchAll clones the RegExp on every call,
        // which dominated scan time on files with many short lines (~10 s for 1 MB).
        const re = global(p)
        re.lastIndex = 0
        for (let m = re.exec(line); m !== null; m = re.exec(line)) {
          if (m[0].length === 0) re.lastIndex++
          const col = m.index
          const ctx = ctxAt(info, col)
          if (rule.contexts && !rule.contexts.includes(ctx)) continue
          const prefix = PROSE_LIKE.includes(ctx) ? sentencePrefix(line, col) : ''
          if (rule.proseImperative && (ctx === 'prose' || ctx === 'hidden-comment' || ctx === 'frontmatter') && !isImperative(prefix)) continue
          if (rule.accept && !rule.accept(m as RegExpExecArray, line)) continue
          let fp: string | undefined
          if (!rule.noDowngrade) {
            if (ctx !== 'code') {
              const cue = defensiveCue(prefix)
              if (cue) fp = `Appears in a defensive / documentation sentence ("${cue}…").`
            }
            if (!fp && ctx === 'code-comment' && rule.contexts) fp = 'Appears inside a code comment.'
            if (!fp && (ctx === 'code' || ctx === 'code-comment') && badExampleComment(line)) fp = 'The line is annotated as a bad/insecure example.'
          }
          addFinding(s, rule.id, {
            line: i,
            col,
            len: m[0].length,
            ctx,
            message: (rule.message ? rule.message(m as RegExpExecArray) : rule.description) + (ctx === 'hidden-comment' ? ' (inside a hidden comment)' : ''),
            possibleFalsePositive: fp,
          })
          reported = true
          break
        }
      }
    }
  }
}

/** Mark lines inside a frontmatter `hooks:` block as code (they hold shell commands). */
function markFrontmatterHooks(lines: readonly string[], infos: LineInfo[]): void {
  let inHooks = false
  for (let i = 1; i < lines.length && infos[i]?.ctx === 'frontmatter'; i++) {
    const l = lines[i]
    if (/^\S/.test(l)) inHooks = /^hooks\s{0,5}:/.test(l)
    else if (inHooks) infos[i] = { ctx: 'code' }
  }
}

export function scanFile(file: ScanFile, opts: ScanOptions = {}): { report: FileReport; findings: Finding[] } {
  const kind = file.kind ?? detectKind(file.path, file.content)
  const disabled = opts.disabledRules ?? new Set<string>()
  const report: FileReport = { path: file.path, kind, size: file.size, lineCount: 0, truncated: file.truncated }
  if (kind === 'binary' || file.content === undefined) {
    const s: FileScan = { path: file.path, kind: 'binary', lines: [], infos: [], findings: [], disabled }
    if (isExecutablePath(file.path) || file.executable) {
      addFinding(s, 'SS-BN-001', {
        line: -1,
        message: `${baseName(file.path)} (${file.size.toLocaleString('en-US')} bytes${file.executable ? `, ${file.executable}` : ''}) is compiled code that cannot be reviewed as source.`,
      })
    }
    s.findings.forEach((f) => (f.line = 0))
    assignFingerprints(s.findings, [])
    return { report: { ...report, kind: 'binary' }, findings: s.findings }
  }
  let text = file.content
  if (text.length > MAX_SCAN_CHARS) {
    text = text.slice(0, MAX_SCAN_CHARS)
    report.truncated = true
  }
  const lines = splitLines(text)
  const infos = classifyLines(lines, kind)
  if (kind === 'skill-md' || kind === 'agent-md') markFrontmatterHooks(lines, infos)
  report.lineCount = lines.length
  report.content = text
  const s: FileScan = { path: file.path, kind, lines, infos, findings: [], disabled }

  runRegexRules(s)
  checkUnicode(s)
  checkHiddenContent(s)
  checkSecrets(s, text)
  if (kind === 'skill-md' || kind === 'agent-md' || kind === 'markdown') checkFrontmatter(s, text)
  if (CONFIG_KINDS.includes(kind) && /\.(?:json|jsonc|json5)$/i.test(file.path) || kind === 'mcp-config' || kind === 'claude-settings') checkJsonConfig(s, text)

  s.findings.sort((a, b) => a.line - b.line || a.column - b.column || sevRank(a.severity) - sevRank(b.severity))
  assignFingerprints(s.findings, lines)
  return { report, findings: s.findings }
}

function archiveFindings(issues: readonly ArchiveIssue[], disabled: ReadonlySet<string>): Finding[] {
  const byArchive = new Map<string, ArchiveIssue[]>()
  for (const i of issues) byArchive.set(i.archive, [...(byArchive.get(i.archive) ?? []), i])
  const out: Finding[] = []
  for (const [archive, list] of byArchive) {
    const s: FileScan = { path: archive, kind: 'binary', lines: [], infos: [], findings: [], disabled }
    for (const i of list) {
      const id = i.kind === 'traversal' ? 'SS-BN-002' : i.kind === 'symlink' ? 'SS-BN-003' : 'SS-BN-004'
      addFinding(s, id, { line: -1, message: `${i.entry}: ${i.detail}` })
    }
    s.findings.forEach((f) => (f.line = 0))
    assignFingerprints(s.findings, [])
    out.push(...s.findings)
  }
  return out
}

/** Scan files, yielding to the event loop between files so the UI stays responsive. */
export async function scanFiles(
  files: readonly ScanFile[],
  opts: ScanOptions = {},
  onProgress?: (done: number, total: number) => void,
): Promise<ScanResult> {
  const reports: FileReport[] = []
  const findings: Finding[] = []
  let last = Date.now()
  for (let i = 0; i < files.length; i++) {
    const r = scanFile(files[i], opts)
    reports.push(r.report)
    findings.push(...r.findings)
    if (Date.now() - last > 30) {
      onProgress?.(i + 1, files.length)
      await new Promise((res) => setTimeout(res, 0))
      last = Date.now()
    }
  }
  findings.push(...archiveFindings(opts.archiveIssues ?? [], opts.disabledRules ?? new Set()))
  onProgress?.(files.length, files.length)
  return { files: reports, findings }
}

/** Synchronous variant (tests, small inputs). */
export function scanFilesSync(files: readonly ScanFile[], opts: ScanOptions = {}): ScanResult {
  const reports: FileReport[] = []
  const findings: Finding[] = []
  for (const f of files) {
    const r = scanFile(f, opts)
    reports.push(r.report)
    findings.push(...r.findings)
  }
  findings.push(...archiveFindings(opts.archiveIssues ?? [], opts.disabledRules ?? new Set()))
  return { files: reports, findings }
}
