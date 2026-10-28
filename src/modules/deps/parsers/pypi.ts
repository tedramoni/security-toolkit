import type { Dependency, ParseResult, SkippedEntry } from '../types.ts'

/** PEP 503 name normalization: lowercase, runs of "-", "_" and "." become a single "-". */
export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-')
}

const NAME = '[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?'
const REQ = new RegExp(`^(${NAME})\\s*(?:\\[[^\\]]*\\])?\\s*(.*)$`)

/** Join backslash line continuations and drop comments. */
function logicalLines(text: string): string[] {
  const out: string[] = []
  let buf = ''
  for (const raw of text.split(/\r?\n/)) {
    // a comment starts with "#" at line start or after whitespace (pip's rule)
    const line = raw.replace(/(^|\s)#.*$/, '')
    if (line.endsWith('\\')) {
      buf += line.slice(0, -1) + ' '
      continue
    }
    out.push((buf + line).trim())
    buf = ''
  }
  if (buf.trim()) out.push(buf.trim())
  return out.filter((l) => l !== '')
}

/**
 * Parse a pip requirements file. Only exact pins (`==` / `===`) can be checked against OSV;
 * everything else is reported as skipped so the user knows what was not covered.
 */
export function parseRequirements(text: string): ParseResult {
  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []

  for (const line of logicalLines(text)) {
    if (line.startsWith('-')) continue // -r, -c, -e, --index-url, --hash continuation… (options, not packages)
    if (/^(https?|git\+|file:|\.{0,2}\/)/i.test(line)) {
      skipped.push({ entry: line, reason: 'skipped: URL or local path requirement' })
      continue
    }
    // drop environment markers and per-requirement options (--hash=…)
    const spec = line.split(';')[0].replace(/\s--?[a-z][\w-]*(=\S*)?/gi, '').trim()
    if (/\s@\s|^\S+\s*@\s*\S/.test(spec) && !spec.includes('==')) {
      skipped.push({ entry: line, reason: 'skipped: direct URL reference' })
      continue
    }
    const m = REQ.exec(spec)
    if (!m) {
      skipped.push({ entry: line, reason: 'skipped: could not parse' })
      continue
    }
    const name = normalizePyName(m[1])
    const constraint = m[2].trim()
    const pin = /^===?\s*([^\s,]+)$/.exec(constraint)
    if (!pin) {
      skipped.push({ entry: line, reason: 'skipped: not pinned' })
      continue
    }
    const version = pin[1]
    if (version.includes('*')) {
      skipped.push({ entry: line, reason: 'skipped: not pinned (wildcard version)' })
      continue
    }
    deps.push({ name, version, ecosystem: 'PyPI' })
  }
  return { deps, skipped }
}

/** Pipfile.lock: {"default": {name: {version: "==1.2.3"}}, "develop": {...}} */
export function parsePipfileLock(text: string): ParseResult {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (e) {
    throw new Error(`Pipfile.lock is not valid JSON: ${(e as Error).message}`)
  }
  if (typeof data !== 'object' || data === null) throw new Error('Pipfile.lock must be a JSON object')
  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []
  for (const [section, dev] of [['default', false], ['develop', true]] as const) {
    const group = (data as Record<string, unknown>)[section]
    if (typeof group !== 'object' || group === null) continue
    for (const [name, raw] of Object.entries(group as Record<string, unknown>)) {
      const v = (raw as { version?: unknown } | null)?.version
      const m = typeof v === 'string' ? /^===?(.+)$/.exec(v.trim()) : null
      if (!m) {
        skipped.push({ entry: name, reason: 'skipped: no pinned version (VCS, path or file dependency)' })
        continue
      }
      deps.push({ name: normalizePyName(name), version: m[1].trim(), ecosystem: 'PyPI', dev })
    }
  }
  return { deps, skipped }
}
