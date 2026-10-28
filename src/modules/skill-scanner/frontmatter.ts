import { frontmatterRange } from './classify'

/**
 * Parser for the small YAML subset used in SKILL.md / agent frontmatter:
 * - `key: scalar` (plain, 'single' or "double" quoted)
 * - block scalars `key: |` / `key: >` (with -, + chomping indicators)
 * - block lists (`key:` followed by `- item` lines) and flow lists `[a, b]`
 * - one level of nested mapping (`metadata:` followed by indented `k: v`)
 * Anything else is recorded as an error but parsing continues. Not a general YAML parser.
 */

export type FmValue = string | string[] | Record<string, string>

export interface Frontmatter {
  data: Record<string, FmValue>
  /** 1-based line number of each top-level key in the file. */
  lines: Record<string, number>
  errors: string[]
  /** 1-based line of the closing delimiter. */
  endLine: number
}

function unquote(raw: string): string {
  const v = raw.trim()
  if (v.length >= 2 && v.startsWith("'") && v.endsWith("'")) return v.slice(1, -1).replace(/''/g, "'")
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
    return v.slice(1, -1).replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (_, e: string) => {
      if (e[0] === 'u' || e[0] === 'x') return String.fromCharCode(parseInt(e.slice(1), 16))
      return ({ n: '\n', t: '\t', r: '\r', '0': '\0', '"': '"', '\\': '\\', '/': '/' } as Record<string, string>)[e] ?? e
    })
  }
  // Plain scalar: strip a trailing " # comment".
  return v.replace(/\s#.*$/, '').trim()
}

function splitFlowList(raw: string): string[] {
  const inner = raw.trim().slice(1, -1)
  const out: string[] = []
  let cur = ''
  let q: string | undefined
  for (const ch of inner) {
    if (q) {
      cur += ch
      if (ch === q) q = undefined
    } else if (ch === '"' || ch === "'") {
      q = ch
      cur += ch
    } else if (ch === ',') {
      out.push(unquote(cur))
      cur = ''
    } else cur += ch
  }
  if (cur.trim() !== '') out.push(unquote(cur))
  return out.filter((s) => s !== '')
}

const KEY_RE = /^([A-Za-z0-9_][A-Za-z0-9_.-]{0,100})\s{0,10}:(?:\s(.*))?$/
const indentOf = (l: string) => l.length - l.trimStart().length

export function parseFrontmatter(text: string): Frontmatter | undefined {
  const lines = text.split(/\r\n|\r|\n/)
  const range = frontmatterRange(lines)
  if (!range) return undefined
  // Null-prototype maps: keys come from untrusted YAML ("__proto__", "constructor"…).
  const fm: Frontmatter = { data: Object.create(null) as Frontmatter['data'], lines: Object.create(null) as Frontmatter['lines'], errors: [], endLine: range.end + 1 }
  let i = range.start
  while (i < range.end) {
    const line = lines[i]
    if (line.trim() === '' || line.trimStart().startsWith('#')) {
      i++
      continue
    }
    if (indentOf(line) > 0) {
      fm.errors.push(`Line ${i + 1}: unexpected indentation`)
      i++
      continue
    }
    const m = KEY_RE.exec(line)
    if (!m) {
      fm.errors.push(`Line ${i + 1}: not a "key: value" pair`)
      i++
      continue
    }
    const key = m[1]
    const rest = (m[2] ?? '').trim()
    fm.lines[key] = i + 1
    i++
    if (/^[|>][+-]?\d?\s*(?:#.*)?$/.test(rest)) {
      // Block scalar.
      const folded = rest[0] === '>'
      const chomp = rest.includes('-') ? 'strip' : rest.includes('+') ? 'keep' : 'clip'
      const body: string[] = []
      let ind = -1
      while (i < range.end) {
        const l = lines[i]
        if (l.trim() === '') {
          body.push('')
          i++
          continue
        }
        const n = indentOf(l)
        if (ind < 0) ind = n
        if (n < ind || n === 0) break
        body.push(l.slice(ind))
        i++
      }
      let value = folded ? body.join('\n').replace(/([^\n])\n(?=[^\n])/g, '$1 ') : body.join('\n')
      if (chomp === 'strip') value = value.replace(/\n+$/, '')
      else if (chomp === 'clip') value = value.replace(/\n+$/, '') + '\n'
      fm.data[key] = chomp === 'clip' ? value.replace(/\n$/, '') : value
      continue
    }
    if (rest === '') {
      // Block list or nested map (or empty value).
      const items: string[] = []
      const map = Object.create(null) as Record<string, string>
      let isMap = false
      while (i < range.end) {
        const l = lines[i]
        if (l.trim() === '') {
          i++
          continue
        }
        if (indentOf(l) === 0 && !l.startsWith('-')) break
        const t = l.trim()
        if (t.startsWith('- ') || t === '-') items.push(unquote(t.slice(1)))
        else {
          const km = KEY_RE.exec(t)
          if (km) {
            isMap = true
            map[km[1]] = unquote(km[2] ?? '')
          } else fm.errors.push(`Line ${i + 1}: unsupported YAML construct`)
        }
        i++
      }
      fm.data[key] = isMap ? map : items.length > 0 ? items : ''
      continue
    }
    if (rest.startsWith('[') && rest.endsWith(']')) {
      fm.data[key] = splitFlowList(rest)
      continue
    }
    // Plain multi-line continuation (indented lines after a plain scalar).
    let value = rest
    while (i < range.end && lines[i].trim() !== '' && indentOf(lines[i]) > 0 && !/^\s+-\s/.test(lines[i])) {
      value += ' ' + lines[i].trim()
      i++
    }
    fm.data[key] = unquote(value)
  }
  return fm
}

export function fmString(v: FmValue | undefined): string | undefined {
  if (v === undefined) return undefined
  if (typeof v === 'string') return v
  if (Array.isArray(v)) return v.join(' ')
  return Object.entries(v)
    .map(([k, x]) => `${k}: ${x}`)
    .join('\n')
}

/**
 * allowed-tools accepts a space- or comma-separated string or a YAML list. Splits on separators
 * outside parentheses so "Bash(git add *)" stays one entry.
 */
export function splitToolList(v: FmValue | undefined): string[] {
  if (v === undefined) return []
  const parts = Array.isArray(v) ? v : typeof v === 'string' ? [v] : Object.keys(v)
  const out: string[] = []
  for (const p of parts) {
    let depth = 0
    let cur = ''
    for (const ch of p) {
      if (ch === '(') depth++
      if (ch === ')') depth = Math.max(0, depth - 1)
      if (depth === 0 && (ch === ',' || /\s/.test(ch))) {
        if (cur.trim()) out.push(cur.trim())
        cur = ''
      } else cur += ch
    }
    if (cur.trim()) out.push(cur.trim())
  }
  return out
}
