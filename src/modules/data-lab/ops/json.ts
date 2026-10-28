/* JSON helpers. Beautify/minify re-tokenise the text instead of parse+stringify, so numbers keep full precision
 * (no 2^53 rounding), key order and duplicate keys are preserved exactly. */
import { OpError } from '../engine/types'

export interface JsonErrorInfo {
  message: string
  line?: number
  column?: number
  position?: number
}

/** Line/column (1-based) for an offset. */
export function lineCol(text: string, pos: number): { line: number; column: number } {
  let line = 1
  let last = -1
  for (let i = 0; i < pos && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      line++
      last = i
    }
  }
  return { line, column: pos - last }
}

const WS = new Set([' ', '\t', '\n', '\r'])
const NUMBER_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y

/**
 * Offset of the first syntax error in a JSON text (RFC 8259), or -1 if valid. Iterative (no recursion), linear.
 * Engines differ in whether their JSON.parse messages include a position, so we compute it ourselves.
 */
export function jsonErrorOffset(t: string): number {
  const stack: string[] = []
  type Expect = 'value' | 'valueOrEnd' | 'key' | 'keyOrEnd' | 'colon' | 'commaOrEnd' | 'done'
  // Cast: the closure below reassigns `expect`, which TypeScript's narrowing does not see.
  let expect = 'value' as Expect
  const afterValue = () => {
    expect = stack.length ? 'commaOrEnd' : 'done'
  }
  let i = 0
  const scanString = (): boolean => {
    // t[i] === '"'
    i++
    while (i < t.length) {
      const c = t.charCodeAt(i)
      if (c === 34) {
        i++
        return true
      }
      if (c < 0x20) return false
      if (c === 92) {
        const n = t[i + 1]
        if (n === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(t.slice(i + 2, i + 6))) return false
          i += 6
        } else if (n !== undefined && '"\\/bfnrt'.includes(n)) i += 2
        else return false
      } else i++
    }
    return false
  }
  while (true) {
    while (i < t.length && WS.has(t[i])) i++
    if (i >= t.length) return expect === 'done' ? -1 : i
    const c = t[i]
    switch (expect) {
      case 'done':
        return i
      case 'colon':
        if (c !== ':') return i
        i++
        expect = 'value'
        break
      case 'key':
      case 'keyOrEnd':
        if (expect === 'keyOrEnd' && c === '}') {
          stack.pop()
          i++
          afterValue()
        } else if (c === '"') {
          if (!scanString()) return i
          expect = 'colon'
        } else return i
        break
      case 'commaOrEnd': {
        const top = stack[stack.length - 1]
        if (c === ',') {
          i++
          expect = top === '{' ? 'key' : 'value'
        } else if ((top === '{' && c === '}') || (top === '[' && c === ']')) {
          stack.pop()
          i++
          afterValue()
        } else return i
        break
      }
      case 'value':
      case 'valueOrEnd':
        if (expect === 'valueOrEnd' && c === ']') {
          stack.pop()
          i++
          afterValue()
        } else if (c === '{' || c === '[') {
          stack.push(c)
          i++
          expect = c === '{' ? 'keyOrEnd' : 'valueOrEnd'
        } else if (c === '"') {
          if (!scanString()) return i
          afterValue()
        } else if (t.startsWith('true', i) || t.startsWith('null', i)) {
          i += 4
          afterValue()
        } else if (t.startsWith('false', i)) {
          i += 5
          afterValue()
        } else {
          NUMBER_RE.lastIndex = i
          const m = NUMBER_RE.exec(t)
          if (!m) return i
          i += m[0].length
          afterValue()
        }
        break
    }
  }
}

/** Validate JSON; on error report the engine's message plus our own computed position. */
export function validateJson(text: string): JsonErrorInfo | null {
  try {
    JSON.parse(text)
    return null
  } catch (e) {
    if (e instanceof RangeError) return { message: 'JSON is nested too deeply for this browser' }
    const msg = (e as Error).message
    const position = jsonErrorOffset(text)
    if (position < 0) return { message: msg }
    return { message: msg, position, ...lineCol(text, position) }
  }
}

/** Human-readable error with a caret pointing at the problem. */
export function describeJsonError(text: string, err: JsonErrorInfo): string {
  let out = `Invalid JSON: ${err.message}`
  if (err.line !== undefined && err.column !== undefined) {
    const lines = text.split('\n')
    const src = lines[err.line - 1] ?? ''
    const start = Math.max(0, err.column - 40)
    out += `\nLine ${err.line}, column ${err.column}:\n  ${src.slice(start, start + 80)}\n  ${' '.repeat(Math.max(0, err.column - 1 - start))}^`
  }
  return out
}

function assertValid(text: string): void {
  const err = validateJson(text)
  if (err) throw new OpError(describeJsonError(text, err))
}

/** Re-indent valid JSON. `indent` = '' produces minified output. */
export function formatJson(text: string, indent: string): string {
  assertValid(text)
  const pretty = indent !== ''
  let out = ''
  let depth = 0
  const nl = () => '\n' + indent.repeat(depth)
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (c === '"') {
      let j = i + 1
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1
      out += text.slice(i, j + 1)
      i = j
      continue
    }
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') continue
    if (c === '{' || c === '[') {
      // Keep empty containers compact.
      let j = i + 1
      while (j < text.length && ' \t\n\r'.includes(text[j])) j++
      if (text[j] === (c === '{' ? '}' : ']')) {
        out += c + text[j]
        i = j
        continue
      }
      depth++
      out += c + (pretty ? nl() : '')
    } else if (c === '}' || c === ']') {
      depth--
      out += (pretty ? nl() : '') + c
    } else if (c === ',') {
      out += ',' + (pretty ? nl() : '')
    } else if (c === ':') {
      out += pretty ? ': ' : ':'
    } else out += c
  }
  return out
}

export function jsonSummary(text: string): string {
  assertValid(text)
  const v: unknown = JSON.parse(text)
  const kind = Array.isArray(v) ? `array with ${v.length} item(s)` : v === null ? 'null' : typeof v === 'object' ? `object with ${Object.keys(v as object).length} key(s)` : typeof v
  return `Valid JSON: ${kind}.`
}

/* ---------- CSV ---------- */

const FORMULA_START = /^[=+\-@\t\r]/

export function csvField(value: string, delim: string, guardFormulas: boolean): string {
  let v = value
  if (guardFormulas && FORMULA_START.test(v)) v = "'" + v
  return v.includes('"') || v.includes(delim) || v.includes('\n') || v.includes('\r') || /^\s|\s$/.test(v) ? `"${v.replace(/"/g, '""')}"` : v
}

function cellText(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

/** Array of objects (or arrays) → CSV (RFC 4180). Nested values are written as JSON. */
export function jsonToCsv(text: string, delim: string, guardFormulas: boolean): string {
  assertValid(text)
  const data: unknown = JSON.parse(text)
  const rows = Array.isArray(data) ? data : [data]
  if (rows.length === 0) return ''
  const line = (cells: string[]) => cells.map((c) => csvField(c, delim, guardFormulas)).join(delim)
  if (rows.every((r) => Array.isArray(r))) return (rows as unknown[][]).map((r) => line(r.map(cellText))).join('\r\n')
  const keys: string[] = []
  const seen = new Set<string>()
  for (const r of rows) {
    if (typeof r !== 'object' || r === null || Array.isArray(r)) throw new OpError('Expected an array of objects (or an array of arrays)')
    for (const k of Object.keys(r)) {
      if (seen.has(k)) continue
      seen.add(k)
      keys.push(k)
    }
  }
  const out = [line(keys)]
  for (const r of rows as Record<string, unknown>[]) out.push(line(keys.map((k) => cellText(r[k]))))
  return out.join('\r\n')
}

/** RFC 4180 CSV parser (quoted fields, "" escapes, CRLF/LF). Linear scan. */
export function parseCsv(text: string, delim: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let quoted = false
  let i = 0
  if (text.charCodeAt(0) === 0xfeff) i = 1
  for (; i < text.length; i++) {
    const c = text[i]
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"'
          i++
        } else quoted = false
      } else field += c
      continue
    }
    if (c === '"' && field === '') quoted = true
    else if (c === delim) {
      row.push(field)
      field = ''
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++
      row.push(field)
      rows.push(row)
      row = []
      field = ''
    } else field += c
  }
  if (quoted) throw new OpError('Unterminated quoted field')
  if (field !== '' || row.length > 0) {
    row.push(field)
    rows.push(row)
  }
  return rows
}

export function csvToJson(text: string, delim: string, header: boolean): string {
  const rows = parseCsv(text, delim)
  if (!header) return JSON.stringify(rows, null, 2)
  const [head = [], ...body] = rows
  // Object.fromEntries defines own properties, so a "__proto__" header cannot touch the prototype.
  const objs = body.map((r) => {
    const entries: [string, string][] = head.map((h, i) => [h, r[i] ?? ''])
    if (r.length > head.length) entries.push(['_extra', r.slice(head.length).join(delim)])
    return Object.fromEntries(entries)
  })
  return JSON.stringify(objs, null, 2)
}

export function detectDelimiter(text: string): string {
  const first = text.slice(0, text.indexOf('\n') === -1 ? text.length : text.indexOf('\n'))
  const counts = [',', ';', '\t', '|'].map((d) => [d, first.split(d).length - 1] as const)
  counts.sort((a, b) => b[1] - a[1])
  return counts[0][1] > 0 ? counts[0][0] : ','
}
