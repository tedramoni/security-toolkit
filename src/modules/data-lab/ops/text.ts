import { argBool, argNum, argStr, utf8Encode } from '../engine/bytes'
import type { ArgValues, OpDef } from '../engine/types'
import { OpError } from '../engine/types'
import { DELIMITERS, delimiterArg, sel, splitLines, textFn } from './helpers'

const C = 'Text' as const

/**
 * User-supplied regular expressions can backtrack catastrophically. Guards: the pattern length and the input size
 * are capped here, and the whole recipe runs in a Web Worker that the UI terminates after a timeout.
 */
export const MAX_REGEX_INPUT = 2 * 1024 * 1024
export const MAX_PATTERN_LENGTH = 1000
/** Upper bound on the output size of Pad Lines (characters). */
export const MAX_PAD_OUTPUT = 64 * 1024 * 1024

export function buildUserRegex(pattern: string, flags: string, inputLength: number): RegExp {
  if (pattern === '') throw new OpError('The regular expression is empty')
  if (pattern.length > MAX_PATTERN_LENGTH) throw new OpError(`Pattern is longer than ${MAX_PATTERN_LENGTH} characters`)
  if (inputLength > MAX_REGEX_INPUT) {
    throw new OpError(`Regex operations are limited to ${MAX_REGEX_INPUT / 1024 / 1024} MB of input to avoid freezing on catastrophic backtracking`)
  }
  try {
    return new RegExp(pattern, flags)
  } catch (e) {
    // Engines already prefix the message with "Invalid regular expression:"; don't repeat it.
    throw new OpError(`Invalid regular expression: ${(e as Error).message.replace(/^Invalid regular expression:\s*/i, '')}`)
  }
}

function regexFlags(a: ArgValues, global: boolean): string {
  return (global ? 'g' : '') + (argBool(a, 'caseInsensitive') ? 'i' : '') + (argBool(a, 'multiline') ? 'm' : '') + (argBool(a, 'dotAll') ? 's' : '') + 'u'
}

const regexFlagArgs = [
  { key: 'caseInsensitive', label: 'Case-insensitive (i)', type: 'boolean', default: false },
  { key: 'multiline', label: 'Multiline ^$ (m)', type: 'boolean', default: true },
  { key: 'dotAll', label: 'Dot matches newline (s)', type: 'boolean', default: false },
] as const

export function titleCase(s: string): string {
  return s.toLowerCase().replace(/(^|[^\p{L}\p{N}'’])(\p{L})/gu, (_m, pre: string, ch: string) => pre + ch.toUpperCase())
}

/** Split an identifier or phrase into words: separators, lower→Upper and ACRONYMWord boundaries. */
export function splitWords(s: string): string[] {
  const words: string[] = []
  let cur = ''
  const chars = Array.from(s)
  const isUpper = (c: string) => c !== c.toLowerCase() && c === c.toUpperCase()
  const isLower = (c: string) => c !== c.toUpperCase() && c === c.toLowerCase()
  const isAlnum = (c: string) => /[\p{L}\p{N}]/u.test(c)
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i]
    if (!isAlnum(c)) {
      if (cur) words.push(cur)
      cur = ''
      continue
    }
    if (cur) {
      const prev = chars[i - 1]
      const next = chars[i + 1] ?? ''
      const lowerToUpper = isUpper(c) && (isLower(prev) || /\p{N}/u.test(prev))
      const acronymEnd = isUpper(c) && isUpper(prev) && isLower(next)
      if (lowerToUpper || acronymEnd) {
        words.push(cur)
        cur = ''
      }
    }
    cur += c
  }
  if (cur) words.push(cur)
  return words
}

export function toCase(line: string, style: 'snake' | 'camel' | 'kebab' | 'pascal' | 'constant'): string {
  const w = splitWords(line).map((x) => x.toLowerCase())
  switch (style) {
    case 'snake':
      return w.join('_')
    case 'constant':
      return w.join('_').toUpperCase()
    case 'kebab':
      return w.join('-')
    case 'camel':
      return w.map((x, i) => (i === 0 ? x : x.charAt(0).toUpperCase() + x.slice(1))).join('')
    case 'pascal':
      return w.map((x) => x.charAt(0).toUpperCase() + x.slice(1)).join('')
  }
}

const JS_ESCAPES: Record<string, string> = { '\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f', '\v': '\\v', '\0': '\\0' }

export function escapeString(s: string, quote: 'single' | 'double' | 'backtick', escapeNonAscii: boolean): string {
  const q = quote === 'single' ? "'" : quote === 'double' ? '"' : '`'
  let out = ''
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number
    if (JS_ESCAPES[ch] !== undefined) {
      // \0 followed by a digit would read as an octal escape — use \x00 instead.
      out += ch === '\0' ? '\\x00' : JS_ESCAPES[ch]
    } else if (ch === q) out += '\\' + ch
    else if (quote === 'backtick' && ch === '$') out += '\\$'
    else if (cp < 0x20 || cp === 0x7f) out += '\\x' + cp.toString(16).padStart(2, '0')
    else if (escapeNonAscii && cp > 0x7e) {
      for (let i = 0; i < ch.length; i++) out += '\\u' + ch.charCodeAt(i).toString(16).padStart(4, '0')
    } else out += ch
  }
  return out
}

const SIMPLE_UNESCAPES: Record<string, string> = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', '0': '\0' }

/** Interpret JS/C-style backslash escapes. Unknown escapes yield the escaped character. Linear scan. */
export function unescapeString(s: string): string {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    if (ch !== '\\' || i === s.length - 1) {
      out += ch
      continue
    }
    const n = s[++i]
    if (SIMPLE_UNESCAPES[n] !== undefined && !(n === '0' && /[0-9]/.test(s[i + 1] ?? ''))) {
      out += SIMPLE_UNESCAPES[n]
    } else if (n === 'x' && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 1, i + 3))) {
      out += String.fromCharCode(parseInt(s.slice(i + 1, i + 3), 16))
      i += 2
    } else if (n === 'u' && s[i + 1] === '{') {
      const end = s.indexOf('}', i + 2)
      const hex = end > 0 ? s.slice(i + 2, end) : ''
      const cp = /^[0-9a-fA-F]{1,6}$/.test(hex) ? parseInt(hex, 16) : NaN
      if (cp <= 0x10ffff) {
        out += String.fromCodePoint(cp)
        i = end
      } else out += 'u'
    } else if (n === 'u' && /^[0-9a-fA-F]{4}$/.test(s.slice(i + 1, i + 5))) {
      out += String.fromCharCode(parseInt(s.slice(i + 1, i + 5), 16))
      i += 4
    } else if (n === '\r' && s[i + 1] === '\n') {
      i++ // line continuation
    } else if (n === '\n') {
      // line continuation
    } else out += n
  }
  return out
}

export function countReport(text: string, bytes: number): string {
  const lines = text === '' ? 0 : splitLines(text).length
  const words = (text.match(/[^\s]+/g) ?? []).length
  const codePoints = Array.from(text).length
  let graphemes = codePoints
  try {
    const Seg = (Intl as unknown as { Segmenter?: new (l?: string, o?: { granularity: string }) => { segment(s: string): Iterable<unknown> } }).Segmenter
    if (Seg) graphemes = Array.from(new Seg(undefined, { granularity: 'grapheme' }).segment(text)).length
  } catch {
    /* Segmenter unavailable */
  }
  return [
    `Bytes:            ${bytes}`,
    `Characters:       ${graphemes} (user-perceived)`,
    `Code points:      ${codePoints}`,
    `UTF-16 units:     ${text.length}`,
    `Words:            ${words}`,
    `Lines:            ${lines}`,
  ].join('\n')
}

const lineFn = (fn: (lines: string[], a: ArgValues) => string[]) => textFn((s, a) => fn(splitLines(s), a).join('\n'))

export const textOps: OpDef[] = [
  {
    id: 'upper-case',
    name: 'Upper Case',
    category: C,
    description: 'Convert text to UPPER CASE (Unicode-aware).',
    args: [],
    run: textFn((s) => s.toUpperCase()),
  },
  {
    id: 'lower-case',
    name: 'Lower Case',
    category: C,
    description: 'Convert text to lower case (Unicode-aware).',
    args: [],
    run: textFn((s) => s.toLowerCase()),
  },
  {
    id: 'title-case',
    name: 'Title Case',
    category: C,
    description: 'Capitalise the first letter of every word, lower-case the rest.',
    args: [],
    run: textFn((s) => titleCase(s)),
  },
  {
    id: 'to-case',
    name: 'To snake / camel / kebab case',
    category: C,
    description: 'Convert each line to snake_case, camelCase, kebab-case, PascalCase or CONSTANT_CASE.',
    args: [sel('style', 'Style', 'snake', [['snake', 'snake_case'], ['camel', 'camelCase'], ['kebab', 'kebab-case'], ['pascal', 'PascalCase'], ['constant', 'CONSTANT_CASE']])],
    run: lineFn((lines, a) => lines.map((l) => toCase(l, argStr(a, 'style') as 'snake'))),
  },
  {
    id: 'reverse',
    name: 'Reverse',
    category: C,
    description: 'Reverse the order of characters (code points), lines or raw bytes.',
    args: [sel('by', 'Reverse by', 'chars', [['chars', 'Character'], ['lines', 'Line'], ['bytes', 'Byte']])],
    run: (input, a) => {
      const by = argStr(a, 'by')
      if (by === 'bytes') return input.slice().reverse()
      return textFn((s) => (by === 'lines' ? splitLines(s).reverse().join('\n') : Array.from(s).reverse().join('')))(input, a)
    },
  },
  {
    id: 'sort-lines',
    name: 'Sort Lines',
    category: C,
    description: 'Sort lines alphabetically (locale-independent code-point order) or numerically.',
    args: [
      sel('order', 'Order', 'asc', [['asc', 'Ascending'], ['desc', 'Descending']]),
      sel('compare', 'Compare', 'alpha', [['alpha', 'Alphabetical'], ['alpha-ci', 'Alphabetical, case-insensitive'], ['numeric', 'Numeric (leading number)'], ['length', 'Length']]),
      { key: 'unique', label: 'Remove duplicates', type: 'boolean', default: false },
    ],
    run: lineFn((lines, a) => {
      const cmp = argStr(a, 'compare')
      const key = (l: string): number => {
        const m = /^\s*(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)/i.exec(l)
        return m ? parseFloat(m[1]) : Number.NaN
      }
      const sorted = [...(argBool(a, 'unique') ? [...new Set(lines)] : lines)]
      sorted.sort((x, y) => {
        if (cmp === 'numeric') {
          const kx = key(x)
          const ky = key(y)
          if (Number.isNaN(kx) || Number.isNaN(ky)) return Number.isNaN(kx) ? (Number.isNaN(ky) ? (x < y ? -1 : x > y ? 1 : 0) : 1) : -1
          return kx - ky
        }
        if (cmp === 'length') return x.length - y.length
        const X = cmp === 'alpha-ci' ? x.toLowerCase() : x
        const Y = cmp === 'alpha-ci' ? y.toLowerCase() : y
        return X < Y ? -1 : X > Y ? 1 : 0
      })
      return argStr(a, 'order') === 'desc' ? sorted.reverse() : sorted
    }),
  },
  {
    id: 'unique-lines',
    name: 'Unique Lines',
    category: C,
    description: 'Remove duplicate lines, keeping the first occurrence. Optionally prefix each line with its count.',
    args: [{ key: 'count', label: 'Show occurrence count', type: 'boolean', default: false }],
    run: lineFn((lines, a) => {
      const counts = new Map<string, number>()
      for (const l of lines) counts.set(l, (counts.get(l) ?? 0) + 1)
      return argBool(a, 'count') ? [...counts].map(([l, n]) => `${String(n).padStart(6)} ${l}`) : [...counts.keys()]
    }),
  },
  {
    id: 'remove-blank-lines',
    name: 'Remove Blank Lines',
    category: C,
    description: 'Drop empty or whitespace-only lines.',
    args: [],
    run: lineFn((lines) => lines.filter((l) => l.trim() !== '')),
  },
  {
    id: 'trim',
    name: 'Trim Whitespace',
    category: C,
    description: 'Remove leading/trailing whitespace from each line or from the whole text.',
    args: [
      sel('scope', 'Scope', 'lines', [['lines', 'Each line'], ['all', 'Whole text']]),
      sel('side', 'Side', 'both', [['both', 'Both'], ['start', 'Start'], ['end', 'End']]),
    ],
    run: textFn((s, a) => {
      const side = argStr(a, 'side')
      const f = (x: string) => (side === 'start' ? x.trimStart() : side === 'end' ? x.trimEnd() : x.trim())
      return argStr(a, 'scope') === 'all' ? f(s) : splitLines(s).map(f).join('\n')
    }),
  },
  {
    id: 'find-replace',
    name: 'Find / Replace',
    category: C,
    description:
      'Replace a literal string or a JavaScript regular expression (replacement supports $1, $<name>, $&). Regex input is capped at 2 MB; runaway patterns are stopped by the bake timeout.',
    args: [
      { key: 'find', label: 'Find', type: 'string', default: '' },
      { key: 'replace', label: 'Replace with', type: 'string', default: '' },
      sel('mode', 'Mode', 'literal', [['literal', 'Literal text'], ['regex', 'Regular expression']]),
      { key: 'global', label: 'Replace all (g)', type: 'boolean', default: true },
      ...regexFlagArgs,
    ],
    run: textFn((s, a) => {
      const find = argStr(a, 'find')
      const rep = argStr(a, 'replace')
      if (argStr(a, 'mode') === 'literal') {
        if (find === '') return s
        if (argBool(a, 'caseInsensitive')) {
          const esc = find.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
          return s.replace(new RegExp(esc, argBool(a, 'global') ? 'gi' : 'i'), () => rep)
        }
        return argBool(a, 'global') ? s.split(find).join(rep) : s.replace(find, () => rep)
      }
      return s.replace(buildUserRegex(find, regexFlags(a, argBool(a, 'global')), s.length), rep)
    }),
  },
  {
    id: 'filter-lines',
    name: 'Filter Lines (regex)',
    category: C,
    description: 'Keep (or drop) lines matching a JavaScript regular expression. Input capped at 2 MB.',
    args: [
      { key: 'pattern', label: 'Regex', type: 'string', default: '' },
      { key: 'invert', label: 'Invert (drop matching lines)', type: 'boolean', default: false },
      { key: 'caseInsensitive', label: 'Case-insensitive (i)', type: 'boolean', default: false },
    ],
    run: textFn((s, a) => {
      const re = buildUserRegex(argStr(a, 'pattern'), argBool(a, 'caseInsensitive') ? 'iu' : 'u', s.length)
      const inv = argBool(a, 'invert')
      return splitLines(s)
        .filter((l) => re.test(l) !== inv)
        .join('\n')
    }),
  },
  {
    id: 'split',
    name: 'Split',
    category: C,
    description: 'Split text on a delimiter and put each piece on its own line (or join with another delimiter). Escapes \\n and \\t are understood.',
    args: [
      { key: 'split', label: 'Split on', type: 'string', default: ',' },
      { key: 'join', label: 'Join with', type: 'string', default: '\\n' },
    ],
    run: textFn((s, a) => {
      const sp = unescapeString(argStr(a, 'split'))
      const jn = unescapeString(argStr(a, 'join'))
      return sp === '' ? Array.from(s).join(jn) : s.split(sp).join(jn)
    }),
  },
  {
    id: 'join-lines',
    name: 'Join Lines',
    category: C,
    description: 'Join all lines with a delimiter.',
    args: [delimiterArg('comma')],
    run: textFn((s, a) => splitLines(s).join(DELIMITERS[argStr(a, 'delimiter')] ?? ',')),
  },
  {
    id: 'head',
    name: 'Head',
    category: C,
    description: 'Keep the first N lines.',
    args: [{ key: 'n', label: 'Lines', type: 'number', default: 10, min: 0, max: 10_000_000, integer: true }],
    run: lineFn((lines, a) => lines.slice(0, argNum(a, 'n'))),
  },
  {
    id: 'tail',
    name: 'Tail',
    category: C,
    description: 'Keep the last N lines.',
    args: [{ key: 'n', label: 'Lines', type: 'number', default: 10, min: 0, max: 10_000_000, integer: true }],
    run: lineFn((lines, a) => (argNum(a, 'n') === 0 ? [] : lines.slice(-argNum(a, 'n')))),
  },
  {
    id: 'line-numbers',
    name: 'Add Line Numbers',
    category: C,
    description: 'Prefix every line with its number.',
    args: [{ key: 'start', label: 'Start at', type: 'number', default: 1, min: 0, max: 1e9, integer: true }],
    run: lineFn((lines, a) => {
      const start = argNum(a, 'start')
      const w = String(start + lines.length).length
      return lines.map((l, i) => `${String(start + i).padStart(w)}  ${l}`)
    }),
  },
  {
    id: 'pad-lines',
    name: 'Pad Lines',
    category: C,
    description: 'Pad each line to a width with a character, at the start or end.',
    args: [
      sel('side', 'Side', 'start', [['start', 'Start'], ['end', 'End']]),
      { key: 'width', label: 'Width', type: 'number', default: 10, min: 0, max: 10000, integer: true },
      { key: 'char', label: 'Pad character', type: 'string', default: ' ', maxLength: 8 },
    ],
    run: lineFn((lines, a) => {
      const ch = argStr(a, 'char') || ' '
      const w = argNum(a, 'width')
      // Width × line count can explode (10,000 × millions of lines) and exhaust memory: refuse up front.
      if (w * lines.length > MAX_PAD_OUTPUT) {
        throw new OpError(`Padding ${lines.length.toLocaleString('en-US')} lines to width ${w} would produce more than ${MAX_PAD_OUTPUT / 1024 / 1024} M characters`)
      }
      return lines.map((l) => (argStr(a, 'side') === 'end' ? l.padEnd(w, ch) : l.padStart(w, ch)))
    }),
  },
  {
    id: 'remove-whitespace',
    name: 'Remove Whitespace',
    category: C,
    description: 'Strip selected whitespace characters.',
    args: [
      { key: 'spaces', label: 'Spaces', type: 'boolean', default: true },
      { key: 'tabs', label: 'Tabs', type: 'boolean', default: true },
      { key: 'lf', label: 'Line feeds', type: 'boolean', default: true },
      { key: 'cr', label: 'Carriage returns', type: 'boolean', default: true },
      { key: 'other', label: 'Other Unicode whitespace (NBSP, FF…)', type: 'boolean', default: true },
    ],
    run: textFn((s, a) => {
      let out = ''
      for (const ch of s) {
        if (ch === ' ' ? argBool(a, 'spaces') : ch === '\t' ? argBool(a, 'tabs') : ch === '\n' ? argBool(a, 'lf') : ch === '\r' ? argBool(a, 'cr') : /\s/u.test(ch) && argBool(a, 'other')) continue
        out += ch
      }
      return out
    }),
  },
  {
    id: 'escape-string',
    name: 'Escape String',
    category: C,
    description: 'Escape text for a JavaScript/JSON-style string literal (\\n, \\t, \\", \\xXX, optional \\uXXXX).',
    args: [
      sel('quote', 'Quote', 'double', [['double', 'Double "'], ['single', "Single '"], ['backtick', 'Backtick `']]),
      { key: 'nonAscii', label: 'Escape non-ASCII as \\uXXXX', type: 'boolean', default: false },
    ],
    run: textFn((s, a) => escapeString(s, argStr(a, 'quote') as 'double', argBool(a, 'nonAscii'))),
  },
  {
    id: 'unescape-string',
    name: 'Unescape String',
    category: C,
    description: 'Interpret backslash escapes: \\n \\r \\t \\b \\f \\v \\0 \\xXX \\uXXXX \\u{…} \\\\ \\" \\\'.',
    args: [],
    run: textFn((s) => unescapeString(s)),
  },
  {
    id: 'count',
    name: 'Count',
    category: C,
    description: 'Report bytes, characters (grapheme clusters), code points, UTF-16 units, words and lines.',
    args: [],
    run: (input) => utf8Encode(countReport(new TextDecoder().decode(input), input.length)),
  },
]
