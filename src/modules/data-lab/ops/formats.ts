import { decodeJwt } from '../../toolbox/jwt'
import { entropyInterpretation, shannonEntropy } from '../engine/analysis'
import { argBool, argNum, argStr, bytesToHex, printableChar, utf8Decode, utf8Encode } from '../engine/bytes'
import type { Bytes, OpDef } from '../engine/types'
import { OpError } from '../engine/types'
import { looseHexDecode } from './encoding'
import { sel, splitLines, textFn } from './helpers'
import { cidrInfo } from './ip'
import { csvToJson, detectDelimiter, formatJson, jsonSummary, jsonToCsv } from './json'
import { domainToUnicode } from './punycode'

const C = 'Data formats' as const
const U = 'Bytes & utilities' as const

/* ---------- timestamps ---------- */

export type TimeUnit = 'auto' | 's' | 'ms' | 'us' | 'ns'

/** Guess the unit of a Unix timestamp from its magnitude (values for dates between ~1973 and ~5138 are unambiguous). */
export function guessUnit(n: number): Exclude<TimeUnit, 'auto'> {
  const a = Math.abs(n)
  if (a >= 1e17) return 'ns'
  if (a >= 1e14) return 'us'
  if (a >= 1e11) return 'ms'
  return 's'
}

const UNIT_MS: Record<Exclude<TimeUnit, 'auto'>, number> = { s: 1000, ms: 1, us: 1e-3, ns: 1e-6 }

export function unixToIso(token: string, unit: TimeUnit): string {
  if (!/^-?\d{1,20}(\.\d{1,9})?$/.test(token)) return `${token}\tnot a number`
  const n = Number(token)
  const u = unit === 'auto' ? guessUnit(n) : unit
  const ms = n * UNIT_MS[u]
  const d = new Date(Math.floor(ms))
  if (Number.isNaN(d.getTime())) return `${token}\tout of range`
  return `${token}\t${d.toISOString()}\t(${u === 's' ? 'seconds' : u === 'ms' ? 'milliseconds' : u === 'us' ? 'microseconds' : 'nanoseconds'})`
}

export function isoToUnix(line: string, unit: 's' | 'ms', assumeUtc: boolean): string {
  let s = line.trim()
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(s)) s = s.replace(' ', 'T')
  // ECMAScript parses date-time strings without an offset as LOCAL time; date-only strings as UTC.
  if (assumeUtc && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?$/.test(s)) s += 'Z'
  const t = Date.parse(s)
  if (Number.isNaN(t)) return `${line}\tunparseable date (use ISO 8601, e.g. 2024-05-01T12:00:00Z)`
  return `${unit === 's' ? Math.floor(t / 1000) : t}`
}

/* ---------- hexdump ---------- */

export function hexdump(bytes: Uint8Array, width: number, upper = false): string {
  const lines: string[] = []
  for (let off = 0; off < bytes.length; off += width) {
    const row = bytes.subarray(off, off + width)
    let hex = ''
    for (let i = 0; i < width; i++) {
      hex += i < row.length ? bytesToHex(row.subarray(i, i + 1), upper) + ' ' : '   '
      if (i === width / 2 - 1 && width >= 16) hex += ' '
    }
    let ascii = ''
    for (let i = 0; i < row.length; i++) ascii += printableChar(row[i])
    lines.push(`${off.toString(16).padStart(8, '0')}  ${hex} |${ascii}|`)
  }
  if (bytes.length > 0) lines.push(bytes.length.toString(16).padStart(8, '0'))
  return lines.join('\n')
}

/** Parse `hexdump -C`, `xxd` and similar dumps back to bytes. */
export function fromHexdump(text: string): Bytes {
  const parts: string[] = []
  let total = 0 // bytes collected so far
  let lastLine: string[] = []
  let lastLineBytes = 0
  let repeatPending = false
  for (const raw of splitLines(text)) {
    let line = raw
    // `hexdump -C` prints "*" instead of lines identical to the previous one: re-expand them using the next offset.
    if (line.trim() === '*') {
      repeatPending = true
      continue
    }
    const bar = line.indexOf('|')
    if (bar >= 0) line = line.slice(0, bar)
    // offset column: hex digits followed by ':' or whitespace
    const m = /^\s*([0-9A-Fa-f]{4,16}):?(\s+|$)/.exec(line)
    if (!m) continue
    if (repeatPending) {
      repeatPending = false
      const offset = parseInt(m[1], 16)
      if (lastLineBytes === 0 || offset < total || (offset - total) % lastLineBytes !== 0) {
        throw new OpError(`Cannot expand the "*" (repeated lines) before offset ${m[1]}`)
      }
      if (offset - total > MAX_HEXDUMP_EXPANSION) {
        throw new OpError(`The "*" before offset ${m[1]} expands to more than ${MAX_HEXDUMP_EXPANSION / 1024 / 1024} MB`)
      }
      parts.push(lastLine.join('').repeat((offset - total) / lastLineBytes))
      total = offset
    }
    let body = line.slice(m[0].length)
    if (bar < 0) {
      // xxd style: hex area and ASCII are separated by two or more spaces
      const sep = /\s{2,}/.exec(body)
      if (sep) body = body.slice(0, sep.index)
    }
    const toks: string[] = []
    let n = 0
    for (const tok of body.trim().split(/\s+/)) {
      if (tok === '') continue
      if (!/^(?:[0-9A-Fa-f]{2}){1,16}$/.test(tok)) throw new OpError(`Unexpected token '${tok.slice(0, 20)}' in hexdump line: ${raw.slice(0, 60)}`)
      toks.push(tok)
      n += tok.length / 2
    }
    if (n > 0) {
      parts.push(...toks)
      total += n
      lastLine = toks
      lastLineBytes = n
    }
  }
  return looseHexDecode(parts.join(''))
}

/** Cap on how much a single "*" line of a hexdump may expand to. */
export const MAX_HEXDUMP_EXPANSION = 64 * 1024 * 1024

/* ---------- character info ---------- */

export function describeChar(ch: string): string {
  const cp = ch.codePointAt(0) as number
  const flags: string[] = []
  if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f || cp === 0x061c) {
    flags.push('BIDI CONTROL (Trojan Source risk)')
  } else if (/\p{Cf}/u.test(ch)) flags.push('invisible format char')
  else if (/\p{Cc}/u.test(ch)) flags.push('control')
  else if (/\p{Zs}/u.test(ch) && cp !== 0x20) flags.push('non-ASCII space')
  if (cp >= 0xe000 && cp <= 0xf8ff) flags.push('private use')
  const shown = /[\p{Cc}\p{Cf}\p{Zs}\p{Zl}\p{Zp}]/u.test(ch) ? '·' : ch
  const utf8 = bytesToHex(utf8Encode(ch)).replace(/(..)(?!$)/g, '$1 ')
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}\t${shown}\tUTF-8: ${utf8}${flags.length ? '\t⚠ ' + flags.join(', ') : ''}`
}

/* ---------- UUID ---------- */

export function generateUuid(version: 'v4' | 'v7', now = Date.now()): string {
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  if (version === 'v7') {
    let ms = now
    for (let i = 5; i >= 0; i--) {
      b[i] = ms % 256
      ms = Math.floor(ms / 256)
    }
    b[6] = 0x70 | (b[6] & 0x0f)
  } else b[6] = 0x40 | (b[6] & 0x0f)
  b[8] = 0x80 | (b[8] & 0x3f)
  const h = bytesToHex(b)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

const GREGORIAN_OFFSET_100NS = 122192928000000000n // 1582-10-15 → 1970-01-01 in 100 ns intervals

export function parseUuid(input: string): string {
  const s = input.trim().replace(/^urn:uuid:/i, '').replace(/^\{|\}$/g, '')
  if (!/^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$/.test(s)) {
    throw new OpError(`'${input.trim().slice(0, 60)}' is not a UUID`)
  }
  const h = s.replace(/-/g, '').toLowerCase()
  const canon = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
  const lines = [`UUID:      ${canon}`]
  if (/^0+$/.test(h)) return [...lines, 'Type:      Nil UUID (RFC 9562 §5.9)'].join('\n')
  if (/^f+$/.test(h)) return [...lines, 'Type:      Max UUID (RFC 9562 §5.10)'].join('\n')
  const variantNibble = parseInt(h[16], 16)
  const variant =
    variantNibble < 8 ? 'NCS (reserved, legacy)' : variantNibble < 12 ? 'RFC 9562 / RFC 4122' : variantNibble < 14 ? 'Microsoft GUID (reserved)' : 'Reserved (future)'
  const version = parseInt(h[12], 16)
  lines.push(`Variant:   ${variant}`)
  if (variantNibble < 8 || variantNibble >= 12) return lines.join('\n')
  const names: Record<number, string> = {
    1: 'time-based (Gregorian, MAC/node)',
    2: 'DCE security',
    3: 'name-based (MD5)',
    4: 'random',
    5: 'name-based (SHA-1)',
    6: 'reordered time-based',
    7: 'Unix-epoch time-based',
    8: 'custom / vendor-specific',
  }
  lines.push(`Version:   ${version} — ${names[version] ?? 'unknown'}`)
  const toIso = (ms: bigint) => {
    const d = new Date(Number(ms))
    return Number.isNaN(d.getTime()) ? 'out of range' : d.toISOString()
  }
  if (version === 1 || version === 6) {
    const t =
      version === 1
        ? (BigInt('0x' + h.slice(13, 16)) << 48n) | (BigInt('0x' + h.slice(8, 12)) << 32n) | BigInt('0x' + h.slice(0, 8))
        : (BigInt('0x' + h.slice(0, 8)) << 28n) | (BigInt('0x' + h.slice(8, 12)) << 12n) | BigInt('0x' + h.slice(13, 16))
    lines.push(`Timestamp: ${toIso((t - GREGORIAN_OFFSET_100NS) / 10000n)}`)
    lines.push(`Clock seq: ${parseInt(h.slice(16, 20), 16) & 0x3fff}`)
    const node = h.slice(20)
    const multicast = (parseInt(node.slice(0, 2), 16) & 1) === 1
    lines.push(`Node:      ${node.replace(/(..)(?!$)/g, '$1:')}${multicast ? ' (random node ID — multicast bit set)' : ' (may be a real MAC address)'}`)
  } else if (version === 7) {
    lines.push(`Timestamp: ${toIso(BigInt('0x' + h.slice(0, 12)))}`)
  } else if (version === 4) {
    lines.push('Contains 122 random bits; no embedded data.')
  }
  return lines.join('\n')
}

/* ---------- number base conversion ---------- */

const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz'

export function parseBigInt(token: string, base: number | 'auto'): bigint {
  let t = token.trim().toLowerCase().replace(/_/g, '')
  let neg = false
  if (t.startsWith('-')) {
    neg = true
    t = t.slice(1)
  } else if (t.startsWith('+')) t = t.slice(1)
  let b = base === 'auto' ? 10 : base
  if (base === 'auto' || base === 16 || base === 2 || base === 8) {
    const pre = t.slice(0, 2)
    const map: Record<string, number> = { '0x': 16, '0b': 2, '0o': 8 }
    if (map[pre] && (base === 'auto' || map[pre] === base)) {
      b = map[pre]
      t = t.slice(2)
    }
  }
  if (t === '' || t.length > 4096) throw new OpError(`Invalid number '${token.slice(0, 30)}'`)
  let v = 0n
  const B = BigInt(b)
  for (const ch of t) {
    const d = DIGITS.indexOf(ch)
    if (d < 0 || d >= b) throw new OpError(`'${token.slice(0, 30)}' is not a valid base-${b} number`)
    v = v * B + BigInt(d)
  }
  return neg ? -v : v
}

/* ---------- ops ---------- */

const indentArg = sel('indent', 'Indent', '2', [['2', '2 spaces'], ['4', '4 spaces'], ['tab', 'Tab']])
const csvDelimArg = sel('delimiter', 'Delimiter', 'comma', [['comma', 'Comma'], ['semicolon', 'Semicolon'], ['tab', 'Tab'], ['pipe', 'Pipe']])
const CSV_DELIMS: Record<string, string> = { comma: ',', semicolon: ';', tab: '\t', pipe: '|', auto: '' }

export const formatOps: OpDef[] = [
  {
    id: 'json-beautify',
    name: 'JSON Beautify',
    category: C,
    description: 'Pretty-print JSON. Re-indents the original tokens, so large numbers, key order and duplicate keys are preserved exactly.',
    args: [indentArg],
    run: textFn((s, a) => formatJson(s.trim(), argStr(a, 'indent') === 'tab' ? '\t' : ' '.repeat(Number(argStr(a, 'indent'))))),
  },
  {
    id: 'json-minify',
    name: 'JSON Minify',
    category: C,
    description: 'Remove all insignificant whitespace from JSON (tokens preserved exactly).',
    args: [],
    run: textFn((s) => formatJson(s.trim(), '')),
  },
  {
    id: 'json-validate',
    name: 'JSON Validate',
    category: C,
    description: 'Check that the input is valid JSON. Errors show the line, column and a caret.',
    args: [],
    run: textFn((s) => jsonSummary(s.trim())),
  },
  {
    id: 'json-to-csv',
    name: 'JSON to CSV',
    category: C,
    description:
      'Convert an array of flat objects (or arrays) to RFC 4180 CSV. Nested values are written as JSON. Formula protection prefixes cells starting with = + - @ with a quote (CSV injection).',
    args: [csvDelimArg, { key: 'guard', label: 'Protect against formula injection', type: 'boolean', default: true }],
    run: textFn((s, a) => jsonToCsv(s.trim(), CSV_DELIMS[argStr(a, 'delimiter')], argBool(a, 'guard'))),
  },
  {
    id: 'csv-to-json',
    name: 'CSV to JSON',
    category: C,
    description: 'Parse RFC 4180 CSV (quoted fields, "" escapes) to JSON — an array of objects using the header row, or an array of arrays.',
    args: [
      sel('delimiter', 'Delimiter', 'auto', [['auto', 'Auto-detect'], ['comma', 'Comma'], ['semicolon', 'Semicolon'], ['tab', 'Tab'], ['pipe', 'Pipe']]),
      { key: 'header', label: 'First row is a header', type: 'boolean', default: true },
    ],
    run: textFn((s, a) => {
      const d = argStr(a, 'delimiter') === 'auto' ? detectDelimiter(s) : CSV_DELIMS[argStr(a, 'delimiter')]
      return csvToJson(s, d, argBool(a, 'header'))
    }),
  },
  {
    id: 'jwt-decode',
    name: 'JWT Decode',
    category: C,
    description: 'Decode a JWT\'s header and payload to JSON. The signature is NOT verified. Use the Dev Toolbox JWT tab to lint the token.',
    args: [],
    run: textFn((s) => {
      try {
        const jwt = decodeJwt(s)
        const out =
          jwt.kind === 'JWE'
            ? { header: jwt.header, note: 'JWE: the payload is encrypted and cannot be decoded without the key' }
            : {
                header: jwt.header,
                payload: jwt.payload ?? jwt.payloadText,
                signature: { present: jwt.signaturePresent, bytes: jwt.signatureBytes, verified: false },
              }
        return JSON.stringify(out, null, 2)
      } catch (e) {
        throw new OpError((e as Error).message)
      }
    }),
  },
  {
    id: 'parse-url',
    name: 'Parse URL',
    category: C,
    description: 'Split an absolute URL into scheme, credentials, host, port, path, query parameters and fragment (WHATWG URL parser).',
    args: [],
    run: textFn((s) => {
      let u: URL
      try {
        u = new URL(s.trim())
      } catch {
        throw new OpError('Not an absolute URL — include the scheme, e.g. https://')
      }
      const host = u.hostname
      let unicodeHost = host
      try {
        unicodeHost = domainToUnicode(host)
      } catch {
        /* keep ASCII */
      }
      const lines = [
        `Scheme:     ${u.protocol.replace(/:$/, '')}`,
        ...(u.username ? [`Username:   ${decodeURIComponentSafe(u.username)}`] : []),
        ...(u.password ? [`Password:   ${decodeURIComponentSafe(u.password)}  ⚠ credentials embedded in URL`] : []),
        `Host:       ${host}${unicodeHost !== host ? `  (Unicode: ${unicodeHost})` : ''}`,
        `Port:       ${u.port || '(default)'}`,
        `Path:       ${u.pathname}`,
        `Query:      ${u.search || '(none)'}`,
        `Fragment:   ${u.hash || '(none)'}`,
        `Origin:     ${u.origin}`,
      ]
      const params = [...u.searchParams]
      if (params.length) {
        lines.push('', 'Query parameters:')
        for (const [k, v] of params) lines.push(`  ${k} = ${v}`)
      }
      return lines.join('\n')
    }),
  },
  {
    id: 'parse-query',
    name: 'Parse Query String',
    category: C,
    description: 'List the key = value pairs of a query string (a full URL or the part after "?"), decoded with form rules.',
    args: [],
    run: textFn((s) => {
      let q = s.trim()
      const qi = q.indexOf('?')
      if (qi >= 0) q = q.slice(qi + 1)
      const hi = q.indexOf('#')
      if (hi >= 0) q = q.slice(0, hi)
      return [...new URLSearchParams(q)].map(([k, v]) => `${k} = ${v}`).join('\n')
    }),
  },
  {
    id: 'unix-to-iso',
    name: 'Unix Timestamp → ISO 8601',
    category: C,
    description: 'Convert Unix timestamps (one per line) to UTC ISO 8601. Auto mode picks s/ms/µs/ns by magnitude.',
    args: [sel('unit', 'Unit', 'auto', [['auto', 'Auto-detect'], ['s', 'Seconds'], ['ms', 'Milliseconds'], ['us', 'Microseconds'], ['ns', 'Nanoseconds']])],
    run: textFn((s, a) =>
      splitLines(s)
        .map((l) => l.trim())
        .filter((l) => l !== '')
        .map((l) => unixToIso(l, argStr(a, 'unit') as TimeUnit))
        .join('\n'),
    ),
  },
  {
    id: 'iso-to-unix',
    name: 'ISO 8601 → Unix Timestamp',
    category: C,
    description: 'Convert dates (one per line) to Unix time. Without an explicit offset, ISO date-times are read as UTC (option) — JavaScript would use local time.',
    args: [
      sel('unit', 'Unit', 's', [['s', 'Seconds'], ['ms', 'Milliseconds']]),
      { key: 'utc', label: 'Assume UTC when no offset is given', type: 'boolean', default: true },
    ],
    run: textFn((s, a) =>
      splitLines(s)
        .filter((l) => l.trim() !== '')
        .map((l) => isoToUnix(l, argStr(a, 'unit') as 's', argBool(a, 'utc')))
        .join('\n'),
    ),
  },
  {
    id: 'to-hexdump',
    name: 'To Hexdump',
    category: C,
    description: 'Classic offset + hex + ASCII dump (like hexdump -C).',
    args: [
      sel('width', 'Bytes per line', '16', [['8', '8'], ['16', '16'], ['32', '32']]),
      { key: 'upper', label: 'Upper-case hex', type: 'boolean', default: false },
    ],
    run: (input, a) => utf8Encode(hexdump(input, Number(argStr(a, 'width')), argBool(a, 'upper'))),
  },
  {
    id: 'from-hexdump',
    name: 'From Hexdump',
    category: C,
    description: 'Turn a hexdump -C / xxd / similar dump back into bytes (offset and ASCII columns are ignored).',
    args: [],
    run: (input) => fromHexdump(utf8Decode(input)),
  },
  {
    id: 'char-info',
    name: 'Character Info',
    category: C,
    description:
      'List each character with its code point and UTF-8 bytes, flagging invisible, control and bidirectional characters (Trojan Source, CVE-2021-42574). First 10,000 characters.',
    args: [{ key: 'onlySuspicious', label: 'Only list non-ASCII / invisible characters', type: 'boolean', default: false }],
    run: textFn((s, a) => {
      const chars = Array.from(s).slice(0, 10000)
      const only = argBool(a, 'onlySuspicious')
      return chars
        .map((ch, i) => [ch, i] as const)
        .filter(([ch]) => !only || !/^[\x20-\x7e\n\r\t]$/.test(ch))
        .map(([ch, i]) => `${String(i).padStart(5)}  ${describeChar(ch)}`)
        .join('\n')
    }),
  },
  {
    id: 'entropy',
    name: 'Entropy',
    category: U,
    description: 'Shannon entropy in bits per byte (0–8) with an interpretation. Short inputs score low by nature (max is log2(length)).',
    args: [],
    run: (input) => {
      const h = shannonEntropy(input)
      const lines = [
        `Shannon entropy:  ${h.toFixed(4)} bits/byte (${((h / 8) * 100).toFixed(1)}% of maximum)`,
        `Interpretation:   ${entropyInterpretation(h)}`,
        `Bytes analysed:   ${input.length}`,
      ]
      if (input.length > 0 && input.length < 256) lines.push(`Note:             with only ${input.length} bytes the maximum possible is ${Math.log2(input.length).toFixed(2)}`)
      return utf8Encode(lines.join('\n'))
    },
  },
  {
    id: 'frequency',
    name: 'Frequency Distribution',
    category: U,
    description: 'Byte histogram: count and percentage of each byte value.',
    args: [
      sel('sort', 'Sort by', 'count', [['count', 'Count'], ['byte', 'Byte value']]),
      { key: 'showZero', label: 'Include bytes that never occur', type: 'boolean', default: false },
    ],
    run: (input, a) => {
      const counts = new Array<number>(256).fill(0)
      for (let i = 0; i < input.length; i++) counts[input[i]]++
      let rows = counts.map((n, b) => ({ b, n })).filter((r) => argBool(a, 'showZero') || r.n > 0)
      if (argStr(a, 'sort') === 'count') rows = rows.sort((x, y) => y.n - x.n || x.b - y.b)
      const max = Math.max(1, ...counts)
      const distinct = counts.filter((n) => n > 0).length
      const out = [`Total bytes: ${input.length}   Distinct values: ${distinct}/256`, '']
      for (const { b, n } of rows) {
        const pct = input.length ? ((n / input.length) * 100).toFixed(2).padStart(6) : '  0.00'
        out.push(`0x${b.toString(16).padStart(2, '0')}  ${printableChar(b)}  ${String(n).padStart(9)}  ${pct}%  ${'#'.repeat(Math.round((n / max) * 40))}`)
      }
      return utf8Encode(out.join('\n'))
    },
  },
  {
    id: 'cidr-info',
    name: 'IP / CIDR Info',
    category: C,
    description: 'Network, broadcast, netmask, host range, address count and special-purpose range (RFC 6890) for IPv4/IPv6 addresses or CIDR blocks, one per line.',
    args: [],
    run: textFn((s) =>
      splitLines(s)
        .map((l) => l.trim())
        .filter((l) => l !== '')
        .map((l) => cidrInfo(l))
        .join('\n\n'),
    ),
  },
  {
    id: 'uuid-generate',
    name: 'Generate UUID',
    category: U,
    description: 'Generate random v4 or time-ordered v7 UUIDs (RFC 9562) with crypto.getRandomValues. Ignores the input.',
    nondeterministic: true,
    args: [
      sel('version', 'Version', 'v4', [['v4', 'v4 (random)'], ['v7', 'v7 (Unix time + random)']]),
      { key: 'count', label: 'How many', type: 'number', default: 1, min: 1, max: 10000, integer: true },
    ],
    run: (_input, a) => {
      const now = Date.now()
      const list = Array.from({ length: argNum(a, 'count') }, () => generateUuid(argStr(a, 'version') as 'v4', now))
      // v7 UUIDs generated in the same millisecond are sorted so the output stays monotonic.
      if (argStr(a, 'version') === 'v7') list.sort()
      return utf8Encode(list.join('\n'))
    },
  },
  {
    id: 'uuid-parse',
    name: 'Parse UUID',
    category: C,
    description: 'Show a UUID\'s version and variant, and decode the timestamp of v1, v6 and v7 UUIDs (one per line).',
    args: [],
    run: textFn((s) =>
      splitLines(s)
        .filter((l) => l.trim() !== '')
        .map(parseUuid)
        .join('\n\n'),
    ),
  },
  {
    id: 'base-convert',
    name: 'Number Base Conversion',
    category: U,
    description: 'Convert whitespace-separated integers of any size between bases 2–36 (BigInt). Auto-detects 0x, 0b and 0o prefixes.',
    args: [
      { key: 'from', label: 'From base (0 = auto)', type: 'number', default: 0, min: 0, max: 36, integer: true },
      { key: 'to', label: 'To base', type: 'number', default: 16, min: 2, max: 36, integer: true },
      { key: 'prefix', label: 'Add 0x / 0b / 0o prefix', type: 'boolean', default: false },
    ],
    run: textFn((s, a) => {
      const from = argNum(a, 'from')
      if (from === 1) throw new OpError('Base 1 is not supported')
      const to = argNum(a, 'to')
      const prefix = argBool(a, 'prefix') ? ({ 16: '0x', 2: '0b', 8: '0o' } as Record<number, string>)[to] ?? '' : ''
      return splitLines(s)
        .map((line) =>
          line
            .split(/\s+/)
            .filter((t) => t !== '')
            .map((t) => {
              const v = parseBigInt(t, from === 0 ? 'auto' : from)
              return (v < 0n ? '-' : '') + prefix + (v < 0n ? -v : v).toString(to)
            })
            .join(' '),
        )
        .join('\n')
    }),
  },
  {
    id: 'take-bytes',
    name: 'Take Bytes',
    category: U,
    description: 'Keep a slice of the input bytes: offset and length (length 0 = to the end).',
    args: [
      { key: 'offset', label: 'Offset', type: 'number', default: 0, min: 0, max: Number.MAX_SAFE_INTEGER, integer: true },
      { key: 'length', label: 'Length (0 = rest)', type: 'number', default: 16, min: 0, max: Number.MAX_SAFE_INTEGER, integer: true },
    ],
    run: (input, a) => {
      const off = argNum(a, 'offset')
      const len = argNum(a, 'length')
      return input.slice(off, len === 0 ? undefined : off + len)
    },
  },
  {
    id: 'drop-bytes',
    name: 'Drop Bytes',
    category: U,
    description: 'Remove a range of bytes: offset and length (length 0 = to the end).',
    args: [
      { key: 'offset', label: 'Offset', type: 'number', default: 0, min: 0, max: Number.MAX_SAFE_INTEGER, integer: true },
      { key: 'length', label: 'Length (0 = rest)', type: 'number', default: 1, min: 0, max: Number.MAX_SAFE_INTEGER, integer: true },
    ],
    run: (input, a) => {
      const off = Math.min(argNum(a, 'offset'), input.length)
      const len = argNum(a, 'length')
      const end = len === 0 ? input.length : Math.min(input.length, off + len)
      const out = new Uint8Array(input.length - (end - off))
      out.set(input.subarray(0, off))
      out.set(input.subarray(end), off)
      return out
    },
  },
]

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}
