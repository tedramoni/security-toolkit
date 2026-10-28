import {
  argBool,
  argNum,
  argStr,
  B64_STD,
  B64_URL,
  base64Decode,
  base64Encode,
  bytesToHex,
  hexVal,
  latin1Decode,
  latin1Encode,
  utf8Decode,
  utf8Encode,
} from '../engine/bytes'
import type { Bytes, OpDef } from '../engine/types'
import { OpError } from '../engine/types'
import {
  ascii85Decode,
  ascii85Encode,
  B32_HEX,
  base32Decode,
  base32Encode,
  BASE58_MAX_BYTES,
  base58Decode,
  base58Encode,
  htmlDecode,
  htmlEncode,
  quotedPrintableDecode,
  quotedPrintableEncode,
  unicodeEscape,
  unicodeUnescape,
  urlDecode,
  urlEncode,
  utf16Decode,
  utf16Encode,
} from './codecs'
import type { HtmlEncodeMode, UnicodeEscapeStyle, UrlEncodeMode } from './codecs'
import { DELIMITERS, delimiterArg, sel, textFn, tokens } from './helpers'
import { domainToAscii, domainToUnicode, punycodeDecode, punycodeEncode } from './punycode'

const C = 'Encoding' as const

const t = (s: string): Bytes => utf8Encode(s)

/** Remove 0x / \x prefixes and common separators, then strict-decode hex. */
export function looseHexDecode(text: string): Bytes {
  const s = text.replace(/0x|\\x|%/gi, ' ')
  const out: number[] = []
  let pending = -1
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    const v = hexVal(c)
    if (v >= 0) {
      if (pending < 0) pending = v
      else {
        out.push((pending << 4) | v)
        pending = -1
      }
      continue
    }
    // whitespace , : ; - are separators
    if (c === 32 || c === 9 || c === 10 || c === 13 || c === 44 || c === 58 || c === 59 || c === 45) {
      continue
    }
    throw new OpError(`Invalid hex character '${s[i]}' at position ${i}`)
  }
  if (pending >= 0) throw new OpError('Hex input has an odd number of digits')
  return Uint8Array.from(out)
}

function bytesFromNumberTokens(text: string, radix: number, what: string): Bytes {
  const toks = tokens(text)
  const out = new Uint8Array(toks.length)
  const valid = radix === 2 ? /^[01]{1,8}$/ : radix === 8 ? /^[0-7]{1,3}$/ : /^[0-9]{1,3}$/
  toks.forEach((tok, i) => {
    const v = valid.test(tok) ? parseInt(tok, radix) : NaN
    if (!(v >= 0 && v <= 255)) throw new OpError(`Invalid ${what} byte '${tok.slice(0, 20)}' (token ${i + 1}); values must be 0–255`)
    out[i] = v
  })
  return out
}

export const encodingOps: OpDef[] = [
  {
    id: 'to-base64',
    name: 'To Base64',
    category: C,
    description: 'Encode bytes as Base64 (RFC 4648). The URL-safe alphabet uses - and _ instead of + and /.',
    args: [
      sel('alphabet', 'Alphabet', 'standard', [['standard', 'Standard (A-Z a-z 0-9 + /)'], ['url', 'URL-safe (A-Z a-z 0-9 - _)']]),
      { key: 'padding', label: 'Padding (=)', type: 'boolean', default: true },
    ],
    run: (input, a) => t(base64Encode(input, argStr(a, 'alphabet') === 'url' ? B64_URL : B64_STD, argBool(a, 'padding'))),
  },
  {
    id: 'from-base64',
    name: 'From Base64',
    category: C,
    description: 'Decode Base64 or Base64URL. Whitespace is ignored and padding is optional.',
    args: [sel('alphabet', 'Alphabet', 'auto', [['auto', 'Auto (accept both)'], ['standard', 'Standard'], ['url', 'URL-safe']])],
    run: (input, a) => base64Decode(utf8Decode(input), argStr(a, 'alphabet') as 'auto' | 'standard' | 'url'),
  },
  {
    id: 'to-base32',
    name: 'To Base32',
    category: C,
    description: 'Encode bytes as Base32 (RFC 4648 §6, A-Z 2-7), or the "base32hex" alphabet (§7).',
    args: [
      sel('alphabet', 'Alphabet', 'standard', [['standard', 'Standard (A-Z 2-7)'], ['hex', 'Extended hex (0-9 A-V)']]),
      { key: 'padding', label: 'Padding (=)', type: 'boolean', default: true },
    ],
    run: (input, a) => t(base32Encode(input, argStr(a, 'alphabet') === 'hex' ? B32_HEX : undefined, argBool(a, 'padding'))),
  },
  {
    id: 'from-base32',
    name: 'From Base32',
    category: C,
    description: 'Decode Base32 (RFC 4648). Case-insensitive, padding optional.',
    args: [sel('alphabet', 'Alphabet', 'standard', [['standard', 'Standard (A-Z 2-7)'], ['hex', 'Extended hex (0-9 A-V)']])],
    run: (input, a) => base32Decode(utf8Decode(input), argStr(a, 'alphabet') === 'hex' ? B32_HEX : undefined),
  },
  {
    id: 'to-base58',
    name: 'To Base58',
    category: C,
    description: 'Encode bytes as Base58 with the Bitcoin alphabet (no 0, O, I, l). Leading zero bytes become "1". Max 64 KB.',
    args: [],
    maxInputBytes: BASE58_MAX_BYTES,
    run: (input) => t(base58Encode(input)),
  },
  {
    id: 'from-base58',
    name: 'From Base58',
    category: C,
    description: 'Decode Base58 (Bitcoin alphabet). Does not verify Base58Check checksums. Max 64 KB.',
    args: [],
    maxInputBytes: BASE58_MAX_BYTES,
    run: (input) => base58Decode(utf8Decode(input)),
  },
  {
    id: 'to-base85',
    name: 'To Base85 (Ascii85)',
    category: C,
    description: 'Encode bytes as Ascii85 (Adobe/btoa variant): 4 bytes → 5 chars from ! to u, "z" for four zero bytes.',
    args: [{ key: 'delimiters', label: 'Add <~ ~> delimiters', type: 'boolean', default: false }],
    run: (input, a) => t(ascii85Encode(input, argBool(a, 'delimiters'))),
  },
  {
    id: 'from-base85',
    name: 'From Base85 (Ascii85)',
    category: C,
    description: 'Decode Ascii85. Optional <~ ~> delimiters and whitespace are ignored.',
    args: [],
    run: (input) => ascii85Decode(utf8Decode(input)),
  },
  {
    id: 'to-hex',
    name: 'To Hex',
    category: C,
    description: 'Show each byte as two hex digits, with a delimiter or a 0x / \\x prefix.',
    args: [
      sel('delimiter', 'Delimiter', 'space', [
        ['space', 'Space'],
        ['none', 'None'],
        ['comma', 'Comma'],
        ['colon', 'Colon'],
        ['newline', 'Line feed'],
        ['0x', '0x prefix (0x48, 0x65)'],
        ['\\x', '\\x prefix (\\x48\\x65)'],
      ]),
      sel('case', 'Case', 'lower', [['lower', 'Lower'], ['upper', 'Upper']]),
      { key: 'perLine', label: 'Bytes per line (0 = no wrap)', type: 'number', default: 0, min: 0, max: 1024, integer: true },
    ],
    run: (input, a) => {
      const hex = bytesToHex(input, argStr(a, 'case') === 'upper')
      const d = argStr(a, 'delimiter')
      const perLine = argNum(a, 'perLine')
      const parts: string[] = []
      for (let i = 0; i < input.length; i++) {
        const h = hex.slice(2 * i, 2 * i + 2)
        parts.push(d === '0x' ? '0x' + h : d === '\\x' ? '\\x' + h : h)
      }
      const sep = d === '0x' ? ', ' : d === '\\x' ? '' : DELIMITERS[d] ?? ' '
      if (perLine > 0) {
        const lines: string[] = []
        for (let i = 0; i < parts.length; i += perLine) lines.push(parts.slice(i, i + perLine).join(sep))
        return t(lines.join('\n'))
      }
      return t(parts.join(sep))
    },
  },
  {
    id: 'from-hex',
    name: 'From Hex',
    category: C,
    description: 'Decode hex digits to bytes. Accepts 0x / \\x / % prefixes and space, comma, colon, dash or newline separators.',
    args: [],
    run: (input) => looseHexDecode(utf8Decode(input)),
  },
  {
    id: 'to-binary',
    name: 'To Binary',
    category: C,
    description: 'Show each byte as 8 binary digits.',
    args: [delimiterArg('space')],
    run: (input, a) => t(Array.from(input, (b) => b.toString(2).padStart(8, '0')).join(DELIMITERS[argStr(a, 'delimiter')] ?? ' ')),
  },
  {
    id: 'from-binary',
    name: 'From Binary',
    category: C,
    description: 'Decode binary digits to bytes. Separated groups of up to 8 bits, or one continuous string whose length is a multiple of 8.',
    args: [],
    run: (input) => {
      const text = utf8Decode(input).trim()
      if (/^[01]+$/.test(text)) {
        if (text.length % 8 !== 0) throw new OpError(`Binary string length ${text.length} is not a multiple of 8`)
        const out = new Uint8Array(text.length / 8)
        for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(8 * i, 8 * i + 8), 2)
        return out
      }
      return bytesFromNumberTokens(text, 2, 'binary')
    },
  },
  {
    id: 'to-decimal',
    name: 'To Decimal',
    category: C,
    description: 'Show each byte as a decimal number (0–255).',
    args: [delimiterArg('space', false)],
    run: (input, a) => t(Array.from(input, (b) => String(b)).join(DELIMITERS[argStr(a, 'delimiter')] ?? ' ')),
  },
  {
    id: 'from-decimal',
    name: 'From Decimal',
    category: C,
    description: 'Decode decimal byte values (0–255) separated by spaces, commas, semicolons or newlines.',
    args: [],
    run: (input) => bytesFromNumberTokens(utf8Decode(input), 10, 'decimal'),
  },
  {
    id: 'to-octal',
    name: 'To Octal',
    category: C,
    description: 'Show each byte as an octal number (0–377).',
    args: [delimiterArg('space', false)],
    run: (input, a) => t(Array.from(input, (b) => b.toString(8)).join(DELIMITERS[argStr(a, 'delimiter')] ?? ' ')),
  },
  {
    id: 'from-octal',
    name: 'From Octal',
    category: C,
    description: 'Decode octal byte values (0–377) separated by spaces, commas or newlines.',
    args: [],
    run: (input) => bytesFromNumberTokens(utf8Decode(input), 8, 'octal'),
  },
  {
    id: 'to-charcode',
    name: 'To Charcode',
    category: C,
    description: 'Show each Unicode code point of the UTF-8 text as a number (unlike "To Decimal", which works on bytes).',
    args: [delimiterArg('space', false), sel('base', 'Base', '10', [['10', 'Decimal'], ['16', 'Hex']])],
    run: (input, a) => {
      const base = argStr(a, 'base') === '16' ? 16 : 10
      return t(Array.from(utf8Decode(input), (c) => (c.codePointAt(0) as number).toString(base)).join(DELIMITERS[argStr(a, 'delimiter')] ?? ' '))
    },
  },
  {
    id: 'from-charcode',
    name: 'From Charcode',
    category: C,
    description: 'Turn a list of Unicode code points (decimal or hex, 0x prefix allowed) into UTF-8 text.',
    args: [sel('base', 'Base', '10', [['10', 'Decimal'], ['16', 'Hex']])],
    run: (input, a) => {
      const base = argStr(a, 'base') === '16' ? 16 : 10
      let out = ''
      for (const tok of tokens(utf8Decode(input))) {
        const clean = base === 16 ? tok.replace(/^(0x|\\u|u\+)/i, '') : tok
        const ok = base === 16 ? /^[0-9a-fA-F]{1,6}$/.test(clean) : /^[0-9]{1,7}$/.test(clean)
        const cp = ok ? parseInt(clean, base) : NaN
        if (!(cp >= 0 && cp <= 0x10ffff)) throw new OpError(`Invalid code point '${tok.slice(0, 20)}'`)
        out += String.fromCodePoint(cp)
      }
      return t(out)
    },
  },
  {
    id: 'url-encode',
    name: 'URL Encode',
    category: C,
    description: 'Percent-encode bytes. "Component" matches encodeURIComponent, "URI" keeps reserved characters like encodeURI, "All" encodes every byte.',
    args: [sel('mode', 'Mode', 'component', [['component', 'Component (encodeURIComponent)'], ['uri', 'URI (keep ;,/?:@&=+$#)'], ['all', 'All characters']])],
    run: (input, a) => t(urlEncode(input, argStr(a, 'mode') as UrlEncodeMode)),
  },
  {
    id: 'url-decode',
    name: 'URL Decode',
    category: C,
    description: 'Decode %XX sequences at byte level (invalid sequences are left as-is). Optionally turn + into space (form encoding).',
    args: [{ key: 'plus', label: 'Treat + as space', type: 'boolean', default: true }],
    run: (input, a) => urlDecode(input, argBool(a, 'plus')),
  },
  {
    id: 'html-entity-encode',
    name: 'HTML Entity Encode',
    category: C,
    description: 'Escape & < > " \' as HTML entities, optionally non-ASCII characters too (named where known, else numeric).',
    args: [
      sel('mode', 'Mode', 'minimal', [
        ['minimal', 'Only & < > " \''],
        ['named', 'Also non-ASCII (named where possible)'],
        ['decimal', 'Also non-ASCII, numeric (&#233;)'],
        ['hex', 'Also non-ASCII, hex (&#xE9;)'],
      ]),
      { key: 'all', label: 'Encode every character', type: 'boolean', default: false },
    ],
    run: textFn((s, a) => htmlEncode(s, argStr(a, 'mode') as HtmlEncodeMode, argBool(a, 'all'))),
  },
  {
    id: 'html-entity-decode',
    name: 'HTML Entity Decode',
    category: C,
    description:
      'Decode numeric (&#233; &#xE9;) and common named entities (≈250 HTML 4/5 names; unknown names are left as-is). Follows the HTML rules for invalid code points.',
    args: [],
    run: textFn((s) => htmlDecode(s)),
  },
  {
    id: 'unicode-escape',
    name: 'Escape Unicode',
    category: C,
    description: 'Escape characters as \\uXXXX (UTF-16, surrogate pairs), \\u{X} or U+XXXX.',
    args: [
      sel('style', 'Style', 'u', [['u', '\\uXXXX (JS/JSON/Java)'], ['ubrace', '\\u{XXXX} (ES6/Rust)'], ['uplus', 'U+XXXX']]),
      { key: 'all', label: 'Escape printable ASCII too', type: 'boolean', default: false },
    ],
    run: textFn((s, a) => unicodeEscape(s, argStr(a, 'style') as UnicodeEscapeStyle, argBool(a, 'all'))),
  },
  {
    id: 'unicode-unescape',
    name: 'Unescape Unicode',
    category: C,
    description: 'Decode \\uXXXX (surrogate pairs are combined), \\u{X}, \\xXX and U+XXXX escapes.',
    args: [],
    run: textFn((s) => unicodeUnescape(s)),
  },
  {
    id: 'to-quoted-printable',
    name: 'To Quoted-Printable',
    category: C,
    description: 'MIME quoted-printable encoding (RFC 2045): =XX escapes, lines wrapped at 76 characters with soft breaks.',
    args: [],
    run: (input) => t(quotedPrintableEncode(input)),
  },
  {
    id: 'from-quoted-printable',
    name: 'From Quoted-Printable',
    category: C,
    description: 'Decode MIME quoted-printable (RFC 2045): =XX escapes and = soft line breaks.',
    args: [],
    run: (input) => quotedPrintableDecode(input),
  },
  {
    id: 'to-punycode',
    name: 'To Punycode',
    category: C,
    description:
      'Punycode (RFC 3492). Domain mode converts each non-ASCII label to "xn--…" (lowercase + NFC only; the full UTS #46 mapping is not applied).',
    args: [{ key: 'domain', label: 'Domain name (add xn-- per label)', type: 'boolean', default: true }],
    run: textFn((s, a) => (argBool(a, 'domain') ? s.split(/\r?\n/).map(domainToAscii).join('\n') : punycodeEncode(s))),
  },
  {
    id: 'from-punycode',
    name: 'From Punycode',
    category: C,
    description: 'Decode Punycode (RFC 3492). Domain mode decodes every "xn--" label of each line.',
    args: [{ key: 'domain', label: 'Domain name (decode xn-- labels)', type: 'boolean', default: true }],
    run: textFn((s, a) => (argBool(a, 'domain') ? s.split(/\r?\n/).map(domainToUnicode).join('\n') : punycodeDecode(s.trim()))),
  },
  {
    id: 'decode-text',
    name: 'Decode Text (to UTF-8)',
    category: C,
    description:
      'Interpret bytes in another character encoding and re-encode as UTF-8. Note: browsers treat the "latin1" label as Windows-1252; the ISO-8859-1 option here is the true one-byte-per-code-point mapping.',
    args: [
      sel('encoding', 'Source encoding', 'utf-16le', [
        ['utf-16le', 'UTF-16LE'],
        ['utf-16be', 'UTF-16BE'],
        ['iso-8859-1', 'ISO-8859-1 (Latin-1)'],
        ['windows-1252', 'Windows-1252'],
      ]),
    ],
    run: (input, a) => {
      const enc = argStr(a, 'encoding')
      if (enc === 'utf-16le' || enc === 'utf-16be') return t(utf16Decode(input, enc === 'utf-16le'))
      if (enc === 'iso-8859-1') return t(latin1Decode(input))
      return t(new TextDecoder('windows-1252').decode(input))
    },
  },
  {
    id: 'encode-text',
    name: 'Encode Text (from UTF-8)',
    category: C,
    description: 'Re-encode UTF-8 text as UTF-16LE/BE (optional BOM) or ISO-8859-1. Characters outside Latin-1 are an error or become "?".',
    args: [
      sel('encoding', 'Target encoding', 'utf-16le', [['utf-16le', 'UTF-16LE'], ['utf-16be', 'UTF-16BE'], ['iso-8859-1', 'ISO-8859-1 (Latin-1)']]),
      { key: 'bom', label: 'Add byte order mark (UTF-16)', type: 'boolean', default: false },
      { key: 'replace', label: 'Replace unrepresentable chars with ?', type: 'boolean', default: false },
    ],
    run: (input, a) => {
      const s = utf8Decode(input)
      const enc = argStr(a, 'encoding')
      if (enc === 'iso-8859-1') return latin1Encode(s, argBool(a, 'replace') ? 0x3f : undefined)
      return utf16Encode(s, enc === 'utf-16le', argBool(a, 'bom'))
    },
  },
]
