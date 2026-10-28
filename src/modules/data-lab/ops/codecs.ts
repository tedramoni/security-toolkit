/* Pure codecs used by the Encoding operations. Own implementations (no third-party code). */
import { hexVal } from '../engine/bytes'
import type { Bytes } from '../engine/types'
import { OpError } from '../engine/types'

/* ---------- Base32 (RFC 4648 §6) ---------- */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const B32_HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV'

export function base32Encode(bytes: Uint8Array, alphabet = B32, pad = true): string {
  let out = ''
  let buffer = 0
  let bits = 0
  for (let i = 0; i < bytes.length; i++) {
    buffer = (buffer << 8) | bytes[i]
    bits += 8
    while (bits >= 5) {
      out += alphabet[(buffer >>> (bits - 5)) & 31]
      bits -= 5
    }
    buffer &= (1 << bits) - 1
  }
  if (bits > 0) out += alphabet[(buffer << (5 - bits)) & 31]
  if (pad) while (out.length % 8 !== 0) out += '='
  return out
}

export function base32Decode(input: string, alphabet = B32): Bytes {
  const out: number[] = []
  let buffer = 0
  let bits = 0
  let padSeen = false
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]
    if (ch === ' ' || ch === '\n' || ch === '\r' || ch === '\t') continue
    if (ch === '=') {
      padSeen = true
      continue
    }
    const v = alphabet.indexOf(ch.toUpperCase())
    if (v < 0) throw new OpError(`Invalid Base32 character '${ch}' at position ${i}`)
    if (padSeen) throw new OpError(`Invalid Base32: data after padding at position ${i}`)
    buffer = ((buffer << 5) | v) & 0xffff
    bits += 5
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Uint8Array.from(out)
}

/* ---------- Base58 (Bitcoin alphabet) ---------- */

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
/** Base58 is O(n²); larger inputs are refused to keep the tab responsive. */
export const BASE58_MAX_BYTES = 64 * 1024

export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  const digits: number[] = [] // base-58 digits, little-endian
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let out = '1'.repeat(zeros)
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]]
  return out
}

export function base58Decode(input: string): Bytes {
  const s = input.trim()
  let zeros = 0
  while (zeros < s.length && s[zeros] === '1') zeros++
  const bytes: number[] = [] // little-endian
  for (let i = zeros; i < s.length; i++) {
    const v = B58.indexOf(s[i])
    if (v < 0) throw new OpError(`Invalid Base58 character '${s[i]}' at position ${i}`)
    let carry = v
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58
      bytes[j] = carry & 255
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 255)
      carry >>= 8
    }
  }
  const out = new Uint8Array(zeros + bytes.length)
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i]
  return out
}

/* ---------- Ascii85 (Adobe variant, 'z' for all-zero groups) ---------- */

export function ascii85Encode(bytes: Uint8Array, delimiters = false): string {
  let out = delimiters ? '<~' : ''
  for (let i = 0; i < bytes.length; i += 4) {
    const n = Math.min(4, bytes.length - i)
    let v = 0
    for (let j = 0; j < 4; j++) v = v * 256 + (j < n ? bytes[i + j] : 0)
    if (n === 4 && v === 0) {
      out += 'z'
      continue
    }
    const chars = new Array<string>(5)
    for (let j = 4; j >= 0; j--) {
      chars[j] = String.fromCharCode(33 + (v % 85))
      v = Math.floor(v / 85)
    }
    out += chars.slice(0, n + 1).join('')
  }
  return out + (delimiters ? '~>' : '')
}

export function ascii85Decode(input: string): Bytes {
  let s = input.trim()
  if (s.startsWith('<~')) s = s.slice(2)
  if (s.endsWith('~>')) s = s.slice(0, -2)
  const out: number[] = []
  const group: number[] = []
  const flush = (len: number) => {
    let v = 0
    for (let j = 0; j < 5; j++) v = v * 85 + (j < len ? group[j] : 84)
    if (v > 0xffffffff) throw new OpError('Invalid Ascii85: group value exceeds 32 bits')
    const b = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]
    for (let j = 0; j < len - 1; j++) out.push(b[j])
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 32 || c === 9 || c === 10 || c === 13 || c === 12) continue
    if (c === 122) {
      if (group.length !== 0) throw new OpError(`Invalid Ascii85: 'z' inside a group at position ${i}`)
      out.push(0, 0, 0, 0)
      continue
    }
    if (c < 33 || c > 117) throw new OpError(`Invalid Ascii85 character '${s[i]}' at position ${i}`)
    group.push(c - 33)
    if (group.length === 5) {
      flush(5)
      group.length = 0
    }
  }
  if (group.length === 1) throw new OpError('Invalid Ascii85: final group has a single character')
  if (group.length > 0) flush(group.length)
  return Uint8Array.from(out)
}

/* ---------- URL (percent) encoding, byte-level ---------- */

const UNRESERVED_COMPONENT = /[A-Za-z0-9\-_.!~*'()]/
const URI_RESERVED = /[;,/?:@&=+$#]/

export type UrlEncodeMode = 'component' | 'uri' | 'all'

/** Percent-encode bytes. 'component' ≡ encodeURIComponent, 'uri' ≡ encodeURI, 'all' encodes every byte. */
export function urlEncode(bytes: Uint8Array, mode: UrlEncodeMode): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]
    const ch = String.fromCharCode(b)
    const keep = mode !== 'all' && b < 0x80 && (UNRESERVED_COMPONENT.test(ch) || (mode === 'uri' && URI_RESERVED.test(ch)))
    out += keep ? ch : '%' + b.toString(16).toUpperCase().padStart(2, '0')
  }
  return out
}

/** Decode %XX sequences at byte level. Malformed sequences are kept literally. */
export function urlDecode(bytes: Uint8Array, plusAsSpace: boolean): Bytes {
  const out = new Uint8Array(bytes.length)
  let o = 0
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]
    if (b === 0x25 && i + 2 < bytes.length) {
      const hi = hexVal(bytes[i + 1])
      const lo = hexVal(bytes[i + 2])
      if (hi >= 0 && lo >= 0) {
        out[o++] = (hi << 4) | lo
        i += 2
        continue
      }
    }
    out[o++] = plusAsSpace && b === 0x2b ? 0x20 : b
  }
  return out.slice(0, o)
}

/* ---------- HTML entities ---------- */

/** HTML 4 Latin-1 entity names for U+00A0..U+00FF, in code point order. */
export const LATIN1_ENTITY_NAMES = (
  'nbsp iexcl cent pound curren yen brvbar sect uml copy ordf laquo not shy reg macr deg plusmn sup2 sup3 acute micro ' +
  'para middot cedil sup1 ordm raquo frac14 frac12 frac34 iquest Agrave Aacute Acirc Atilde Auml Aring AElig Ccedil ' +
  'Egrave Eacute Ecirc Euml Igrave Iacute Icirc Iuml ETH Ntilde Ograve Oacute Ocirc Otilde Ouml times Oslash Ugrave ' +
  'Uacute Ucirc Uuml Yacute THORN szlig agrave aacute acirc atilde auml aring aelig ccedil egrave eacute ecirc euml ' +
  'igrave iacute icirc iuml eth ntilde ograve oacute ocirc otilde ouml divide oslash ugrave uacute ucirc uuml yacute ' +
  'thorn yuml'
).split(' ')

const GREEK_UPPER = 'Alpha Beta Gamma Delta Epsilon Zeta Eta Theta Iota Kappa Lambda Mu Nu Xi Omicron Pi Rho - Sigma Tau Upsilon Phi Chi Psi Omega'.split(' ')
const GREEK_LOWER = 'alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigmaf sigma tau upsilon phi chi psi omega'.split(' ')

const OTHER_ENTITIES: Record<string, number> = {
  Tab: 9, NewLine: 10, excl: 33, quot: 34, num: 35, dollar: 36, percnt: 37, amp: 38, apos: 39, lpar: 40, rpar: 41,
  ast: 42, plus: 43, comma: 44, period: 46, sol: 47, colon: 58, semi: 59, lt: 60, equals: 61, gt: 62, quest: 63,
  commat: 64, lsqb: 91, lbrack: 91, bsol: 92, rsqb: 93, rbrack: 93, lowbar: 95, grave: 96, lcub: 123, lbrace: 123,
  verbar: 124, vert: 124, rcub: 125, rbrace: 125,
  OElig: 338, oelig: 339, Scaron: 352, scaron: 353, Yuml: 376, fnof: 402, circ: 710, tilde: 732, thetasym: 977,
  upsih: 978, piv: 982, ensp: 8194, emsp: 8195, thinsp: 8201, zwnj: 8204, zwj: 8205, lrm: 8206, rlm: 8207,
  ndash: 8211, mdash: 8212, lsquo: 8216, rsquo: 8217, sbquo: 8218, ldquo: 8220, rdquo: 8221, bdquo: 8222,
  dagger: 8224, Dagger: 8225, bull: 8226, hellip: 8230, permil: 8240, prime: 8242, Prime: 8243, lsaquo: 8249,
  rsaquo: 8250, oline: 8254, frasl: 8260, euro: 8364, image: 8465, weierp: 8472, real: 8476, trade: 8482,
  alefsym: 8501, larr: 8592, uarr: 8593, rarr: 8594, darr: 8595, harr: 8596, crarr: 8629, lArr: 8656, uArr: 8657,
  rArr: 8658, dArr: 8659, hArr: 8660, forall: 8704, part: 8706, exist: 8707, empty: 8709, nabla: 8711, isin: 8712,
  notin: 8713, ni: 8715, prod: 8719, sum: 8721, minus: 8722, lowast: 8727, radic: 8730, prop: 8733, infin: 8734,
  ang: 8736, and: 8743, or: 8744, cap: 8745, cup: 8746, int: 8747, there4: 8756, sim: 8764, cong: 8773,
  asymp: 8776, ne: 8800, equiv: 8801, le: 8804, ge: 8805, sub: 8834, sup: 8835, nsub: 8836, sube: 8838, supe: 8839,
  oplus: 8853, otimes: 8855, perp: 8869, sdot: 8901, lceil: 8968, rceil: 8969, lfloor: 8970, rfloor: 8971,
  lang: 9001, rang: 9002, loz: 9674, spades: 9824, clubs: 9827, hearts: 9829, diams: 9830,
}

export const NAMED_ENTITIES: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>()
  LATIN1_ENTITY_NAMES.forEach((n, i) => m.set(n, 0xa0 + i))
  GREEK_UPPER.forEach((n, i) => n !== '-' && m.set(n, 913 + i))
  GREEK_LOWER.forEach((n, i) => m.set(n, 945 + i))
  for (const [n, c] of Object.entries(OTHER_ENTITIES)) m.set(n, c)
  return m
})()

/** Preferred name for each code point when encoding (first-registered name wins; short punctuation names excluded). */
const ENCODE_NAMES: ReadonlyMap<number, string> = (() => {
  const m = new Map<number, string>()
  for (const [name, cp] of NAMED_ENTITIES) {
    if (cp < 0x80 && !['quot', 'amp', 'lt', 'gt', 'apos'].includes(name)) continue
    if (!m.has(cp)) m.set(cp, name)
  }
  m.set(39, '#39') // &apos; is not HTML 4; &#39; works everywhere
  return m
})()

/** HTML numeric references to C1 controls are remapped per the HTML spec (windows-1252 table). */
const C1_REMAP: Record<number, number> = {
  0x80: 0x20ac, 0x82: 0x201a, 0x83: 0x0192, 0x84: 0x201e, 0x85: 0x2026, 0x86: 0x2020, 0x87: 0x2021, 0x88: 0x02c6,
  0x89: 0x2030, 0x8a: 0x0160, 0x8b: 0x2039, 0x8c: 0x0152, 0x8e: 0x017d, 0x91: 0x2018, 0x92: 0x2019, 0x93: 0x201c,
  0x94: 0x201d, 0x95: 0x2022, 0x96: 0x2013, 0x97: 0x2014, 0x98: 0x02dc, 0x99: 0x2122, 0x9a: 0x0161, 0x9b: 0x203a,
  0x9c: 0x0153, 0x9e: 0x017e, 0x9f: 0x0178,
}

export type HtmlEncodeMode = 'minimal' | 'named' | 'decimal' | 'hex'

const HTML_SPECIAL = new Set([38, 60, 62, 34, 39])

export function htmlEncode(text: string, mode: HtmlEncodeMode, all = false): string {
  let out = ''
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0
    const special = HTML_SPECIAL.has(cp)
    const nonAscii = cp > 0x7e
    if (!all && !special && (mode === 'minimal' || !nonAscii)) {
      out += ch
      continue
    }
    if (mode === 'minimal' || mode === 'named') {
      const name = ENCODE_NAMES.get(cp)
      if (name) {
        out += `&${name};`
        continue
      }
    }
    out += mode === 'hex' ? `&#x${cp.toString(16).toUpperCase()};` : `&#${cp};`
  }
  return out
}

const ENTITY_RE = /&(?:#([0-9]{1,8});?|#[xX]([0-9a-fA-F]{1,8});?|([A-Za-z][A-Za-z0-9]{1,31});)/g

export function htmlDecode(text: string): string {
  return text.replace(ENTITY_RE, (m, dec: string | undefined, hex: string | undefined, name: string | undefined) => {
    if (name !== undefined) {
      const cp = NAMED_ENTITIES.get(name)
      return cp === undefined ? m : String.fromCodePoint(cp)
    }
    let cp = dec !== undefined ? parseInt(dec, 10) : parseInt(hex ?? '', 16)
    if (C1_REMAP[cp] !== undefined) cp = C1_REMAP[cp]
    if (cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '�'
    return String.fromCodePoint(cp)
  })
}

/* ---------- Unicode escapes ---------- */

export type UnicodeEscapeStyle = 'u' | 'ubrace' | 'uplus'

export function unicodeEscape(text: string, style: UnicodeEscapeStyle, all: boolean): string {
  let out = ''
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0
    if (!all && cp >= 0x20 && cp < 0x7f) {
      out += ch
      continue
    }
    if (style === 'u') {
      for (let i = 0; i < ch.length; i++) out += '\\u' + ch.charCodeAt(i).toString(16).toUpperCase().padStart(4, '0')
    } else if (style === 'ubrace') {
      out += '\\u{' + cp.toString(16).toUpperCase() + '}'
    } else {
      out += 'U+' + cp.toString(16).toUpperCase().padStart(4, '0')
    }
  }
  return out
}

const UNESCAPE_RE = /\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|U\+([0-9a-fA-F]{4,6})(?![0-9a-fA-F])/g

/** Decode \uXXXX (surrogate pairs combine naturally), \u{…}, \xXX and U+XXXX. */
export function unicodeUnescape(text: string): string {
  return text.replace(UNESCAPE_RE, (m, brace?: string, u4?: string, x2?: string, plus?: string) => {
    if (u4 !== undefined) return String.fromCharCode(parseInt(u4, 16))
    if (x2 !== undefined) return String.fromCharCode(parseInt(x2, 16))
    const cp = parseInt((brace ?? plus) as string, 16)
    return cp <= 0x10ffff ? String.fromCodePoint(cp) : m
  })
}

/* ---------- Quoted-printable (RFC 2045 §6.7) ---------- */

export function quotedPrintableEncode(bytes: Uint8Array): string {
  const lines: { tokens: string[]; crlf: boolean }[] = []
  let cur: string[] = []
  let sawCrlf = false
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]
    if (b === 0x0a) {
      const crlf = cur.length > 0 && cur[cur.length - 1] === '=0D'
      if (crlf) {
        cur.pop()
        sawCrlf = true
      }
      lines.push({ tokens: cur, crlf })
      cur = []
      continue
    }
    if ((b >= 33 && b <= 126 && b !== 61) || b === 32 || b === 9) cur.push(String.fromCharCode(b))
    else cur.push('=' + b.toString(16).toUpperCase().padStart(2, '0'))
  }
  lines.push({ tokens: cur, crlf: false })
  const softBreak = sawCrlf ? '=\r\n' : '=\n'
  let out = ''
  lines.forEach((line, idx) => {
    const t = line.tokens
    // Trailing whitespace before a hard line break (or end of data) must be encoded.
    if (t.length > 0 && (t[t.length - 1] === ' ' || t[t.length - 1] === '\t')) {
      t[t.length - 1] = t[t.length - 1] === ' ' ? '=20' : '=09'
    }
    let len = 0
    for (const tok of t) {
      if (len + tok.length > 75) {
        out += softBreak
        len = 0
      }
      out += tok
      len += tok.length
    }
    if (idx < lines.length - 1) out += line.crlf ? '\r\n' : '\n'
  })
  return out
}

export function quotedPrintableDecode(bytes: Uint8Array): Bytes {
  const out = new Uint8Array(bytes.length)
  let o = 0
  const n = bytes.length
  for (let i = 0; i < n; i++) {
    const b = bytes[i]
    if (b === 0x20 || b === 0x09) {
      // Trailing whitespace at the end of a line is padding added in transport: drop it.
      let j = i
      while (j < n && (bytes[j] === 0x20 || bytes[j] === 0x09)) j++
      if (j === n || bytes[j] === 0x0a || (bytes[j] === 0x0d && bytes[j + 1] === 0x0a)) {
        i = j - 1
        continue
      }
      for (let k = i; k < j; k++) out[o++] = bytes[k]
      i = j - 1
      continue
    }
    if (b === 0x3d) {
      const hi = i + 1 < n ? hexVal(bytes[i + 1]) : -1
      const lo = i + 2 < n ? hexVal(bytes[i + 2]) : -1
      if (hi >= 0 && lo >= 0) {
        out[o++] = (hi << 4) | lo
        i += 2
        continue
      }
      // Soft line break: '=' [whitespace] (CRLF | LF | end)
      let j = i + 1
      while (j < n && (bytes[j] === 0x20 || bytes[j] === 0x09)) j++
      if (j === n) {
        i = j - 1
        continue
      }
      if (bytes[j] === 0x0a) {
        i = j
        continue
      }
      if (bytes[j] === 0x0d && bytes[j + 1] === 0x0a) {
        i = j + 1
        continue
      }
    }
    out[o++] = b
  }
  return out.slice(0, o)
}

/* ---------- UTF-16 ---------- */

export function utf16Encode(text: string, littleEndian: boolean, bom = false): Bytes {
  const out = new Uint8Array((text.length + (bom ? 1 : 0)) * 2)
  const view = new DataView(out.buffer)
  let o = 0
  if (bom) {
    view.setUint16(0, 0xfeff, littleEndian)
    o = 2
  }
  for (let i = 0; i < text.length; i++, o += 2) view.setUint16(o, text.charCodeAt(i), littleEndian)
  return out
}

export function utf16Decode(bytes: Uint8Array, littleEndian: boolean): string {
  let start = 0
  if (bytes.length >= 2) {
    const bomLE = bytes[0] === 0xff && bytes[1] === 0xfe
    const bomBE = bytes[0] === 0xfe && bytes[1] === 0xff
    if ((littleEndian && bomLE) || (!littleEndian && bomBE)) start = 2
  }
  const units = Math.floor((bytes.length - start) / 2)
  const codes = new Uint16Array(units)
  for (let i = 0; i < units; i++) {
    const a = bytes[start + 2 * i]
    const b = bytes[start + 2 * i + 1]
    codes[i] = littleEndian ? a | (b << 8) : (a << 8) | b
  }
  let out = ''
  for (let i = 0; i < codes.length; i += 0x8000) out += String.fromCharCode(...codes.subarray(i, i + 0x8000))
  if ((bytes.length - start) % 2 === 1) out += '�'
  return out
}

