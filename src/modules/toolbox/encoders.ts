/* Pure, browser-safe encoders / decoders. Nothing here touches the DOM. */

const utf8Encoder = new TextEncoder()

export class DecodeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DecodeError'
  }
}

/* ---------- bytes <-> text ---------- */

export function utf8Bytes(text: string): Uint8Array {
  return utf8Encoder.encode(text)
}

/** Strict UTF-8 decode: throws a DecodeError (with a hex preview) for binary data. */
export function bytesToUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    const preview = bytesToHex(bytes.subarray(0, 32))
    throw new DecodeError(
      `Decoded bytes are not valid UTF-8 text (binary data?). First bytes as hex: ${preview}${bytes.length > 32 ? '…' : ''}`,
    )
  }
}

/* ---------- Base64 / Base64URL ---------- */

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}

/**
 * Decode standard or URL-safe Base64 (padding optional, whitespace ignored).
 * Throws DecodeError on invalid input.
 */
export function base64ToBytes(input: string): Uint8Array {
  let s = input.replace(/\s+/g, '')
  if (!/^[A-Za-z0-9+/\-_]*={0,2}$/.test(s)) {
    throw new DecodeError('Invalid Base64: contains characters outside the Base64/Base64URL alphabet')
  }
  s = s.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/')
  if (s.length % 4 === 1) throw new DecodeError('Invalid Base64: impossible length (truncated input?)')
  s += '='.repeat((4 - (s.length % 4)) % 4)
  let binary: string
  try {
    binary = atob(s)
  } catch {
    throw new DecodeError('Invalid Base64 input')
  }
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export function base64Encode(text: string): string {
  return bytesToBase64(utf8Bytes(text))
}

export function base64Decode(input: string): string {
  return bytesToUtf8(base64ToBytes(input))
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64UrlEncode(text: string): string {
  return bytesToBase64Url(utf8Bytes(text))
}

export function base64UrlDecode(input: string): string {
  return base64Decode(input)
}

/* ---------- URL ---------- */

export function urlEncode(text: string): string {
  return encodeURIComponent(text)
}

export function urlDecode(text: string): string {
  try {
    return decodeURIComponent(text)
  } catch {
    throw new DecodeError('Malformed percent-encoding (e.g. a lone "%" or an invalid UTF-8 sequence)')
  }
}

/* ---------- HTML entities ---------- */

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

/** Escape the five HTML-significant characters (safe for element content and quoted attributes). */
export function htmlEncode(text: string): string {
  return text.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c])
}

/** Common named entities. Unknown named entities are left untouched. */
const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  copy: '©', reg: '®', trade: '™', hellip: '…', mdash: '—', ndash: '–',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', laquo: '«', raquo: '»',
  bull: '•', middot: '·', deg: '°', plusmn: '±', times: '×', divide: '÷',
  euro: '€', pound: '£', yen: '¥', cent: '¢', sect: '§', para: '¶',
  eacute: 'é', egrave: 'è', ecirc: 'ê', agrave: 'à', aacute: 'á', ccedil: 'ç',
  ouml: 'ö', uuml: 'ü', auml: 'ä', szlig: 'ß', grave: '`', colon: ':',
  sol: '/', bsol: '\\', lpar: '(', rpar: ')', equals: '=', num: '#',
  semi: ';', excl: '!', quest: '?', lowbar: '_', Tab: '\t', NewLine: '\n',
}

function codePointToString(cp: number): string {
  if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '�'
  return String.fromCodePoint(cp)
}

/**
 * Decode HTML character references with a manual parser — never injects input into a DOM.
 * Supports &#123; &#x7B; (semicolon optional for numeric refs) and common named entities.
 */
export function htmlDecode(text: string): string {
  return text.replace(/&(?:#[xX]([0-9a-fA-F]{1,8});?|#([0-9]{1,10});?|([A-Za-z][A-Za-z0-9]{1,31});)/g, (m, hex, dec, name) => {
    if (hex !== undefined) return codePointToString(parseInt(hex, 16))
    if (dec !== undefined) return codePointToString(parseInt(dec, 10))
    return Object.hasOwn(NAMED_ENTITIES, name) ? NAMED_ENTITIES[name] : m
  })
}

/* ---------- Hex ---------- */

export function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

export function hexEncode(text: string): string {
  return bytesToHex(utf8Bytes(text))
}

/** Accepts "48656c6c6f", "48 65 6c", "48:65:6c", "0x48 0x65" and "\x48\x65". */
export function hexToBytes(input: string): Uint8Array {
  const s = input.replace(/0x|\\x/gi, '').replace(/[\s:,-]+/g, '')
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new DecodeError('Invalid hex: only 0-9 and a-f are allowed')
  if (s.length % 2 !== 0) throw new DecodeError('Invalid hex: odd number of digits')
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function hexDecode(input: string): string {
  return bytesToUtf8(hexToBytes(input))
}

/* ---------- Unicode escapes ---------- */

/** Escape every non-printable-ASCII UTF-16 code unit as \uXXXX (JavaScript / JSON compatible). */
export function unicodeEscape(text: string): string {
  let out = ''
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i)
    if (code >= 0x20 && code < 0x7f && code !== 0x5c) out += text[i]
    else out += '\\u' + code.toString(16).padStart(4, '0')
  }
  return out
}

/** Reverse \uXXXX, \u{XXXXX}, \xHH escapes (and \\). Other text is kept as-is. */
export function unicodeUnescape(text: string): string {
  return text.replace(/\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\\\/g, (_m, braced, u4, x2) => {
    if (braced !== undefined) return codePointToString(parseInt(braced, 16))
    if (u4 !== undefined) return String.fromCharCode(parseInt(u4, 16))
    if (x2 !== undefined) return String.fromCharCode(parseInt(x2, 16))
    return '\\'
  })
}

/* ---------- Hashes ---------- */

export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'

export async function hashHex(algorithm: HashAlgorithm, text: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new DecodeError('WebCrypto is unavailable (hashes require a secure context: https:// or localhost)')
  }
  const digest = await crypto.subtle.digest(algorithm, utf8Bytes(text) as Uint8Array<ArrayBuffer>)
  return bytesToHex(new Uint8Array(digest))
}

/* ---------- Operation registry for the UI ---------- */

export interface Operation {
  id: string
  label: string
  group: 'Base64' | 'URL' | 'HTML' | 'Hex' | 'Unicode' | 'Hash'
  run: (input: string) => string | Promise<string>
  note?: string
}

export const OPERATIONS: readonly Operation[] = [
  { id: 'b64-enc', label: 'Base64 encode', group: 'Base64', run: base64Encode },
  { id: 'b64-dec', label: 'Base64 decode', group: 'Base64', run: base64Decode },
  { id: 'b64url-enc', label: 'Base64URL encode', group: 'Base64', run: base64UrlEncode },
  { id: 'b64url-dec', label: 'Base64URL decode', group: 'Base64', run: base64UrlDecode },
  { id: 'url-enc', label: 'URL encode', group: 'URL', run: urlEncode, note: 'encodeURIComponent: encodes everything except A-Z a-z 0-9 - _ . ! ~ * \' ( )' },
  { id: 'url-dec', label: 'URL decode', group: 'URL', run: urlDecode, note: 'decodeURIComponent: "+" is NOT turned into a space (that is form encoding).' },
  { id: 'html-enc', label: 'HTML encode', group: 'HTML', run: htmlEncode, note: 'Escapes & < > " \' — correct for HTML text and quoted attributes, NOT for JavaScript, CSS or URL contexts.' },
  { id: 'html-dec', label: 'HTML decode', group: 'HTML', run: htmlDecode },
  { id: 'hex-enc', label: 'Hex encode', group: 'Hex', run: hexEncode },
  { id: 'hex-dec', label: 'Hex decode', group: 'Hex', run: hexDecode },
  { id: 'uni-esc', label: 'Unicode escape', group: 'Unicode', run: unicodeEscape },
  { id: 'uni-unesc', label: 'Unicode unescape', group: 'Unicode', run: unicodeUnescape },
  { id: 'sha1', label: 'SHA-1', group: 'Hash', run: (s) => hashHex('SHA-1', s), note: 'SHA-1 is broken for collision resistance (SHAttered, 2017). Use only for legacy compatibility, never for signatures or integrity.' },
  { id: 'sha256', label: 'SHA-256', group: 'Hash', run: (s) => hashHex('SHA-256', s) },
  { id: 'sha384', label: 'SHA-384', group: 'Hash', run: (s) => hashHex('SHA-384', s) },
  { id: 'sha512', label: 'SHA-512', group: 'Hash', run: (s) => hashHex('SHA-512', s) },
]
