import type { ArgValues, Bytes, ToggleValue } from './types'
import { OpError } from './types'

const encoder = new TextEncoder()
const lenientDecoder = new TextDecoder('utf-8', { fatal: false })

/** Copy any ArrayBufferView / ArrayBuffer into a fresh, plain Bytes value (safe across realms). */
export function toBytes(data: ArrayBuffer | ArrayBufferView | ArrayLike<number>): Bytes {
  // instanceof fails across realms (e.g. buffers from another window/worker or test environments).
  if (Object.prototype.toString.call(data) === '[object ArrayBuffer]') return new Uint8Array((data as ArrayBuffer).slice(0))
  if (ArrayBuffer.isView(data)) {
    const out = new Uint8Array(data.byteLength)
    out.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength))
    return out
  }
  return Uint8Array.from(data as ArrayLike<number>)
}

export function utf8Encode(text: string): Bytes {
  return encoder.encode(text)
}

/** Lenient UTF-8 decode: invalid sequences become U+FFFD. */
export function utf8Decode(bytes: Uint8Array): string {
  return lenientDecoder.decode(bytes)
}

/** True when the bytes are well-formed UTF-8. */
export function isValidUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    return true
  } catch {
    return false
  }
}

/** ISO-8859-1: one byte per code point (U+0000–U+00FF). */
export function latin1Decode(bytes: Uint8Array): string {
  let out = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    out += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return out
}

/** ISO-8859-1 encode. Throws for characters above U+00FF unless a replacement byte is given. */
export function latin1Encode(text: string, replacement?: number): Bytes {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c > 0xff) {
      if (replacement === undefined) {
        throw new OpError(`Character U+${c.toString(16).toUpperCase().padStart(4, '0')} at position ${i} cannot be represented in Latin-1`)
      }
      out[i] = replacement
    } else out[i] = c
  }
  return out
}

const HEX = '0123456789abcdef'

export function bytesToHex(bytes: Uint8Array, upper = false): string {
  const digits = upper ? HEX.toUpperCase() : HEX
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += digits[bytes[i] >> 4] + digits[bytes[i] & 15]
  return out
}

/** Strict hex decode (whitespace ignored, optional 0x prefix). */
export function hexToBytes(input: string): Bytes {
  let s = input.replace(/\s+/g, '')
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2)
  if (s.length % 2 !== 0) throw new OpError('Hex string has an odd number of digits')
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) {
    const hi = hexVal(s.charCodeAt(2 * i))
    const lo = hexVal(s.charCodeAt(2 * i + 1))
    if (hi < 0 || lo < 0) throw new OpError(`Invalid hex digit near position ${2 * i}`)
    out[i] = (hi << 4) | lo
  }
  return out
}

export function hexVal(c: number): number {
  if (c >= 48 && c <= 57) return c - 48
  if (c >= 97 && c <= 102) return c - 87
  if (c >= 65 && c <= 70) return c - 55
  return -1
}

export const B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
export const B64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

export function base64Encode(bytes: Uint8Array, alphabet: string = B64_STD, pad = true): string {
  let out = ''
  let i = 0
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    out += alphabet[n >> 18] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + alphabet[n & 63]
  }
  const rest = bytes.length - i
  if (rest === 1) {
    const n = bytes[i] << 16
    out += alphabet[n >> 18] + alphabet[(n >> 12) & 63] + (pad ? '==' : '')
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8)
    out += alphabet[n >> 18] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + (pad ? '=' : '')
  }
  return out
}

/**
 * Base64 decode. `alphabet`: 'auto' accepts both + / and - _. Whitespace is ignored, padding optional.
 * Throws OpError with the position of the first invalid character.
 */
export function base64Decode(input: string, alphabet: 'auto' | 'standard' | 'url' = 'auto'): Bytes {
  const vals = new Uint8Array(input.length)
  let n = 0
  let padSeen = 0
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i)
    if (c === 32 || c === 9 || c === 10 || c === 13 || c === 12) continue
    if (c === 61) {
      padSeen++
      continue
    }
    let v = -1
    if (c >= 65 && c <= 90) v = c - 65
    else if (c >= 97 && c <= 122) v = c - 71
    else if (c >= 48 && c <= 57) v = c + 4
    else if ((c === 43 && alphabet !== 'url') || (c === 45 && alphabet !== 'standard')) v = 62
    else if ((c === 47 && alphabet !== 'url') || (c === 95 && alphabet !== 'standard')) v = 63
    if (v < 0) {
      throw new OpError(`Invalid Base64 character '${input[i]}' at position ${i}`)
    }
    if (padSeen) throw new OpError(`Invalid Base64: data after padding at position ${i}`)
    vals[n++] = v
  }
  if (padSeen > 2) throw new OpError('Invalid Base64: too much padding')
  if (n % 4 === 1) throw new OpError('Invalid Base64: impossible length (truncated input?)')
  const out = new Uint8Array(Math.floor((n * 3) / 4))
  let o = 0
  let i = 0
  for (; i + 3 < n; i += 4) {
    const x = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3]
    out[o++] = x >> 16
    out[o++] = (x >> 8) & 255
    out[o++] = x & 255
  }
  const rest = n - i
  if (rest === 2) {
    out[o++] = (vals[i] << 2) | (vals[i + 1] >> 4)
  } else if (rest === 3) {
    const x = (vals[i] << 10) | (vals[i + 1] << 4) | (vals[i + 2] >> 2)
    out[o++] = x >> 8
    out[o++] = x & 255
  }
  return out
}

export function concatBytes(parts: readonly Uint8Array[]): Bytes {
  let len = 0
  for (const p of parts) len += p.length
  const out = new Uint8Array(len)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

/** Decode a toggle-string argument (key, IV, salt…) into bytes. */
export function toggleBytes(t: ToggleValue): Bytes {
  switch (t.encoding) {
    case 'utf8':
      return utf8Encode(t.value)
    case 'latin1':
      return latin1Encode(t.value)
    case 'hex':
      return hexToBytes(t.value.replace(/[\s:,-]/g, ''))
    case 'base64':
      return base64Decode(t.value, 'auto')
  }
}

/* ---------- typed argument accessors (the recipe validator guarantees types) ---------- */

export function argStr(args: ArgValues, key: string): string {
  const v = args[key]
  return typeof v === 'string' ? v : ''
}
export function argNum(args: ArgValues, key: string): number {
  const v = args[key]
  return typeof v === 'number' ? v : 0
}
export function argBool(args: ArgValues, key: string): boolean {
  return args[key] === true
}
export function argToggle(args: ArgValues, key: string): ToggleValue {
  const v = args[key]
  return typeof v === 'object' && v !== null ? v : { value: '', encoding: 'utf8' }
}

/** Throw an AbortError-like OpError if the signal is aborted. */
export function checkAbort(signal?: AbortSignal): void {
  if (signal?.aborted) throw new OpError('Aborted')
}

/** Show a byte as a printable char, or '.' (for hexdumps and previews). */
export function printableChar(b: number): string {
  return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'
}
