/** Small byte helpers (hex, base64, base64url) shared by the PKI module. Pure, no DOM. */

export type Bytes = Uint8Array<ArrayBuffer>

export function toBytes(data: ArrayBuffer | ArrayBufferView): Bytes {
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  const copy = new Uint8Array(data.byteLength)
  copy.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength))
  return copy
}

export function toHex(data: ArrayBuffer | ArrayBufferView, sep = ''): string {
  const b = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  const out: string[] = new Array(b.length)
  for (let i = 0; i < b.length; i++) out[i] = b[i].toString(16).padStart(2, '0')
  return out.join(sep)
}

/** Parse hex, ignoring whitespace and ':' separators. Throws on odd length / invalid chars. */
export function fromHex(hex: string): Bytes {
  const clean = hex.replace(/[\s:]/g, '')
  if (clean.length % 2 !== 0) throw new Error('Hex string has an odd number of digits')
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('Invalid hex character')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export function toBase64(data: ArrayBuffer | ArrayBufferView): string {
  const b = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  let out = ''
  let i = 0
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2]
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63]
  }
  if (i < b.length) {
    const n = (b[i] << 16) | ((i + 1 < b.length ? b[i + 1] : 0) << 8)
    out += B64[n >> 18] + B64[(n >> 12) & 63]
    out += i + 1 < b.length ? B64[(n >> 6) & 63] + '=' : '=='
  }
  return out
}

export function toBase64Url(data: ArrayBuffer | ArrayBufferView): string {
  return toBase64(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const B64_LOOKUP: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1)
  for (let i = 0; i < B64.length; i++) t[B64.charCodeAt(i)] = i
  t['-'.charCodeAt(0)] = 62
  t['_'.charCodeAt(0)] = 63
  return t
})()

/**
 * Decode standard or URL-safe base64. Whitespace is ignored; padding is optional.
 * Throws on any other character or an impossible length.
 */
export function fromBase64(input: string): Bytes {
  let s = input.replace(/\s+/g, '')
  s = s.replace(/=+$/, '')
  if (s.length % 4 === 1) throw new Error('Invalid base64 length')
  const out = new Uint8Array(Math.floor((s.length * 3) / 4))
  let o = 0
  let acc = 0
  let bits = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    const v = c < 128 ? B64_LOOKUP[c] : -1
    if (v < 0) throw new Error(`Invalid base64 character at position ${i}`)
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[o++] = (acc >> bits) & 0xff
    }
  }
  return out.slice(0, o)
}

export function bytesEqual(a: ArrayBuffer | ArrayBufferView, b: ArrayBuffer | ArrayBufferView): boolean {
  const x = toBytes(a)
  const y = toBytes(b)
  if (x.length !== y.length) return false
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false
  return true
}

export async function sha(alg: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512', data: ArrayBuffer | ArrayBufferView): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest(alg, toBytes(data)))
}

/** Upper-case colon-separated hex, as shown by openssl / browsers for fingerprints. */
export function fingerprintHex(data: ArrayBuffer | ArrayBufferView): string {
  return toHex(data, ':').toUpperCase()
}
