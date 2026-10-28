import {
  argBool,
  argNum,
  argStr,
  argToggle,
  base64Decode,
  base64Encode,
  bytesToHex,
  checkAbort,
  concatBytes,
  toBytes,
  toggleBytes,
  utf8Decode,
  utf8Encode,
} from '../engine/bytes'
import { englishScore, printableRatio } from '../engine/analysis'
import type { ArgValues, Bytes, OpDef, SelectArg, ToggleStringArg } from '../engine/types'
import { OpError } from '../engine/types'
import { looseHexDecode } from './encoding'
import { safePreview, sel, textFn } from './helpers'

const C = 'Ciphers & crypto' as const

/* ---------- classical ciphers (pure) ---------- */

export function rotLetters(text: string, shift: number, rotDigits = false): string {
  const s = ((shift % 26) + 26) % 26
  let out = ''
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c >= 65 && c <= 90) out += String.fromCharCode(((c - 65 + s) % 26) + 65)
    else if (c >= 97 && c <= 122) out += String.fromCharCode(((c - 97 + s) % 26) + 97)
    else if (rotDigits && c >= 48 && c <= 57) out += String.fromCharCode(((c - 48 + 5) % 10) + 48)
    else out += text[i]
  }
  return out
}

export function rot47(text: string): string {
  let out = ''
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    out += c >= 33 && c <= 126 ? String.fromCharCode(33 + ((c - 33 + 47) % 94)) : text[i]
  }
  return out
}

export function atbash(text: string): string {
  let out = ''
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c >= 65 && c <= 90) out += String.fromCharCode(90 - (c - 65))
    else if (c >= 97 && c <= 122) out += String.fromCharCode(122 - (c - 97))
    else out += text[i]
  }
  return out
}

/** Vigenère over A–Z/a–z; other characters pass through and do not consume key letters. */
export function vigenere(text: string, key: string, decrypt: boolean): string {
  const k = key.toLowerCase().replace(/[^a-z]/g, '')
  if (k.length === 0) throw new OpError('Vigenère key must contain at least one letter')
  let out = ''
  let j = 0
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    const base = c >= 65 && c <= 90 ? 65 : c >= 97 && c <= 122 ? 97 : 0
    if (!base) {
      out += text[i]
      continue
    }
    const shift = k.charCodeAt(j++ % k.length) - 97
    out += String.fromCharCode(((c - base + (decrypt ? 26 - shift : shift)) % 26) + base)
  }
  return out
}

export function xorBytes(input: Uint8Array, key: Uint8Array): Bytes {
  const out = new Uint8Array(input.length)
  if (key.length === 0) {
    out.set(input)
    return out
  }
  for (let i = 0; i < input.length; i++) out[i] = input[i] ^ key[i % key.length]
  return out
}

export interface XorCandidate {
  key: number
  score: number
  output: Bytes
}

/** Try every single-byte key, rank by English-likeness. `crib` (if non-empty) must appear in the output. */
export function xorBruteForce(input: Uint8Array, crib: string, top: number): XorCandidate[] {
  const sample = input.subarray(0, 4096)
  const cribLower = crib.toLowerCase()
  const cands: XorCandidate[] = []
  for (let k = 0; k < 256; k++) {
    const out = xorBytes(sample, Uint8Array.of(k))
    if (cribLower && !utf8Decode(out).toLowerCase().includes(cribLower)) continue
    const score = englishScore(out) * printableRatio(out)
    cands.push({ key: k, score, output: out })
  }
  cands.sort((a, b) => b.score - a.score || a.key - b.key)
  return cands.slice(0, top)
}

/* ---------- WebCrypto helpers ---------- */

const HASHES = [
  ['SHA-1', 'SHA-1 (legacy)'],
  ['SHA-256', 'SHA-256'],
  ['SHA-384', 'SHA-384'],
  ['SHA-512', 'SHA-512'],
] as const

function toggleArg(key: string, label: string, encoding: 'hex' | 'utf8' = 'hex', secret = false, hint?: string): ToggleStringArg {
  return { key, label, type: 'toggleString', default: { value: '', encoding }, secret, hint }
}

function formatOut(bytes: Bytes, fmt: string): Bytes {
  if (fmt === 'hex') return utf8Encode(bytesToHex(bytes))
  if (fmt === 'base64') return utf8Encode(base64Encode(bytes))
  return bytes
}

function parseIn(bytes: Bytes, fmt: string): Bytes {
  if (fmt === 'hex') return looseHexDecode(utf8Decode(bytes))
  if (fmt === 'base64') return base64Decode(utf8Decode(bytes))
  return bytes
}

const outFormat = (def: string): SelectArg => sel('output', 'Output', def, [['raw', 'Raw bytes'], ['hex', 'Hex'], ['base64', 'Base64']])
const inFormat = (def: string): SelectArg => sel('inputFormat', 'Input is', def, [['raw', 'Raw bytes'], ['hex', 'Hex'], ['base64', 'Base64']])

function subtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) throw new OpError('WebCrypto is unavailable (the page must be served over HTTPS or localhost)')
  return globalThis.crypto.subtle
}

function keyBytes(args: ArgValues): Bytes {
  const key = toggleBytes(argToggle(args, 'key'))
  if (![16, 24, 32].includes(key.length)) {
    throw new OpError(`AES key must be 16, 24 or 32 bytes (AES-128/192/256); got ${key.length}. Check the key encoding (hex/UTF-8/Base64).`)
  }
  return key
}

export type AesMode = 'GCM' | 'CBC' | 'CTR'

export interface AesParams {
  mode: AesMode
  key: Bytes
  iv: Bytes
  aad?: Bytes
  tagBits?: number
}

function algoParams(p: AesParams): AlgorithmIdentifier & Record<string, unknown> {
  if (p.mode === 'GCM') {
    if (p.iv.length === 0) throw new OpError('AES-GCM needs an IV/nonce (12 bytes recommended)')
    return { name: 'AES-GCM', iv: p.iv, tagLength: p.tagBits ?? 128, ...(p.aad && p.aad.length ? { additionalData: p.aad } : {}) }
  }
  if (p.iv.length !== 16) throw new OpError(`AES-${p.mode} needs a 16-byte ${p.mode === 'CTR' ? 'counter block' : 'IV'}; got ${p.iv.length} bytes`)
  if (p.mode === 'CBC') return { name: 'AES-CBC', iv: p.iv }
  return { name: 'AES-CTR', counter: p.iv, length: 64 }
}

async function importAes(p: AesParams): Promise<CryptoKey> {
  try {
    return await subtle().importKey('raw', p.key, { name: `AES-${p.mode}` }, false, ['encrypt', 'decrypt'])
  } catch (e) {
    if (p.key.length === 24) throw new OpError('This browser does not support 192-bit AES keys in WebCrypto (Chromium only supports 128 and 256)')
    throw new OpError(`Could not import AES key: ${(e as Error).message}`)
  }
}

export async function aesEncrypt(data: Bytes, p: AesParams): Promise<Bytes> {
  const params = algoParams(p)
  const key = await importAes(p)
  return toBytes(await subtle().encrypt(params, key, data))
}

export async function aesDecrypt(data: Bytes, p: AesParams): Promise<Bytes> {
  const params = algoParams(p)
  const key = await importAes(p)
  try {
    return toBytes(await subtle().decrypt(params, key, data))
  } catch {
    if (p.mode === 'GCM') throw new OpError('AES-GCM authentication failed: wrong key, IV, additional data or tag, or the data was modified')
    if (p.mode === 'CBC') throw new OpError('AES-CBC decryption failed: wrong key/IV, or the data is not PKCS#7-padded')
    throw new OpError('AES decryption failed')
  }
}

export async function hmac(hash: string, key: Bytes, data: Bytes): Promise<Bytes> {
  if (key.length === 0) throw new OpError('HMAC key must not be empty (WebCrypto rejects zero-length keys)')
  const k = await subtle().importKey('raw', key, { name: 'HMAC', hash }, false, ['sign'])
  return toBytes(await subtle().sign('HMAC', k, data))
}

export const PBKDF2_MAX_ITERATIONS = 10_000_000

export async function pbkdf2(password: Bytes, salt: Bytes, iterations: number, hash: string, lengthBytes: number): Promise<Bytes> {
  if (!Number.isInteger(iterations) || iterations < 1) throw new OpError('Iterations must be a positive integer')
  const k = await subtle().importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
  return toBytes(await subtle().deriveBits({ name: 'PBKDF2', salt, iterations, hash }, k, lengthBytes * 8))
}

const aesModeArg = sel('mode', 'Mode', 'GCM', [['GCM', 'GCM (authenticated)'], ['CBC', 'CBC (PKCS#7 padding)'], ['CTR', 'CTR (64-bit counter)']])
const tagArg = sel('tagLength', 'GCM tag length (bits)', '128', [['128', '128'], ['120', '120'], ['112', '112'], ['104', '104'], ['96', '96']])

function aesParamsFromArgs(a: ArgValues): AesParams {
  return {
    mode: argStr(a, 'mode') as AesMode,
    key: keyBytes(a),
    iv: toggleBytes(argToggle(a, 'iv')),
    aad: toggleBytes(argToggle(a, 'aad')),
    tagBits: Number(argStr(a, 'tagLength')) || 128,
  }
}

export const cryptoOps: OpDef[] = [
  {
    id: 'rot13',
    name: 'ROT13',
    category: C,
    description: 'Rotate letters by 13 (its own inverse). Optionally rotate digits by 5 (ROT18).',
    args: [{ key: 'digits', label: 'Also rotate digits (ROT5)', type: 'boolean', default: false }],
    run: textFn((s, a) => rotLetters(s, 13, argBool(a, 'digits'))),
  },
  {
    id: 'rot47',
    name: 'ROT47',
    category: C,
    description: 'Rotate printable ASCII (! to ~) by 47. Its own inverse.',
    args: [],
    run: textFn((s) => rot47(s)),
  },
  {
    id: 'caesar',
    name: 'Caesar Shift',
    category: C,
    description: 'Shift letters by N positions (negative to decode). Not encryption: there are only 25 keys.',
    args: [{ key: 'shift', label: 'Shift', type: 'number', default: 3, min: -25, max: 25, integer: true }],
    run: textFn((s, a) => rotLetters(s, argNum(a, 'shift'))),
  },
  {
    id: 'vigenere-encode',
    name: 'Vigenère Encode',
    category: C,
    description: 'Classical polyalphabetic cipher over A–Z. Non-letters pass through unchanged. Trivially breakable.',
    args: [{ key: 'key', label: 'Key (letters)', type: 'string', default: 'KEY', secret: true }],
    run: textFn((s, a) => vigenere(s, argStr(a, 'key'), false)),
  },
  {
    id: 'vigenere-decode',
    name: 'Vigenère Decode',
    category: C,
    description: 'Reverse a Vigenère cipher with a known key.',
    args: [{ key: 'key', label: 'Key (letters)', type: 'string', default: 'KEY', secret: true }],
    run: textFn((s, a) => vigenere(s, argStr(a, 'key'), true)),
  },
  {
    id: 'atbash',
    name: 'Atbash',
    category: C,
    description: 'Mirror the alphabet (A↔Z, B↔Y…). Its own inverse.',
    args: [],
    run: textFn((s) => atbash(s)),
  },
  {
    id: 'xor',
    name: 'XOR',
    category: C,
    description: 'XOR every byte with a repeating key. An empty key returns the input unchanged.',
    args: [toggleArg('key', 'Key', 'hex', true)],
    run: (input, a) => xorBytes(input, toggleBytes(argToggle(a, 'key'))),
  },
  {
    id: 'xor-brute-force',
    name: 'XOR Brute Force',
    category: C,
    description:
      'Try all 256 single-byte XOR keys on the first 4 KB and list the most English-like results. Use a crib (known plaintext) to filter.',
    args: [
      { key: 'crib', label: 'Crib (must appear, case-insensitive)', type: 'string', default: '' },
      { key: 'top', label: 'Results to show', type: 'number', default: 10, min: 1, max: 256, integer: true },
    ],
    run: (input, a) => {
      const cands = xorBruteForce(input, argStr(a, 'crib'), argNum(a, 'top'))
      if (cands.length === 0) return utf8Encode('No key produced output containing the crib.')
      const lines = cands.map(
        (c) => `Key 0x${c.key.toString(16).padStart(2, '0')} (score ${c.score.toFixed(3)}): ${safePreview(utf8Decode(c.output), 100)}`,
      )
      return utf8Encode(lines.join('\n'))
    },
  },
  {
    id: 'aes-encrypt',
    name: 'AES Encrypt',
    category: C,
    description:
      'AES via WebCrypto. GCM (recommended) authenticates the data: the output is ciphertext followed by the tag. Never reuse an IV/nonce with the same key — for GCM that breaks both confidentiality and authenticity.',
    args: [
      aesModeArg,
      toggleArg('key', 'Key (16/24/32 bytes)', 'hex', true),
      toggleArg('iv', 'IV / nonce (GCM: 12 bytes; CBC/CTR: 16 bytes)', 'hex'),
      toggleArg('aad', 'GCM additional data (optional)', 'utf8', false, 'Authenticated but not encrypted. Must be identical when decrypting.'),
      tagArg,
      outFormat('hex'),
    ],
    run: async (input, a) => formatOut(await aesEncrypt(input, aesParamsFromArgs(a)), argStr(a, 'output')),
  },
  {
    id: 'aes-decrypt',
    name: 'AES Decrypt',
    category: C,
    description:
      'AES via WebCrypto. For GCM the input must be ciphertext followed by the tag (as WebCrypto, Node and most libraries produce), or give the tag separately.',
    args: [
      aesModeArg,
      toggleArg('key', 'Key (16/24/32 bytes)', 'hex', true),
      toggleArg('iv', 'IV / nonce', 'hex'),
      toggleArg('aad', 'GCM additional data (optional)', 'utf8'),
      toggleArg('tag', 'GCM tag, if not appended to the input', 'hex'),
      tagArg,
      inFormat('hex'),
    ],
    run: async (input, a) => {
      const p = aesParamsFromArgs(a)
      let data = parseIn(input, argStr(a, 'inputFormat'))
      const tag = toggleBytes(argToggle(a, 'tag'))
      if (p.mode === 'GCM' && tag.length > 0) {
        if (tag.length * 8 !== p.tagBits) throw new OpError(`Tag is ${tag.length * 8} bits but the tag length is set to ${p.tagBits}`)
        data = concatBytes([data, tag])
      }
      return aesDecrypt(data, p)
    },
  },
  {
    id: 'pbkdf2',
    name: 'Derive Key (PBKDF2)',
    category: C,
    description:
      'PBKDF2 (RFC 8018) of the input as the password. OWASP (2023) suggests ≥600,000 iterations with HMAC-SHA-256 for password storage; prefer Argon2id where available.',
    args: [
      toggleArg('salt', 'Salt', 'utf8'),
      { key: 'iterations', label: 'Iterations', type: 'number', default: 600000, min: 1, max: PBKDF2_MAX_ITERATIONS, integer: true },
      sel('hash', 'Hash', 'SHA-256', HASHES),
      { key: 'length', label: 'Key length (bytes)', type: 'number', default: 32, min: 1, max: 1024, integer: true },
      outFormat('hex'),
    ],
    run: async (input, a, ctx) => {
      checkAbort(ctx.signal)
      const out = await pbkdf2(input, toggleBytes(argToggle(a, 'salt')), argNum(a, 'iterations'), argStr(a, 'hash'), argNum(a, 'length'))
      return formatOut(out, argStr(a, 'output'))
    },
  },
  {
    id: 'hmac',
    name: 'HMAC',
    category: C,
    description: 'Keyed hash (RFC 2104) via WebCrypto. HMAC-SHA-1 is still considered secure as a MAC, but prefer SHA-256.',
    args: [toggleArg('key', 'Key', 'utf8', true), sel('hash', 'Hash', 'SHA-256', HASHES), outFormat('hex')],
    run: async (input, a) => formatOut(await hmac(argStr(a, 'hash'), toggleBytes(argToggle(a, 'key')), input), argStr(a, 'output')),
  },
  {
    id: 'random-bytes',
    name: 'Generate Random Bytes',
    category: C,
    description: 'Cryptographically secure random bytes (crypto.getRandomValues). Ignores the input.',
    nondeterministic: true,
    args: [
      { key: 'length', label: 'Length (bytes)', type: 'number', default: 32, min: 1, max: 1048576, integer: true },
      outFormat('hex'),
    ],
    run: (_input, a) => {
      const out = new Uint8Array(argNum(a, 'length'))
      for (let i = 0; i < out.length; i += 65536) crypto.getRandomValues(out.subarray(i, i + 65536))
      return formatOut(out, argStr(a, 'output'))
    },
  },
]
