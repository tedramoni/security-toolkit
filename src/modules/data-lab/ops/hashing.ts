import { argStr, bytesToHex, checkAbort, toBytes, utf8Encode } from '../engine/bytes'
import type { Bytes, OpContext, OpDef } from '../engine/types'
import { OpError } from '../engine/types'
import { adler32, crc32, md5, u32Bytes } from './checksums'
import { sel } from './helpers'

const H = 'Hashing' as const
const Z = 'Compression' as const

const outArg = sel('output', 'Output', 'hex', [['hex', 'Hex'], ['raw', 'Raw bytes']])

const fmt = (bytes: Bytes, f: string): Bytes => (f === 'raw' ? bytes : utf8Encode(bytesToHex(bytes)))

async function digest(alg: string, input: Bytes): Promise<Bytes> {
  if (!globalThis.crypto?.subtle) throw new OpError('WebCrypto is unavailable (the page must be served over HTTPS or localhost)')
  return toBytes(await crypto.subtle.digest(alg, input))
}

function sha(id: string, alg: string, note: string): OpDef {
  return {
    id,
    name: alg,
    category: H,
    description: `${alg} digest via WebCrypto. ${note}`,
    args: [outArg],
    run: async (input, a) => fmt(await digest(alg, input), argStr(a, 'output')),
  }
}

/* ---------- Compression streams ---------- */

/** Refuse to inflate beyond this, to survive decompression bombs. */
export const MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024

export type StreamFormat = 'gzip' | 'deflate' | 'deflate-raw'

async function pump(input: Bytes, transform: CompressionStream | DecompressionStream, ctx: OpContext, limit: number): Promise<Bytes> {
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(input)
      controller.close()
    },
  })
  const reader = source.pipeThrough(transform as unknown as ReadableWritablePair<Uint8Array, Uint8Array>).getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      checkAbort(ctx.signal)
      const { done, value } = await reader.read()
      if (done) break
      total += value.length
      if (total > limit) {
        await reader.cancel()
        throw new OpError(`Output exceeds ${limit / 1024 / 1024} MB — refusing to continue (possible decompression bomb)`)
      }
      chunks.push(value)
    }
  } catch (e) {
    if (e instanceof OpError) throw e
    throw new OpError(`Corrupt or truncated input: ${(e as Error).message || 'decompression failed'}`)
  }
  const out = new Uint8Array(total)
  let o = 0
  for (const c of chunks) {
    out.set(c, o)
    o += c.length
  }
  return out
}

export function compress(input: Bytes, format: StreamFormat, ctx: OpContext = {}): Promise<Bytes> {
  if (typeof CompressionStream === 'undefined') throw new OpError('CompressionStream is not supported by this browser')
  return pump(input, new CompressionStream(format), ctx, Number.MAX_SAFE_INTEGER)
}

export function decompress(input: Bytes, format: StreamFormat, ctx: OpContext = {}): Promise<Bytes> {
  if (typeof DecompressionStream === 'undefined') throw new OpError('DecompressionStream is not supported by this browser')
  if (input.length === 0) throw new OpError('Input is empty')
  return pump(input, new DecompressionStream(format), ctx, MAX_DECOMPRESSED_BYTES)
}

export const hashingOps: OpDef[] = [
  {
    id: 'md5',
    name: 'MD5',
    category: H,
    description: 'MD5 (RFC 1321). Broken: practical collisions since 2004. Use only for checksums and threat-intel lookups, never for security.',
    args: [outArg],
    run: (input, a) => fmt(md5(input), argStr(a, 'output')),
  },
  sha('sha1', 'SHA-1', 'Broken for collision resistance (SHAttered, 2017). Fine for legacy lookups (e.g. git, IOCs), not for signatures.'),
  sha('sha256', 'SHA-256', 'Plain hashes are not for password storage — use Argon2id, scrypt or bcrypt.'),
  sha('sha384', 'SHA-384', 'Plain hashes are not for password storage — use Argon2id, scrypt or bcrypt.'),
  sha('sha512', 'SHA-512', 'Plain hashes are not for password storage — use Argon2id, scrypt or bcrypt.'),
  {
    id: 'crc32',
    name: 'CRC-32',
    category: H,
    description: 'CRC-32 (IEEE 802.3 / zip / PNG). Detects accidental corruption only — trivially forgeable.',
    args: [outArg],
    run: (input, a) => fmt(u32Bytes(crc32(input)), argStr(a, 'output')),
  },
  {
    id: 'adler32',
    name: 'Adler-32',
    category: H,
    description: 'Adler-32 checksum (RFC 1950, used by zlib). Not a security hash.',
    args: [outArg],
    run: (input, a) => fmt(u32Bytes(adler32(input)), argStr(a, 'output')),
  },
  {
    id: 'gzip',
    name: 'Gzip',
    category: Z,
    description: 'Compress with gzip (RFC 1952) via the browser CompressionStream.',
    args: [],
    run: (input, _a, ctx) => compress(input, 'gzip', ctx),
  },
  {
    id: 'gunzip',
    name: 'Gunzip',
    category: Z,
    description: 'Decompress gzip data (starts with 1f 8b). Output is capped at 256 MB.',
    args: [],
    run: (input, _a, ctx) => decompress(input, 'gzip', ctx),
  },
  {
    id: 'zlib-deflate',
    name: 'Zlib Deflate',
    category: Z,
    description: 'Compress with zlib framing (RFC 1950, usually starts with 78 9c). Browsers call this format "deflate".',
    args: [],
    run: (input, _a, ctx) => compress(input, 'deflate', ctx),
  },
  {
    id: 'zlib-inflate',
    name: 'Zlib Inflate',
    category: Z,
    description: 'Decompress zlib-framed data (RFC 1950). Output is capped at 256 MB.',
    args: [],
    run: (input, _a, ctx) => decompress(input, 'deflate', ctx),
  },
  {
    id: 'raw-deflate',
    name: 'Raw Deflate',
    category: Z,
    description: 'Compress to a raw DEFLATE stream (RFC 1951, no header/checksum), as used inside ZIP and SAML redirect binding.',
    args: [],
    run: (input, _a, ctx) => compress(input, 'deflate-raw', ctx),
  },
  {
    id: 'raw-inflate',
    name: 'Raw Inflate',
    category: Z,
    description: 'Decompress a raw DEFLATE stream (RFC 1951), e.g. a SAMLRequest after URL- and Base64-decoding. Capped at 256 MB.',
    args: [],
    run: (input, _a, ctx) => decompress(input, 'deflate-raw', ctx),
  },
]
