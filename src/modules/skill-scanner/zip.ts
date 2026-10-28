/*
 * Minimal, defensive ZIP reader (no dependencies).
 * - Parses the End Of Central Directory record and the central directory (authoritative sizes/names).
 * - Supports "stored" (0) and "deflate" (8) via the browser's DecompressionStream('deflate-raw').
 * - Zip-bomb guards: entry count, per-entry and total uncompressed size, compression ratio, and a hard cap
 *   enforced WHILE inflating (declared sizes can lie). CRC-32 is verified.
 * - Rejects absolute paths, drive letters, ".." segments, NUL bytes (Zip Slip) and symlink entries.
 * - ZIP64, encryption and other compression methods are reported as skipped entries.
 * Spec: PKWARE APPNOTE.TXT https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 */

export interface ZipLimits {
  maxEntries: number
  maxEntryBytes: number
  maxTotalBytes: number
  /** Max uncompressed/compressed ratio for entries over 1 MB. */
  maxRatio: number
  maxArchiveBytes: number
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxEntries: 5000,
  maxEntryBytes: 5 * 1024 * 1024,
  maxTotalBytes: 50 * 1024 * 1024,
  maxRatio: 100,
  maxArchiveBytes: 100 * 1024 * 1024,
}

export interface ZipEntry {
  name: string
  /** Uncompressed size from the central directory. */
  size: number
  /** Undefined when the content was not extracted (skipped, but name still useful e.g. for executables). */
  data?: Uint8Array
}

export interface ZipIssue {
  entry: string
  kind: 'traversal' | 'symlink' | 'skipped'
  detail: string
}

export interface ZipResult {
  entries: ZipEntry[]
  issues: ZipIssue[]
}

export class ZipError extends Error {}

const SIG_EOCD = 0x06054b50
const SIG_CEN = 0x02014b50
const SIG_LOC = 0x04034b50

let CRC_TABLE: Uint32Array | undefined
export function crc32(data: Uint8Array): number {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256)
    for (let n = 0; n < 256; n++) {
      let c = n
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      CRC_TABLE[n] = c >>> 0
    }
  }
  let crc = 0xffffffff
  for (let i = 0; i < data.length; i++) crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

/** Reasons a name is unsafe to extract, or undefined. */
export function unsafeEntryName(name: string): string | undefined {
  if (name.includes('\0')) return 'contains a NUL byte'
  const n = name.replace(/\\/g, '/')
  if (n.startsWith('/')) return 'absolute path'
  if (/^[A-Za-z]:/.test(n)) return 'drive-letter path'
  if (n.split('/').some((seg) => seg === '..')) return 'contains ".." (path traversal)'
  return undefined
}

async function inflateRaw(data: Uint8Array, limit: number): Promise<Uint8Array> {
  if (typeof DecompressionStream === 'undefined') throw new ZipError('This browser does not support DecompressionStream (needed for deflate).')
  const ds = new DecompressionStream('deflate-raw')
  const writer = ds.writable.getWriter()
  // Errors surface on the readable side; avoid unhandled rejections here.
  writer.write(data as Uint8Array<ArrayBuffer>).catch(() => {})
  writer.close().catch(() => {})
  const reader = ds.readable.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.length
    if (total > limit) {
      await reader.cancel().catch(() => {})
      throw new ZipError(`inflates beyond ${limit.toLocaleString('en-US')} bytes`)
    }
    chunks.push(value)
  }
  const out = new Uint8Array(total)
  let o = 0
  for (const c of chunks) {
    out.set(c, o)
    o += c.length
  }
  return out
}

export async function readZip(input: Uint8Array, limits: ZipLimits = DEFAULT_ZIP_LIMITS): Promise<ZipResult> {
  if (input.length > limits.maxArchiveBytes) throw new ZipError(`Archive is larger than ${limits.maxArchiveBytes / 1024 / 1024} MB.`)
  if (input.length < 22) throw new ZipError('Not a ZIP file (too small).')
  const dv = new DataView(input.buffer, input.byteOffset, input.byteLength)
  const u16 = (p: number) => dv.getUint16(p, true)
  const u32 = (p: number) => dv.getUint32(p, true)

  let eocd = -1
  for (let p = input.length - 22; p >= Math.max(0, input.length - 22 - 0xffff); p--) {
    if (u32(p) === SIG_EOCD) {
      eocd = p
      break
    }
  }
  if (eocd < 0) throw new ZipError('Not a ZIP file (no end-of-central-directory record).')
  const total = u16(eocd + 10)
  const cdSize = u32(eocd + 12)
  const cdOffset = u32(eocd + 16)
  if (total === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) throw new ZipError('ZIP64 archives are not supported.')
  if (u16(eocd + 4) !== 0 || u16(eocd + 6) !== 0) throw new ZipError('Multi-disk (split) archives are not supported.')
  if (cdOffset + cdSize > eocd) throw new ZipError('Corrupt ZIP: central directory out of bounds.')
  if (total > limits.maxEntries) throw new ZipError(`Archive has ${total} entries (limit ${limits.maxEntries}).`)

  const decoder = new TextDecoder('utf-8', { fatal: false })
  const entries: ZipEntry[] = []
  const issues: ZipIssue[] = []
  let p = cdOffset
  let budget = limits.maxTotalBytes
  for (let i = 0; i < total; i++) {
    if (p + 46 > eocd || u32(p) !== SIG_CEN) throw new ZipError('Corrupt ZIP: bad central directory entry.')
    const madeBy = u16(p + 4)
    const flags = u16(p + 8)
    const method = u16(p + 10)
    const crc = u32(p + 16)
    const compSize = u32(p + 20)
    const size = u32(p + 24)
    const nameLen = u16(p + 28)
    const extraLen = u16(p + 30)
    const commentLen = u16(p + 32)
    const extAttr = u32(p + 38)
    const localOffset = u32(p + 42)
    if (p + 46 + nameLen > eocd) throw new ZipError('Corrupt ZIP: entry name out of bounds.')
    const name = decoder.decode(input.subarray(p + 46, p + 46 + nameLen))
    p += 46 + nameLen + extraLen + commentLen

    if (name.endsWith('/') || name.endsWith('\\')) continue // directory
    const unsafe = unsafeEntryName(name)
    if (unsafe) {
      issues.push({ entry: name, kind: 'traversal', detail: `Unsafe entry name: ${unsafe}. Not extracted.` })
      continue
    }
    const hostOs = madeBy >>> 8
    if (hostOs === 3 && ((extAttr >>> 16) & 0o170000) === 0o120000) {
      issues.push({ entry: name, kind: 'symlink', detail: 'Symbolic link entry. Not extracted.' })
      continue
    }
    const skip = (detail: string) => {
      issues.push({ entry: name, kind: 'skipped', detail })
      entries.push({ name, size })
    }
    if (flags & 1) {
      skip('Encrypted entry — cannot be scanned.')
      continue
    }
    if (method !== 0 && method !== 8) {
      skip(`Unsupported compression method ${method}.`)
      continue
    }
    if (compSize === 0xffffffff || size === 0xffffffff) {
      skip('ZIP64 entry — not supported.')
      continue
    }
    if (size > limits.maxEntryBytes) {
      skip(`Uncompressed size ${size.toLocaleString('en-US')} bytes exceeds the per-file limit.`)
      continue
    }
    if (size > 1024 * 1024 && compSize > 0 && size / compSize > limits.maxRatio) {
      skip(`Compression ratio ${Math.round(size / compSize)}:1 exceeds ${limits.maxRatio}:1 (possible zip bomb).`)
      continue
    }
    if (size > budget) {
      skip('Total uncompressed size limit reached (possible zip bomb).')
      continue
    }
    if (localOffset + 30 > input.length || u32(localOffset) !== SIG_LOC) {
      skip('Local header missing or corrupt.')
      continue
    }
    const dataStart = localOffset + 30 + u16(localOffset + 26) + u16(localOffset + 28)
    const dataEnd = dataStart + compSize
    if (dataEnd > input.length) {
      skip('Entry data out of bounds.')
      continue
    }
    const raw = input.subarray(dataStart, dataEnd)
    let data: Uint8Array
    try {
      if (method === 0) {
        if (compSize !== size) throw new ZipError('stored entry size mismatch')
        data = raw.slice()
      } else {
        // Hard cap while inflating: never more than the declared size (or remaining budget).
        data = await inflateRaw(raw, Math.min(size, budget))
      }
    } catch (e) {
      skip(`Could not extract: ${e instanceof ZipError ? e.message : 'invalid compressed data'}.`)
      continue
    }
    if (data.length !== size) {
      skip(`Size mismatch (declared ${size}, got ${data.length}).`)
      continue
    }
    if (crc32(data) !== crc) {
      skip('CRC-32 mismatch (corrupt or tampered entry).')
      continue
    }
    budget -= size
    entries.push({ name, size, data })
  }
  return { entries, issues }
}
