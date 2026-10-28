import { isValidUtf8, utf8Decode } from './bytes'

/** Shannon entropy in bits per byte (0–8). */
export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0
  const counts = new Uint32Array(256)
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++
  let h = 0
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue
    const p = counts[i] / bytes.length
    h -= p * Math.log2(p)
  }
  return h
}

export function entropyInterpretation(h: number): string {
  if (h < 1) return 'very low: highly repetitive data'
  if (h < 3.5) return 'low: simple or highly structured data'
  if (h < 5) return 'typical of natural-language text, source code or hex'
  if (h < 6.5) return 'moderate: encoded data such as Base64 (≈6), or mixed text/binary'
  if (h < 7.5) return 'high: binary formats, possibly compressed'
  return 'very high: likely compressed, encrypted or random data'
}

/** Fraction of bytes that are printable ASCII, tab, CR or LF (UTF-8 multibyte sequences count as printable). */
export function printableRatio(bytes: Uint8Array): number {
  if (bytes.length === 0) return 1
  let ok = 0
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]
    if ((b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13 || b >= 0x80) ok++
  }
  // Non-ASCII bytes only count if the whole buffer is valid UTF-8.
  if (ok > 0 && !isValidUtf8(bytes)) {
    let ascii = 0
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i]
      if ((b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13) ascii++
    }
    return ascii / bytes.length
  }
  return ok / bytes.length
}

/* English letter frequencies (%), plus space — used for cosine similarity. */
const ENGLISH_FREQ = [
  8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095,
  5.987, 6.327, 9.056, 2.758, 0.978, 2.36, 0.15, 1.974, 0.074,
]
const SPACE_FREQ = 19 // spaces are ≈ 1 in 6 characters of English prose
const ENGLISH_VEC = [...ENGLISH_FREQ, SPACE_FREQ]
const ENGLISH_NORM = Math.sqrt(ENGLISH_VEC.reduce((s, x) => s + x * x, 0))

/**
 * How English-like the bytes are, 0–1. Cosine similarity of the letter+space histogram with English,
 * weighted by the share of bytes that are letters/space/common punctuation. Only the first 64 KB are examined.
 */
export function englishScore(bytes: Uint8Array): number {
  const n = Math.min(bytes.length, 65536)
  if (n === 0) return 0
  const counts = new Array<number>(27).fill(0)
  let textish = 0
  for (let i = 0; i < n; i++) {
    let b = bytes[i]
    if (b >= 65 && b <= 90) b += 32
    if (b >= 97 && b <= 122) {
      counts[b - 97]++
      textish++
    } else if (b === 32) {
      counts[26]++
      textish++
    } else if (b === 10 || b === 13 || b === 9 || (b >= 33 && b <= 63) || b === 39) {
      textish += 0.5
    }
  }
  let dot = 0
  let norm = 0
  for (let i = 0; i < 27; i++) {
    dot += counts[i] * ENGLISH_VEC[i]
    norm += counts[i] * counts[i]
  }
  if (norm === 0) return 0
  const cos = dot / (Math.sqrt(norm) * ENGLISH_NORM)
  return Math.max(0, Math.min(1, cos * (textish / n)))
}

export interface FileSignature {
  name: string
  mime?: string
  ext: string
}

const SIGNATURES: readonly { magic: readonly number[]; offset?: number; sig: FileSignature }[] = [
  { magic: [0x1f, 0x8b, 0x08], sig: { name: 'Gzip compressed data', ext: 'gz', mime: 'application/gzip' } },
  { magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], sig: { name: 'PNG image', ext: 'png', mime: 'image/png' } },
  { magic: [0xff, 0xd8, 0xff], sig: { name: 'JPEG image', ext: 'jpg', mime: 'image/jpeg' } },
  { magic: [0x47, 0x49, 0x46, 0x38], sig: { name: 'GIF image', ext: 'gif', mime: 'image/gif' } },
  { magic: [0x25, 0x50, 0x44, 0x46, 0x2d], sig: { name: 'PDF document', ext: 'pdf', mime: 'application/pdf' } },
  { magic: [0x50, 0x4b, 0x03, 0x04], sig: { name: 'ZIP archive (also DOCX/XLSX/JAR/APK)', ext: 'zip', mime: 'application/zip' } },
  { magic: [0x50, 0x4b, 0x05, 0x06], sig: { name: 'ZIP archive (empty)', ext: 'zip', mime: 'application/zip' } },
  { magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], sig: { name: '7-Zip archive', ext: '7z' } },
  { magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], sig: { name: 'RAR archive', ext: 'rar' } },
  { magic: [0x42, 0x5a, 0x68], sig: { name: 'Bzip2 compressed data', ext: 'bz2' } },
  { magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], sig: { name: 'XZ compressed data', ext: 'xz' } },
  { magic: [0x28, 0xb5, 0x2f, 0xfd], sig: { name: 'Zstandard compressed data', ext: 'zst' } },
  { magic: [0x7f, 0x45, 0x4c, 0x46], sig: { name: 'ELF executable', ext: 'elf' } },
  { magic: [0x4d, 0x5a], sig: { name: 'Windows PE/DOS executable (MZ)', ext: 'exe' } },
  { magic: [0xca, 0xfe, 0xba, 0xbe], sig: { name: 'Java class file or Mach-O fat binary', ext: 'bin' } },
  { magic: [0xcf, 0xfa, 0xed, 0xfe], sig: { name: 'Mach-O 64-bit executable', ext: 'bin' } },
  { magic: [0x00, 0x61, 0x73, 0x6d], sig: { name: 'WebAssembly module', ext: 'wasm', mime: 'application/wasm' } },
  { magic: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00], sig: { name: 'SQLite 3 database', ext: 'sqlite' } },
  { magic: [0x4f, 0x67, 0x67, 0x53], sig: { name: 'Ogg media', ext: 'ogg' } },
  { magic: [0x52, 0x49, 0x46, 0x46], sig: { name: 'RIFF container (WAV/AVI/WebP)', ext: 'riff' } },
  { magic: [0x49, 0x44, 0x33], sig: { name: 'MP3 audio (ID3)', ext: 'mp3' } },
  { magic: [0x66, 0x74, 0x79, 0x70], offset: 4, sig: { name: 'ISO media (MP4/MOV/HEIC)', ext: 'mp4' } },
  { magic: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], sig: { name: 'Microsoft OLE2 document (DOC/XLS/MSI)', ext: 'ole' } },
]

/** Identify common binary formats from their magic bytes. */
export function detectFileType(bytes: Uint8Array): FileSignature | undefined {
  for (const { magic, offset = 0, sig } of SIGNATURES) {
    if (bytes.length < offset + magic.length) continue
    let ok = true
    for (let i = 0; i < magic.length; i++) {
      if (bytes[offset + i] !== magic[i]) {
        ok = false
        break
      }
    }
    if (ok) return sig
  }
  // zlib: CMF=0x78 (deflate, 32K window) and (CMF*256+FLG) % 31 == 0 (RFC 1950)
  if (bytes.length >= 2 && bytes[0] === 0x78 && ((bytes[0] << 8) | bytes[1]) % 31 === 0) {
    return { name: 'Zlib compressed data', ext: 'zlib' }
  }
  // DER SEQUENCE with long-form length: certificates, keys, CSRs…
  if (bytes.length >= 4 && bytes[0] === 0x30 && (bytes[1] === 0x82 || bytes[1] === 0x81)) {
    return { name: 'ASN.1 DER structure (certificate/key?)', ext: 'der' }
  }
  return undefined
}

/** Best-effort description of what the bytes contain, for the output stats bar. */
export function detectType(bytes: Uint8Array): string {
  if (bytes.length === 0) return 'empty'
  const sig = detectFileType(bytes)
  if (sig) return sig.name
  if (!isValidUtf8(bytes)) return 'binary data'
  const text = utf8Decode(bytes.subarray(0, Math.min(bytes.length, 4096))).trim()
  if (/^eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/.test(text)) return 'JWT (JSON Web Token)'
  if (text.startsWith('-----BEGIN ')) return 'PEM block'
  if ((text.startsWith('{') || text.startsWith('[')) && bytes.length <= 4096) {
    try {
      JSON.parse(text)
      return 'JSON'
    } catch {
      /* not JSON */
    }
  }
  if (text.startsWith('<?xml')) return 'XML'
  if (/^<!doctype html|^<html/i.test(text)) return 'HTML'
  if (/^[0-9a-fA-F\s]+$/.test(text) && text.replace(/\s/g, '').length % 2 === 0) return 'hex-encoded text'
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0 && text.length >= 8) return 'Base64-like text'
  return printableRatio(bytes) > 0.95 ? 'UTF-8 text' : 'UTF-8 text with control characters'
}
