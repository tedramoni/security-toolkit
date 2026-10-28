/**
 * Minimal, defensive ASN.1 BER/DER reader + DER writer.
 *
 * The reader never trusts lengths: every TLV is bounds-checked against its parent, recursion depth and total node
 * count are capped, and errors are reported per node instead of throwing from deep inside the tree. Indefinite
 * lengths (BER, seen in some .p7b files) are accepted for constructed values.
 */
import type { Bytes } from './bytes'
import { toHex } from './bytes'

export type TagClass = 'universal' | 'application' | 'context' | 'private'

export interface AsnNode {
  tagClass: TagClass
  constructed: boolean
  tagNumber: number
  /** Offset of the first identifier byte. */
  offset: number
  headerLength: number
  /** Length of the contents (for indefinite length: up to, excluding, the end-of-contents octets). */
  length: number
  indefinite?: boolean
  children?: AsnNode[]
  /** Children were parsed from the contents of a primitive OCTET STRING / BIT STRING (encapsulated DER). */
  encapsulated?: boolean
  error?: string
}

export class DerError extends Error {
  readonly offset: number
  constructor(message: string, offset: number) {
    super(`${message} (at offset ${offset})`)
    this.name = 'DerError'
    this.offset = offset
  }
}

export interface Header {
  tagClass: TagClass
  constructed: boolean
  tagNumber: number
  headerLength: number
  /** -1 for indefinite. */
  length: number
}

const CLASSES: TagClass[] = ['universal', 'application', 'context', 'private']

/** Read one identifier + length header. Throws DerError if malformed or not fully inside [offset, end). */
export function readHeader(b: Uint8Array, offset: number, end = b.length): Header {
  let p = offset
  if (p >= end) throw new DerError('Unexpected end of data while reading tag', p)
  const first = b[p++]
  const tagClass = CLASSES[first >> 6]
  const constructed = (first & 0x20) !== 0
  let tagNumber = first & 0x1f
  if (tagNumber === 0x1f) {
    tagNumber = 0
    for (let i = 0; ; i++) {
      if (p >= end) throw new DerError('Truncated high tag number', p)
      if (i >= 4) throw new DerError('Tag number too large', p)
      const c = b[p++]
      tagNumber = tagNumber * 128 + (c & 0x7f)
      if ((c & 0x80) === 0) break
    }
  }
  if (p >= end) throw new DerError('Unexpected end of data while reading length', p)
  const lb = b[p++]
  let length: number
  if (lb < 0x80) length = lb
  else if (lb === 0x80) {
    if (!constructed) throw new DerError('Indefinite length on a primitive value', offset)
    length = -1
  } else {
    const n = lb & 0x7f
    if (n > 4) throw new DerError(`Length uses ${n} bytes (too large)`, offset)
    if (p + n > end) throw new DerError('Truncated length', p)
    length = 0
    for (let i = 0; i < n; i++) length = length * 256 + b[p++]
  }
  const headerLength = p - offset
  if (length >= 0 && p + length > end) {
    throw new DerError(`Length ${length} exceeds the ${end - p} bytes available`, offset)
  }
  return { tagClass, constructed, tagNumber, headerLength, length }
}

export interface ParseOptions {
  maxDepth?: number
  maxNodes?: number
  /** Try to parse OCTET STRING / BIT STRING contents as nested DER (default true). */
  encapsulated?: boolean
  /** Max headers read in total before encapsulation attempts stop (default max(4 × maxNodes, 50 000)). */
  encapsulationBudget?: number
}

export interface ParseResult {
  nodes: AsnNode[]
  /** Fatal / top-level problems (per-node problems are on the node). */
  errors: string[]
  nodeCount: number
  truncated: boolean
}

/** Parse a buffer into a tree. Never throws; never recurses deeper than maxDepth. */
export function parseDer(b: Uint8Array, opts: ParseOptions = {}): ParseResult {
  const maxDepth = opts.maxDepth ?? 64
  const maxNodes = opts.maxNodes ?? 20000
  const tryEncap = opts.encapsulated ?? true
  // Total headers read, including speculative encapsulation attempts that are later discarded. Without this cap,
  // nested OCTET STRINGs with a bad trailing byte at every level make each level re-walk its whole subtree
  // (O(size × depth): several seconds per MB). Once spent, no further encapsulation is attempted.
  const encapBudget = opts.encapsulationBudget ?? Math.max(maxNodes * 4, 50_000)
  const state = { count: 0, truncated: false, work: 0, speculative: 0 }
  const errors: string[] = []

  // Returns [nodes, endOffset]. For indefinite content, stops at the EOC marker.
  function parseRange(start: number, end: number, depth: number, untilEoc: boolean): [AsnNode[], number, string?] {
    const out: AsnNode[] = []
    let p = start
    while (p < end) {
      if (untilEoc && p + 1 < end && b[p] === 0 && b[p + 1] === 0) return [out, p + 2]
      if (state.count >= maxNodes) {
        state.truncated = true
        return [out, end, `Node limit (${maxNodes}) reached — tree truncated`]
      }
      if (state.speculative > 0 && state.work >= encapBudget) return [out, end, 'Encapsulation budget exhausted']
      state.work++
      let h: Header
      try {
        h = readHeader(b, p, end)
      } catch (e) {
        return [out, end, (e as Error).message]
      }
      state.count++
      const node: AsnNode = {
        tagClass: h.tagClass,
        constructed: h.constructed,
        tagNumber: h.tagNumber,
        offset: p,
        headerLength: h.headerLength,
        length: h.length,
      }
      out.push(node)
      const contentStart = p + h.headerLength
      if (h.constructed) {
        if (depth + 1 > maxDepth) {
          node.error = `Maximum nesting depth (${maxDepth}) exceeded`
          if (h.length < 0) return [out, end, node.error]
          p = contentStart + h.length
          continue
        }
        if (h.length < 0) {
          node.indefinite = true
          const [kids, after, err] = parseRange(contentStart, end, depth + 1, true)
          node.children = kids
          if (err) {
            node.error = err
            node.length = end - contentStart
            return [out, end]
          }
          node.length = after - 2 - contentStart
          p = after
        } else {
          const [kids, , err] = parseRange(contentStart, contentStart + h.length, depth + 1, false)
          node.children = kids
          if (err) node.error = err
          p = contentStart + h.length
        }
      } else {
        p = contentStart + h.length
        if (tryEncap && h.tagClass === 'universal' && (h.tagNumber === 4 || h.tagNumber === 3) && depth + 1 <= maxDepth) {
          const s = h.tagNumber === 3 ? contentStart + 1 : contentStart
          if (h.tagNumber !== 3 || (h.length > 1 && b[contentStart] === 0)) tryEncapsulated(node, s, p, depth)
        }
      }
    }
    if (untilEoc) return [out, end + 1, 'Missing end-of-contents for indefinite length']
    return [out, p]
  }

  function tryEncapsulated(node: AsnNode, start: number, end: number, depth: number) {
    if (end - start < 2 || state.work >= encapBudget) return
    const t = b[start]
    // Only constructed SEQUENCE/SET or context tags — avoids false positives on random binary.
    if (t !== 0x30 && t !== 0x31 && (t & 0xe0) !== 0xa0 && t !== 0x04 && t !== 0x02 && t !== 0x03) return
    const saved = state.count
    const savedTrunc = state.truncated
    state.speculative++
    const [kids, after, err] = parseRange(start, end, depth + 1, false)
    state.speculative--
    if (err || after !== end || kids.length === 0 || hasError(kids)) {
      state.count = saved
      state.truncated = savedTrunc
      return
    }
    node.children = kids
    node.encapsulated = true
  }

  const [nodes, , err] = parseRange(0, b.length, 0, false)
  if (err) errors.push(err)
  return { nodes, errors, nodeCount: state.count, truncated: state.truncated }
}

function hasError(nodes: AsnNode[]): boolean {
  for (const n of nodes) {
    if (n.error) return true
    if (n.children && hasError(n.children)) return true
  }
  return false
}

// ---------------------------------------------------------------------------------------------- value decoding

export const UNIVERSAL_TAGS: Record<number, string> = {
  0: 'END-OF-CONTENTS',
  1: 'BOOLEAN',
  2: 'INTEGER',
  3: 'BIT STRING',
  4: 'OCTET STRING',
  5: 'NULL',
  6: 'OBJECT IDENTIFIER',
  7: 'ObjectDescriptor',
  9: 'REAL',
  10: 'ENUMERATED',
  12: 'UTF8String',
  13: 'RELATIVE-OID',
  16: 'SEQUENCE',
  17: 'SET',
  18: 'NumericString',
  19: 'PrintableString',
  20: 'T61String',
  21: 'VideotexString',
  22: 'IA5String',
  23: 'UTCTime',
  24: 'GeneralizedTime',
  26: 'VisibleString',
  27: 'GeneralString',
  28: 'UniversalString',
  30: 'BMPString',
}

export function tagName(n: Pick<AsnNode, 'tagClass' | 'tagNumber' | 'constructed'>): string {
  if (n.tagClass === 'universal') return UNIVERSAL_TAGS[n.tagNumber] ?? `[UNIVERSAL ${n.tagNumber}]`
  if (n.tagClass === 'context') return `[${n.tagNumber}]`
  return `[${n.tagClass.toUpperCase()} ${n.tagNumber}]`
}

export function contents(b: Uint8Array, n: AsnNode): Bytes {
  const s = n.offset + n.headerLength
  return b.slice(s, s + n.length)
}

/** Whole TLV bytes of a node. */
export function tlvBytes(b: Uint8Array, n: AsnNode): Bytes {
  return b.slice(n.offset, n.offset + n.headerLength + n.length + (n.indefinite ? 2 : 0))
}

export function decodeOid(c: Uint8Array): string {
  if (c.length === 0) throw new Error('Empty OID')
  if (c.length > 200) throw new Error('OID too long')
  const arcs: bigint[] = []
  let v = 0n
  let started = false
  for (let i = 0; i < c.length; i++) {
    v = (v << 7n) | BigInt(c[i] & 0x7f)
    started = true
    if ((c[i] & 0x80) === 0) {
      arcs.push(v)
      v = 0n
      started = false
    }
  }
  if (started) throw new Error('Truncated OID')
  const first = arcs[0]
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n]
  return [...head, ...arcs.slice(1)].map(String).join('.')
}

export function encodeOid(oid: string): Bytes {
  if (!/^[0-2](\.\d{1,40}){1,64}$/.test(oid)) throw new Error(`Invalid OID: ${oid}`)
  const arcs = oid.split('.').map((s) => BigInt(s))
  if (arcs[0] < 2n && arcs[1] >= 40n) throw new Error(`Invalid OID: ${oid}`)
  const values = [arcs[0] * 40n + arcs[1], ...arcs.slice(2)]
  const out: number[] = []
  for (const val of values) {
    const tmp: number[] = []
    let x = val
    do {
      tmp.unshift(Number(x & 0x7fn))
      x >>= 7n
    } while (x > 0n)
    for (let i = 0; i < tmp.length - 1; i++) tmp[i] |= 0x80
    out.push(...tmp)
  }
  return new Uint8Array(out)
}

function latin1(c: Uint8Array): string {
  let s = ''
  for (let i = 0; i < c.length; i++) s += String.fromCharCode(c[i])
  return s
}

/** Decode the common ASN.1 string types to a JS string. Returns undefined for non-string tags. */
export function decodeString(tagNumber: number, c: Uint8Array): string | undefined {
  switch (tagNumber) {
    case 12:
      return new TextDecoder('utf-8', { fatal: false }).decode(c)
    case 18:
    case 19:
    case 22:
    case 26:
    case 20:
    case 21:
    case 27:
      return latin1(c)
    case 30: {
      let s = ''
      for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1])
      return s
    }
    case 28: {
      let s = ''
      for (let i = 0; i + 3 < c.length; i += 4) {
        const cp = ((c[i] << 24) | (c[i + 1] << 16) | (c[i + 2] << 8) | c[i + 3]) >>> 0
        s += cp <= 0x10ffff ? String.fromCodePoint(cp) : '�'
      }
      return s
    }
    default:
      return undefined
  }
}

/** UTCTime / GeneralizedTime → Date (UTC). Accepts the DER forms (Z) and tolerates missing seconds. */
export function decodeTime(tagNumber: number, c: Uint8Array): Date {
  const s = latin1(c)
  let m: RegExpExecArray | null
  if (tagNumber === 23) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s)
    if (!m) throw new Error(`Bad UTCTime: ${s.slice(0, 32)}`)
    const yy = Number(m[1])
    const year = yy >= 50 ? 1900 + yy : 2000 + yy
    return utcDate(s, year, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0), 0)
  }
  m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:\.(\d{1,9}))?Z$/.exec(s)
  if (!m) throw new Error(`Bad GeneralizedTime: ${s.slice(0, 32)}`)
  const ms = m[7] ? Number(m[7].padEnd(3, '0').slice(0, 3)) : 0
  return utcDate(s, Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5] ?? 0), Number(m[6] ?? 0), ms)
}

/** Build a UTC date, rejecting out-of-range fields instead of letting Date roll them over (month 13, Feb 30…). */
function utcDate(src: string, year: number, month: number, day: number, h: number, min: number, sec: number, ms: number): Date {
  const d = new Date(0)
  // setUTCFullYear, unlike Date.UTC, does not map years 0–99 to 1900–1999.
  d.setUTCFullYear(year, month - 1, day)
  d.setUTCHours(h, min, sec, ms)
  if (month < 1 || month > 12 || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day || h > 23 || min > 59 || sec > 59) {
    throw new Error(`Invalid date/time value: ${src.slice(0, 32)}`)
  }
  return d
}

/** Human-readable one-line value preview for the tree view (bounded length). */
export function describeValue(b: Uint8Array, n: AsnNode, oidName?: (oid: string) => string | undefined): string {
  if (n.constructed || n.encapsulated) {
    const k = n.children?.length ?? 0
    return n.encapsulated ? `(encapsulates ${k} element${k === 1 ? '' : 's'})` : `(${k} element${k === 1 ? '' : 's'})`
  }
  const c = contents(b, n)
  const clip = (s: string) => (s.length > 120 ? `${s.slice(0, 120)}…` : s)
  if (n.tagClass !== 'universal') {
    // Common implicit tags: [2] dNSName, [1] rfc822Name, [6] URI → printable text.
    const txt = isPrintableAscii(c) && c.length > 0 ? `"${clip(latin1(c))}"` : clip(toHex(c, ' '))
    return txt
  }
  try {
    switch (n.tagNumber) {
      case 1:
        return c.length === 1 ? (c[0] === 0 ? 'FALSE' : 'TRUE') : 'invalid BOOLEAN'
      case 2:
      case 10: {
        if (c.length === 0) return 'invalid INTEGER (empty)'
        if (c.length <= 6) return `${intToBigInt(c)} (0x${toHex(c)})`
        return `(${c.length * 8} bit) ${clip(toHex(c, ' '))}`
      }
      case 3:
        return c.length === 0 ? 'invalid BIT STRING' : `(${(c.length - 1) * 8 - c[0]} bit) ${clip(toHex(c.subarray(1), ' '))}`
      case 4:
        return `(${c.length} byte) ${clip(toHex(c, ' '))}`
      case 5:
        return c.length === 0 ? 'NULL' : 'invalid NULL'
      case 6: {
        const oid = decodeOid(c)
        const name = oidName?.(oid)
        return name ? `${oid} (${name})` : oid
      }
      case 23:
      case 24:
        return `${latin1(c)} → ${decodeTime(n.tagNumber, c).toISOString()}`
      default: {
        const s = decodeString(n.tagNumber, c)
        return s === undefined ? clip(toHex(c, ' ')) : `"${clip(s)}"`
      }
    }
  } catch (e) {
    return `⚠ ${(e as Error).message}`
  }
}

function isPrintableAscii(c: Uint8Array): boolean {
  for (let i = 0; i < c.length; i++) if (c[i] < 0x20 || c[i] > 0x7e) return false
  return true
}

/** Two's-complement big-endian integer → bigint. */
export function intToBigInt(c: Uint8Array): bigint {
  let v = 0n
  for (let i = 0; i < c.length; i++) v = (v << 8n) | BigInt(c[i])
  if (c.length > 0 && c[0] & 0x80) v -= 1n << BigInt(c.length * 8)
  return v
}

// ---------------------------------------------------------------------------------------------- DER writer

export function encodeLength(len: number): number[] {
  if (len < 0x80) return [len]
  const out: number[] = []
  let x = len
  while (x > 0) {
    out.unshift(x & 0xff)
    x = Math.floor(x / 256)
  }
  return [0x80 | out.length, ...out]
}

export function tlv(tag: number, content: Uint8Array): Bytes {
  const len = encodeLength(content.length)
  const out = new Uint8Array(1 + len.length + content.length)
  out[0] = tag
  out.set(len, 1)
  out.set(content, 1 + len.length)
  return out
}

export function concat(...parts: Uint8Array[]): Bytes {
  const total = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export const derSeq = (...parts: Uint8Array[]) => tlv(0x30, concat(...parts))
export const derOid = (oid: string) => tlv(0x06, encodeOid(oid))
export const derNull = () => new Uint8Array([0x05, 0x00])
export const derOctets = (c: Uint8Array) => tlv(0x04, c)

/** DER INTEGER from unsigned big-endian magnitude bytes (adds a 0x00 sign byte if needed, strips extra zeros). */
export function derUInt(mag: Uint8Array): Bytes {
  let i = 0
  while (i < mag.length - 1 && mag[i] === 0) i++
  let m = mag.subarray(i)
  if (m.length === 0) m = new Uint8Array([0])
  return tlv(0x02, m[0] & 0x80 ? concat(new Uint8Array([0]), m) : m)
}

// ---------------------------------------------------------------------------------------------- navigation helpers

/** Parse exactly one top-level element with no limits on encapsulation (structure navigation). Throws on error. */
export function parseOne(b: Uint8Array): AsnNode {
  const r = parseDer(b, { encapsulated: false, maxNodes: 2_000_000 })
  if (r.errors.length) throw new Error(r.errors[0])
  if (r.nodes.length === 0) throw new Error('No ASN.1 data')
  const n = r.nodes[0]
  if (n.error) throw new Error(n.error)
  return n
}

/**
 * Copy of the first definite-length TLV only, dropping trailing bytes (e.g. a newline after a binary .der/.csr), so
 * fingerprints, downloads and signature checks use the exact object. Throws if the header is malformed/truncated.
 */
export function trimToFirstTlv(b: Uint8Array): Bytes {
  const h = readHeader(b, 0)
  return h.length < 0 ? Uint8Array.from(b) : b.slice(0, h.headerLength + h.length)
}

export function child(n: AsnNode | undefined, i: number): AsnNode | undefined {
  return n?.children?.[i]
}

export function isUniversal(n: AsnNode | undefined, tag: number): boolean {
  return !!n && n.tagClass === 'universal' && n.tagNumber === tag
}

export function isContext(n: AsnNode | undefined, tag: number): boolean {
  return !!n && n.tagClass === 'context' && n.tagNumber === tag
}
