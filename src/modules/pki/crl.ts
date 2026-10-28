/**
 * CRL (RFC 5280 §5) parsing with a streaming-style reader: revoked entries are read with readHeader directly
 * (no tree for the whole list), so CRLs with hundreds of thousands of entries stay fast.
 */
import type { Bytes } from './bytes'
import { toHex } from './bytes'
import type { SignatureAlg } from './cert'
import { signatureAlg } from './cert'
import type { AsnNode } from './der'
import { decodeTime, parseDer, readHeader } from './der'
import type { ExtensionInfo } from './extensions'
import { decodeExtensionsNode, extDecoded } from './extensions'
import type { Rdn } from './names'
import { decodeName, formatName } from './names'
import { CRL_REASONS, OID } from './oids'

export interface CrlEntry {
  /** Serial magnitude, lower-case hex without leading zeros (canonical for lookups). */
  serial: string
  revocationDate: Date
  reason?: number
}

export interface CrlInfo {
  der: Bytes
  version: number
  signatureAlg: SignatureAlg
  issuer: Rdn[]
  issuerString: string
  issuerDer: Bytes
  thisUpdate: Date
  nextUpdate?: Date
  entries: CrlEntry[]
  extensions: ExtensionInfo[]
  crlNumber?: string
  akiKeyId?: string
  /** Entries whose extensions could not be read (still listed). */
  entryWarnings: number
}

/** Canonical serial form: lower-case hex, no separators, no leading zeros ("0" for zero). */
export function normalizeSerial(s: string): string {
  const hex = s.replace(/[\s:]/g, '').toLowerCase().replace(/^0x/, '')
  if (!/^[0-9a-f]*$/.test(hex)) throw new Error('Serial must be hexadecimal')
  return hex.replace(/^0+/, '') || '0'
}

function serialFromContent(c: Uint8Array): string {
  return toHex(c).replace(/^0+/, '') || '0'
}

/** CRL entry extension: reasonCode (2.5.29.21) → ENUMERATED value. */
const REASON_OID_DER = [0x06, 0x03, 0x55, 0x1d, 0x15]

function readEntryReason(b: Uint8Array, start: number, end: number): number | undefined {
  // Linear byte search for the reasonCode OID inside this entry's extensions, then read the ENUMERATED.
  for (let i = start; i + REASON_OID_DER.length < end; i++) {
    let ok = true
    for (let k = 0; k < REASON_OID_DER.length; k++) if (b[i + k] !== REASON_OID_DER[k]) ok = false
    if (!ok) continue
    let p = i + REASON_OID_DER.length
    if (b[p] === 0x01) p += 3 // critical BOOLEAN
    if (b[p] !== 0x04) return undefined
    const oct = readHeader(b, p, end)
    const q = p + oct.headerLength
    if (b[q] !== 0x0a) return undefined
    const en = readHeader(b, q, end)
    return b[q + en.headerLength + en.length - 1]
  }
  return undefined
}

export function decodeCrl(der: Uint8Array): CrlInfo {
  const outer = readHeader(der, 0)
  if (outer.tagNumber !== 16 || !outer.constructed) throw new Error('Not a CRL (expected SEQUENCE)')
  if (outer.length < 0) throw new Error('Indefinite-length (BER) CRLs are not supported; CRLs must be DER')
  // Ignore bytes after the CRL (e.g. a trailing newline in a .crl file) so signature checks see the exact DER.
  const b = der.slice(0, outer.headerLength + outer.length)
  const tbsStart = outer.headerLength
  const tbsH = readHeader(b, tbsStart)
  if (tbsH.tagNumber !== 16) throw new Error('Not a CRL (TBSCertList is not a SEQUENCE)')
  const tbsEnd = tbsStart + tbsH.headerLength + tbsH.length
  const algStart = tbsEnd
  const algH = readHeader(b, algStart)
  const sigAlgDer = b.subarray(algStart, algStart + algH.headerLength + algH.length)
  const sigAlgNode = parseDer(sigAlgDer, { encapsulated: false }).nodes[0]

  let p = tbsStart + tbsH.headerLength
  const next = () => {
    const h = readHeader(b, p, tbsEnd)
    const node = { start: p, h, cStart: p + h.headerLength, end: p + h.headerLength + h.length }
    return node
  }
  let version = 1
  let n = next()
  if (n.h.tagClass === 'universal' && n.h.tagNumber === 2) {
    version = b[n.cStart] + 1
    p = n.end
    n = next()
  }
  // signature AlgorithmIdentifier (inner) — skip
  p = n.end
  n = next()
  const issuerDer = b.slice(n.start, n.end)
  const issuer = decodeName(issuerDer)
  p = n.end
  n = next()
  const thisUpdate = decodeTime(n.h.tagNumber, b.subarray(n.cStart, n.end))
  p = n.end
  let nextUpdate: Date | undefined
  const entries: CrlEntry[] = []
  let extensions: ExtensionInfo[] = []
  let entryWarnings = 0
  while (p < tbsEnd) {
    n = next()
    const isTime = n.h.tagClass === 'universal' && (n.h.tagNumber === 23 || n.h.tagNumber === 24)
    if (isTime) {
      nextUpdate = decodeTime(n.h.tagNumber, b.subarray(n.cStart, n.end))
    } else if (n.h.tagClass === 'universal' && n.h.tagNumber === 16) {
      // revokedCertificates
      let q = n.cStart
      while (q < n.end) {
        const e = readHeader(b, q, n.end)
        const eStart = q + e.headerLength
        const eEnd = eStart + e.length
        const s = readHeader(b, eStart, eEnd)
        const serial = serialFromContent(b.subarray(eStart + s.headerLength, eStart + s.headerLength + s.length))
        const tStart = eStart + s.headerLength + s.length
        const t = readHeader(b, tStart, eEnd)
        const revocationDate = decodeTime(t.tagNumber, b.subarray(tStart + t.headerLength, tStart + t.headerLength + t.length))
        let reason: number | undefined
        const extStart = tStart + t.headerLength + t.length
        if (extStart < eEnd) {
          try {
            reason = readEntryReason(b, extStart, eEnd)
          } catch {
            entryWarnings++
          }
        }
        entries.push({ serial, revocationDate, reason })
        q = eEnd
      }
    } else if (n.h.tagClass === 'context' && n.h.tagNumber === 0) {
      const sub = b.subarray(n.cStart, n.end)
      const parsed = parseDer(sub, { encapsulated: false })
      extensions = decodeExtensionsNode(sub, parsed.nodes[0])
    }
    p = n.end
  }
  const info: CrlInfo = {
    der: b,
    version,
    signatureAlg: signatureAlg(sigAlgDer, sigAlgNode as AsnNode),
    issuer,
    issuerString: formatName(issuer),
    issuerDer,
    thisUpdate,
    nextUpdate,
    entries,
    extensions,
    entryWarnings,
  }
  info.crlNumber = extDecoded(extensions, OID.crlNumber, 'integer')?.value
  info.akiKeyId = extDecoded(extensions, OID.authorityKeyIdentifier, 'aki')?.keyId
  return info
}

export function reasonName(code: number | undefined): string {
  return code === undefined ? '—' : (CRL_REASONS[code] ?? `unknown (${code})`)
}

/** Build a serial → entry index for O(1) lookups on big CRLs. */
export function indexCrl(info: CrlInfo): Map<string, CrlEntry> {
  const m = new Map<string, CrlEntry>()
  for (const e of info.entries) m.set(e.serial, e)
  return m
}

export type Freshness = { state: 'fresh' | 'stale' | 'not-yet-valid' | 'no-next-update'; detail: string }

export function crlFreshness(info: CrlInfo, now = new Date()): Freshness {
  if (now < info.thisUpdate) return { state: 'not-yet-valid', detail: `thisUpdate is in the future (${info.thisUpdate.toISOString()}).` }
  if (!info.nextUpdate) return { state: 'no-next-update', detail: 'No nextUpdate: RFC 5280 requires conforming CAs to include it.' }
  if (now > info.nextUpdate) {
    const h = Math.floor((now.getTime() - info.nextUpdate.getTime()) / 3_600_000)
    return { state: 'stale', detail: `nextUpdate passed ${h >= 48 ? `${Math.floor(h / 24)} days` : `${h} hours`} ago — this CRL is stale; fetch a fresh one.` }
  }
  return { state: 'fresh', detail: `Valid until ${info.nextUpdate.toISOString()}.` }
}
