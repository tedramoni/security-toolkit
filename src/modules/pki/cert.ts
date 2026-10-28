/** X.509 certificate decoding from DER (own defensive walker + asn1-x509 for extension bodies). */
import type { Bytes } from './bytes'
import { bytesEqual, fingerprintHex, sha, toHex } from './bytes'
import type { AsnNode } from './der'
import { child, contents, decodeOid, decodeTime, isContext, isUniversal, parseOne, tlvBytes, trimToFirstTlv } from './der'
import type { ExtensionInfo } from './extensions'
import { decodeExtensionsNode } from './extensions'
import type { Rdn } from './names'
import { decodeNameNode, formatName } from './names'
import { SIGNATURE_ALGS } from './oids'
import type { KeyInfo } from './spki'
import { describeSpkiNode } from './spki'

export interface SignatureAlg {
  oid: string
  name: string
  hash?: string
  weak?: 'md' | 'sha1'
}

export interface CertInfo {
  der: Bytes
  version: number
  /** Serial as lower-case hex of the DER INTEGER contents (including a 0x00 sign byte if present). */
  serialHex: string
  /** Serial magnitude without leading zero bytes. */
  serialBytes: Bytes
  serialNegative: boolean
  /** Number of significant bits in the serial. */
  serialBits: number
  /** Raw encoded INTEGER content length in octets (RFC 5280 limit: 20). */
  serialOctets: number
  subject: Rdn[]
  issuer: Rdn[]
  subjectString: string
  issuerString: string
  subjectDer: Bytes
  issuerDer: Bytes
  notBefore: Date
  notAfter: Date
  signatureAlg: SignatureAlg
  /** Algorithm in TBS must equal the outer one (RFC 5280 §4.1.1.2). */
  signatureAlgMismatch: boolean
  publicKey: KeyInfo
  spkiDer: Bytes
  extensions: ExtensionInfo[]
}

export function signatureAlg(b: Uint8Array, algId: AsnNode | undefined): SignatureAlg {
  const o = child(algId, 0)
  if (!o || !isUniversal(o, 6)) throw new Error('Malformed AlgorithmIdentifier')
  const oid = decodeOid(contents(b, o))
  const known = SIGNATURE_ALGS[oid]
  if (oid === '1.2.840.113549.1.1.10') {
    // RSASSA-PSS-params: [0] hashAlgorithm (default SHA-1)
    let hash = 'SHA-1'
    const params = child(algId, 1)
    for (const p of params?.children ?? []) {
      if (isContext(p, 0)) {
        const h = child(child(p, 0), 0)
        if (h) {
          const hoid = decodeOid(contents(b, h))
          hash = ({ '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512', '1.3.14.3.2.26': 'SHA-1' } as Record<string, string>)[hoid] ?? hoid
        }
      }
    }
    return { oid, name: `RSASSA-PSS (${hash})`, hash, weak: hash === 'SHA-1' ? 'sha1' : undefined }
  }
  return { oid, name: known?.name ?? oid, hash: known?.hash, weak: known?.weak }
}

function readTime(b: Uint8Array, n: AsnNode | undefined): Date {
  if (!n || n.tagClass !== 'universal' || (n.tagNumber !== 23 && n.tagNumber !== 24)) throw new Error('Malformed Time')
  return decodeTime(n.tagNumber, contents(b, n))
}

export function decodeCertificate(der: Uint8Array): CertInfo {
  const b = trimToFirstTlv(der)
  const root = parseOne(b)
  if (!isUniversal(root, 16) || (root.children?.length ?? 0) !== 3) throw new Error('Not an X.509 certificate (expected SEQUENCE of 3 elements)')
  const tbs = child(root, 0)!
  if (!isUniversal(tbs, 16)) throw new Error('Not an X.509 certificate (TBSCertificate is not a SEQUENCE)')
  const t = tbs.children ?? []
  let i = 0
  let version = 1
  if (isContext(t[0], 0)) {
    const v = child(t[0], 0)
    if (v) version = contents(b, v)[0] + 1
    i++
  }
  const serialNode = t[i++]
  const sigInner = t[i++]
  const issuerNode = t[i++]
  const validity = t[i++]
  const subjectNode = t[i++]
  const spkiNode = t[i++]
  if (!isUniversal(serialNode, 2) || !isUniversal(issuerNode, 16) || !isUniversal(validity, 16) || !isUniversal(subjectNode, 16) || !isUniversal(spkiNode, 16)) {
    throw new Error('Malformed TBSCertificate')
  }
  let extNode: AsnNode | undefined
  for (; i < t.length; i++) if (isContext(t[i], 3)) extNode = child(t[i], 0)

  const serialRaw = contents(b, serialNode!)
  let s = 0
  while (s < serialRaw.length - 1 && serialRaw[s] === 0) s++
  const serialBytes = serialRaw.slice(s)
  let bits = 0
  {
    let k = 0
    while (k < serialBytes.length && serialBytes[k] === 0) k++
    if (k < serialBytes.length) bits = (serialBytes.length - k - 1) * 8 + (32 - Math.clz32(serialBytes[k]))
  }
  const subject = decodeNameNode(b, subjectNode!)
  const issuer = decodeNameNode(b, issuerNode!)
  const outerAlg = child(root, 1)
  const sigAlgInfo = signatureAlg(b, outerAlg)
  return {
    der: b,
    version,
    serialHex: toHex(serialRaw),
    serialBytes,
    serialNegative: serialRaw.length > 0 && (serialRaw[0] & 0x80) !== 0,
    serialBits: bits,
    serialOctets: serialRaw.length,
    subject,
    issuer,
    subjectString: formatName(subject),
    issuerString: formatName(issuer),
    subjectDer: tlvBytes(b, subjectNode!),
    issuerDer: tlvBytes(b, issuerNode!),
    notBefore: readTime(b, child(validity, 0)),
    notAfter: readTime(b, child(validity, 1)),
    signatureAlg: sigAlgInfo,
    signatureAlgMismatch: !!sigInner && !!outerAlg && !bytesEqual(tlvBytes(b, sigInner), tlvBytes(b, outerAlg)),
    publicKey: describeSpkiNode(b, spkiNode!),
    spkiDer: tlvBytes(b, spkiNode!),
    extensions: decodeExtensionsNode(b, extNode),
  }
}

export interface Fingerprints {
  sha1: string
  sha256: string
  spkiSha256: string
}

export async function fingerprints(info: Pick<CertInfo, 'der' | 'spkiDer'>): Promise<Fingerprints> {
  const [a, c, k] = await Promise.all([sha('SHA-1', info.der), sha('SHA-256', info.der), sha('SHA-256', info.spkiDer)])
  return { sha1: fingerprintHex(a), sha256: fingerprintHex(c), spkiSha256: fingerprintHex(k) }
}

/** Serial in the usual colon-separated upper-case hex (sign byte dropped). */
export function serialDisplay(info: Pick<CertInfo, 'serialBytes'>): string {
  return toHex(info.serialBytes, ':').toUpperCase()
}

export function isSelfIssued(info: Pick<CertInfo, 'subjectDer' | 'issuerDer'>): boolean {
  return bytesEqual(info.subjectDer, info.issuerDer)
}

export function daysBetween(a: Date, b: Date): number {
  return (b.getTime() - a.getTime()) / 86_400_000
}
