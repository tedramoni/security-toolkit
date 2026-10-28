/** Decoding of X.509 v3 certificate / CSR / CRL extensions. Every decoder is wrapped: failures become `error`. */
import { AsnConvert } from '@peculiar/asn1-schema'
import type { GeneralName } from '@peculiar/asn1-x509'
import {
  AuthorityInfoAccessSyntax,
  AuthorityKeyIdentifier,
  CRLDistributionPoints,
  CertificatePolicies,
  DisplayText,
  IssuingDistributionPoint,
  NameConstraints,
  SubjectAlternativeName,
  UserNotice,
} from '@peculiar/asn1-x509'
import type { Bytes } from './bytes'
import { toBase64, toHex } from './bytes'
import type { AsnNode } from './der'
import { child, contents, decodeOid, decodeString, decodeTime, intToBigInt, isUniversal, parseOne } from './der'
import { decodeName, formatName } from './names'
import { ACCESS_METHODS, CRL_REASONS, EKUS, EXTENSIONS, OID, POLICIES } from './oids'

export type GeneralNameType = 'DNS' | 'IP' | 'email' | 'URI' | 'DirName' | 'otherName' | 'RID' | 'other'

export interface GeneralNameInfo {
  type: GeneralNameType
  value: string
}

export interface SctInfo {
  version: number
  logIdBase64: string
  logIdHex: string
  timestamp: Date
  hashAlg: number
  sigAlg: number
}

export type DecodedExtension =
  | { kind: 'names'; names: GeneralNameInfo[] }
  | { kind: 'ku'; usages: string[] }
  | { kind: 'eku'; usages: { oid: string; name?: string }[] }
  | { kind: 'bc'; ca: boolean; pathLen?: number }
  | { kind: 'keyId'; keyId: string }
  | { kind: 'aki'; keyId?: string; issuer?: GeneralNameInfo[]; serial?: string }
  | { kind: 'access'; items: { method: string; methodName?: string; location: GeneralNameInfo }[] }
  | { kind: 'crldp'; points: { names: GeneralNameInfo[]; reasons?: string[]; crlIssuer?: GeneralNameInfo[] }[] }
  | { kind: 'policies'; policies: { oid: string; name?: string; cps: string[]; notices: string[] }[] }
  | { kind: 'sct'; scts: SctInfo[] }
  | { kind: 'nc'; permitted: GeneralNameInfo[]; excluded: GeneralNameInfo[] }
  | { kind: 'tlsFeature'; features: number[] }
  | { kind: 'integer'; value: string }
  | { kind: 'reason'; code: number; name: string }
  | { kind: 'time'; date: Date }
  | { kind: 'idp'; names: GeneralNameInfo[]; onlyUser: boolean; onlyCA: boolean; indirect: boolean }
  | { kind: 'flag'; text: string }
  | { kind: 'text'; text: string }

export interface ExtensionInfo {
  oid: string
  name?: string
  critical: boolean
  /** extnValue contents (the DER inside the OCTET STRING). */
  value: Bytes
  decoded?: DecodedExtension
  error?: string
}

// ------------------------------------------------------------------------------------------------ GeneralName

const UPN_OID = '1.3.6.1.4.1.311.20.2.3'

function firstString(b: Uint8Array, n: AsnNode | undefined, depth = 0): string | undefined {
  if (!n || depth > 6) return undefined
  if (n.tagClass === 'universal' && !n.constructed) return decodeString(n.tagNumber, contents(b, n))
  for (const c of n.children ?? []) {
    const s = firstString(b, c, depth + 1)
    if (s !== undefined) return s
  }
  return undefined
}

export function formatGeneralName(g: GeneralName): GeneralNameInfo {
  if (g.dNSName !== undefined) return { type: 'DNS', value: g.dNSName }
  if (g.iPAddress !== undefined) return { type: 'IP', value: g.iPAddress }
  if (g.rfc822Name !== undefined) return { type: 'email', value: g.rfc822Name }
  if (g.uniformResourceIdentifier !== undefined) return { type: 'URI', value: g.uniformResourceIdentifier }
  if (g.directoryName !== undefined) {
    try {
      return { type: 'DirName', value: formatName(decodeName(new Uint8Array(AsnConvert.serialize(g.directoryName)))) }
    } catch {
      return { type: 'DirName', value: '(unparseable name)' }
    }
  }
  if (g.registeredID !== undefined) return { type: 'RID', value: g.registeredID }
  if (g.otherName !== undefined) {
    const raw = new Uint8Array(g.otherName.value)
    let text: string | undefined
    try {
      text = firstString(raw, parseOne(raw))
    } catch {
      /* ignore */
    }
    const label = g.otherName.typeId === UPN_OID ? 'UPN' : g.otherName.typeId
    return { type: 'otherName', value: `${label}: ${text ?? toHex(raw)}` }
  }
  return { type: 'other', value: '(unsupported GeneralName)' }
}

const gnList = (names: GeneralName[] | undefined) => (names ?? []).map(formatGeneralName)

// ------------------------------------------------------------------------------------------------ helpers

const KU_NAMES = [
  'digitalSignature',
  'nonRepudiation (contentCommitment)',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
]

export function decodeKeyUsageBits(v: Uint8Array): string[] {
  const n = parseOne(v)
  if (!isUniversal(n, 3)) throw new Error('KeyUsage is not a BIT STRING')
  const c = contents(v, n)
  const out: string[] = []
  for (let i = 0; i < KU_NAMES.length; i++) {
    const byte = c[1 + (i >> 3)]
    if (byte !== undefined && byte & (0x80 >> (i & 7))) out.push(KU_NAMES[i])
  }
  return out
}

/** RFC 6962 §3.3 SignedCertificateTimestampList (TLS encoding inside an OCTET STRING). */
export function decodeSctList(v: Uint8Array): SctInfo[] {
  const n = parseOne(v)
  if (!isUniversal(n, 4)) throw new Error('SCT list is not an OCTET STRING')
  const d = contents(v, n)
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength)
  if (d.length < 2) throw new Error('SCT list too short')
  const total = dv.getUint16(0)
  if (total + 2 !== d.length) throw new Error('SCT list length mismatch')
  const scts: SctInfo[] = []
  let p = 2
  while (p < d.length) {
    if (p + 2 > d.length) throw new Error('Truncated SCT')
    const len = dv.getUint16(p)
    p += 2
    const end = p + len
    if (end > d.length || len < 1 + 32 + 8 + 2) throw new Error('Truncated SCT')
    const version = d[p]
    const logId = d.subarray(p + 1, p + 33)
    const hi = dv.getUint32(p + 33)
    const lo = dv.getUint32(p + 37)
    const ts = hi * 2 ** 32 + lo
    let q = p + 41
    const extLen = dv.getUint16(q)
    q += 2 + extLen
    if (q + 4 > end) throw new Error('Truncated SCT signature')
    scts.push({ version, logIdBase64: toBase64(logId), logIdHex: toHex(logId), timestamp: new Date(ts), hashAlg: d[q], sigAlg: d[q + 1] })
    p = end
    if (scts.length > 100) break
  }
  return scts
}

function decodeIntegerValue(v: Uint8Array): string {
  const n = parseOne(v)
  if (!isUniversal(n, 2)) throw new Error('Not an INTEGER')
  return intToBigInt(contents(v, n)).toString()
}

function displayText(t: DisplayText | undefined): string {
  return t ? t.toString() : ''
}

// ------------------------------------------------------------------------------------------------ main decoder

export function decodeExtensionValue(oid: string, v: Bytes): DecodedExtension | undefined {
  switch (oid) {
    case OID.subjectAltName:
    case OID.issuerAltName:
    case OID.certificateIssuer:
      return { kind: 'names', names: gnList(AsnConvert.parse(v, SubjectAlternativeName)) }
    case OID.keyUsage:
      return { kind: 'ku', usages: decodeKeyUsageBits(v) }
    case OID.extKeyUsage: {
      const n = parseOne(v)
      if (!isUniversal(n, 16)) throw new Error('EKU is not a SEQUENCE')
      const usages = (n.children ?? []).map((c) => {
        const o = decodeOid(contents(v, c))
        return { oid: o, name: EKUS[o] }
      })
      return { kind: 'eku', usages }
    }
    case OID.basicConstraints: {
      const n = parseOne(v)
      if (!isUniversal(n, 16)) throw new Error('BasicConstraints is not a SEQUENCE')
      let ca = false
      let pathLen: number | undefined
      for (const c of n.children ?? []) {
        if (isUniversal(c, 1)) ca = contents(v, c)[0] !== 0
        else if (isUniversal(c, 2)) pathLen = Number(intToBigInt(contents(v, c)))
      }
      return { kind: 'bc', ca, pathLen }
    }
    case OID.subjectKeyIdentifier: {
      const n = parseOne(v)
      if (!isUniversal(n, 4)) throw new Error('SKI is not an OCTET STRING')
      return { kind: 'keyId', keyId: toHex(contents(v, n), ':') }
    }
    case OID.authorityKeyIdentifier: {
      const aki = AsnConvert.parse(v, AuthorityKeyIdentifier)
      return {
        kind: 'aki',
        keyId: aki.keyIdentifier ? toHex(aki.keyIdentifier.buffer, ':') : undefined,
        issuer: aki.authorityCertIssuer ? gnList(aki.authorityCertIssuer) : undefined,
        serial: aki.authorityCertSerialNumber ? toHex(aki.authorityCertSerialNumber, ':') : undefined,
      }
    }
    case OID.authorityInfoAccess:
    case OID.subjectInfoAccess: {
      const aia = AsnConvert.parse(v, AuthorityInfoAccessSyntax)
      return {
        kind: 'access',
        items: aia.map((a) => ({ method: a.accessMethod, methodName: ACCESS_METHODS[a.accessMethod], location: formatGeneralName(a.accessLocation) })),
      }
    }
    case OID.crlDistributionPoints:
    case OID.freshestCrl: {
      const dps = AsnConvert.parse(v, CRLDistributionPoints)
      return {
        kind: 'crldp',
        points: dps.map((dp) => ({
          names: gnList(dp.distributionPoint?.fullName),
          reasons: dp.reasons?.toJSON(),
          crlIssuer: dp.cRLIssuer ? gnList(dp.cRLIssuer) : undefined,
        })),
      }
    }
    case OID.certificatePolicies: {
      const cps = AsnConvert.parse(v, CertificatePolicies)
      return {
        kind: 'policies',
        policies: cps.map((p) => {
          const cpsUris: string[] = []
          const notices: string[] = []
          for (const q of p.policyQualifiers ?? []) {
            try {
              if (q.policyQualifierId === '1.3.6.1.5.5.7.2.1') {
                const raw = new Uint8Array(q.qualifier)
                const s = firstString(raw, parseOne(raw))
                if (s) cpsUris.push(s)
              } else if (q.policyQualifierId === '1.3.6.1.5.5.7.2.2') {
                const un = AsnConvert.parse(q.qualifier, UserNotice)
                const t = displayText(un.explicitText)
                if (t) notices.push(t)
              }
            } catch {
              /* skip malformed qualifier */
            }
          }
          return { oid: p.policyIdentifier, name: POLICIES[p.policyIdentifier], cps: cpsUris, notices }
        }),
      }
    }
    case OID.sctList:
      return { kind: 'sct', scts: decodeSctList(v) }
    case OID.ctPoison:
      return { kind: 'flag', text: 'Precertificate (RFC 6962) — not a usable certificate' }
    case OID.ocspNoCheck:
      return { kind: 'flag', text: 'OCSP responder certificate: revocation is not checked' }
    case OID.nameConstraints: {
      const nc = AsnConvert.parse(v, NameConstraints)
      return {
        kind: 'nc',
        permitted: (nc.permittedSubtrees ?? []).map((s) => formatGeneralName(s.base)),
        excluded: (nc.excludedSubtrees ?? []).map((s) => formatGeneralName(s.base)),
      }
    }
    case OID.tlsFeature: {
      const n = parseOne(v)
      return { kind: 'tlsFeature', features: (n.children ?? []).map((c) => Number(intToBigInt(contents(v, c)))) }
    }
    case OID.crlNumber:
    case OID.deltaCrlIndicator:
    case OID.inhibitAnyPolicy:
      return { kind: 'integer', value: decodeIntegerValue(v) }
    case OID.crlReason: {
      const n = parseOne(v)
      const code = Number(intToBigInt(contents(v, n)))
      return { kind: 'reason', code, name: CRL_REASONS[code] ?? `unknown (${code})` }
    }
    case OID.invalidityDate: {
      const n = parseOne(v)
      return { kind: 'time', date: decodeTime(n.tagNumber, contents(v, n)) }
    }
    case OID.issuingDistributionPoint: {
      const idp = AsnConvert.parse(v, IssuingDistributionPoint)
      return {
        kind: 'idp',
        names: gnList(idp.distributionPoint?.fullName),
        onlyUser: idp.onlyContainsUserCerts,
        onlyCA: idp.onlyContainsCACerts,
        indirect: idp.indirectCRL,
      }
    }
    case '2.16.840.1.113730.1.13': {
      const n = parseOne(v)
      return { kind: 'text', text: decodeString(n.tagNumber, contents(v, n)) ?? '' }
    }
    default:
      return undefined
  }
}

/** Parse an `Extensions` SEQUENCE node (from a cert / CRL / CSR extensionRequest). */
export function decodeExtensionsNode(b: Uint8Array, seq: AsnNode | undefined): ExtensionInfo[] {
  const out: ExtensionInfo[] = []
  for (const ext of seq?.children ?? []) {
    const oidNode = child(ext, 0)
    if (!oidNode || !isUniversal(oidNode, 6)) continue
    const oid = decodeOid(contents(b, oidNode))
    let critical = false
    let valueNode = child(ext, 1)
    if (isUniversal(valueNode, 1)) {
      critical = contents(b, valueNode!)[0] !== 0
      valueNode = child(ext, 2)
    }
    if (!valueNode || !isUniversal(valueNode, 4)) {
      out.push({ oid, name: EXTENSIONS[oid], critical, value: new Uint8Array(0), error: 'Missing extnValue' })
      continue
    }
    const value = contents(b, valueNode)
    const info: ExtensionInfo = { oid, name: EXTENSIONS[oid], critical, value }
    try {
      info.decoded = decodeExtensionValue(oid, value)
    } catch (e) {
      info.error = `Could not decode: ${(e as Error).message}`
    }
    out.push(info)
  }
  return out
}

export function findExt(exts: readonly ExtensionInfo[], oid: string): ExtensionInfo | undefined {
  return exts.find((e) => e.oid === oid)
}

/** Typed accessors over decoded extensions. */
export function extDecoded<K extends DecodedExtension['kind']>(
  exts: readonly ExtensionInfo[],
  oid: string,
  kind: K,
): Extract<DecodedExtension, { kind: K }> | undefined {
  const d = findExt(exts, oid)?.decoded
  return d && d.kind === kind ? (d as Extract<DecodedExtension, { kind: K }>) : undefined
}

export function sanNames(exts: readonly ExtensionInfo[]): GeneralNameInfo[] {
  return extDecoded(exts, OID.subjectAltName, 'names')?.names ?? []
}

export function accessUrls(exts: readonly ExtensionInfo[], method: string): string[] {
  const acc = extDecoded(exts, OID.authorityInfoAccess, 'access')
  return (acc?.items ?? []).filter((i) => i.method === method && i.location.type === 'URI').map((i) => i.location.value)
}

export function crlUrls(exts: readonly ExtensionInfo[]): string[] {
  const d = extDecoded(exts, OID.crlDistributionPoints, 'crldp')
  return (d?.points ?? []).flatMap((p) => p.names.filter((n) => n.type === 'URI').map((n) => n.value))
}
