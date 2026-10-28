/** PKCS#10 certificate signing request decoding + lint. */
import type { Finding } from '../toolbox/types'
import type { Bytes } from './bytes'
import type { SignatureAlg } from './cert'
import { signatureAlg } from './cert'
import { child, contents, decodeOid, decodeString, isContext, isUniversal, parseOne, tlvBytes, trimToFirstTlv } from './der'
import type { ExtensionInfo } from './extensions'
import { decodeExtensionsNode, extDecoded, sanNames } from './extensions'
import { normalizeHostname, parseIp } from './hostname'
import type { Rdn } from './names'
import { decodeNameNode, formatName, nameField } from './names'
import { OID, oidName } from './oids'
import type { KeyInfo } from './spki'
import { describeSpkiNode } from './spki'

export interface CsrAttribute {
  oid: string
  name?: string
  /** Printable value(s) when decodable. */
  values: string[]
}

export interface CsrInfo {
  der: Bytes
  version: number
  subject: Rdn[]
  subjectString: string
  publicKey: KeyInfo
  spkiDer: Bytes
  signatureAlg: SignatureAlg
  extensions: ExtensionInfo[]
  attributes: CsrAttribute[]
  challengePassword?: string
}

export function decodeCsr(der: Uint8Array): CsrInfo {
  const b = trimToFirstTlv(der)
  const root = parseOne(b)
  const info = child(root, 0)
  if (!isUniversal(root, 16) || !isUniversal(info, 16) || (root.children?.length ?? 0) !== 3) throw new Error('Not a PKCS#10 CSR (expected SEQUENCE { CertificationRequestInfo, AlgorithmIdentifier, BIT STRING })')
  const [ver, subj, spki, attrs] = info!.children ?? []
  if (!isUniversal(ver, 2) || !isUniversal(subj, 16) || !isUniversal(spki, 16)) throw new Error('Malformed CertificationRequestInfo')
  const subject = decodeNameNode(b, subj!)
  const out: CsrInfo = {
    der: b,
    version: contents(b, ver!)[0] + 1,
    subject,
    subjectString: formatName(subject),
    publicKey: describeSpkiNode(b, spki!),
    spkiDer: tlvBytes(b, spki!),
    signatureAlg: signatureAlg(b, child(root, 1)),
    extensions: [],
    attributes: [],
  }
  if (attrs && isContext(attrs, 0)) {
    for (const a of attrs.children ?? []) {
      const oidNode = child(a, 0)
      const set = child(a, 1)
      if (!oidNode || !isUniversal(oidNode, 6)) continue
      const oid = decodeOid(contents(b, oidNode))
      const attr: CsrAttribute = { oid, name: oidName(oid), values: [] }
      if (oid === OID.extensionRequest) {
        out.extensions.push(...decodeExtensionsNode(b, child(set, 0)))
      } else {
        for (const v of set?.children ?? []) {
          const s = v.tagClass === 'universal' && !v.constructed ? decodeString(v.tagNumber, contents(b, v)) : undefined
          if (s !== undefined) attr.values.push(s)
        }
        if (oid === OID.challengePassword) out.challengePassword = attr.values[0] ?? ''
      }
      out.attributes.push(attr)
    }
  }
  return out
}

export function lintCsr(csr: CsrInfo, signatureOk: boolean | undefined): Finding[] {
  const f: Finding[] = []
  if (signatureOk === false) {
    f.push({ severity: 'critical', title: 'CSR signature does not verify', detail: 'The request was modified after signing, or was signed with a different key. A CA will reject it (proof of possession fails).' })
  }
  const pk = csr.publicKey
  if ((pk.type === 'RSA' || pk.type === 'RSA-PSS') && pk.bits !== undefined && pk.bits < 2048) {
    f.push({ severity: pk.bits < 1024 ? 'critical' : 'high', title: `Weak key: RSA ${pk.bits} bits`, detail: 'Public CAs refuse RSA keys below 2048 bits.', fix: 'Generate a new RSA ≥ 2048 or ECDSA P-256 key.' })
  }
  if (pk.type === 'EC' && pk.curve && !['P-256', 'P-384', 'P-521'].includes(pk.curve)) {
    f.push({ severity: 'medium', title: `Curve ${pk.curve} not accepted by public CAs`, detail: 'Use P-256 or P-384.' })
  }
  if (pk.type === 'DSA') f.push({ severity: 'high', title: 'DSA key', detail: 'DSA is deprecated and not accepted by public CAs.' })
  if (csr.signatureAlg.weak) {
    f.push({ severity: 'high', title: `Weak signature: ${csr.signatureAlg.name}`, detail: 'Many CAs reject SHA-1/MD5-signed requests.', fix: 'Re-create the CSR with -sha256.' })
  }
  const sans = sanNames(csr.extensions)
  const cns = nameField(csr.subject, OID.commonName)
  if (sans.length === 0) {
    f.push({ severity: 'medium', title: 'No Subject Alternative Name requested', detail: 'Browsers only check SAN entries. Many CAs copy the CN into the SAN, but you should request every hostname explicitly.', fix: 'Add -addext "subjectAltName=DNS:example.com,DNS:www.example.com".' })
  }
  for (const cn of cns) {
    const ip = parseIp(cn)
    const host = ip ? undefined : normalizeHostname(cn)
    if (sans.length > 0 && (ip || (host && cn.includes('.')))) {
      const covered = sans.some((s) => (ip ? s.type === 'IP' && parseIp(s.value)?.join('.') === ip.join('.') : s.type === 'DNS' && s.value.toLowerCase() === host))
      if (!covered) f.push({ severity: 'medium', title: `CN "${cn}" is not in the SAN`, detail: 'Public CAs require the CN to also appear in the SAN.' })
    }
  }
  if (csr.challengePassword !== undefined) {
    f.push({ severity: 'info', title: 'challengePassword attribute present', detail: 'It is stored in clear text inside the CSR (it is NOT a key password) and is ignored by most CAs. Treat the value as disclosed; leave it empty when prompted by openssl.' })
  }
  const bc = extDecoded(csr.extensions, OID.basicConstraints, 'bc')
  if (bc?.ca) f.push({ severity: 'info', title: 'Requests CA:TRUE', detail: 'This is a request for a CA certificate; a public CA will never grant it to a subscriber.' })
  for (const e of csr.extensions) if (e.error) f.push({ severity: 'medium', title: `Malformed extension ${e.name ?? e.oid}`, detail: e.error })
  if (f.filter((x) => x.severity !== 'info').length === 0) f.push({ severity: 'pass', title: 'No problems found', detail: 'None of the lint rules triggered.' })
  return f
}
