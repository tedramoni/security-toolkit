/**
 * Key handling for the key matcher / converter: identify PEM blocks, convert PKCS#1 / SEC1 private keys to PKCS#8,
 * derive the public key from a private key, and compare keys by a canonical SPKI SHA-256.
 * Private keys only ever live in memory; nothing is persisted.
 */
import type { Bytes } from './bytes'
import { fingerprintHex, sha } from './bytes'
import { decodeCertificate } from './cert'
import { decodeCsr } from './csr'
import type { AsnNode } from './der'
import { child, concat, contents, decodeOid, derNull, derOctets, derOid, derSeq, isContext, isUniversal, parseOne, tlv, tlvBytes } from './der'
import { CURVES, KEY_ALGS, OID } from './oids'
import type { PemBlock } from './pem'
import type { KeyInfo } from './spki'
import { describeSpki } from './spki'

export type KeyItemKind = 'certificate' | 'csr' | 'public-key' | 'rsa-public-key' | 'private-key' | 'rsa-private-key' | 'ec-private-key' | 'unsupported'

export interface KeyItem {
  label: string
  kind: KeyItemKind
  /** Short description of the source (subject, key type…). */
  description: string
  spki?: Bytes
  key?: KeyInfo
  /** SHA-256 of the canonical SPKI (colon hex) — equal ⇔ same key pair. */
  fingerprint?: string
  error?: string
  /** Extra advice, e.g. the openssl command to convert. */
  note?: string
  isPrivate: boolean
}

const bitString = (b: Uint8Array) => tlv(0x03, concat(new Uint8Array([0]), b))

/** PKCS#1 RSAPublicKey → SubjectPublicKeyInfo. */
export function rsaPublicToSpki(pkcs1: Uint8Array): Bytes {
  return derSeq(derSeq(derOid(OID.rsaEncryption), derNull()), bitString(pkcs1))
}

/** PKCS#1 RSAPrivateKey → PKCS#8 PrivateKeyInfo. */
export function pkcs1PrivateToPkcs8(pkcs1: Uint8Array): Bytes {
  return derSeq(new Uint8Array([0x02, 0x01, 0x00]), derSeq(derOid(OID.rsaEncryption), derNull()), derOctets(pkcs1))
}

/** SEC1 ECPrivateKey → PKCS#8 (curve taken from the [0] parameters unless given). */
export function sec1ToPkcs8(sec1: Uint8Array, curveOid?: string): Bytes {
  const n = parseOne(sec1)
  let curve = curveOid
  for (const c of n.children ?? []) {
    if (isContext(c, 0)) {
      const o = child(c, 0)
      if (o && isUniversal(o, 6)) curve = decodeOid(contents(sec1, o))
    }
  }
  if (!curve) throw new Error('EC private key has no curve parameters')
  return derSeq(new Uint8Array([0x02, 0x01, 0x00]), derSeq(derOid(OID.ecPublicKey), derOid(curve)), derOctets(sec1))
}

/** Canonical SPKI: RSA keys (incl. RSA-PSS) re-encoded as rsaEncryption(n, e); others unchanged. */
export function canonicalSpki(spki: Uint8Array): Bytes {
  const n = parseOne(spki)
  const algOid = decodeOid(contents(spki, child(child(n, 0), 0)!))
  if (algOid === OID.rsaPss || algOid === OID.rsaEncryption) {
    const bits = contents(spki, child(n, 1)!).subarray(1)
    const rsa = parseOne(bits)
    const mod = child(rsa, 0)
    const exp = child(rsa, 1)
    if (!mod || !exp) throw new Error('Malformed RSA public key')
    return rsaPublicToSpki(derSeq(tlvBytes(bits, mod), tlvBytes(bits, exp)))
  }
  return Uint8Array.from(spki)
}

function importParamsFor(algOid: string, algNode: AsnNode | undefined, b: Uint8Array): { alg: RsaHashedImportParams | EcKeyImportParams | Algorithm; usages: KeyUsage[] } {
  if (algOid === OID.rsaEncryption) return { alg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, usages: ['sign'] }
  if (algOid === OID.ecPublicKey) {
    const p = child(algNode, 1)
    const curveOid = p && isUniversal(p, 6) ? decodeOid(contents(b, p)) : ''
    const curve = CURVES[curveOid]
    if (!curve || !['P-256', 'P-384', 'P-521'].includes(curve)) throw new Error(`WebCrypto does not support curve ${curve ?? (curveOid || 'explicit parameters')}`)
    return { alg: { name: 'ECDSA', namedCurve: curve }, usages: ['sign'] }
  }
  if (algOid === OID.ed25519) return { alg: { name: 'Ed25519' }, usages: ['sign'] }
  if (algOid === OID.x25519) return { alg: { name: 'X25519' }, usages: ['deriveBits'] }
  throw new Error(`Unsupported private key algorithm ${KEY_ALGS[algOid] ?? algOid}`)
}

/** Try to read the public key straight from the private key structure (no WebCrypto). */
function publicFromPkcs8Asn1(pkcs8: Uint8Array): Bytes | undefined {
  const n = parseOne(pkcs8)
  const alg = child(n, 1)
  const algOid = decodeOid(contents(pkcs8, child(alg, 0)!))
  const inner = contents(pkcs8, child(n, 2)!)
  // OneAsymmetricKey [1] publicKey
  for (const c of n.children ?? []) {
    if (isContext(c, 1)) return derSeq(tlvBytes(pkcs8, alg!), bitString(contents(pkcs8, c).subarray(1)))
  }
  if (algOid === OID.rsaEncryption || algOid === OID.rsaPss) {
    const k = parseOne(inner)
    const mod = child(k, 1)
    const exp = child(k, 2)
    if (mod && exp) return rsaPublicToSpki(derSeq(tlvBytes(inner, mod), tlvBytes(inner, exp)))
  }
  if (algOid === OID.ecPublicKey) {
    const k = parseOne(inner)
    for (const c of k.children ?? []) {
      if (isContext(c, 1)) {
        const bs = child(c, 0)
        if (bs && isUniversal(bs, 3)) return derSeq(tlvBytes(pkcs8, alg!), tlvBytes(inner, bs))
      }
    }
  }
  return undefined
}

/** Derive the SubjectPublicKeyInfo for a PKCS#8 private key (WebCrypto: import → JWK → drop private parts → SPKI). */
export async function publicFromPkcs8(pkcs8: Uint8Array): Promise<Bytes> {
  const n = parseOne(pkcs8)
  const alg = child(n, 1)
  if (!isUniversal(n, 16) || !alg || !isUniversal(child(n, 2), 4)) throw new Error('Not a PKCS#8 PrivateKeyInfo')
  const algOid = decodeOid(contents(pkcs8, child(alg, 0)!))
  try {
    const { alg: params, usages } = importParamsFor(algOid, alg, pkcs8)
    const priv = await crypto.subtle.importKey('pkcs8', Uint8Array.from(pkcs8), params, true, usages)
    const jwk = await crypto.subtle.exportKey('jwk', priv)
    for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'] as const) delete (jwk as Record<string, unknown>)[k]
    delete jwk.key_ops
    const pubUsages: KeyUsage[] = usages.includes('sign') ? ['verify'] : []
    const pub = await crypto.subtle.importKey('jwk', jwk, params, true, pubUsages)
    return new Uint8Array(await crypto.subtle.exportKey('spki', pub))
  } catch (e) {
    const fallback = publicFromPkcs8Asn1(pkcs8)
    if (fallback) return fallback
    throw e
  }
}

export async function spkiFingerprint(spki: Uint8Array): Promise<string> {
  return fingerprintHex(await sha('SHA-256', canonicalSpki(spki)))
}

const CONVERT_NOTE: Record<string, string> = {
  'rsa-private-key': 'PKCS#1 key converted to PKCS#8 in the browser. Equivalent: openssl pkcs8 -topk8 -nocrypt -in rsa.key -out key.pem',
  'ec-private-key': 'SEC1 key converted to PKCS#8 in the browser. Equivalent: openssl pkcs8 -topk8 -nocrypt -in ec.key -out key.pem',
}

/** Identify a PEM block and compute its public key fingerprint. Never throws. */
export async function analyzeKeyBlock(block: PemBlock): Promise<KeyItem> {
  const label = block.label || '(DER)'
  const base = { label, isPrivate: false } as const
  try {
    if (block.encrypted) {
      return { ...base, kind: 'unsupported', isPrivate: true, description: 'Encrypted private key (legacy OpenSSL format)', error: 'Encrypted keys cannot be read here.', note: 'Decrypt locally first: openssl pkey -in encrypted.key -out key.pem' }
    }
    let kind: KeyItemKind
    let spki: Bytes
    let description = ''
    let note: string | undefined
    switch (block.label) {
      case 'CERTIFICATE':
      case 'TRUSTED CERTIFICATE':
      case 'X509 CERTIFICATE': {
        const c = decodeCertificate(block.der)
        kind = 'certificate'
        spki = c.spkiDer
        description = c.subjectString || '(empty subject)'
        break
      }
      case 'CERTIFICATE REQUEST':
      case 'NEW CERTIFICATE REQUEST': {
        const c = decodeCsr(block.der)
        kind = 'csr'
        spki = c.spkiDer
        description = c.subjectString || '(empty subject)'
        break
      }
      case 'PUBLIC KEY':
        kind = 'public-key'
        spki = Uint8Array.from(block.der)
        description = 'SubjectPublicKeyInfo'
        break
      case 'RSA PUBLIC KEY':
        kind = 'rsa-public-key'
        spki = rsaPublicToSpki(block.der)
        description = 'PKCS#1 RSA public key'
        break
      case 'PRIVATE KEY':
        kind = 'private-key'
        spki = await publicFromPkcs8(block.der)
        description = 'PKCS#8 private key'
        break
      case 'RSA PRIVATE KEY':
        kind = 'rsa-private-key'
        spki = await publicFromPkcs8(pkcs1PrivateToPkcs8(block.der))
        description = 'PKCS#1 RSA private key'
        note = CONVERT_NOTE[kind]
        break
      case 'EC PRIVATE KEY':
        kind = 'ec-private-key'
        spki = await publicFromPkcs8(sec1ToPkcs8(block.der))
        description = 'SEC1 EC private key'
        note = CONVERT_NOTE[kind]
        break
      case 'ENCRYPTED PRIVATE KEY':
        return { ...base, kind: 'unsupported', isPrivate: true, description: 'Encrypted PKCS#8 private key', error: 'Encrypted keys cannot be read here (WebCrypto has no PBES2 import).', note: 'Decrypt locally first: openssl pkcs8 -in encrypted.key -out key.pem' }
      default: {
        if (block.label === '') {
          // Unlabelled DER: try certificate, CSR, SPKI, PKCS#8 in turn.
          for (const lbl of ['CERTIFICATE', 'CERTIFICATE REQUEST', 'PUBLIC KEY', 'PRIVATE KEY']) {
            const r = await analyzeKeyBlock({ ...block, label: lbl })
            if (!r.error) return { ...r, label: `${lbl} (DER)` }
          }
        }
        return { ...base, kind: 'unsupported', description: `Unsupported block "${label}"`, error: 'Not a certificate, CSR, public or private key.' }
      }
    }
    const isPrivate = kind.endsWith('private-key')
    return { label, kind, description, spki, key: describeSpki(spki), fingerprint: await spkiFingerprint(spki), note, isPrivate }
  } catch (e) {
    return { ...base, kind: 'unsupported', isPrivate: block.label.includes('PRIVATE'), description: `Could not read "${label}"`, error: (e as Error).message }
  }
}

/** n×n boolean matrix: same key pair? (undefined when either side has no fingerprint). */
export function matchMatrix(items: readonly KeyItem[]): (boolean | undefined)[][] {
  return items.map((a) => items.map((b) => (a.fingerprint && b.fingerprint ? a.fingerprint === b.fingerprint : undefined)))
}
