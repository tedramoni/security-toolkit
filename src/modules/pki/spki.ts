/** SubjectPublicKeyInfo inspection (algorithm, size / curve) from raw DER. */
import type { AsnNode } from './der'
import { child, contents, decodeOid, intToBigInt, isUniversal, parseOne } from './der'
import { CURVES, KEY_ALGS, OID } from './oids'

export interface KeyInfo {
  algOid: string
  /** RSA, EC, Ed25519, … or the OID when unknown. */
  type: string
  /** Modulus size (RSA/DSA) or field size (EC / EdDSA). */
  bits?: number
  curve?: string
  curveOid?: string
  exponent?: string
  /** Short description, e.g. "RSA 2048 bit" or "EC P-256". */
  summary: string
}

/** Bit length of an unsigned big-endian magnitude (leading zero bytes ignored). */
export function bitLength(mag: Uint8Array): number {
  let i = 0
  while (i < mag.length && mag[i] === 0) i++
  if (i === mag.length) return 0
  return (mag.length - i - 1) * 8 + (32 - Math.clz32(mag[i]))
}

const EC_FIELD_BITS: Record<string, number> = {
  'P-256': 256,
  'P-384': 384,
  'P-521': 521,
  'P-192': 192,
  'P-224': 224,
  secp256k1: 256,
  brainpoolP256r1: 256,
  brainpoolP384r1: 384,
  brainpoolP512r1: 512,
}

export function describeSpkiNode(b: Uint8Array, spki: AsnNode): KeyInfo {
  const alg = child(spki, 0)
  const bits = child(spki, 1)
  const algOidNode = child(alg, 0)
  if (!algOidNode || !isUniversal(algOidNode, 6) || !bits || !isUniversal(bits, 3)) {
    throw new Error('Malformed SubjectPublicKeyInfo')
  }
  const algOid = decodeOid(contents(b, algOidNode))
  const type = KEY_ALGS[algOid] ?? algOid
  const info: KeyInfo = { algOid, type, summary: type }
  const keyBytes = contents(b, bits).subarray(1)
  if (algOid === OID.rsaEncryption || algOid === OID.rsaPss) {
    try {
      const rsa = parseOne(keyBytes)
      const n = child(rsa, 0)
      const e = child(rsa, 1)
      if (n && e) {
        info.bits = bitLength(contents(keyBytes, n))
        info.exponent = intToBigInt(contents(keyBytes, e)).toString()
        info.summary = `${type} ${info.bits} bit (e=${info.exponent})`
      }
    } catch {
      info.summary = `${type} (unparseable key)`
    }
  } else if (algOid === OID.ecPublicKey) {
    const params = child(alg, 1)
    if (params && isUniversal(params, 6)) {
      info.curveOid = decodeOid(contents(b, params))
      info.curve = CURVES[info.curveOid] ?? info.curveOid
      info.bits = EC_FIELD_BITS[info.curve]
      info.summary = `EC ${info.curve}`
    } else {
      info.curve = 'explicit parameters'
      info.summary = 'EC (explicit curve parameters)'
    }
  } else if (algOid === OID.ed25519 || algOid === OID.x25519) {
    info.bits = 256
  } else if (algOid === OID.ed448 || algOid === OID.x448) {
    info.bits = 448
  } else if (algOid === OID.dsa) {
    const p = child(child(alg, 1), 0)
    if (p) {
      info.bits = bitLength(contents(b, p))
      info.summary = `DSA ${info.bits} bit`
    }
  }
  return info
}

export function describeSpki(der: Uint8Array): KeyInfo {
  return describeSpkiNode(der, parseOne(der))
}
