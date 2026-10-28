/** Format conversions: PKCS#7 → certificates, SPKI ↔ JWK, certificate → JWK (x5c, x5t#S256), RFC 7638 thumbprint. */
import type { Bytes } from './bytes'
import { sha, toBase64, toBase64Url } from './bytes'
import { decodeCertificate } from './cert'
import { child, contents, decodeOid, isContext, isUniversal, parseDer, tlvBytes } from './der'
import { CURVES, OID } from './oids'

/** Extract certificates (and count CRLs) from a CMS/PKCS#7 SignedData (DER or BER, e.g. a .p7b file). */
export function extractPkcs7(der: Uint8Array): { certs: Bytes[]; crls: Bytes[] } {
  const r = parseDer(der, { encapsulated: false, maxNodes: 500_000 })
  if (r.errors.length || r.nodes.length === 0) throw new Error(r.errors[0] ?? 'Empty input')
  const ci = r.nodes[0]
  const typeNode = child(ci, 0)
  if (!isUniversal(ci, 16) || !typeNode || !isUniversal(typeNode, 6)) throw new Error('Not a CMS ContentInfo')
  const type = decodeOid(contents(der, typeNode))
  if (type !== OID.signedData) throw new Error(`ContentInfo type ${type} is not signedData (1.2.840.113549.1.7.2)`)
  const sd = child(child(ci, 1), 0)
  if (!isUniversal(sd, 16)) throw new Error('Malformed SignedData')
  const certs: Bytes[] = []
  const crls: Bytes[] = []
  for (const c of sd!.children ?? []) {
    if (isContext(c, 0)) {
      for (const cert of c.children ?? []) if (isUniversal(cert, 16)) certs.push(tlvBytes(der, cert))
    } else if (isContext(c, 1)) {
      for (const crl of c.children ?? []) if (isUniversal(crl, 16)) crls.push(tlvBytes(der, crl))
    }
  }
  return { certs, crls }
}

export type PublicJwk = { kty: 'RSA'; n: string; e: string } | { kty: 'EC'; crv: string; x: string; y: string } | { kty: 'OKP'; crv: string; x: string }

function importParams(spkiAlg: string, curve?: string): { alg: RsaHashedImportParams | EcKeyImportParams | Algorithm; usages: KeyUsage[] } {
  if (spkiAlg === OID.rsaEncryption) return { alg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, usages: ['verify'] }
  if (spkiAlg === OID.ecPublicKey && curve && ['P-256', 'P-384', 'P-521'].includes(curve)) return { alg: { name: 'ECDSA', namedCurve: curve }, usages: ['verify'] }
  if (spkiAlg === OID.ed25519) return { alg: { name: 'Ed25519' }, usages: ['verify'] }
  if (spkiAlg === OID.x25519) return { alg: { name: 'X25519' }, usages: [] }
  throw new Error('Only RSA, EC P-256/P-384/P-521, Ed25519 and X25519 keys can be converted to JWK')
}

function spkiAlg(spki: Uint8Array): { oid: string; curve?: string } {
  const r = parseDer(spki, { encapsulated: false })
  const alg = child(r.nodes[0], 0)
  const o = child(alg, 0)
  if (!o || !isUniversal(o, 6)) throw new Error('Not a SubjectPublicKeyInfo')
  const oid = decodeOid(contents(spki, o))
  const p = child(alg, 1)
  const curve = p && isUniversal(p, 6) ? CURVES[decodeOid(contents(spki, p))] : undefined
  return { oid, curve }
}

/** Public JWK with only the required members (RFC 7517/7518), no alg/use/key_ops. */
export async function spkiToJwk(spki: Uint8Array): Promise<PublicJwk> {
  const { oid, curve } = spkiAlg(spki)
  const { alg, usages } = importParams(oid, curve)
  const key = await crypto.subtle.importKey('spki', Uint8Array.from(spki), alg, true, usages)
  const jwk = await crypto.subtle.exportKey('jwk', key)
  if (jwk.kty === 'RSA') return { kty: 'RSA', n: jwk.n!, e: jwk.e! }
  if (jwk.kty === 'EC') return { kty: 'EC', crv: jwk.crv!, x: jwk.x!, y: jwk.y! }
  return { kty: 'OKP', crv: jwk.crv!, x: jwk.x! }
}

export async function jwkToSpki(jwkInput: unknown): Promise<Bytes> {
  if (typeof jwkInput !== 'object' || jwkInput === null || Array.isArray(jwkInput)) throw new Error('JWK must be a JSON object')
  const j = jwkInput as Record<string, unknown>
  if ('d' in j) throw new Error('This is a PRIVATE JWK (it has "d"). Paste the public JWK only.')
  let alg: RsaHashedImportParams | EcKeyImportParams | Algorithm
  let usages: KeyUsage[] = ['verify']
  if (j.kty === 'RSA') alg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
  else if (j.kty === 'EC' && typeof j.crv === 'string' && ['P-256', 'P-384', 'P-521'].includes(j.crv)) alg = { name: 'ECDSA', namedCurve: j.crv }
  else if (j.kty === 'OKP' && j.crv === 'Ed25519') alg = { name: 'Ed25519' }
  else if (j.kty === 'OKP' && j.crv === 'X25519') {
    alg = { name: 'X25519' }
    usages = []
  } else throw new Error('Unsupported JWK (supported: RSA, EC P-256/P-384/P-521, OKP Ed25519/X25519)')
  const clean: JsonWebKey = { ...(j as JsonWebKey), ext: true }
  delete clean.key_ops
  delete clean.alg
  delete clean.use
  const key = await crypto.subtle.importKey('jwk', clean, alg, true, usages)
  return new Uint8Array(await crypto.subtle.exportKey('spki', key))
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export async function jwkThumbprint(jwk: PublicJwk): Promise<string> {
  let canonical: string
  if (jwk.kty === 'RSA') canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })
  else if (jwk.kty === 'EC') canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
  else canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })
  return toBase64Url(await sha('SHA-256', new TextEncoder().encode(canonical)))
}

/** JWK for a certificate's public key, with kid (RFC 7638), x5c (RFC 7517 §4.7, std base64) and x5t#S256. */
export async function certToJwk(certDers: Uint8Array[]): Promise<Record<string, unknown>> {
  if (certDers.length === 0) throw new Error('No certificate')
  const leaf = decodeCertificate(certDers[0])
  const jwk = await spkiToJwk(leaf.spkiDer)
  return {
    ...jwk,
    kid: await jwkThumbprint(jwk),
    x5c: certDers.map((d) => toBase64(d)),
    'x5t#S256': toBase64Url(await sha('SHA-256', certDers[0])),
  }
}

export const PKCS12_COMMANDS: readonly { title: string; cmd: string; note?: string }[] = [
  { title: 'Inspect a .pfx / .p12', cmd: 'openssl pkcs12 -info -in bundle.pfx -noout', note: 'OpenSSL 3 cannot read old files encrypted with RC2/3DES (most Windows exports before 2020) unless you add -legacy.' },
  { title: 'Extract the certificate(s)', cmd: 'openssl pkcs12 -in bundle.pfx -nokeys -out certs.pem' },
  { title: 'Extract only the leaf certificate', cmd: 'openssl pkcs12 -in bundle.pfx -clcerts -nokeys -out cert.pem' },
  { title: 'Extract the private key (unencrypted PKCS#8)', cmd: 'openssl pkcs12 -in bundle.pfx -nocerts -nodes -out key.pem', note: 'The output key is NOT protected: restrict file permissions and delete it when done.' },
  { title: 'Old file fails with "unsupported" / "RC2-40-CBC" (OpenSSL 3)', cmd: 'openssl pkcs12 -legacy -in bundle.pfx -nodes -out all.pem' },
  { title: 'Create a .pfx from key + cert + chain', cmd: 'openssl pkcs12 -export -inkey key.pem -in cert.pem -certfile chain.pem -out bundle.pfx', note: 'OpenSSL 3 uses AES-256-CBC + PBKDF2 by default; add -legacy for very old Windows / Java versions.' },
]
