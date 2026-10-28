/** OCSP (RFC 6960) helper: build the request DER / GET URL and the equivalent openssl command. */
import type { Bytes } from './bytes'
import { fromHex, sha, toBase64, toHex } from './bytes'
import type { CertInfo } from './cert'
import { child, contents, derNull, derOctets, derOid, derSeq, parseOne, tlv } from './der'
import { accessUrls } from './extensions'
import { OID } from './oids'
import { shellQuote } from './generate'

export interface OcspRequestInfo {
  der: Bytes
  base64: string
  /** RFC 6960 Appendix A.1 GET URL (undefined if the responder URL is unknown). */
  getUrl?: string
  issuerNameHash: string
  issuerKeyHash: string
  serialHex: string
}

/** Contents of the issuer's subjectPublicKey BIT STRING (without the unused-bits byte) — what issuerKeyHash hashes. */
export function issuerKeyBits(issuer: Pick<CertInfo, 'spkiDer'>): Bytes {
  const spki = parseOne(issuer.spkiDer)
  const bits = child(spki, 1)
  if (!bits) throw new Error('Malformed issuer public key')
  return contents(issuer.spkiDer, bits).slice(1)
}

/** Build an OCSPRequest for one certificate (SHA-1 CertID, no nonce — what `openssl ocsp -no_nonce` sends). */
export async function buildOcspRequest(cert: CertInfo, issuer: CertInfo, responderUrl?: string): Promise<OcspRequestInfo> {
  const nameHash = await sha('SHA-1', cert.issuerDer)
  const keyHash = await sha('SHA-1', issuerKeyBits(issuer))
  const serial = tlv(0x02, fromHex(cert.serialHex))
  const certId = derSeq(derSeq(derOid(OID.sha1), derNull()), derOctets(nameHash), derOctets(keyHash), serial)
  const der = derSeq(derSeq(derSeq(derSeq(certId))))
  const base64 = toBase64(der)
  let getUrl: string | undefined
  if (responderUrl && /^https?:\/\//i.test(responderUrl)) {
    getUrl = `${responderUrl.replace(/\/+$/, '')}/${encodeURIComponent(base64)}`
  }
  return { der, base64, getUrl, issuerNameHash: toHex(nameHash), issuerKeyHash: toHex(keyHash), serialHex: cert.serialHex }
}

export function ocspUrls(cert: CertInfo): string[] {
  return accessUrls(cert.extensions, OID.ocsp)
}

export function opensslOcspCommand(url: string | undefined, certFile = 'cert.pem', issuerFile = 'issuer.pem'): string {
  const u = url && /^https?:\/\//i.test(url) ? url : 'http://ocsp.example.com'
  return [`openssl ocsp -issuer ${shellQuote(issuerFile)} -cert ${shellQuote(certFile)}`, `-url ${shellQuote(u)}`, '-resp_text -noverify'].join(' \\\n  ')
}

export function curlOcspCommand(getUrl: string): string {
  return `curl -s ${shellQuote(getUrl)} -o resp.der && openssl ocsp -respin resp.der -resp_text -noverify`
}

export const OCSP_FIELDS: readonly { field: string; meaning: string }[] = [
  { field: 'OCSP Response Status', meaning: 'successful means the responder answered. malformedRequest / unauthorized usually mean the responder does not know this issuer (wrong -issuer) or no longer serves OCSP.' },
  { field: 'Cert Status', meaning: 'good, revoked (with Revocation Time and Reason) or unknown (the responder is not authoritative for this certificate).' },
  { field: 'This Update / Next Update', meaning: 'Validity window of this signed answer. Responses are usually pre-signed and cached for hours to days; a response past Next Update is stale.' },
  { field: 'Responder Id', meaning: 'Who signed the response: the CA itself or a delegated OCSP signing certificate (EKU OCSPSigning, issued by the CA).' },
  { field: 'Response verify OK', meaning: 'Shown when you drop -noverify and pass -CAfile: the response signature chains to the CA. Without it, an attacker could forge "good".' },
  { field: 'Nonce', meaning: 'Optional replay protection. Most large CAs ignore nonces and serve cached responses, so openssl prints "WARNING: no nonce in response" — normal; use -no_nonce to silence it.' },
]
