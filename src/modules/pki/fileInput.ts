/** Convert an uploaded file to text for the input boxes (binary DER becomes PEM so the user can see it). */
import { decodeCertificate } from './cert'
import { extractPkcs7 } from './convert'
import { decodeCrl } from './crl'
import { decodeCsr } from './csr'
import { parseInputBytes, toPem } from './pem'
import { describeSpki } from './spki'

/** Guess a PEM label for unlabelled DER by trying each structure. */
export function guessDerLabel(der: Uint8Array, fallback: string): string {
  const tries: [string, (d: Uint8Array) => unknown][] = [
    ['PKCS7', extractPkcs7],
    ['CERTIFICATE', decodeCertificate],
    ['CERTIFICATE REQUEST', decodeCsr],
    ['X509 CRL', decodeCrl],
    ['PUBLIC KEY', describeSpki],
  ]
  for (const [label, fn] of tries) {
    try {
      fn(der)
      return label
    } catch {
      /* try next */
    }
  }
  return fallback
}

export function bytesToInputText(bytes: Uint8Array, defaultLabel: string): string {
  const parsed = parseInputBytes(bytes)
  const der = parsed.blocks.length === 1 && parsed.blocks[0].source === 'der' ? parsed.blocks[0].der : undefined
  if (der) return toPem(der, guessDerLabel(der, defaultLabel))
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 20 * 1024 * 1024))
}
