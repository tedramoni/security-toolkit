/** Turn pasted text / an uploaded file into certificate DERs (PEM, DER, base64, PKCS#7 bundles). */
import type { Bytes } from './bytes'
import { extractPkcs7 } from './convert'
import type { ParsedInput } from './pem'
import { parseInputBytes, parseInputText } from './pem'

export interface CertInputResult {
  certs: Bytes[]
  warnings: string[]
  /** Blocks of other kinds that were skipped (e.g. PRIVATE KEY). */
  skipped: string[]
}

const CERT_LABELS = new Set(['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'])
const P7_LABELS = new Set(['PKCS7', 'CMS', 'PKCS #7 SIGNED DATA'])

export function certsFromParsed(p: ParsedInput): CertInputResult {
  const certs: Bytes[] = []
  const warnings = [...p.warnings]
  const skipped: string[] = []
  for (const b of p.blocks) {
    if (CERT_LABELS.has(b.label)) certs.push(b.der)
    else if (P7_LABELS.has(b.label)) {
      try {
        certs.push(...extractPkcs7(b.der).certs)
      } catch (e) {
        warnings.push(`PKCS#7 block: ${(e as Error).message}`)
      }
    } else if (b.label === '') {
      // Unlabelled DER: PKCS#7 starts with an OID right after the outer SEQUENCE header.
      let used = false
      try {
        const r = extractPkcs7(b.der)
        if (r.certs.length) {
          certs.push(...r.certs)
          used = true
        }
      } catch {
        /* not PKCS#7 */
      }
      if (!used) certs.push(b.der)
    } else skipped.push(b.label)
  }
  if (skipped.some((s) => s.includes('PRIVATE KEY'))) {
    warnings.push('A private key was pasted and ignored. Never share production private keys; this tool does not need them.')
  }
  return { certs, warnings, skipped }
}

export function certsFromText(text: string): CertInputResult {
  return certsFromParsed(parseInputText(text))
}

export function certsFromBytes(bytes: Uint8Array): CertInputResult {
  return certsFromParsed(parseInputBytes(bytes))
}
