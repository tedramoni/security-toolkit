/** Signature verification wrappers around @peculiar/x509 (WebCrypto). Never throw: return a result object. */
import { x509 } from './x509'

export interface VerifyResult {
  ok: boolean
  /** Verification could not be attempted (unsupported algorithm, malformed key…). */
  error?: string
}

function asBuffer(b: Uint8Array): ArrayBuffer {
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer
}

/** Verify `certDer`'s signature with the public key of `issuerCertDer` (signature only, dates ignored). */
export async function verifyCertSignature(certDer: Uint8Array, issuerCertDer: Uint8Array): Promise<VerifyResult> {
  try {
    const cert = new x509.X509Certificate(asBuffer(certDer))
    const issuer = new x509.X509Certificate(asBuffer(issuerCertDer))
    const ok = await cert.verify({ publicKey: issuer.publicKey, signatureOnly: true })
    return { ok }
  } catch (e) {
    return { ok: false, error: (e as Error).message || String(e) }
  }
}

export async function verifyCsrSignature(csrDer: Uint8Array): Promise<VerifyResult> {
  try {
    const csr = new x509.Pkcs10CertificateRequest(asBuffer(csrDer))
    return { ok: await csr.verify() }
  } catch (e) {
    return { ok: false, error: (e as Error).message || String(e) }
  }
}

export async function verifyCrlSignature(crlDer: Uint8Array, issuerCertDer: Uint8Array): Promise<VerifyResult> {
  try {
    const crl = new x509.X509Crl(asBuffer(crlDer))
    const issuer = new x509.X509Certificate(asBuffer(issuerCertDer))
    return { ok: await crl.verify({ publicKey: issuer.publicKey }) }
  } catch (e) {
    return { ok: false, error: (e as Error).message || String(e) }
  }
}

export { asBuffer }
