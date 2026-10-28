import { useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import type { CertInfo } from './cert'
import { decodeCertificate } from './cert'
import { certsFromText } from './certInput'
import { bytesToInputText } from './fileInput'
import type { OcspRequestInfo } from './ocsp'
import { buildOcspRequest, curlOcspCommand, OCSP_FIELDS, ocspUrls, opensslOcspCommand } from './ocsp'
import { crlUrls } from './extensions'
import { shellQuote } from './generate'
import { getSamplePki } from './samples'
import { ISRG_ROOT_X1_PEM, LE_R12_PEM } from './publicCerts'
import { PemInput, PrivacyNote, SafeLink } from './ui'
import { downloadBytes, useAsync, useDebounced } from './hooks'

function decodeFirst(text: string, n = 0): { info?: CertInfo; error?: string; count: number } {
  const r = certsFromText(text)
  if (r.certs.length <= n) return { count: r.certs.length }
  try {
    return { info: decodeCertificate(r.certs[n]), count: r.certs.length }
  } catch (e) {
    return { error: (e as Error).message, count: r.certs.length }
  }
}

const buildReq = (a: { c: CertInfo; i: CertInfo; url?: string } | undefined): Promise<OcspRequestInfo | undefined> => (a ? buildOcspRequest(a.c, a.i, a.url) : Promise.resolve(undefined))

export function OcspTab() {
  const [certText, setCertText] = useState('')
  const [issuerText, setIssuerText] = useState('')
  const dc = useDebounced(certText, 250)
  const di = useDebounced(issuerText, 250)
  const cert = useMemo(() => decodeFirst(dc), [dc])
  // A bundle pasted in the first box: use its second certificate as the issuer.
  const issuer = useMemo(() => (di.trim() ? decodeFirst(di) : decodeFirst(dc, 1)), [di, dc])
  const urls = cert.info ? ocspUrls(cert.info) : []
  const url = urls[0]
  const reqArg = useMemo(() => {
    const c = cert.info
    const i = issuer.info
    return c && i ? { c, i, url: ocspUrls(c)[0] } : undefined
  }, [cert, issuer])
  const { data: req, error: reqErr } = useAsync(reqArg, buildReq)
  const issuerMismatch = cert.info && issuer.info && cert.info.issuerString !== issuer.info.subjectString
  const cmd = opensslOcspCommand(url)

  const loadSample = async (which: 'gen' | 'le') => {
    if (which === 'le') {
      setCertText(LE_R12_PEM)
      setIssuerText(ISRG_ROOT_X1_PEM)
      return
    }
    const pki = await getSamplePki()
    setCertText(pki.pem.leaf)
    setIssuerText(pki.pem.intermediate)
  }

  return (
    <div className="stack">
      <PrivacyNote />
      <div className="callout warn small">
        Browsers cannot query most OCSP responders from a web page (plain HTTP, no CORS headers), so this tab prepares
        the request and the commands to run yourself. Note that <strong>Let’s Encrypt shut down its OCSP service</strong>{' '}
        (OCSP URLs removed from new certificates on 2025-05-07, responders turned off on 2025-08-06) and the CA/B Forum
        made OCSP optional for public TLS CAs — <strong>CRLs are the primary revocation mechanism again</strong>. Check the
        certificate’s CRL Distribution Points (CRL tab) when there is no OCSP URL.{' '}
        <SafeLink href="https://letsencrypt.org/2024/12/05/ending-ocsp/">Let’s Encrypt announcement</SafeLink>
      </div>
      <div className="pki-split">
        <PemInput
          label="Certificate to check (or a bundle: certificate first, then its issuer)"
          value={certText}
          onChange={setCertText}
          onFile={(b) => setCertText(bytesToInputText(b, 'CERTIFICATE'))}
          rows={6}
          placeholder="-----BEGIN CERTIFICATE-----"
          extraButtons={
            <>
              <button type="button" className="btn btn-sm" onClick={() => loadSample('gen')}>
                Sample: generated leaf + issuer
              </button>
              <button type="button" className="btn btn-sm" onClick={() => loadSample('le')}>
                Sample: R12 + ISRG Root X1
              </button>
            </>
          }
        />
        <PemInput label="Issuer certificate (needed for the CertID hashes)" value={issuerText} onChange={setIssuerText} onFile={(b) => setIssuerText(bytesToInputText(b, 'CERTIFICATE'))} rows={6} placeholder="-----BEGIN CERTIFICATE-----" />
      </div>
      {cert.error && <div className="callout error">{cert.error}</div>}
      {issuer.error && <div className="callout error">{issuer.error}</div>}
      {issuerMismatch && <div className="callout warn small">The issuer certificate’s subject does not match the certificate’s issuer name — the OCSP request would ask about the wrong CA.</div>}
      {cert.info && (
        <section className="card stack" aria-label="OCSP">
          <h2 className="pki-h">Responder</h2>
          {urls.length ? (
            <ul className="pki-list">
              {urls.map((u, i) => (
                <li key={i}>
                  OCSP: <SafeLink href={u} />
                </li>
              ))}
            </ul>
          ) : (
            <div className="callout small">
              This certificate has <strong>no OCSP URL</strong> in its Authority Information Access extension.
              {crlUrls(cert.info.extensions).length > 0 ? ' Use its CRL instead: ' : ' It has no CRL distribution point either.'}
              {crlUrls(cert.info.extensions).map((u, i) => (
                <SafeLink key={i} href={u} />
              ))}
            </div>
          )}
          <div className="row">
            <h3 className="pki-h">OpenSSL command</h3>
            <span className="spacer" />
            <CopyButton text={cmd} />
          </div>
          <pre className="codeblock">{cmd}</pre>
          <p className="small muted">
            Save the certificate as cert.pem and the issuer as issuer.pem. Drop <code>-noverify</code> and add <code>-CAfile root.pem</code> to also verify the response signature. Some responders need <code>-header Host=ocsp.example.com</code> with OpenSSL 1.0.x.
          </p>
          {reqErr && <div className="callout error small">{reqErr}</div>}
          {req && (
            <>
              <h3 className="pki-h">OCSP request (DER, built in the browser)</h3>
              <ul className="pki-list small">
                <li>
                  hashAlgorithm: SHA-1 (what responders expect) · issuerNameHash <code>{req.issuerNameHash}</code>
                </li>
                <li>
                  issuerKeyHash <code>{req.issuerKeyHash}</code> · serialNumber <code>{req.serialHex}</code>
                </li>
              </ul>
              <div className="row">
                <span className="small muted">Base64 OCSPRequest (no nonce, identical to openssl -no_nonce -reqout):</span>
                <span className="spacer" />
                <CopyButton text={req.base64} />
                <button type="button" className="btn" onClick={() => downloadBytes('ocsp-request.der', req.der, 'application/ocsp-request')}>
                  Download .der
                </button>
              </div>
              <pre className="codeblock pki-pem">{req.base64}</pre>
              {req.getUrl && (
                <>
                  <div className="row">
                    <span className="small muted">RFC 6960 GET URL (responder URL + "/" + URL-encoded base64):</span>
                    <span className="spacer" />
                    <CopyButton text={curlOcspCommand(req.getUrl)} label="Copy curl + openssl command" />
                  </div>
                  <pre className="codeblock pki-pem">{req.getUrl}</pre>
                </>
              )}
              <p className="small muted">
                POST alternative: <code>curl -s --data-binary @ocsp-request.der -H 'Content-Type: application/ocsp-request' {shellQuote(url ?? 'http://ocsp.example.com')} -o resp.der</code>
              </p>
            </>
          )}
          {!issuer.info && <p className="small muted">Paste the issuer certificate to build the request DER.</p>}
        </section>
      )}
      <section className="card stack" aria-label="Reading the response">
        <h3 className="pki-h">Reading the output</h3>
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">Meaning</th>
            </tr>
          </thead>
          <tbody>
            {OCSP_FIELDS.map((f) => (
              <tr key={f.field}>
                <td>
                  <strong>{f.field}</strong>
                </td>
                <td>{f.meaning}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}
