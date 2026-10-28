import { useId, useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { bytesEqual } from './bytes'
import type { CertInfo } from './cert'
import { decodeCertificate, serialDisplay } from './cert'
import { certsFromText } from './certInput'
import type { CrlInfo } from './crl'
import { crlFreshness, decodeCrl, indexCrl, normalizeSerial, reasonName } from './crl'
import { crlUrls, extDecoded } from './extensions'
import { shellQuote } from './generate'
import { namesEqualLoose } from './names'
import { OID } from './oids'
import type { PemBlock } from './pem'
import { parseInputBytes, parseInputText } from './pem'
import { getSamplePki } from './samples'
import { ExtensionsTable, KV, PemInput, PrivacyNote, SafeLink } from './ui'
import { useAsync, useDebounced } from './hooks'
import { bytesToInputText } from './fileInput'
import { verifyCrlSignature } from './verify'

const PAGE = 100

const verifySig = (a: { crl: Uint8Array; issuer: Uint8Array } | undefined) => (a ? verifyCrlSignature(a.crl, a.issuer) : Promise.resolve(undefined))

function pickCrl(blocks: PemBlock[]): PemBlock | undefined {
  return blocks.find((b) => b.label === 'X509 CRL' || b.label === 'CRL' || b.label === '')
}

function firstCert(text: string): { info?: CertInfo; error?: string } {
  const r = certsFromText(text)
  if (r.certs.length === 0) return { error: text.trim() ? 'No certificate found' : undefined }
  try {
    return { info: decodeCertificate(r.certs[0]) }
  } catch (e) {
    return { error: (e as Error).message }
  }
}

export function CrlTab() {
  const [text, setText] = useState('')
  const [file, setFile] = useState<{ name: string; der: Uint8Array }>()
  const [issuerText, setIssuerText] = useState('')
  const [certText, setCertText] = useState('')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(0)
  const ids = useId()

  const debounced = useDebounced(text, 300)
  const crlResult = useMemo((): { crl?: CrlInfo; error?: string; warnings: string[] } => {
    let der: Uint8Array | undefined = file?.der
    let warnings: string[] = []
    if (!der) {
      const p = parseInputText(debounced)
      warnings = p.warnings
      der = pickCrl(p.blocks)?.der
      if (!der) return { warnings, error: debounced.trim() && p.blocks.length ? `No X509 CRL block found (found: ${p.blocks.map((b) => b.label).join(', ')})` : undefined }
    }
    try {
      return { crl: decodeCrl(der), warnings }
    } catch (e) {
      return { error: `Could not parse CRL: ${(e as Error).message}`, warnings }
    }
  }, [debounced, file])
  const crl = crlResult.crl
  const index = useMemo(() => (crl ? indexCrl(crl) : undefined), [crl])
  const issuer = useMemo(() => firstCert(issuerText), [issuerText])
  const target = useMemo(() => firstCert(certText), [certText])

  const sigArg = useMemo(() => (crl && issuer.info ? { crl: crl.der, issuer: issuer.info.der } : undefined), [crl, issuer.info])
  const { data: sig } = useAsync(sigArg, verifySig)

  const filtered = useMemo(() => {
    if (!crl) return []
    const q = query.replace(/[\s:]/g, '').toLowerCase().replace(/^0+/, '')
    if (!q) return crl.entries
    if (!/^[0-9a-f]+$/.test(q)) return []
    return crl.entries.filter((e) => e.serial.includes(q)).slice(0, 10_000)
  }, [crl, query])
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE))
  const curPage = Math.min(page, pages - 1)

  const loadSample = async () => {
    const pki = await getSamplePki()
    setFile(undefined)
    setText(pki.pem.crl)
    setIssuerText(pki.pem.intermediate)
    setCertText(pki.pem.badLeaf)
  }

  const fresh = crl ? crlFreshness(crl) : undefined
  const targetCdp = target.info ? crlUrls(target.info.extensions) : []

  return (
    <div className="stack">
      <PrivacyNote />
      <PemInput
        label="CRL: PEM (X509 CRL), base64 DER, or a .crl file"
        value={file ? `(binary CRL loaded: ${file.name}, ${file.der.length.toLocaleString()} bytes)` : text}
        onChange={(v) => {
          setFile(undefined)
          setText(v)
          setPage(0)
        }}
        onFile={(b, name) => {
          setPage(0)
          const p = parseInputBytes(b)
          if (p.blocks.length === 1 && p.blocks[0].source === 'der') setFile({ name, der: p.blocks[0].der })
          else {
            setFile(undefined)
            setText(new TextDecoder().decode(b))
          }
        }}
        rows={5}
        placeholder="-----BEGIN X509 CRL-----"
        extraButtons={
          <button type="button" className="btn btn-sm" onClick={loadSample}>
            Sample: CRL + issuer + revoked cert
          </button>
        }
      />
      <div className="callout small">
        Fetching a CRL from its distribution point URL inside the browser usually fails (CRLs are served over plain
        HTTP without CORS headers). Download it yourself, e.g. <code>curl -s -o ca.crl http://crl.example.com/ca.crl</code>, then
        open the file here.
      </div>
      {crlResult.warnings.map((w, i) => (
        <div key={i} className="callout warn small">
          {w}
        </div>
      ))}
      {crlResult.error && (
        <div className="callout error" role="alert">
          {crlResult.error}
        </div>
      )}
      {crl && fresh && (
        <section className="card stack" aria-label="CRL details">
          <div className="row">
            <h2 className="pki-h">CRL</h2>
            <span className={`badge ${fresh.state === 'fresh' ? 'sev-ok' : 'sev-high'}`}>{fresh.state === 'fresh' ? 'fresh' : fresh.state.replace(/-/g, ' ')}</span>
            {sig && <span className={`badge ${sig.ok ? 'sev-ok' : 'sev-critical'}`}>{sig.ok ? 'signature valid' : sig.error ? 'signature not checked' : 'signature INVALID'}</span>}
          </div>
          <KV
            rows={[
              ['Issuer', crl.issuerString],
              ['Version', `v${crl.version}`],
              ['This update', crl.thisUpdate.toISOString()],
              ['Next update', crl.nextUpdate?.toISOString() ?? '—'],
              ['Freshness', fresh.detail],
              ['CRL number', crl.crlNumber ?? '—'],
              ['Authority key ID', crl.akiKeyId ? <code key="a" className="pki-break">{crl.akiKeyId}</code> : '—'],
              ['Signature algorithm', crl.signatureAlg.name],
              ['Revoked entries', crl.entries.length.toLocaleString()],
            ]}
          />
          {crl.extensions.length > 0 && (
            <details className="pki-details">
              <summary>CRL extensions ({crl.extensions.length})</summary>
              <ExtensionsTable extensions={crl.extensions} />
            </details>
          )}
        </section>
      )}
      <div className="pki-split">
        <section className="card stack" aria-label="Issuer certificate">
          <h3 className="pki-h">Verify the CRL signature</h3>
          <PemInput label="Issuer (CA) certificate" value={issuerText} onChange={setIssuerText} onFile={(b) => setIssuerText(bytesToInputText(b, 'CERTIFICATE'))} rows={4} placeholder="-----BEGIN CERTIFICATE-----" />
          {issuer.error && <span className="pki-err small">{issuer.error}</span>}
          {crl && issuer.info && (
            <ul className="pki-list small">
              <li>{bytesEqual(issuer.info.subjectDer, crl.issuerDer) || namesEqualLoose(issuer.info.subject, crl.issuer) ? '✓ Certificate subject matches the CRL issuer' : '✗ Certificate subject differs from the CRL issuer'}</li>
              {sig && <li>{sig.ok ? '✓ CRL signature verifies with this certificate’s key' : sig.error ? `Could not verify: ${sig.error}` : '✗ CRL signature does NOT verify with this key'}</li>}
              {extDecoded(issuer.info.extensions, OID.keyUsage, 'ku') && !extDecoded(issuer.info.extensions, OID.keyUsage, 'ku')?.usages.includes('cRLSign') && <li className="pki-err">Issuer Key Usage lacks cRLSign</li>}
            </ul>
          )}
        </section>
        <section className="card stack" aria-label="Check a certificate">
          <h3 className="pki-h">Check a certificate against this CRL</h3>
          <PemInput label="Certificate to check" value={certText} onChange={setCertText} onFile={(b) => setCertText(bytesToInputText(b, 'CERTIFICATE'))} rows={4} placeholder="-----BEGIN CERTIFICATE-----" />
          {target.error && <span className="pki-err small">{target.error}</span>}
          {target.info && crl && index && <CertCheck cert={target.info} crl={crl} index={index} />}
          {targetCdp.length > 0 && (
            <div className="small">
              This certificate’s CRL distribution point(s):
              <ul className="pki-list">
                {targetCdp.map((u, i) => (
                  <li key={i}>
                    <SafeLink href={u} /> <CopyButton text={`curl -s -o crl.der ${shellQuote(u)}`} label="Copy curl command" />
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      </div>
      {crl && (
        <section className="card stack" aria-label="Revoked certificates">
          <div className="row">
            <h3 className="pki-h">Revoked certificates</h3>
            <span className="spacer" />
            <label htmlFor={`${ids}-q`} className="inline small">
              Search serial (hex)
            </label>
            <input
              id={`${ids}-q`}
              type="search"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value)
                setPage(0)
              }}
              placeholder="e.g. 0A:1B:2C"
              spellCheck={false}
            />
          </div>
          <p className="small muted">
            {filtered.length.toLocaleString()} of {crl.entries.length.toLocaleString()} entries{query && filtered.length === 10_000 ? ' (first 10,000 matches)' : ''}.
          </p>
          {filtered.length > 0 && (
            <div className="pki-table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Serial</th>
                    <th scope="col">Revocation date</th>
                    <th scope="col">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.slice(curPage * PAGE, curPage * PAGE + PAGE).map((e, i) => (
                    <tr key={`${curPage}-${i}`}>
                      <td>
                        <code>{e.serial.toUpperCase()}</code>
                      </td>
                      <td>{e.revocationDate.toISOString()}</td>
                      <td>{reasonName(e.reason)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {pages > 1 && (
            <div className="row" role="navigation" aria-label="Pages">
              <button type="button" className="btn btn-sm" disabled={curPage === 0} onClick={() => setPage(curPage - 1)}>
                ← Previous
              </button>
              <span className="small">
                Page {curPage + 1} / {pages}
              </span>
              <button type="button" className="btn btn-sm" disabled={curPage >= pages - 1} onClick={() => setPage(curPage + 1)}>
                Next →
              </button>
            </div>
          )}
        </section>
      )}
    </div>
  )
}

function CertCheck({ cert, crl, index }: { cert: CertInfo; crl: CrlInfo; index: Map<string, { serial: string; revocationDate: Date; reason?: number }> }) {
  const serial = normalizeSerial(cert.serialHex)
  const entry = index.get(serial)
  const issuerMatches = bytesEqual(cert.issuerDer, crl.issuerDer) || namesEqualLoose(cert.issuer, crl.issuer)
  const certAki = extDecoded(cert.extensions, OID.authorityKeyIdentifier, 'aki')?.keyId
  const akiMismatch = !!certAki && !!crl.akiKeyId && certAki !== crl.akiKeyId
  const authoritative = issuerMatches && !akiMismatch
  return (
    <div className="stack">
      <div className="small">
        Serial <code>{serialDisplay(cert)}</code>
      </div>
      {!issuerMatches && (
        <div className="callout warn small">
          The certificate’s issuer (<code>{cert.issuerString}</code>) is not this CRL’s issuer — this CRL says nothing about it (unless it is an indirect CRL).
        </div>
      )}
      {akiMismatch && <div className="callout warn small">Authority Key Identifiers differ: the CRL was signed by a different key of that CA (re-keyed CA?).</div>}
      {entry && authoritative && (
        <div className="callout error" role="status">
          <strong>REVOKED</strong> on {entry.revocationDate.toISOString()} — reason: {reasonName(entry.reason)}
        </div>
      )}
      {entry && !authoritative && (
        <div className="callout warn" role="status">
          This CRL lists the same serial number (revoked {entry.revocationDate.toISOString()}), but it is not this certificate’s
          issuer{issuerMatches ? ' key' : ''}. Serial numbers are only unique per CA, so this does <strong>not</strong> mean the
          certificate is revoked — load the CRL from the certificate’s own CRL distribution point.
        </div>
      )}
      {!entry && (
        <div className="callout" role="status">
          {authoritative ? '✓ Not on this CRL (not revoked as of thisUpdate).' : 'Serial not on this CRL — but this CRL does not cover this certificate anyway.'}
        </div>
      )}
    </div>
  )
}
