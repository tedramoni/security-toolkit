import { useMemo, useState } from 'react'
import type { CsrInfo } from './csr'
import { decodeCsr, lintCsr } from './csr'
import { bytesToInputText } from './fileInput'
import { parseInputText } from './pem'
import { getSamplePki } from './samples'
import { fingerprintHex, sha } from './bytes'
import { canonicalSpki } from './keys'
import { RdnList } from './CertTab'
import { AsnTree, ExtensionsTable, KV, PemInput, PkiFindingList, PrivacyNote } from './ui'
import { useAsync, useDebounced } from './hooks'
import { verifyCsrSignature } from './verify'

interface Result {
  csr?: CsrInfo
  error?: string
  sigOk?: boolean
  sigError?: string
  spkiFp?: string
}

async function analyze(der: Uint8Array | undefined): Promise<Result | undefined> {
  if (!der) return undefined
  try {
    const csr = decodeCsr(der)
    const [v, fp] = await Promise.all([verifyCsrSignature(csr.der), sha('SHA-256', canonicalSpki(csr.spkiDer))])
    return { csr, sigOk: v.error ? undefined : v.ok, sigError: v.error, spkiFp: fingerprintHex(fp) }
  } catch (e) {
    return { error: (e as Error).message }
  }
}

export function CsrTab() {
  const [text, setText] = useState('')
  const debounced = useDebounced(text, 250)
  const parsed = useMemo(() => parseInputText(debounced), [debounced])
  const block = parsed.blocks.find((b) => b.label.includes('CERTIFICATE REQUEST') || b.label === '')
  const der = block?.der
  const { data } = useAsync(der, analyze)
  const csr = data?.csr

  return (
    <div className="stack">
      <PrivacyNote />
      <PemInput
        label="Certificate signing request (PKCS#10): PEM, base64 DER or a .csr/.req/.der file"
        value={text}
        onChange={setText}
        onFile={(b) => setText(bytesToInputText(b, 'CERTIFICATE REQUEST'))}
        placeholder="-----BEGIN CERTIFICATE REQUEST-----"
        extraButtons={
          <button type="button" className="btn btn-sm" onClick={async () => setText((await getSamplePki()).pem.csr)}>
            Sample CSR
          </button>
        }
      />
      {parsed.warnings.map((w, i) => (
        <div key={i} className="callout warn small">
          {w}
        </div>
      ))}
      {debounced.trim() !== '' && !block && parsed.blocks.length > 0 && (
        <div className="callout warn">No CERTIFICATE REQUEST block found (found: {parsed.blocks.map((b) => b.label).join(', ')}). Use the Certificate tab for certificates.</div>
      )}
      {data?.error && (
        <div className="callout error" role="alert">
          {data.error}
        </div>
      )}
      {csr && data && (
        <section className="card stack" aria-label="Decoded CSR">
          <div className="row">
            <h2 className="pki-h">CSR</h2>
            {data.sigOk === true && <span className="badge sev-ok">self-signature valid (proof of possession)</span>}
            {data.sigOk === false && <span className="badge sev-critical">signature INVALID</span>}
            {data.sigError && <span className="badge sev-medium" title={data.sigError}>signature not checked</span>}
          </div>
          <KV
            rows={[
              ['Subject', <RdnList key="s" rdns={csr.subject} />],
              ['Version', `v${csr.version}`],
              ['Public key', csr.publicKey.summary],
              ['SPKI SHA-256', <code key="f" className="pki-break">{data.spkiFp}</code>],
              ['Signature', csr.signatureAlg.name],
              ['Attributes', csr.attributes.length ? csr.attributes.map((a) => a.name ?? a.oid).join(', ') : '—'],
            ]}
          />
          {data.sigError && <p className="small muted">Could not verify the signature in this browser: {data.sigError}</p>}
          <h3>Requested extensions</h3>
          <ExtensionsTable extensions={csr.extensions} />
          <h3>Lint</h3>
          <PkiFindingList findings={lintCsr(csr, data.sigOk)} reportTitle="CSR lint" />
          <details className="pki-details">
            <summary>Raw ASN.1 structure</summary>
            <AsnTree der={csr.der} />
          </details>
        </section>
      )}
    </div>
  )
}
