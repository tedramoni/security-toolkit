import { useId, useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { downloadText } from '../../lib/download'
import { certsFromText } from './certInput'
import type { BuiltChain, ChainReport } from './chain'
import { buildChains, chainToPem } from './chain'
import { sanNames } from './extensions'
import { bytesToInputText } from './fileInput'
import { shellQuote } from './generate'
import { matchHostname } from './hostname'
import { nameField } from './names'
import { OID } from './oids'
import { ISRG_ROOT_X1_PEM, ISRG_ROOT_X2_PEM, LE_R12_PEM } from './publicCerts'
import { getSamplePki } from './samples'
import { DaysBadge, PemInput, PrivacyNote, SafeLink } from './ui'
import { useAsync, useDebounced } from './hooks'

const run = (ders: Uint8Array[]): Promise<ChainReport | undefined> => (ders.length ? buildChains(ders) : Promise.resolve(undefined))

export function ChainTab() {
  const [text, setText] = useState('')
  const [host, setHost] = useState('')
  const hostId = useId()
  const debounced = useDebounced(text, 300)
  const input = useMemo(() => certsFromText(debounced), [debounced])
  const { data: report, loading, error } = useAsync(input.certs, run)

  const loadSample = async (which: 'gen' | 'le') => {
    if (which === 'le') {
      setText(`${ISRG_ROOT_X1_PEM}${ISRG_ROOT_X2_PEM}${LE_R12_PEM}`)
      return
    }
    const pki = await getSamplePki()
    // Deliberately shuffled.
    setText(`${pki.pem.root}\n${pki.pem.leaf}\n${pki.pem.intermediate}`)
    setHost('shop.api.example.test')
  }

  return (
    <div className="stack">
      <PrivacyNote />
      <div className="callout warn small">
        This checks structure and signatures only. <strong>Trust is not evaluated</strong>: there is no root store here,
        so a chain ending in any self-signed root "completes". Compare the root’s fingerprint with your trust store.
      </div>
      <PemInput
        label="Certificate bundle (any order: leaf, intermediates, root)"
        value={text}
        onChange={setText}
        onFile={(b) => setText(bytesToInputText(b, 'CERTIFICATE'))}
        placeholder="Paste fullchain.pem, a server's chain, or several PEM blocks"
        extraButtons={
          <>
            <button type="button" className="btn btn-sm" onClick={() => loadSample('gen')}>
              Sample: generated chain (shuffled)
            </button>
            <button type="button" className="btn btn-sm" onClick={() => loadSample('le')}>
              Sample: Let’s Encrypt R12 + roots
            </button>
          </>
        }
      />
      <div className="stack pki-narrow">
        <label htmlFor={hostId}>Hostname or IP to check against the leaf (optional)</label>
        <input id={hostId} type="text" value={host} onChange={(e) => setHost(e.target.value)} placeholder="www.example.com" spellCheck={false} autoComplete="off" />
      </div>
      {input.warnings.map((w, i) => (
        <div key={i} className="callout warn small">
          {w}
        </div>
      ))}
      {error && <div className="callout error">{error}</div>}
      {loading && input.certs.length > 0 && !report && <p className="muted">Building and verifying…</p>}
      {report?.parseErrors.map((e, i) => (
        <div key={i} className="callout error">
          {e}
        </div>
      ))}
      {report?.chains.map((c, i) => <ChainView key={i} chain={c} index={i} total={report.chains.length} host={host} />)}
      {report && report.unused.length > 0 && (
        <p className="small muted">{report.unused.length} certificate(s) were not part of any chain (duplicates are merged; unrelated roots are listed here).</p>
      )}
    </div>
  )
}

function ChainView({ chain, index, total, host }: { chain: BuiltChain; index: number; total: number; host: string }) {
  const leaf = chain.links[0].info
  const hostResult = host.trim() ? matchHostname(host, sanNames(leaf.extensions), nameField(leaf.subject, OID.commonName)) : undefined
  const allSigOk = chain.links.every((l) => l.signature?.ok)
  const problems = chain.links.reduce((a, l) => a + l.problems.length, 0)
  const rootPresent = chain.complete
  const withoutRoot = chainToPem(chain, false)
  const full = chainToPem(chain, true)
  return (
    <section className="card stack" aria-label={`Chain ${index + 1}`}>
      <div className="row">
        <h2 className="pki-h">{total > 1 ? `Chain ${index + 1}` : 'Chain'}</h2>
        <span className={`badge ${allSigOk ? 'sev-ok' : 'sev-critical'}`}>{allSigOk ? 'signatures valid' : 'signature problem'}</span>
        <span className={`badge ${rootPresent ? 'sev-ok' : 'sev-medium'}`}>{rootPresent ? 'self-signed root present' : 'root not in bundle'}</span>
        {problems > 0 && <span className="badge sev-high">{problems} problem(s)</span>}
        <span className="spacer" />
        <CopyButton text={withoutRoot} label="Copy chain (no root)" />
        <button type="button" className="btn" onClick={() => downloadText('chain.pem', full, 'application/x-pem-file')}>
          Download ordered PEM (with root)
        </button>
      </div>
      <ol className="pki-chain">
        {chain.links.map((l, i) => (
          <li key={i} className="pki-chain-link">
            <div className="row">
              <strong>{l.selfSigned ? (i === 0 ? 'Self-signed (alone)' : 'Root') : i === 0 ? 'Leaf' : 'Intermediate'}</strong>
              <span>{l.info.subjectString || '(empty subject)'}</span>
              <DaysBadge notBefore={l.info.notBefore} notAfter={l.info.notAfter} />
              {l.signature &&
                (l.signature.ok ? (
                  <span className="badge sev-ok">{l.selfSigned ? 'self-signature OK' : 'signed by next ✓'}</span>
                ) : (
                  <span className="badge sev-critical" title={l.signature.error}>
                    signature ✗
                  </span>
                ))}
            </div>
            <div className="small muted">
              Issuer: {l.info.issuerString} · {l.info.publicKey.summary} · {l.info.signatureAlg.name}
            </div>
            {l.problems.map((p, i) => (
              <div key={i} className="pki-err small">
                ⚠ This certificate {p}.
              </div>
            ))}
            {l.signature?.error && <div className="small pki-err">Verification error: {l.signature.error}</div>}
          </li>
        ))}
      </ol>
      {chain.missingIssuer && (
        <div className="callout warn">
          <strong>Missing issuer:</strong> no certificate in the bundle issued <code>{chain.missingIssuer.issuer}</code>.
          {chain.missingIssuer.caIssuersUrls.length > 0 ? (
            <>
              {' '}
              Its AIA "CA Issuers" URL points to the issuer certificate — download it and paste it here:
              <ul className="pki-list">
                {chain.missingIssuer.caIssuersUrls.map((u, i) => (
                  <li key={i}>
                    <SafeLink href={u} />
                  </li>
                ))}
              </ul>
              <span className="small">
                Browsers usually cannot fetch it from this page (plain HTTP + no CORS headers). Use:{' '}
                <code>curl -s -o issuer.der {shellQuote(chain.missingIssuer.caIssuersUrls[0])}</code> (usually DER or PKCS#7; open it with the file button).
              </span>
            </>
          ) : (
            ' The certificate has no AIA CA Issuers URL; ask your CA for the intermediate.'
          )}
          {chain.links.length === 1 && chain.links[0].info.subjectString === chain.links[0].info.issuerString && ' It is self-issued but its signature does not verify.'}
        </div>
      )}
      {!chain.complete && !chain.missingIssuer && <div className="callout warn">Chain building stopped (loop or depth limit).</div>}
      {hostResult && (
        <div className={`callout ${hostResult.match ? '' : 'error'}`} role="status">
          <strong>{hostResult.match ? '✓ Hostname matches' : '✗ Hostname does not match'}:</strong> {hostResult.reason}
          <div className="small muted">Rules: SAN only (CN ignored, like browsers); "*" only as the whole left-most label, matching exactly one label (RFC 9525, formerly RFC 6125).</div>
        </div>
      )}
      <p className="small muted">Servers should send the leaf and intermediates, not the root ("Copy chain (no root)").</p>
    </section>
  )
}
