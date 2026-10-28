import { useMemo, useState } from 'react'
import type { KeyItem } from './keys'
import { analyzeKeyBlock, matchMatrix } from './keys'
import { parseInputText } from './pem'
import { exportPrivateKeyPem } from './generate'
import { getSamplePki } from './samples'
import { PemInput } from './ui'
import { useAsync, useDebounced } from './hooks'
import { bytesToInputText } from './fileInput'

const analyzeAll = (text: string): Promise<{ items: KeyItem[]; warnings: string[] }> => {
  const p = parseInputText(text)
  return Promise.all(p.blocks.slice(0, 20).map(analyzeKeyBlock)).then((items) => ({
    items,
    warnings: [...p.warnings, ...(p.blocks.length > 20 ? ['Only the first 20 blocks are compared.'] : [])],
  }))
}

export function KeyMatchTab() {
  const [text, setText] = useState('')
  const debounced = useDebounced(text, 300)
  const { data, loading } = useAsync(debounced, analyzeAll)
  const items = useMemo(() => data?.items ?? [], [data])
  const matrix = useMemo(() => matchMatrix(items), [items])
  const hasPrivate = items.some((i) => i.isPrivate)

  const loadSample = async () => {
    const pki = await getSamplePki()
    setText(`${pki.pem.leaf}\n${pki.pem.csr}\n${await exportPrivateKeyPem(pki.leafKeys.privateKey)}\n${pki.pem.intermediate}`)
  }

  return (
    <div className="stack">
      <div className="callout warn small">
        <strong>Do not paste production private keys</strong> into any web page, including this one. Everything stays in
        this tab (nothing is uploaded or stored), but keys can leak via the clipboard, browser extensions or screen
        sharing. Safer: compare on the server with{' '}
        <code>openssl pkey -in key.pem -pubout | openssl sha256</code> vs <code>openssl x509 -in cert.pem -noout -pubkey | openssl sha256</code>.
      </div>
      <PemInput
        label="Paste two or more of: certificate, CSR, public key (SPKI), private key (PKCS#8, PKCS#1 RSA or SEC1 EC)"
        value={text}
        onChange={setText}
        onFile={(b) => setText((t) => `${t}${t && !t.endsWith('\n') ? '\n' : ''}${bytesToInputText(b, 'CERTIFICATE')}`)}
        placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----BEGIN PRIVATE KEY-----\n…'}
        rows={10}
        extraButtons={
          <button type="button" className="btn btn-sm" onClick={loadSample}>
            Sample: cert + CSR + test key + other cert
          </button>
        }
      />
      {hasPrivate && <div className="callout small">A private key was read in memory only. Click “Clear” when done.</div>}
      {data?.warnings.map((w, i) => (
        <div key={i} className="callout warn small">
          {w}
        </div>
      ))}
      {loading && debounced.trim() !== '' && !data && <p className="muted">Deriving public keys…</p>}
      {items.length > 0 && (
        <section className="card stack" aria-label="Keys found">
          <h3 className="pki-h">Items</h3>
          <div className="pki-table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">#</th>
                  <th scope="col">Type</th>
                  <th scope="col">Description</th>
                  <th scope="col">Key</th>
                  <th scope="col">Public key SHA-256 (canonical SPKI)</th>
                </tr>
              </thead>
              <tbody>
                {items.map((it, i) => (
                  <tr key={i}>
                    <td>{i + 1}</td>
                    <td>
                      {it.label} {it.isPrivate && <span className="badge sev-high">private</span>}
                    </td>
                    <td className="pki-break">
                      {it.description}
                      {it.error && <div className="pki-err small">{it.error}</div>}
                      {it.note && <div className="small muted">{it.note}</div>}
                    </td>
                    <td className="pki-nowrap">{it.key?.summary ?? "—"}</td>
                    <td>
                      <code className="pki-break small">{it.fingerprint ?? '—'}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {items.length >= 2 && (
            <>
              <h3 className="pki-h">Match matrix</h3>
              <div className="pki-table-wrap">
                <table className="table pki-matrix">
                  <thead>
                    <tr>
                      <th scope="col">
                        <span className="sr-only">Item</span>
                      </th>
                      {items.map((_, j) => (
                        <th key={j} scope="col">
                          #{j + 1}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {matrix.map((row, i) => (
                      <tr key={i}>
                        <th scope="row">
                          #{i + 1} {items[i].label}
                        </th>
                        {row.map((m, j) => (
                          <td key={j} className={i === j ? 'muted' : m === true ? 'pki-yes' : m === false ? 'pki-no' : 'muted'}>
                            {i === j ? '—' : m === true ? '✓ match' : m === false ? '✗' : '?'}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="small muted">
                ✓ = same key pair. Keys are compared by the SHA-256 of their SubjectPublicKeyInfo (RSA keys normalized to
                n/e, so RSA-PSS and rsaEncryption encodings of the same key match).
              </p>
            </>
          )}
        </section>
      )}
    </div>
  )
}
