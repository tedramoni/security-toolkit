import { useId, useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { downloadText } from '../../lib/download'
import type { Bytes } from './bytes'
import { certToJwk, extractPkcs7, jwkToSpki, PKCS12_COMMANDS, spkiToJwk } from './convert'
import { guessDerLabel } from './fileInput'
import type { PemBlock } from './pem'
import { parseInputBytes, parseInputText, toPem } from './pem'
import { ISRG_ROOT_X2_PEM } from './publicCerts'
import { PemInput, PrivacyNote } from './ui'
import { downloadBytes, useAsync, useDebounced } from './hooks'

const LABELS = ['CERTIFICATE', 'CERTIFICATE REQUEST', 'X509 CRL', 'PUBLIC KEY', 'PRIVATE KEY', 'PKCS7']

const SAMPLE_JWK = `{
  "kty": "EC",
  "crv": "P-256",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
}`

export function ConvertTab() {
  const [text, setText] = useState('')
  const [fileBlocks, setFileBlocks] = useState<{ name: string; blocks: PemBlock[] }>()
  const debounced = useDebounced(text, 250)
  const parsed = useMemo(() => parseInputText(debounced), [debounced])
  const blocks = fileBlocks?.blocks ?? parsed.blocks

  return (
    <div className="stack">
      <PrivacyNote />
      <section className="card stack" aria-label="PEM, DER and PKCS#7">
        <h2 className="pki-h">PEM ⇄ DER ⇄ base64, PKCS#7 → PEM, key → JWK</h2>
        <PemInput
          label="Input: PEM block(s), base64 or hex DER, or a binary file (.der/.cer/.p7b/.crl…)"
          value={fileBlocks ? `(binary file loaded: ${fileBlocks.name})` : text}
          onChange={(v) => {
            setFileBlocks(undefined)
            setText(v)
          }}
          onFile={(b, name) => {
            const p = parseInputBytes(b)
            if (p.blocks.length === 1 && p.blocks[0].source === 'der') setFileBlocks({ name, blocks: p.blocks })
            else {
              setFileBlocks(undefined)
              setText(new TextDecoder().decode(b))
            }
          }}
          rows={6}
          extraButtons={
            <button type="button" className="btn btn-sm" onClick={() => setText(ISRG_ROOT_X2_PEM)}>
              Sample: ISRG Root X2
            </button>
          }
        />
        {!fileBlocks &&
          parsed.warnings.map((w, i) => (
            <div key={i} className="callout warn small">
              {w}
            </div>
          ))}
        {blocks.map((b, i) => (
          <BlockView key={`${i}-${b.der.length}`} block={b} index={i} />
        ))}
      </section>
      <JwkToPem />
      <section className="card stack" aria-label="PKCS#12">
        <h2 className="pki-h">PKCS#12 / PFX</h2>
        <p className="small">
          PKCS#12 files are password-protected key + certificate containers. Converting them needs the password and legacy
          ciphers (RC2/3DES) that WebCrypto does not provide, so use OpenSSL locally:
        </p>
        {PKCS12_COMMANDS.map((c) => (
          <div key={c.title} className="stack pki-tight">
            <div className="row">
              <strong>{c.title}</strong>
              <span className="spacer" />
              <CopyButton text={c.cmd} />
            </div>
            <pre className="codeblock">{c.cmd}</pre>
            {c.note && <p className="small muted">{c.note}</p>}
          </div>
        ))}
      </section>
    </div>
  )
}

function BlockView({ block, index }: { block: PemBlock; index: number }) {
  const [label, setLabel] = useState(() => block.label || guessDerLabel(block.der, 'CERTIFICATE'))
  const labelId = useId()
  const pem = toPem(block.der, label)
  const isP7 = label === 'PKCS7' || label === 'CMS'
  const p7 = useMemo(() => {
    if (!isP7) return undefined
    try {
      return extractPkcs7(block.der)
    } catch (e) {
      return { error: (e as Error).message }
    }
  }, [block.der, isP7])
  const jwkSource = label === 'CERTIFICATE' || label === 'PUBLIC KEY' ? label : undefined
  const ext = label === 'CERTIFICATE' ? 'cer' : label === 'X509 CRL' ? 'crl' : label === 'CERTIFICATE REQUEST' ? 'csr' : label === 'PKCS7' ? 'p7b' : 'der'
  return (
    <div className="pki-block stack">
      <div className="row">
        <strong>
          #{index + 1} {block.label || '(no PEM label)'}
        </strong>
        <span className="muted small">
          {block.der.length} bytes · from {block.source}
        </span>
        {!block.label && (
          <>
            <label htmlFor={labelId} className="inline small">
              PEM label
            </label>
            <select id={labelId} value={label} onChange={(e) => setLabel(e.target.value)}>
              {LABELS.map((l) => (
                <option key={l}>{l}</option>
              ))}
            </select>
          </>
        )}
        <span className="spacer" />
        <CopyButton text={pem} label="Copy PEM" />
        <button type="button" className="btn" onClick={() => downloadBytes(`converted-${index + 1}.${ext}`, block.der)}>
          Download DER
        </button>
        {label.includes('PRIVATE') && <span className="badge sev-high">private key — handle with care</span>}
      </div>
      {block.source !== 'pem' && <pre className="codeblock pki-pem">{pem}</pre>}
      {p7 && 'error' in p7 && <div className="callout error small">{p7.error}</div>}
      {p7 && 'certs' in p7 && (
        <div className="stack">
          <div className="row">
            <span>
              PKCS#7 contains {p7.certs.length} certificate(s){p7.crls.length ? ` and ${p7.crls.length} CRL(s)` : ''}.
            </span>
            <span className="spacer" />
            {p7.certs.length > 0 && <CopyButton text={p7.certs.map((c) => toPem(c, 'CERTIFICATE')).join('')} label="Copy certificates as PEM" />}
            {p7.certs.length > 0 && (
              <button type="button" className="btn" onClick={() => downloadText('certificates.pem', p7.certs.map((c) => toPem(c, 'CERTIFICATE')).join(''), 'application/x-pem-file')}>
                Download PEM
              </button>
            )}
          </div>
          <pre className="codeblock pki-pem">{p7.certs.map((c) => toPem(c, 'CERTIFICATE')).join('')}</pre>
        </div>
      )}
      {jwkSource && <JwkOf der={block.der} kind={jwkSource} />}
    </div>
  )
}

async function toJwk(arg: { der: Bytes; kind: string }): Promise<string> {
  const obj = arg.kind === 'CERTIFICATE' ? await certToJwk([arg.der]) : await spkiToJwk(arg.der)
  return JSON.stringify(obj, null, 2)
}

function JwkOf({ der, kind }: { der: Bytes; kind: string }) {
  const arg = useMemo(() => ({ der, kind }), [der, kind])
  const { data, error } = useAsync(arg, toJwk)
  return (
    <details className="pki-details">
      <summary>{kind === 'CERTIFICATE' ? 'Public key as JWK (with kid, x5c, x5t#S256)' : 'Public key as JWK'}</summary>
      {error && <div className="callout warn small">{error}</div>}
      {data && (
        <div className="stack">
          <div className="row">
            <span className="small muted">kid = RFC 7638 thumbprint; x5c = standard base64 DER; x5t#S256 = base64url SHA-256 of the DER.</span>
            <span className="spacer" />
            <CopyButton text={data} />
          </div>
          <pre className="codeblock">{data}</pre>
        </div>
      )}
    </details>
  )
}

async function jwkToPem(text: string): Promise<string | undefined> {
  if (text.trim() === '') return undefined
  let obj: unknown
  try {
    obj = JSON.parse(text)
  } catch {
    throw new Error('Not valid JSON')
  }
  if (obj && typeof obj === 'object' && Array.isArray((obj as { keys?: unknown }).keys)) {
    const keys = (obj as { keys: unknown[] }).keys.slice(0, 50)
    const pems = await Promise.all(keys.map(async (k) => toPem(await jwkToSpki(k), 'PUBLIC KEY')))
    return pems.join('')
  }
  return toPem(await jwkToSpki(obj), 'PUBLIC KEY')
}

function JwkToPem() {
  const [text, setText] = useState('')
  const id = useId()
  const debounced = useDebounced(text, 300)
  const { data, error } = useAsync(debounced, jwkToPem)
  return (
    <section className="card stack" aria-label="JWK to PEM">
      <h2 className="pki-h">JWK / JWKS → public key PEM</h2>
      <label htmlFor={id}>Public JWK or JWKS (&#123;"keys": […]&#125;) — RSA, EC P-256/384/521, OKP Ed25519/X25519</label>
      <textarea id={id} rows={6} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} placeholder='{"kty":"RSA","n":"…","e":"AQAB"}' />
      <div className="row">
        <button type="button" className="btn btn-sm" onClick={() => setText(SAMPLE_JWK)}>
          Sample JWK (RFC 7515 A.3 example)
        </button>
        <button type="button" className="btn btn-sm" onClick={() => setText('')} disabled={!text}>
          Clear
        </button>
      </div>
      {error && <div className="callout error small">{error}</div>}
      {data && (
        <>
          <div className="row">
            <span className="spacer" />
            <CopyButton text={data} />
          </div>
          <pre className="codeblock pki-pem">{data}</pre>
        </>
      )}
    </section>
  )
}
