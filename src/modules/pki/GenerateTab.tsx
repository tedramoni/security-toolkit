import { useEffect, useId, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { downloadText } from '../../lib/download'
import type { HashName, KeyType, SubjectFields } from './generate'
import { EMPTY_SUBJECT, KEY_TYPES, generateCsr, generateSelfSigned, opensslReqCommand, parseSanList, supportsEd25519, validateSubject } from './generate'
import { PrivacyNote } from './ui'

const FIELDS: { key: keyof SubjectFields; label: string; placeholder: string }[] = [
  { key: 'CN', label: 'Common Name (CN)', placeholder: 'www.example.com' },
  { key: 'O', label: 'Organization (O)', placeholder: 'Example Corp' },
  { key: 'OU', label: 'Organizational Unit (OU)', placeholder: 'optional — deprecated in public TLS certs' },
  { key: 'L', label: 'Locality (L)', placeholder: 'Paris' },
  { key: 'ST', label: 'State / Province (ST)', placeholder: 'Île-de-France' },
  { key: 'C', label: 'Country (C, 2 letters)', placeholder: 'FR' },
  { key: 'E', label: 'E-mail (emailAddress)', placeholder: 'optional' },
]

interface Output {
  kind: 'csr' | 'cert'
  pem: string
  privateKeyPem: string
}

export function GenerateTab() {
  const [keyType, setKeyType] = useState<KeyType>('P-256')
  const [hash, setHash] = useState<HashName>('SHA-256')
  const [subject, setSubject] = useState<SubjectFields>({ ...EMPTY_SUBJECT })
  const [sanText, setSanText] = useState('')
  const [mode, setMode] = useState<'csr' | 'cert'>('csr')
  const [days, setDays] = useState(30)
  const [ed25519, setEd25519] = useState<boolean | undefined>()
  const [busy, setBusy] = useState(false)
  const [out, setOut] = useState<Output>()
  const [err, setErr] = useState<string>()
  const ids = useId()

  useEffect(() => {
    supportsEd25519().then(setEd25519)
  }, [])

  const subjErrors = validateSubject(subject)
  const sans = parseSanList(sanText)
  const daysOk = Number.isInteger(days) && days >= 1 && days <= 3650
  const valid = Object.keys(subjErrors).length === 0 && sans.errors.length === 0 && (mode === 'csr' || daysOk)
  const cnNotInSan = subject.CN !== '' && sans.sans.length > 0 && !sans.sans.some((s) => s.value.toLowerCase() === subject.CN.toLowerCase())
  const cmd = opensslReqCommand({ keyType, hash, subject, sans: sans.sans, selfSigned: mode === 'cert', days })

  const generate = async () => {
    setBusy(true)
    setErr(undefined)
    setOut(undefined)
    try {
      if (mode === 'csr') {
        const r = await generateCsr({ keyType, hash, subject, sans: sans.sans })
        setOut({ kind: 'csr', pem: r.csrPem, privateKeyPem: r.privateKeyPem })
      } else {
        const r = await generateSelfSigned({ keyType, hash, subject, sans: sans.sans, days })
        setOut({ kind: 'cert', pem: r.certPem, privateKeyPem: r.privateKeyPem })
      }
    } catch (e) {
      setErr((e as Error).message || String(e))
    } finally {
      setBusy(false)
    }
  }

  const base = (subject.CN || 'request').replace(/[^A-Za-z0-9.-]+/g, '_')

  return (
    <div className="stack">
      <PrivacyNote />
      <div className="callout warn small">
        Keys generated here exist only in this tab’s memory and are exportable so you can download them.{' '}
        <strong>Prefer generating production keys on the server that will use them</strong> (the OpenSSL command below),
        so the private key never transits through a browser, clipboard or Downloads folder. WebCrypto cannot produce
        password-encrypted PKCS#8, so the downloaded key is <strong>unencrypted</strong>.
      </div>
      <div className="pki-form-grid">
        <fieldset className="pki-fieldset">
          <legend>Key</legend>
          <div className="stack">
            <label htmlFor={`${ids}-kt`}>Key type</label>
            <select id={`${ids}-kt`} value={keyType} onChange={(e) => setKeyType(e.target.value as KeyType)}>
              {KEY_TYPES.map((k) => (
                <option key={k.id} value={k.id} disabled={k.id === 'Ed25519' && ed25519 === false}>
                  {k.label}
                  {k.id === 'Ed25519' && ed25519 === false ? ' (not supported by this browser)' : ''}
                </option>
              ))}
            </select>
            {keyType === 'Ed25519' && <p className="small muted">Ed25519 is not accepted by public TLS CAs (CA/B Forum allows RSA and ECDSA only) — fine for private PKI.</p>}
            {keyType === 'RSA-4096' && <p className="small muted">RSA 4096 generation can take a few seconds.</p>}
            <label htmlFor={`${ids}-h`}>Signature hash</label>
            <select id={`${ids}-h`} value={hash} onChange={(e) => setHash(e.target.value as HashName)} disabled={keyType === 'Ed25519'}>
              <option value="SHA-256">SHA-256</option>
              <option value="SHA-384">SHA-384</option>
              <option value="SHA-512">SHA-512</option>
            </select>
            <span className="row">
              <label className="inline">
                <input type="radio" name={`${ids}-mode`} checked={mode === 'csr'} onChange={() => setMode('csr')} /> CSR
              </label>
              <label className="inline">
                <input type="radio" name={`${ids}-mode`} checked={mode === 'cert'} onChange={() => setMode('cert')} /> Self-signed test certificate
              </label>
            </span>
            {mode === 'cert' && (
              <>
                <label htmlFor={`${ids}-days`}>Validity (days)</label>
                <input id={`${ids}-days`} type="number" min={1} max={3650} value={days} onChange={(e) => setDays(Math.floor(Number(e.target.value)))} aria-invalid={!daysOk} />
                {!daysOk && <span className="pki-err small">1 – 3650 days</span>}
                <div className="callout warn small">Test only: a self-signed certificate is trusted by nobody. Use an internal CA or ACME for anything real.</div>
              </>
            )}
          </div>
        </fieldset>
        <fieldset className="pki-fieldset">
          <legend>Subject</legend>
          <div className="stack">
            {FIELDS.map((f) => (
              <div key={f.key} className="stack pki-tight">
                <label htmlFor={`${ids}-${f.key}`}>{f.label}</label>
                <input
                  id={`${ids}-${f.key}`}
                  type="text"
                  value={subject[f.key]}
                  placeholder={f.placeholder}
                  maxLength={f.key === 'C' ? 2 : 200}
                  onChange={(e) => setSubject((s) => ({ ...s, [f.key]: f.key === 'C' ? e.target.value.toUpperCase() : e.target.value }))}
                  aria-invalid={!!subjErrors[f.key]}
                  aria-describedby={subjErrors[f.key] ? `${ids}-${f.key}-err` : undefined}
                  spellCheck={false}
                />
                {subjErrors[f.key] && (
                  <span id={`${ids}-${f.key}-err`} className="pki-err small">
                    {subjErrors[f.key]}
                  </span>
                )}
              </div>
            ))}
          </div>
        </fieldset>
        <fieldset className="pki-fieldset">
          <legend>Subject Alternative Names</legend>
          <div className="stack">
            <label htmlFor={`${ids}-san`}>DNS names, IPs and e-mails (comma, space or newline separated; optional DNS:/IP:/email: prefix)</label>
            <textarea id={`${ids}-san`} rows={6} value={sanText} onChange={(e) => setSanText(e.target.value)} placeholder={'www.example.com\nexample.com\n10.0.0.5'} spellCheck={false} />
            {sans.errors.map((e, i) => (
              <span key={i} className="pki-err small">
                {e}
              </span>
            ))}
            {sans.sans.length > 0 && (
              <p className="small muted">
                {sans.sans.length} SAN(s): {sans.sans.map((s) => `${s.type.toUpperCase()}:${s.value}`).join(', ')}
              </p>
            )}
            {cnNotInSan && <p className="small pki-warn">The CN is not in the SAN list; public CAs require it there (browsers ignore the CN).</p>}
            {sans.sans.length === 0 && subject.CN && <p className="small pki-warn">Add at least one SAN — browsers only check SANs.</p>}
          </div>
        </fieldset>
      </div>
      <div className="row">
        <button type="button" className="btn btn-primary" disabled={!valid || busy} onClick={generate}>
          {busy ? 'Generating…' : mode === 'csr' ? 'Generate key + CSR' : 'Generate key + self-signed certificate'}
        </button>
      </div>
      {err && (
        <div className="callout error" role="alert">
          {err}
        </div>
      )}
      <section className="card stack" aria-label="OpenSSL command">
        <div className="row">
          <h3 className="pki-h">Equivalent OpenSSL command (recommended for production keys)</h3>
          <span className="spacer" />
          <CopyButton text={cmd} />
        </div>
        <pre className="codeblock">{cmd}</pre>
        <p className="small muted">
          POSIX shell (bash/zsh), OpenSSL ≥ 1.1.1. In Git Bash on Windows, prefix with <code>MSYS_NO_PATHCONV=1</code> so the -subj value is not rewritten as a path.
          Leave the challenge password empty if prompted.
        </p>
      </section>
      {out && (
        <div className="pki-split">
          <section className="card stack" aria-label={out.kind === 'csr' ? 'CSR' : 'Certificate'}>
            <div className="row">
              <h3 className="pki-h">{out.kind === 'csr' ? 'CSR (send this to the CA)' : 'Self-signed certificate'}</h3>
              <span className="spacer" />
              <CopyButton text={out.pem} />
              <button type="button" className="btn" onClick={() => downloadText(`${base}.${out.kind === 'csr' ? 'csr' : 'crt'}`, out.pem, 'application/x-pem-file')}>
                Download
              </button>
            </div>
            <pre className="codeblock pki-pem">{out.pem}</pre>
          </section>
          <section className="card stack" aria-label="Private key">
            <div className="row">
              <h3 className="pki-h">Private key (PKCS#8, unencrypted)</h3>
              <span className="spacer" />
              <CopyButton text={out.privateKeyPem} />
              <button type="button" className="btn btn-danger" onClick={() => downloadText(`${base}.key`, out.privateKeyPem, 'application/x-pem-file')}>
                Download key
              </button>
            </div>
            <div className="callout warn small">
              Store it safely (chmod 600, secrets manager or HSM), never commit it, and delete stray copies. To add a password:{' '}
              <code>openssl pkcs8 -topk8 -v2 aes-256-cbc -in {base}.key -out {base}.enc.key</code>. It is not saved anywhere by this page and disappears when you close the tab.
            </div>
            <pre className="codeblock pki-pem">{out.privateKeyPem}</pre>
            <div className="row">
              <button type="button" className="btn btn-sm" onClick={() => setOut(undefined)}>
                Forget generated key
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
