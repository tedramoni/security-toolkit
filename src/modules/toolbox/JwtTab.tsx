import { useEffect, useId, useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { FindingList } from './FindingList'
import type { DecodedJwt } from './jwt'
import { JwtError, SAMPLE_JWT, decodeJwt, describeTimeClaims, lintJwt } from './jwt'

type Result = { ok: true; jwt: DecodedJwt } | { ok: false; error: string } | undefined

function JsonBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="card">
      <div className="row toolbox-json-label">
        <h3 style={{ margin: 0 }}>{label}</h3>
        <span className="spacer" />
        <CopyButton text={value} />
      </div>
      <pre className="codeblock toolbox-json">{value}</pre>
    </div>
  )
}

export function JwtTab() {
  const [token, setToken] = useState('')
  const inputId = useId()
  // Clock for exp/nbf checks and relative times; refreshed every 30 s.
  const [now, setNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now() / 1000), 30_000)
    return () => clearInterval(t)
  }, [])

  const result: Result = useMemo(() => {
    if (token.trim() === '') return undefined
    try {
      return { ok: true, jwt: decodeJwt(token) }
    } catch (e) {
      return { ok: false, error: e instanceof JwtError ? e.message : `Could not decode token: ${(e as Error).message}` }
    }
  }, [token])

  const findings = result?.ok ? lintJwt(result.jwt, now) : []
  const times = result?.ok ? describeTimeClaims(result.jwt.payload, now) : []

  return (
    <div className="stack">
      <div className="callout small">
        Decoding happens entirely in your browser. The signature is <strong>not verified</strong> — that requires the
        key and must be done by the server that trusts the token. Avoid pasting live production tokens anyway; prefer
        expired or test tokens.
      </div>

      <label htmlFor={inputId}>JWT (header.payload.signature — "Bearer " prefix is accepted)</label>
      <textarea
        id={inputId}
        value={token}
        onChange={(e) => setToken(e.target.value)}
        placeholder="eyJhbGciOi..."
        spellCheck={false}
        autoComplete="off"
        rows={5}
      />
      <div className="row">
        <button type="button" className="btn btn-sm" onClick={() => setToken(SAMPLE_JWT)}>
          Load sample token
        </button>
        <button type="button" className="btn btn-sm" onClick={() => setToken('')} disabled={token === ''}>
          Clear
        </button>
      </div>

      {result && !result.ok && (
        <div className="callout error" role="alert">
          {result.error}
        </div>
      )}

      {result?.ok && (
        <>
          <div className="toolbox-split">
            <JsonBlock label={`Header (${result.jwt.kind})`} value={JSON.stringify(result.jwt.header, null, 2)} />
            {result.jwt.kind === 'JWE' ? (
              <div className="card">
                <h3>Payload</h3>
                <p className="muted">Encrypted (JWE) — cannot be decoded without the recipient&apos;s private key.</p>
              </div>
            ) : (
              <JsonBlock
                label="Payload"
                value={result.jwt.payloadText ?? JSON.stringify(result.jwt.payload, null, 2)}
              />
            )}
          </div>

          <div className="card">
            <h3>Signature &amp; validity</h3>
            <table className="table">
              <tbody>
                {result.jwt.kind === 'JWS' && (
                  <tr>
                    <th scope="row">Signature</th>
                    <td>
                      {result.jwt.signaturePresent ? (
                        <span className="toolbox-yes">Present ({result.jwt.signatureBytes} bytes, not verified)</span>
                      ) : (
                        <span className="toolbox-no">Empty — token is unsigned</span>
                      )}
                    </td>
                  </tr>
                )}
                {times.map((t) => (
                  <tr key={t.claim}>
                    <th scope="row">
                      {t.label} <code>{t.claim}</code>
                    </th>
                    <td>
                      {t.valid ? (
                        <>
                          {new Date((t.value as number) * 1000).toLocaleString()}{' '}
                          <span className="muted">
                            ({t.relative}) · <code>{t.iso}</code>
                          </span>
                        </>
                      ) : (
                        <span className="toolbox-no">Invalid value: {JSON.stringify(t.value)}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="card">
            <h3>Findings</h3>
            <FindingList findings={findings} reportTitle="JWT review" />
          </div>
        </>
      )}
    </div>
  )
}
