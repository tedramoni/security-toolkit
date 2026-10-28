import { useDeferredValue, useId, useMemo, useState } from 'react'
import { FindingList } from './FindingList'
import { SAMPLE_HEADERS, analyzeHeaders } from './headers'

function YesNo({ ok }: { ok: boolean }) {
  return ok ? <span className="toolbox-yes">Yes</span> : <span className="toolbox-no">No</span>
}

function formatLifetime(s: number | undefined): string {
  if (s === undefined) return 'Session'
  if (s <= 0) return 'Deleted'
  if (s < 3600) return `${Math.round(s / 60)} min`
  if (s < 86400) return `${Math.round(s / 3600)} h`
  return `${Math.round(s / 86400)} days`
}

export function HeadersTab() {
  const [raw, setRaw] = useState('')
  const deferred = useDeferredValue(raw)
  const id = useId()
  const analysis = useMemo(() => (deferred.trim() ? analyzeHeaders(deferred) : undefined), [deferred])
  const cookieFindings = analysis ? analysis.cookies.flatMap((c) => c.findings) : []

  return (
    <div className="stack">
      <label htmlFor={id}>
        <span>
          Raw HTTP response headers — from DevTools (Network → response headers → Raw) or <code>curl -sI https://your.site</code>
        </span>
      </label>
      <textarea id={id} value={raw} onChange={(e) => setRaw(e.target.value)} spellCheck={false} rows={10} placeholder={'HTTP/2 200\ncontent-type: text/html\nstrict-transport-security: max-age=63072000; includeSubDomains'} />
      <div className="row">
        <button type="button" className="btn btn-sm" onClick={() => setRaw(SAMPLE_HEADERS)}>
          Load weak sample
        </button>
        <button type="button" className="btn btn-sm" onClick={() => setRaw('')} disabled={raw === ''}>
          Clear
        </button>
        <span className="small muted">Check HTML page responses (not just API/JSON) — browser security headers apply to documents.</span>
      </div>

      {analysis && analysis.parsed.headers.size === 0 && (
        <div className="callout warn" role="alert">
          No headers recognised. Paste lines in the form <code>Name: value</code>.
        </div>
      )}

      {analysis && analysis.parsed.headers.size > 0 && (
        <>
          <div className="card row" style={{ gap: '1.25rem' }}>
            <div className={`toolbox-grade toolbox-grade-${analysis.grade[0].toLowerCase()}`} aria-label={`Grade ${analysis.grade}`}>
              {analysis.grade}
            </div>
            <div className="stack" style={{ flex: 1, minWidth: 220 }}>
              <div>
                <strong>Score {analysis.score}/100</strong>{' '}
                <span className="muted small">
                  {analysis.parsed.statusLine ?? 'no status line'} · {analysis.parsed.headers.size} headers · {analysis.cookies.length} cookies
                </span>
              </div>
              <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={analysis.score} aria-label="Security header score">
                <span style={{ width: `${analysis.score}%` }} />
              </div>
              <span className="small muted">Penalties: critical −30, high −15, medium −8, low −3. A heuristic to prioritise work, not a certification.</span>
            </div>
          </div>

          <div className="card">
            <h3>Header checks</h3>
            <FindingList findings={analysis.findings} reportTitle="HTTP security headers review" />
          </div>

          {analysis.cookies.length > 0 && (
            <div className="card stack">
              <h3>Cookies</h3>
              <div className="toolbox-table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Secure</th>
                      <th>HttpOnly</th>
                      <th>SameSite</th>
                      <th>Domain</th>
                      <th>Path</th>
                      <th>Lifetime</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.cookies.map((c, i) => (
                      <tr key={`${c.name}-${i}`}>
                        <td className="toolbox-break">
                          <code>{c.name}</code>
                          {c.sessionLike && <span className="muted small"> (session-like)</span>}
                        </td>
                        <td><YesNo ok={c.secure} /></td>
                        <td><YesNo ok={c.httpOnly} /></td>
                        <td>{c.sameSite ?? <span className="muted">not set</span>}</td>
                        <td>{c.domain ?? <span className="muted">host-only</span>}</td>
                        <td>{c.path ?? <span className="muted">default</span>}</td>
                        <td className="toolbox-nowrap">{formatLifetime(c.lifetimeSeconds)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <FindingList findings={cookieFindings} reportTitle="Cookie review" />
            </div>
          )}

          <details className="toolbox-details card">
            <summary>Parsed headers ({analysis.parsed.headers.size})</summary>
            <div className="toolbox-table-wrap">
              <table className="table">
                <tbody>
                  {[...analysis.parsed.headers].map(([name, values]) =>
                    values.map((v, i) => (
                      <tr key={`${name}-${i}`}>
                        <th scope="row" className="toolbox-nowrap">{name}</th>
                        <td className="toolbox-break"><code>{v}</code></td>
                      </tr>
                    )),
                  )}
                </tbody>
              </table>
            </div>
          </details>
        </>
      )}
    </div>
  )
}
