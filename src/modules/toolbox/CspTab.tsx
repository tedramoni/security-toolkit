import { useId, useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { FindingList } from './FindingList'
import type { CspBuilderOptions } from './csp'
import { DEFAULT_BUILDER_OPTIONS, NONCE_PLACEHOLDER, buildCsp, evaluateCsp, parseCsp, sampleNonce } from './csp'

const SAMPLE_CSP =
  "default-src 'self'; script-src 'self' 'unsafe-inline' https://ajax.googleapis.com *.cloudfront.net; style-src 'self' 'unsafe-inline'; img-src * data:; plugin-types application/pdf"

type HostField = 'scriptHosts' | 'styleHosts' | 'imgHosts' | 'connectHosts' | 'fontHosts' | 'frameHosts'
const HOST_FIELDS: { key: HostField; label: string }[] = [
  { key: 'scriptHosts', label: 'script-src hosts' },
  { key: 'styleHosts', label: 'style-src hosts' },
  { key: 'imgHosts', label: 'img-src hosts' },
  { key: 'connectHosts', label: 'connect-src hosts (APIs, websockets)' },
  { key: 'fontHosts', label: 'font-src hosts' },
  { key: 'frameHosts', label: 'frame-src hosts (embedded iframes)' },
]

function Evaluator({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId()
  const parsed = useMemo(() => parseCsp(value), [value])
  const findings = useMemo(() => (value.trim() ? evaluateCsp(parsed) : []), [parsed, value])

  return (
    <div className="card stack">
      <h2>Evaluate a policy</h2>
      <label htmlFor={id}>Content-Security-Policy value (or the full header line)</label>
      <textarea id={id} value={value} onChange={(e) => onChange(e.target.value)} spellCheck={false} rows={4} placeholder="default-src 'self'; script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'none'" />
      <div className="row">
        <button type="button" className="btn btn-sm" onClick={() => onChange(SAMPLE_CSP)}>
          Load weak sample
        </button>
        <button type="button" className="btn btn-sm" onClick={() => onChange('')} disabled={value === ''}>
          Clear
        </button>
      </div>
      {value.trim() !== '' && (
        <>
          {parsed.directives.length > 0 && (
            <details className="toolbox-details" open>
              <summary>Parsed directives ({parsed.directives.length})</summary>
              <div className="toolbox-table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Directive</th>
                      <th>Sources</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parsed.directives.map((d) => (
                      <tr key={d.name}>
                        <td className="toolbox-nowrap">
                          <code>{d.name}</code>
                        </td>
                        <td className="toolbox-break">
                          <code>{d.values.join(' ') || '(no value)'}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}
          <FindingList findings={findings} reportTitle="CSP review" />
        </>
      )}
    </div>
  )
}

function Builder({ onEvaluate }: { onEvaluate: (csp: string) => void }) {
  const [o, setO] = useState<CspBuilderOptions>(DEFAULT_BUILDER_OPTIONS)
  const [nonce] = useState(sampleNonce)
  const set = <K extends keyof CspBuilderOptions>(k: K, v: CspBuilderOptions[K]) => setO((prev) => ({ ...prev, [k]: v }))
  const policy = buildCsp(o)
  const header = `Content-Security-Policy: ${policy}`
  const ids = useId()

  return (
    <div className="card stack">
      <h2>Build a starter policy</h2>
      <fieldset className="toolbox-fieldset">
        <legend>Policy style</legend>
        <div className="stack">
          <label className="inline">
            <input type="radio" name={`${ids}-mode`} checked={o.mode === 'strict'} onChange={() => set('mode', 'strict')} />
            Strict (nonce + &apos;strict-dynamic&apos;) — recommended; works with any CDN, needs server-side nonce generation
          </label>
          <label className="inline">
            <input type="radio" name={`${ids}-mode`} checked={o.mode === 'allowlist'} onChange={() => set('mode', 'allowlist')} />
            Allowlist (&apos;self&apos; + hosts) — for static sites without a server to inject nonces
          </label>
        </div>
      </fieldset>

      {o.mode === 'allowlist' && (
        <div className="toolbox-builder-grid">
          {HOST_FIELDS.map((f) => (
            <label key={f.key}>
              {f.label}
              <input type="text" value={o[f.key]} onChange={(e) => set(f.key, e.target.value)} placeholder="https://cdn.example.com" />
            </label>
          ))}
        </div>
      )}

      <div className="toolbox-builder-grid">
        <label>
          Framing (frame-ancestors)
          <select value={o.frameAncestors} onChange={(e) => set('frameAncestors', e.target.value as 'none' | 'self')}>
            <option value="none">&apos;none&apos; — never framed</option>
            <option value="self">&apos;self&apos; — same origin only</option>
          </select>
        </label>
        <label>
          report-to group name
          <input type="text" value={o.reportTo} onChange={(e) => set('reportTo', e.target.value)} placeholder="csp-endpoint" />
        </label>
        <label>
          report-uri (fallback)
          <input type="text" value={o.reportUri} onChange={(e) => set('reportUri', e.target.value)} placeholder="https://example.com/csp-report" />
        </label>
      </div>
      <div className="row">
        <label className="inline">
          <input type="checkbox" checked={o.formActionSelf} onChange={(e) => set('formActionSelf', e.target.checked)} />
          form-action &apos;self&apos;
        </label>
        <label className="inline">
          <input type="checkbox" checked={o.upgradeInsecureRequests} onChange={(e) => set('upgradeInsecureRequests', e.target.checked)} />
          upgrade-insecure-requests
        </label>
        <label className="inline">
          <input type="checkbox" checked={o.trustedTypes} onChange={(e) => set('trustedTypes', e.target.checked)} />
          Trusted Types (require-trusted-types-for &apos;script&apos;)
        </label>
      </div>

      <pre className="codeblock">{header}</pre>
      <div className="row">
        <CopyButton text={header} label="Copy header" />
        <CopyButton text={policy} label="Copy value only" />
        <button type="button" className="btn" onClick={() => onEvaluate(policy)}>
          Evaluate this policy
        </button>
      </div>

      {o.mode === 'strict' && (
        <div className="callout small">
          Replace <code>{NONCE_PLACEHOLDER}</code> with a fresh, unpredictable value for <strong>every response</strong>{' '}
          (≥128 bits from a CSPRNG, e.g. <code>{nonce}</code>) and add the same value to every script tag:{' '}
          <code>{'<script nonce="…">'}</code>. Never reuse or hard-code a nonce. The <code>https:</code> and{' '}
          <code>&apos;unsafe-inline&apos;</code> sources are fallbacks ignored by modern browsers.
        </div>
      )}
      {o.reportTo.trim() !== '' && (
        <div className="callout small">
          report-to needs a matching header, e.g. <code>Reporting-Endpoints: {o.reportTo.trim()}=&quot;https://example.com/csp-report&quot;</code>
        </div>
      )}
      <p className="small muted">
        Roll out with <code>Content-Security-Policy-Report-Only</code> first, fix the violations, then enforce. Sources:{' '}
        <a href="https://web.dev/articles/strict-csp" target="_blank" rel="noopener noreferrer">web.dev strict CSP</a>,{' '}
        <a href="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer">OWASP CSP cheat sheet</a>.
      </p>
    </div>
  )
}

export function CspTab() {
  const [value, setValue] = useState('')
  return (
    <div className="stack">
      <Evaluator value={value} onChange={setValue} />
      <Builder
        onEvaluate={(csp) => {
          setValue(csp)
          window.scrollTo({ top: 0, behavior: 'smooth' })
        }}
      />
    </div>
  )
}
