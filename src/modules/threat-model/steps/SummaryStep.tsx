import { useMemo } from 'react'
import { CopyButton } from '../../../lib/CopyButton.tsx'
import { downloadJSON, downloadText, slugify } from '../../../lib/download.ts'
import { summarize, textualDfd, toMarkdown, toMermaid } from '../export.ts'
import { displayName, STRIDE, STRIDE_NAMES } from '../model.ts'
import { RISK_LABELS, RISK_LEVELS, riskClass, riskOf, riskScore } from '../risk.ts'
import type { StepProps } from '../Wizard.tsx'

export function SummaryStep({ model, goTo }: StepProps) {
  const s = useMemo(() => summarize(model), [model])
  const dfd = useMemo(() => textualDfd(model), [model])
  const mermaid = useMemo(() => toMermaid(model), [model])
  const markdown = useMemo(() => toMarkdown(model), [model])
  const slug = slugify(model.name)
  const pct = s.total ? Math.round((s.addressed / s.total) * 100) : 0
  const elName = (id: string) => {
    const el = model.elements.find((e) => e.id === id)
    return el ? displayName(model, el) : '?'
  }

  return (
    <div className="stack">
      <div className="card stack">
        <div className="row">
          <h2 className="tm-flush">Export</h2>
          <span className="spacer" />
          <button type="button" className="btn btn-primary" onClick={() => downloadText(`threat-model-${slug}.md`, markdown, 'text/markdown')}>
            Download Markdown report
          </button>
          <CopyButton text={markdown} label="Copy Markdown" />
          <button type="button" className="btn" onClick={() => downloadJSON(`threat-model-${slug}.json`, model)}>
            Download JSON
          </button>
        </div>
        <p className="small muted">
          Commit the Markdown report next to the code (e.g. <code>docs/threat-model.md</code>) — GitHub renders the
          embedded Mermaid diagram. Keep the JSON to re-import and update the model later.
        </p>
      </div>

      <div className="grid">
        <div className="card stack">
          <h2>Progress</h2>
          <p>
            <strong>{s.total}</strong> threats · <strong>{s.open}</strong> open · {s.addressed} addressed
            {s.stale > 0 && <> · {s.stale} stale (excluded)</>}
          </p>
          <div className="progress" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Threats addressed">
            <span style={{ width: `${pct}%` }} />
          </div>
          <p className="small muted">{pct}% addressed (mitigated, accepted, transferred or not applicable)</p>
        </div>
        <div className="card">
          <h2>By risk</h2>
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Risk</th>
                <th scope="col">Total</th>
                <th scope="col">Open</th>
              </tr>
            </thead>
            <tbody>
              {[...RISK_LEVELS].reverse().map((r) => (
                <tr key={r}>
                  <td>
                    <span className={`badge ${riskClass(r)}`}>{RISK_LABELS[r]}</span>
                  </td>
                  <td>{s.byRisk[r].total}</td>
                  <td>{s.byRisk[r].open}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h2>By STRIDE category</h2>
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Category</th>
                <th scope="col">Total</th>
                <th scope="col">Open</th>
              </tr>
            </thead>
            <tbody>
              {STRIDE.map((c) => (
                <tr key={c}>
                  <td>
                    <span className="mono">{c}</span> {STRIDE_NAMES[c]}
                  </td>
                  <td>{s.byCategory[c].total}</td>
                  <td>{s.byCategory[c].open}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card stack">
        <h2>Open high & critical threats ({s.openHighCritical.length})</h2>
        {s.openHighCritical.length === 0 ? (
          <p className="muted">{s.total ? 'None — well done.' : 'No threats yet.'}</p>
        ) : (
          <div className="tm-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Risk</th>
                  <th scope="col">Element</th>
                  <th scope="col">Threat</th>
                  <th scope="col">Owner</th>
                </tr>
              </thead>
              <tbody>
                {s.openHighCritical.map((t) => {
                  const level = riskOf(t)
                  return (
                    <tr key={t.id}>
                      <td>
                        <span className={`badge ${riskClass(level)}`}>
                          {RISK_LABELS[level]} {riskScore(t.likelihood, t.impact)}
                        </span>
                      </td>
                      <td>{elName(t.elementId)}</td>
                      <td>
                        <span className="mono">{t.category}</span> {t.title}
                      </td>
                      <td>{t.owner || <span className="muted">unassigned</span>}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {s.openHighCritical.length > 0 && (
          <div>
            <button type="button" className="btn btn-sm" onClick={() => goTo('threats')}>
              Work on threats →
            </button>
          </div>
        )}
      </div>

      <div className="card stack">
        <h2>Data flow diagram (text)</h2>
        {dfd.length === 0 ? (
          <p className="muted">No data flows.</p>
        ) : (
          <pre className="codeblock">{dfd.join('\n')}</pre>
        )}
      </div>

      <div className="card stack">
        <div className="row">
          <h2 className="tm-flush">Mermaid diagram</h2>
          <span className="spacer" />
          <CopyButton text={'```mermaid\n' + mermaid + '\n```'} label="Copy for GitHub Markdown" />
          <CopyButton text={mermaid} label="Copy Mermaid only" />
        </div>
        <p className="small muted">
          Paste into an issue, PR or <code>.md</code> file on GitHub, or into mermaid.live, to render it. Circles are
          processes, cylinders data stores, rectangles external entities; dashed orange arrows cross a trust boundary.
        </p>
        <pre className="codeblock">{mermaid}</pre>
      </div>

      <details className="card">
        <summary className="tm-summary">Preview Markdown report</summary>
        <pre className="codeblock tm-mt">{markdown}</pre>
      </details>
    </div>
  )
}
