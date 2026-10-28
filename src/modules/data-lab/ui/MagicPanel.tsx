import type { MagicResult } from '../engine/magic'
import { safePreview } from '../ops/helpers'

interface Props {
  results: MagicResult[] | null
  running: boolean
  error?: string
  auto: boolean
  onAutoChange(v: boolean): void
  onRun(): void
  onApply(r: MagicResult): void
  target: string
}

export function MagicPanel({ results, running, error, auto, onAutoChange, onRun, onApply, target }: Props) {
  return (
    <section className="card data-lab-magic" aria-labelledby="data-lab-magic-h">
      <div className="row data-lab-io-head">
        <h2 id="data-lab-magic-h">
          <span aria-hidden="true">✨</span> Magic
        </h2>
        <span className="spacer" />
        <label className="inline small">
          <input type="checkbox" checked={auto} onChange={(e) => onAutoChange(e.target.checked)} />
          Auto
        </label>
        <button type="button" className="btn btn-sm" onClick={onRun} disabled={running}>
          {running ? 'Analysing…' : 'Run Magic'}
        </button>
      </div>
      <p className="small muted">
        Tries likely decodings of the {target} (up to 3 steps deep, about 1.5 s, first 1 MB) and ranks them by how readable the result is.
      </p>
      {error && <p className="callout error">{error}</p>}
      <div aria-live="polite">
        {results && results.length === 0 && !running && <p className="small muted">No likely decoding found.</p>}
        {results && results.length > 0 && (
          <ul className="data-lab-magic-list">
            {results.map((r, i) => (
              <li key={i} className="data-lab-magic-item">
                <div className="row">
                  <strong>{r.labels.join(' → ')}</strong>
                  <span className="badge sev-info" title="Heuristic score">
                    {Math.round(Math.max(0, Math.min(1, r.score)) * 100)}%
                  </span>
                  <span className="spacer" />
                  <button type="button" className="btn btn-sm btn-primary" onClick={() => onApply(r)} aria-label={`Add ${r.labels.join(' then ')} to the recipe`}>
                    Add
                  </button>
                </div>
                <p className="small muted">{r.reason}</p>
                <pre className="data-lab-magic-preview">{safePreview(r.preview, 240)}</pre>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
