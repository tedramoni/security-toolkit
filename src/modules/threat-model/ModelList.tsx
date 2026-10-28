import { useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { downloadJSON, readFileText, slugify } from '../../lib/download.ts'
import { newId } from '../../lib/storage.ts'
import { exampleModel } from './example.ts'
import type { SetModels } from './index.tsx'
import type { ThreatModel } from './model.ts'
import { createModel, duplicateModel, flowsOf, nodesOf, parseImport } from './model.ts'
import { refreshThreats } from './stride.ts'
import { summarize } from './export.ts'

interface Props {
  base: string
  models: ThreatModel[]
  setModels: SetModels
  /** Persisted entries that could not be loaded (kept in storage untouched). */
  invalid: unknown[]
  discardInvalid: () => void
}

export function ModelList({ base, models, setModels, invalid, discardInvalid }: Props) {
  const navigate = useNavigate()
  const fileRef = useRef<HTMLInputElement>(null)
  const [importErrors, setImportErrors] = useState<string[]>([])
  const [notice, setNotice] = useState('')

  const open = (id: string) => navigate(`${base}/${encodeURIComponent(id)}/system`)

  const create = () => {
    const m = createModel(newId(), 'New threat model')
    setModels((ms) => [...ms, m])
    open(m.id)
  }

  const loadExample = () => {
    const { model } = refreshThreats(exampleModel(newId()), newId)
    setModels((ms) => [...ms, model])
    open(model.id)
  }

  const onImport = async (file: File | undefined) => {
    setImportErrors([])
    setNotice('')
    if (!file) return
    if (file.size > 5_000_000) {
      setImportErrors(['File is larger than 5 MB — that does not look like a threat model export.'])
      return
    }
    const text = await readFileText(file)
    const res = parseImport(
      text,
      models.map((m) => m.id),
      newId,
    )
    if (!res.ok) {
      setImportErrors(res.errors)
      return
    }
    setModels((ms) => [...ms, ...res.models])
    setNotice(`Imported ${res.models.length} model${res.models.length > 1 ? 's' : ''}: ${res.models.map((m) => m.name).join(', ')}`)
  }

  const sorted = [...models].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))

  return (
    <div className="stack">
      <header className="page-header">
        <h1>Threat Modeling</h1>
        <p>
          Describe your system as a data-flow diagram (processes, data stores, external entities and the flows between
          them), generate STRIDE-per-element threats with concrete mitigations, track decisions and export a Markdown
          report for the repo or the PR. Everything stays in this browser.
        </p>
      </header>

      <div className="row">
        <button type="button" className="btn btn-primary" onClick={create}>
          New threat model
        </button>
        <button type="button" className="btn" onClick={loadExample}>
          Load example
        </button>
        <button type="button" className="btn" onClick={() => fileRef.current?.click()}>
          Import JSON…
        </button>
        <input
          ref={fileRef}
          type="file"
          accept="application/json,.json"
          hidden
          aria-label="Import threat model JSON file"
          onChange={(e) => {
            void onImport(e.target.files?.[0])
            e.target.value = ''
          }}
        />
        {models.length > 0 && (
          <>
            <span className="spacer" />
            <button type="button" className="btn" onClick={() => downloadJSON('threat-models.json', models)}>
              Export all ({models.length})
            </button>
          </>
        )}
      </div>

      {invalid.length > 0 && (
        <div className="callout warn row" role="alert">
          <span>
            {invalid.length} saved entr{invalid.length > 1 ? 'ies' : 'y'} in this browser could not be read as a threat
            model (corrupted or from an incompatible version). They are kept untouched; download them to inspect or repair.
          </span>
          <span className="spacer" />
          <button type="button" className="btn btn-sm" onClick={() => downloadJSON('threat-models-unreadable.json', invalid)}>
            Download unreadable entries
          </button>
          <button
            type="button"
            className="btn btn-sm btn-danger"
            onClick={() => {
              if (window.confirm('Permanently delete the unreadable entries? Download them first if unsure.')) discardInvalid()
            }}
          >
            Discard them
          </button>
        </div>
      )}
      {notice && (
        <div className="callout" role="status">
          {notice}
        </div>
      )}
      {importErrors.length > 0 && (
        <div className="callout error" role="alert">
          <strong>Import rejected — nothing was changed.</strong>
          <ul className="small tm-errors">
            {importErrors.map((e, i) => (
              <li key={i}>
                <code>{e}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {sorted.length === 0 ? (
        <div className="card">
          <h2>No threat models yet</h2>
          <p className="muted">
            Start a new model, or load the example (a web shop with an API, a database, a payment provider and an audit
            log) to see what the generated threats look like.
          </p>
        </div>
      ) : (
        <div className="grid">
          {sorted.map((m) => (
            <ModelCard
              key={m.id}
              base={base}
              model={m}
              onDuplicate={() => {
                const copy = duplicateModel(m, newId())
                setModels((ms) => [...ms, copy])
              }}
              onDelete={() => {
                if (window.confirm(`Delete threat model "${m.name}"? This cannot be undone (export it first if unsure).`)) {
                  setModels((ms) => ms.filter((x) => x.id !== m.id))
                }
              }}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function ModelCard({
  base,
  model,
  onDuplicate,
  onDelete,
}: {
  base: string
  model: ThreatModel
  onDuplicate: () => void
  onDelete: () => void
}) {
  const s = summarize(model)
  const pct = s.total ? Math.round((s.addressed / s.total) * 100) : 0
  const hc = s.openHighCritical.length
  return (
    <article className="card stack">
      <div>
        <h2 className="tm-card-title">
          <Link to={`${base}/${encodeURIComponent(model.id)}/system`}>{model.name || 'Untitled'}</Link>
        </h2>
        <p className="muted small">
          {model.owner ? `${model.owner} · ` : ''}updated {model.updatedAt.slice(0, 10)}
        </p>
      </div>
      <p className="small">
        {nodesOf(model).length} elements · {flowsOf(model).length} flows · {s.total} threats
        {hc > 0 && (
          <>
            {' · '}
            <span className="badge sev-high">{hc} open high/critical</span>
          </>
        )}
      </p>
      <div>
        <div className="progress" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Threats addressed">
          <span style={{ width: `${pct}%` }} />
        </div>
        <p className="small muted">{s.total ? `${pct}% of threats addressed` : 'No threats generated yet'}</p>
      </div>
      <div className="row">
        <Link className="btn btn-sm tm-linkbtn" to={`${base}/${encodeURIComponent(model.id)}/system`}>
          Open
        </Link>
        <button type="button" className="btn btn-sm" onClick={onDuplicate}>
          Duplicate
        </button>
        <button type="button" className="btn btn-sm" onClick={() => downloadJSON(`threat-model-${slugify(model.name)}.json`, model)}>
          JSON
        </button>
        <span className="spacer" />
        <button type="button" className="btn btn-sm btn-danger" onClick={onDelete}>
          Delete
        </button>
      </div>
    </article>
  )
}
