import { useState } from 'react'
import type { StepProps } from '../Wizard.tsx'
import { LIMITS } from '../model.ts'

export function SystemStep({ model, update }: StepProps) {
  const [draft, setDraft] = useState('')

  const addAssumption = () => {
    const text = draft.trim()
    if (!text) return
    update((m) => ({ ...m, assumptions: [...m.assumptions, text] }))
    setDraft('')
  }

  return (
    <div className="stack">
      <div className="card stack">
        <h2>System</h2>
        <label>
          Name
          <input type="text" maxLength={LIMITS.text} value={model.name} onChange={(e) => update((m) => ({ ...m, name: e.target.value }))} />
        </label>
        <label>
          Owner (team or person accountable for the risks)
          <input type="text" maxLength={LIMITS.text} value={model.owner} onChange={(e) => update((m) => ({ ...m, owner: e.target.value }))} />
        </label>
        <label>
          Description — what does the system do, for whom, and what is in scope?
          <textarea maxLength={LIMITS.text}
            className="tm-prose"
            value={model.description}
            onChange={(e) => update((m) => ({ ...m, description: e.target.value }))}
          />
        </label>
      </div>

      <div className="card stack">
        <h2>Assumptions</h2>
        <p className="muted small">
          Record what you take for granted (e.g. "the database is only reachable from the VPC", "SSO enforces MFA"). Each
          assumption is something to verify — if it turns out to be false, the threat model must be revisited.
        </p>
        {model.assumptions.length > 0 && (
          <ol className="tm-assumptions">
            {model.assumptions.map((a, i) => (
              <li key={i} className="row">
                <input
                  type="text"
                  maxLength={LIMITS.text}
                  aria-label={`Assumption ${i + 1}`}
                  value={a}
                  onChange={(e) =>
                    update((m) => ({ ...m, assumptions: m.assumptions.map((x, j) => (j === i ? e.target.value : x)) }))
                  }
                  className="tm-grow"
                />
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={() => update((m) => ({ ...m, assumptions: m.assumptions.filter((_, j) => j !== i) }))}
                >
                  Remove
                </button>
              </li>
            ))}
          </ol>
        )}
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault()
            addAssumption()
          }}
        >
          <label className="tm-grow">
            New assumption
            <input type="text" maxLength={LIMITS.text} value={draft} onChange={(e) => setDraft(e.target.value)} />
          </label>
          <button type="submit" className="btn tm-align-end" disabled={!draft.trim()}>
            Add assumption
          </button>
        </form>
      </div>
    </div>
  )
}
