import { useState } from 'react'
import { newId } from '../../../lib/storage.ts'
import type { ModelElement, NodeType } from '../model.ts'
import { createNode, LIMITS, ELEMENT_TYPE_LABELS, NODE_TYPES, nodesOf, removalImpact, removeElement, TAGS, tagsForType, upsertElement } from '../model.ts'
import { applicableCategories } from '../stride.ts'
import type { StepProps } from '../Wizard.tsx'

const TYPE_HELP: Record<NodeType, string> = {
  process: 'Code that runs and transforms data: web app, API, worker, function, SPA.',
  datastore: 'Where data rests: database, bucket, queue, cache, file share, log store.',
  external: 'People or systems outside your control: users, partners, SaaS vendors.',
}

export function ElementsStep({ model, update, goTo }: StepProps) {
  const [editing, setEditing] = useState<ModelElement | null>(null)
  const nodes = nodesOf(model)

  const remove = (el: ModelElement) => {
    const impact = removalImpact(model, el.id)
    const parts = [`Remove "${el.name || 'unnamed'}"?`]
    if (impact.flows.length) parts.push(`${impact.flows.length} data flow(s) connected to it will also be removed.`)
    if (impact.threatCount) parts.push(`${impact.threatCount} threat(s) on it and on those flows will be deleted.`)
    if (!window.confirm(parts.join('\n'))) return
    update((m) => removeElement(m, el.id))
    if (editing?.id === el.id) setEditing(null)
  }

  return (
    <div className="stack">
      <ElementForm
        key={editing?.id ?? 'new'}
        initial={editing}
        onCancel={() => setEditing(null)}
        onSave={(el) => {
          update((m) => upsertElement(m, el))
          setEditing(null)
        }}
      />

      <div className="card stack">
        <h2>Elements ({nodes.length})</h2>
        {nodes.length === 0 ? (
          <p className="muted">
            No elements yet. A typical web system has at least: the user (external entity), the front-end and API
            (processes) and a database (data store).
          </p>
        ) : (
          <div className="tm-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Type</th>
                  <th scope="col">Tags</th>
                  <th scope="col">STRIDE</th>
                  <th scope="col">
                    <span className="tm-sr">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {nodes.map((el) => (
                  <tr key={el.id}>
                    <td>
                      <strong>{el.name || 'unnamed'}</strong>
                      {el.description && <div className="small muted">{el.description}</div>}
                    </td>
                    <td>{ELEMENT_TYPE_LABELS[el.type]}</td>
                    <td>
                      <div className="row">
                        {el.tags.map((t) => (
                          <span key={t} className="badge sev-info">
                            {TAGS.find((d) => d.id === t)?.label ?? t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="mono">{applicableCategories(el).join(' ')}</td>
                    <td>
                      <div className="row tm-nowrap">
                        <button type="button" className="btn btn-sm" onClick={() => setEditing(el)}>
                          Edit
                        </button>
                        <button type="button" className="btn btn-sm btn-danger" onClick={() => remove(el)}>
                          Remove
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {nodes.length >= 2 && (
          <div className="row">
            <span className="spacer" />
            <button type="button" className="btn" onClick={() => goTo('flows')}>
              Connect them with data flows →
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function ElementForm({
  initial,
  onSave,
  onCancel,
}: {
  initial: ModelElement | null
  onSave: (el: ModelElement) => void
  onCancel: () => void
}) {
  const [type, setType] = useState<NodeType>(initial && initial.type !== 'dataflow' ? initial.type : 'process')
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [tags, setTags] = useState<string[]>(initial?.tags ?? [])
  const available = tagsForType(type)

  const submit = () => {
    if (!name.trim()) return
    const allowed = new Set(available.map((t) => t.id))
    // Keep unknown (imported/custom) tags; drop known tags that do not fit the chosen type.
    const known = new Set(TAGS.map((t) => t.id))
    const keptTags = tags.filter((t) => allowed.has(t) || !known.has(t))
    const base = initial ?? createNode(newId(), type, '')
    onSave({ ...base, type, name: name.trim(), description: description.trim(), tags: keptTags })
    if (!initial) {
      setName('')
      setDescription('')
      setTags([])
    }
  }

  return (
    <form
      className="card stack"
      onSubmit={(e) => {
        e.preventDefault()
        submit()
      }}
    >
      <h2>{initial ? `Edit "${initial.name}"` : 'Add an element'}</h2>
      <div className="tm-form-grid">
        <label>
          Type
          <select value={type} onChange={(e) => setType(e.target.value as NodeType)}>
            {NODE_TYPES.map((t) => (
              <option key={t} value={t}>
                {ELEMENT_TYPE_LABELS[t]}
              </option>
            ))}
          </select>
          <span className="small muted">{TYPE_HELP[type]}</span>
        </label>
        <label>
          Name
          <input type="text" maxLength={LIMITS.text} value={name} required onChange={(e) => setName(e.target.value)} placeholder="e.g. Orders API" />
        </label>
      </div>
      <label>
        Description (optional)
        <input type="text" maxLength={LIMITS.text} value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      <fieldset className="tm-fieldset">
        <legend className="small muted">Characteristics (drive the generated threats)</legend>
        <div className="tm-tags">
          {available.map((t) => (
            <label key={t.id} className="inline" title={t.hint}>
              <input
                type="checkbox"
                checked={tags.includes(t.id)}
                onChange={(e) => setTags((ts) => (e.target.checked ? [...ts, t.id] : ts.filter((x) => x !== t.id)))}
              />
              <span>
                {t.label} <span className="small muted">— {t.hint}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      <div className="row">
        <button type="submit" className="btn btn-primary" disabled={!name.trim()}>
          {initial ? 'Save changes' : 'Add element'}
        </button>
        {initial && (
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  )
}
