import { useState } from 'react'
import { newId } from '../../../lib/storage.ts'
import type { DataClassification, ModelElement } from '../model.ts'
import { createFlow, LIMITS, DATA_CLASSIFICATIONS, displayName, ELEMENT_TYPE_LABELS, flowsOf, nodesOf, removalImpact, removeElement, upsertElement } from '../model.ts'
import { transportSecurity } from '../stride.ts'
import type { StepProps } from '../Wizard.tsx'

const PROTOCOLS = ['HTTPS', 'HTTP', 'gRPC over TLS', 'WSS', 'PostgreSQL over TLS', 'PostgreSQL', 'MySQL', 'AMQPS', 'Kafka (TLS)', 'SFTP', 'FTP', 'SSH', 'SMTP', 'SMTPS', 'TLS syslog', 'TCP']

const CLASSIFICATION_HELP: Record<DataClassification, string> = {
  public: 'Public — anyone may see it (marketing pages, public catalogue)',
  internal: 'Internal — not for outsiders, low harm if leaked',
  confidential: 'Confidential — personal data, customer data, business secrets',
  secret: 'Secret — credentials, keys, tokens, card data',
}

export function FlowsStep({ model, update, goTo }: StepProps) {
  const [editing, setEditing] = useState<ModelElement | null>(null)
  const nodes = nodesOf(model)
  const flows = flowsOf(model)
  const nodeName = (id: string | undefined) => {
    const n = model.elements.find((e) => e.id === id)
    return n ? displayName(model, n) : '?'
  }

  const remove = (f: ModelElement) => {
    const { threatCount } = removalImpact(model, f.id)
    const msg = `Remove data flow "${displayName(model, f)}"?${threatCount ? `\n${threatCount} threat(s) on this flow will be deleted.` : ''}`
    if (!window.confirm(msg)) return
    update((m) => removeElement(m, f.id))
    if (editing?.id === f.id) setEditing(null)
  }

  if (nodes.length < 2) {
    return (
      <div className="card stack">
        <h2>Data flows</h2>
        <p className="muted">A data flow connects two elements. Add at least two elements first.</p>
        <div>
          <button type="button" className="btn btn-primary" onClick={() => goTo('elements')}>
            ← Add elements
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="stack">
      <FlowForm
        key={editing?.id ?? 'new'}
        nodes={nodes}
        initial={editing}
        onCancel={() => setEditing(null)}
        onSave={(f) => {
          update((m) => upsertElement(m, f))
          setEditing(null)
        }}
      />
      <div className="card stack">
        <h2>Data flows ({flows.length})</h2>
        {flows.length === 0 ? (
          <p className="muted">No flows yet. Draw every path data takes, including callbacks/webhooks, admin access and logging.</p>
        ) : (
          <div className="tm-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">From → To</th>
                  <th scope="col">Protocol</th>
                  <th scope="col">Data</th>
                  <th scope="col">Trust boundary</th>
                  <th scope="col">
                    <span className="tm-sr">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {flows.map((f) => {
                  const sec = transportSecurity(f.protocol)
                  return (
                    <tr key={f.id}>
                      <td>
                        <strong>
                          {nodeName(f.fromId)} → {nodeName(f.toId)}
                        </strong>
                        {f.name && <div className="small muted">{f.name}</div>}
                      </td>
                      <td>
                        {f.protocol || <span className="muted">—</span>}{' '}
                        {sec === 'plaintext' && <span className="badge sev-high">cleartext</span>}
                        {sec === 'unknown' && f.crossesTrustBoundary && <span className="badge sev-medium">encryption?</span>}
                      </td>
                      <td>{f.dataClassification}</td>
                      <td>{f.crossesTrustBoundary ? <span className="badge sev-medium">crosses</span> : <span className="muted">no</span>}</td>
                      <td>
                        <div className="row tm-nowrap">
                          <button type="button" className="btn btn-sm" onClick={() => setEditing(f)}>
                            Edit
                          </button>
                          <button type="button" className="btn btn-sm btn-danger" onClick={() => remove(f)}>
                            Remove
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {flows.length > 0 && (
          <div className="row">
            <span className="spacer" />
            <button type="button" className="btn" onClick={() => goTo('threats')}>
              Generate threats →
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function FlowForm({
  nodes,
  initial,
  onSave,
  onCancel,
}: {
  nodes: ModelElement[]
  initial: ModelElement | null
  onSave: (f: ModelElement) => void
  onCancel: () => void
}) {
  const [fromId, setFromId] = useState(initial?.fromId ?? nodes[0]?.id ?? '')
  const [toId, setToId] = useState(initial?.toId ?? nodes[1]?.id ?? '')
  const [name, setName] = useState(initial?.name ?? '')
  const [protocol, setProtocol] = useState(initial?.protocol ?? 'HTTPS')
  const [dataClassification, setClassification] = useState<DataClassification>(initial?.dataClassification ?? 'internal')
  const [crossesTrustBoundary, setCrosses] = useState(initial?.crossesTrustBoundary ?? false)
  const [description, setDescription] = useState(initial?.description ?? '')

  const validEnds = nodes.some((n) => n.id === fromId) && nodes.some((n) => n.id === toId)
  const error = !validEnds ? 'Choose both a source and a destination.' : fromId === toId ? 'Source and destination must differ.' : ''
  const sec = transportSecurity(protocol)

  const submit = () => {
    if (error) return
    const base = initial ?? createFlow(newId(), fromId, toId)
    onSave({ ...base, fromId, toId, name: name.trim(), protocol: protocol.trim(), dataClassification, crossesTrustBoundary, description: description.trim() })
    if (!initial) {
      setName('')
      setDescription('')
    }
  }

  const option = (n: ModelElement) => (
    <option key={n.id} value={n.id}>
      {n.name || 'unnamed'} ({ELEMENT_TYPE_LABELS[n.type]})
    </option>
  )

  return (
    <form
      className="card stack"
      onSubmit={(e) => {
        e.preventDefault()
        submit()
      }}
    >
      <h2>{initial ? 'Edit data flow' : 'Add a data flow'}</h2>
      <div className="tm-form-grid">
        <label>
          From
          <select value={fromId} onChange={(e) => setFromId(e.target.value)}>
            {nodes.map(option)}
          </select>
        </label>
        <label>
          To
          <select value={toId} onChange={(e) => setToId(e.target.value)}>
            {nodes.map(option)}
          </select>
        </label>
        <label>
          Label (optional)
          <input type="text" maxLength={LIMITS.text} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Login request" />
        </label>
        <label>
          Protocol
          <input type="text" maxLength={LIMITS.text} list="tm-protocols" value={protocol} onChange={(e) => setProtocol(e.target.value)} />
          <datalist id="tm-protocols">
            {PROTOCOLS.map((p) => (
              <option key={p} value={p} />
            ))}
          </datalist>
          <span className="small muted">
            {sec === 'encrypted' ? 'Detected as encrypted.' : sec === 'plaintext' ? 'Detected as cleartext.' : 'Encryption unknown — write e.g. "PostgreSQL over TLS" if TLS is enforced.'}
          </span>
        </label>
        <label>
          Data classification
          <select value={dataClassification} onChange={(e) => setClassification(e.target.value as DataClassification)}>
            {DATA_CLASSIFICATIONS.map((c) => (
              <option key={c} value={c}>
                {c[0].toUpperCase() + c.slice(1)}
              </option>
            ))}
          </select>
          <span className="small muted">{CLASSIFICATION_HELP[dataClassification]}</span>
        </label>
        <label className="inline tm-align-end">
          <input type="checkbox" checked={crossesTrustBoundary} onChange={(e) => setCrosses(e.target.checked)} />
          Crosses a trust boundary
        </label>
      </div>
      <p className="small muted">
        A trust boundary is where the level of trust changes: internet ↔ your network, your system ↔ a vendor, user
        device ↔ server, one tenant/account ↔ another.
      </p>
      <label>
        Description (optional)
        <input type="text" maxLength={LIMITS.text} value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      {error && (
        <p className="small sev-medium" role="alert">
          {error}
        </p>
      )}
      <div className="row">
        <button type="submit" className="btn btn-primary" disabled={!!error}>
          {initial ? 'Save changes' : 'Add data flow'}
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
