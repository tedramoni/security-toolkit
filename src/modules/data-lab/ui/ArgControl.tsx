import { useId, useState } from 'react'
import type { ArgDef, ArgValue, ToggleEncoding, ToggleValue } from '../engine/types'
import { TOGGLE_ENCODING_LABELS, TOGGLE_ENCODINGS } from '../engine/types'

interface Props {
  def: ArgDef
  value: ArgValue
  onChange(v: ArgValue): void
}

/** Number field that lets the user type freely and only commits valid, in-range values. */
function NumberField({ def, value, onChange, id }: { def: Extract<ArgDef, { type: 'number' }>; value: number; onChange(v: number): void; id: string }) {
  const [text, setText] = useState(String(value))
  // Re-sync the draft when the value changes from outside (e.g. step moved or recipe loaded).
  const [synced, setSynced] = useState(value)
  if (synced !== value) {
    setSynced(value)
    setText(String(value))
  }
  const commit = (t: string) => {
    const n = Number(t)
    if (t.trim() === '' || !Number.isFinite(n)) return
    let v = def.integer ? Math.trunc(n) : n
    if (def.min !== undefined) v = Math.max(def.min, v)
    if (def.max !== undefined) v = Math.min(def.max, v)
    onChange(v)
  }
  return (
    <input
      id={id}
      type="number"
      value={text}
      min={def.min}
      max={def.max}
      step={def.integer ? 1 : 'any'}
      onChange={(e) => {
        setText(e.target.value)
        const n = Number(e.target.value)
        if (e.target.value.trim() !== '' && Number.isFinite(n) && (def.min === undefined || n >= def.min) && (def.max === undefined || n <= def.max)) {
          commit(e.target.value)
        }
      }}
      onBlur={() => {
        commit(text)
        setText(String(value))
      }}
    />
  )
}

export function ArgControl({ def, value, onChange }: Props) {
  const id = useId()
  const hint = def.hint ? <span className="small muted">{def.hint}</span> : null
  switch (def.type) {
    case 'boolean':
      return (
        <label className="inline data-lab-arg data-lab-arg-bool">
          <input type="checkbox" checked={value === true} onChange={(e) => onChange(e.target.checked)} />
          {def.label}
        </label>
      )
    case 'select':
      return (
        <label className="data-lab-arg" htmlFor={id}>
          {def.label}
          <select id={id} value={String(value)} onChange={(e) => onChange(e.target.value)}>
            {def.options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          {hint}
        </label>
      )
    case 'number':
      return (
        <label className="data-lab-arg" htmlFor={id}>
          {def.label}
          <NumberField def={def} value={typeof value === 'number' ? value : def.default} onChange={onChange} id={id} />
          {hint}
        </label>
      )
    case 'string':
      return (
        <label className="data-lab-arg" htmlFor={id}>
          {def.label}
          <input
            id={id}
            type="text"
            value={typeof value === 'string' ? value : ''}
            maxLength={def.maxLength ?? 4096}
            placeholder={def.placeholder}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => onChange(e.target.value)}
          />
          {hint}
        </label>
      )
    case 'toggleString': {
      const tv: ToggleValue = typeof value === 'object' ? value : def.default
      return (
        <div className="data-lab-arg">
          <label htmlFor={id}>{def.label}</label>
          <div className="data-lab-toggle">
            <input
              id={id}
              type="text"
              className="mono"
              value={tv.value}
              maxLength={4096}
              spellCheck={false}
              autoComplete="off"
              onChange={(e) => onChange({ ...tv, value: e.target.value })}
            />
            <select aria-label={`${def.label} encoding`} value={tv.encoding} onChange={(e) => onChange({ ...tv, encoding: e.target.value as ToggleEncoding })}>
              {TOGGLE_ENCODINGS.map((enc) => (
                <option key={enc} value={enc}>
                  {TOGGLE_ENCODING_LABELS[enc]}
                </option>
              ))}
            </select>
          </div>
          {hint}
        </div>
      )
    }
  }
}
