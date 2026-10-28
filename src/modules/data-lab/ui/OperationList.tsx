import { useId, useMemo, useState } from 'react'
import type { OpDef } from '../engine/types'
import { CATEGORIES } from '../engine/types'
import { OPERATIONS } from '../ops'

interface Props {
  onAdd(op: OpDef): void
}

function matches(op: OpDef, q: string): boolean {
  const s = q.toLowerCase()
  return op.name.toLowerCase().includes(s) || op.id.includes(s) || op.description.toLowerCase().includes(s) || op.category.toLowerCase().includes(s)
}

export function OperationList({ onAdd }: Props) {
  const [query, setQuery] = useState('')
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(() => new Set())
  const searchId = useId()
  const q = query.trim()
  const filtered = useMemo(() => (q ? OPERATIONS.filter((o) => matches(o, q)) : OPERATIONS), [q])
  // Name matches first when searching.
  const ranked = useMemo(
    () => (q ? [...filtered].sort((a, b) => Number(!a.name.toLowerCase().includes(q.toLowerCase())) - Number(!b.name.toLowerCase().includes(q.toLowerCase()))) : filtered),
    [filtered, q],
  )

  const toggle = (cat: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(cat)) next.delete(cat)
      else next.add(cat)
      return next
    })

  const opButton = (op: OpDef, showDesc: boolean) => (
    <li key={op.id}>
      <button type="button" className="data-lab-op" title={op.description} onClick={() => onAdd(op)}>
        <span className="data-lab-op-name">{op.name}</span>
        {showDesc && <span className="data-lab-op-desc">{op.description}</span>}
      </button>
    </li>
  )

  return (
    <nav className="data-lab-ops card" aria-label="Operations">
      <label htmlFor={searchId} className="sr-only">
        Search operations
      </label>
      <input
        id={searchId}
        type="search"
        placeholder={`Search ${OPERATIONS.length} operations…`}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && ranked.length > 0) {
            e.preventDefault()
            onAdd(ranked[0])
          }
        }}
        aria-describedby={`${searchId}-hint`}
      />
      <p id={`${searchId}-hint`} className="small muted data-lab-ops-hint">
        Click or press Enter to add to the recipe.
      </p>
      {q ? (
        <>
          <p className="small muted" role="status">
            {ranked.length} match{ranked.length === 1 ? '' : 'es'}
          </p>
          <ul className="data-lab-op-list">{ranked.map((op) => opButton(op, true))}</ul>
        </>
      ) : (
        CATEGORIES.map((cat) => {
          const ops = filtered.filter((o) => o.category === cat)
          if (!ops.length) return null
          const open = !collapsed.has(cat)
          const listId = `${searchId}-${cat.replace(/\W+/g, '-')}`
          return (
            <section key={cat} className="data-lab-cat">
              <h3>
                <button type="button" className="data-lab-cat-toggle" aria-expanded={open} aria-controls={listId} onClick={() => toggle(cat)}>
                  <span aria-hidden="true">{open ? '▾' : '▸'}</span> {cat} <span className="muted small">({ops.length})</span>
                </button>
              </h3>
              <ul id={listId} className="data-lab-op-list" hidden={!open}>
                {ops.map((op) => opButton(op, false))}
              </ul>
            </section>
          )
        })
      )}
      <p className="small muted data-lab-ops-note">
        Not included: DES/3DES, Blowfish and RC4. They are legacy or broken, and browsers don&apos;t provide them.
      </p>
    </nav>
  )
}
