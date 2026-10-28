import { useId, useMemo, useState } from 'react'
import { ALL_RULES } from './rules'
import type { Category } from './types'
import { CATEGORIES, sevRank } from './types'
import { SevBadge } from './VisibleText'

export function RulesTab({ disabled, onChange }: { disabled: ReadonlySet<string>; onChange: (next: string[]) => void }) {
  const [q, setQ] = useState('')
  const searchId = useId()
  const grouped = useMemo(() => {
    const query = q.trim().toLowerCase()
    const m = new Map<Category, typeof ALL_RULES>()
    for (const r of ALL_RULES) {
      if (query && !`${r.id} ${r.title} ${r.description}`.toLowerCase().includes(query)) continue
      m.set(r.category, [...(m.get(r.category) ?? []), r])
    }
    return [...m.entries()].map(([c, list]) => [c, [...list].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id))] as const)
  }, [q])

  const toggle = (id: string, on: boolean) => {
    const next = new Set(disabled)
    if (on) next.delete(id)
    else next.add(id)
    onChange([...next])
  }

  return (
    <div className="stack">
      <p className="muted">
        {ALL_RULES.length} rules ({ALL_RULES.length - disabled.size} enabled). Disabled rules are skipped on the next scan; your choice is saved in this browser.
      </p>
      <div className="row">
        <label htmlFor={searchId} className="sr-only">
          Search rules
        </label>
        <input id={searchId} type="search" placeholder="Search rules…" value={q} onChange={(e) => setQ(e.target.value)} className="skill-scanner-search" />
        <button type="button" className="btn btn-sm" onClick={() => onChange([])} disabled={disabled.size === 0}>
          Enable all
        </button>
      </div>
      {grouped.map(([cat, rules]) => (
        <section key={cat} className="card">
          <h3>
            {CATEGORIES[cat].label}{' '}
            <a className="small" href={CATEGORIES[cat].ref} target="_blank" rel="noopener noreferrer">
              reference
            </a>
          </h3>
          <table className="table">
            <thead>
              <tr>
                <th>On</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>What it detects / fix</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td>
                    <input type="checkbox" aria-label={`Enable ${r.id} ${r.title}`} checked={!disabled.has(r.id)} onChange={(e) => toggle(r.id, e.target.checked)} />
                  </td>
                  <td>
                    <div className="mono small">{r.id}</div>
                    <strong>{r.title}</strong>
                  </td>
                  <td>
                    <SevBadge severity={r.severity} />
                  </td>
                  <td className="small">
                    <div>{r.description}</div>
                    <div className="muted">Fix: {r.remediation}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
    </div>
  )
}
