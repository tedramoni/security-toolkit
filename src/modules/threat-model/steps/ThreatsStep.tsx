import { Fragment, useMemo, useState } from 'react'
import { newId } from '../../../lib/storage.ts'
import type { StrideCategory, Threat, ThreatStatus } from '../model.ts'
import {
  displayName,
  ELEMENT_TYPE_LABELS,
  LIMITS,
  STATUS_LABELS,
  STRIDE_NAMES,
  STRIDE_PROPERTY,
  THREAT_STATUSES,
  updateThreat,
} from '../model.ts'
import type { RiskLevel } from '../risk.ts'
import { IMPACT_LABELS, LIKELIHOOD_LABELS, RISK_LABELS, RISK_LEVELS, riskClass, riskOf, riskScore } from '../risk.ts'
import type { MergeStats } from '../stride.ts'
import { applicableCategories, refreshThreats, removeStaleThreats, suggestedMitigationText } from '../stride.ts'
import type { ThreatFilter } from '../view.ts'
import { DEFAULT_FILTER, groupThreats, matchesFilter } from '../view.ts'
import type { StepProps, UpdateModel } from '../Wizard.tsx'

export function ThreatsStep({ model, update, goTo }: StepProps) {
  const [groupBy, setGroupBy] = useState<'element' | 'category'>('element')
  const [filter, setFilter] = useState<ThreatFilter>(DEFAULT_FILTER)
  const [stats, setStats] = useState<MergeStats | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  const visible = useMemo(() => model.threats.filter((t) => matchesFilter(t, filter)), [model.threats, filter])
  const groups = useMemo(() => groupThreats(model, visible, groupBy), [model, visible, groupBy])
  const staleCount = model.threats.filter((t) => t.stale).length
  const hasElements = model.elements.length > 0

  const regenerate = () => {
    // Compute stats from the current model, then apply the same pure transformation in the updater.
    setStats(refreshThreats(model, () => 'preview').stats)
    update((m) => refreshThreats(m, newId).model)
  }

  return (
    <div className="stack">
      <div className="card stack">
        <div className="row">
          <h2 className="tm-flush">Threats ({model.threats.length})</h2>
          <span className="spacer" />
          <button type="button" className="btn btn-primary" onClick={regenerate} disabled={!hasElements}>
            {model.threats.some((t) => t.generated) ? 'Refresh generated threats' : 'Generate threats'}
          </button>
        </div>
        <p className="small muted">
          Threats are generated per element with STRIDE (external entities: S R · processes: S T R I D E · data stores: T
          I D, plus R for log stores · data flows: T I D) and refined by tags, protocol, data classification and trust
          boundaries. Refreshing is safe: your status, mitigation, likelihood, impact, owner and ticket are kept; threats
          that no longer apply are flagged <span className="badge sev-info">stale</span>, never deleted.
        </p>
        {!hasElements && (
          <div className="callout warn">
            Add elements and data flows first.{' '}
            <button type="button" className="btn btn-sm" onClick={() => goTo('elements')}>
              Go to elements
            </button>
          </div>
        )}
        {stats && (
          <div className="callout" role="status">
            {stats.added} added · {stats.refreshed} wording updated · {stats.unchanged} unchanged · {stats.revived} back from stale ·{' '}
            {stats.newlyStale} newly stale
          </div>
        )}
        {staleCount > 0 && (
          <div className="callout warn row">
            <span>
              {staleCount} stale threat{staleCount > 1 ? 's' : ''}: their rule no longer matches the model (e.g. the
              protocol was changed to HTTPS). Review them, then remove.
            </span>
            <span className="spacer" />
            <button
              type="button"
              className="btn btn-sm btn-danger"
              onClick={() => {
                if (window.confirm(`Delete ${staleCount} stale threat(s)?`)) update(removeStaleThreats)
              }}
            >
              Remove stale threats
            </button>
          </div>
        )}
      </div>

      {model.threats.length > 0 && (
        <div className="card stack">
          <div className="tm-filters">
            <div role="group" aria-label="Group threats by" className="row">
              <span className="small muted">Group by</span>
              {(['element', 'category'] as const).map((g) => (
                <button key={g} type="button" className="btn btn-sm" aria-pressed={groupBy === g} onClick={() => setGroupBy(g)}>
                  {g === 'element' ? 'Element' : 'STRIDE category'}
                </button>
              ))}
            </div>
            <label>
              Status
              <select value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value as ThreatFilter['status'] })}>
                <option value="all">All</option>
                {THREAT_STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {STATUS_LABELS[s]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Risk
              <select value={filter.risk} onChange={(e) => setFilter({ ...filter, risk: e.target.value as ThreatFilter['risk'] })}>
                <option value="all">All</option>
                <option value="high+">High and critical</option>
                {[...RISK_LEVELS].reverse().map((r) => (
                  <option key={r} value={r}>
                    {RISK_LABELS[r]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Search
              <input type="search" value={filter.text} onChange={(e) => setFilter({ ...filter, text: e.target.value })} />
            </label>
            <label className="inline tm-align-end">
              <input type="checkbox" checked={filter.includeStale} onChange={(e) => setFilter({ ...filter, includeStale: e.target.checked })} />
              Show stale
            </label>
          </div>
          <p className="small muted" aria-live="polite">
            Showing {visible.length} of {model.threats.length}
          </p>

          {groups.map((g) => (
            <section key={g.key} className="stack">
              <h3 className="tm-flush">
                {g.title} {g.subtitle && <span className="small muted">({g.subtitle})</span>}
              </h3>
              <div className="tm-scroll">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Risk</th>
                      <th scope="col">STRIDE</th>
                      <th scope="col">Threat</th>
                      <th scope="col">Status</th>
                      <th scope="col">
                        <span className="tm-sr">Details</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {g.threats.map((t) => (
                      <Fragment key={t.id}>
                        <ThreatRow
                          threat={t}
                          elementLabel={groupBy === 'category' ? elementName(t.elementId) : ''}
                          expanded={expanded === t.id}
                          onToggle={() => setExpanded(expanded === t.id ? null : t.id)}
                          update={update}
                        />
                        {expanded === t.id && (
                          <tr className="tm-detail">
                            <td colSpan={5}>
                              <ThreatEditor threat={t} update={update} onDone={() => setExpanded(null)} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ))}
          {groups.length === 0 && <p className="muted">No threats match the filters.</p>}
        </div>
      )}

      {hasElements && <ManualThreatForm model={model} update={update} />}
    </div>
  )

  function elementName(id: string): string {
    const el = model.elements.find((e) => e.id === id)
    return el ? displayName(model, el) : '?'
  }
}

function RiskBadge({ t }: { t: Pick<Threat, 'likelihood' | 'impact'> }) {
  const level: RiskLevel = riskOf(t)
  return (
    <span className={`badge ${riskClass(level)}`} title={`Likelihood ${t.likelihood} × impact ${t.impact}`}>
      {RISK_LABELS[level]} {riskScore(t.likelihood, t.impact)}
    </span>
  )
}

function ThreatRow({
  threat: t,
  elementLabel,
  expanded,
  onToggle,
  update,
}: {
  threat: Threat
  elementLabel: string
  expanded: boolean
  onToggle: () => void
  update: UpdateModel
}) {
  return (
    <tr className={t.stale ? 'tm-stale' : undefined}>
      <td>
        <RiskBadge t={t} />
      </td>
      <td title={STRIDE_NAMES[t.category]} className="mono">
        {t.category}
      </td>
      <td>
        {elementLabel && <div className="small muted">{elementLabel}</div>}
        {t.title}{' '}
        {t.stale && <span className="badge sev-info">stale</span>}
        {!t.generated && <span className="badge sev-info">manual</span>}
        {(t.owner || t.ticket) && <div className="small muted">{[t.owner, t.ticket].filter(Boolean).join(' · ')}</div>}
      </td>
      <td>
        <select
          aria-label={`Status of "${t.title}"`}
          value={t.status}
          onChange={(e) => update((m) => updateThreat(m, t.id, { status: e.target.value as ThreatStatus }))}
        >
          {THREAT_STATUSES.map((s) => (
            <option key={s} value={s}>
              {STATUS_LABELS[s]}
            </option>
          ))}
        </select>
      </td>
      <td>
        <button type="button" className="btn btn-sm" aria-expanded={expanded} onClick={onToggle}>
          {expanded ? 'Close' : 'Details'}
        </button>
      </td>
    </tr>
  )
}

function ScoreSelect({ label, value, labels, onChange }: { label: string; value: number; labels: Record<number, string>; onChange: (n: number) => void }) {
  return (
    <label>
      {label}
      <select value={value} onChange={(e) => onChange(Number(e.target.value))}>
        {[1, 2, 3].map((n) => (
          <option key={n} value={n}>
            {labels[n]}
          </option>
        ))}
      </select>
    </label>
  )
}

function ThreatEditor({ threat: t, update, onDone }: { threat: Threat; update: UpdateModel; onDone: () => void }) {
  const set = (patch: Partial<Threat>) => update((m) => updateThreat(m, t.id, patch))
  const suggestions = t.suggestedMitigations ?? []
  return (
    <div className="stack">
      {t.stale && (
        <div className="callout warn small">
          This generated threat no longer matches the model (rule {t.ruleId}). Keep it if it is still relevant, otherwise
          delete it.
        </div>
      )}
      {t.generated ? (
        <p className="tm-prose-text">{t.description}</p>
      ) : (
        <>
          <label>
            Title
            <input type="text" maxLength={LIMITS.text} value={t.title} onChange={(e) => set({ title: e.target.value })} />
          </label>
          <label>
            Description
            <textarea maxLength={LIMITS.text} className="tm-prose tm-short" value={t.description} onChange={(e) => set({ description: e.target.value })} />
          </label>
        </>
      )}
      <p className="small muted">
        {STRIDE_NAMES[t.category]} violates <strong>{STRIDE_PROPERTY[t.category]}</strong>
        {t.ruleId && <> · rule {t.ruleId}</>}
      </p>
      {suggestions.length > 0 && (
        <div className="stack tm-suggestions">
          <strong className="small">Suggested mitigations</strong>
          <ul className="small">
            {suggestions.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
        </div>
      )}
      <label>
        Mitigation / decision rationale
        <textarea maxLength={LIMITS.text} className="tm-prose tm-short" value={t.mitigation} onChange={(e) => set({ mitigation: e.target.value })} />
      </label>
      {suggestions.length > 0 && (
        <div className="row">
          <button type="button" className="btn btn-sm" onClick={() => set({ mitigation: suggestedMitigationText(suggestions) })}>
            Reset to suggested mitigations
          </button>
        </div>
      )}
      <div className="tm-form-grid">
        <ScoreSelect label="Likelihood" value={t.likelihood} labels={LIKELIHOOD_LABELS} onChange={(n) => set({ likelihood: n })} />
        <ScoreSelect label="Impact" value={t.impact} labels={IMPACT_LABELS} onChange={(n) => set({ impact: n })} />
        <label>
          Owner
          <input type="text" maxLength={LIMITS.text} value={t.owner ?? ''} onChange={(e) => set({ owner: e.target.value })} />
        </label>
        <label>
          Ticket / link
          <input type="text" maxLength={LIMITS.text} value={t.ticket ?? ''} onChange={(e) => set({ ticket: e.target.value })} placeholder="e.g. SEC-123" />
        </label>
      </div>
      {t.references && t.references.length > 0 && (
        <div className="small">
          <span className="muted">References: </span>
          {t.references.map((r, i) => (
            <Fragment key={r}>
              {i > 0 && ' · '}
              <SafeLink href={r} />
            </Fragment>
          ))}
        </div>
      )}
      <div className="row">
        <span className="small muted">Current risk:</span>
        <RiskBadge t={t} />
        <span className="spacer" />
        <button
          type="button"
          className="btn btn-sm btn-danger"
          onClick={() => {
            const note = t.generated && !t.stale ? '\nIt will come back on the next refresh — prefer status "Not applicable".' : ''
            if (window.confirm(`Delete threat "${t.title}"?${note}`)) update((m) => ({ ...m, threats: m.threats.filter((x) => x.id !== t.id) }))
          }}
        >
          Delete threat
        </button>
        <button type="button" className="btn btn-sm" onClick={onDone}>
          Close
        </button>
      </div>
    </div>
  )
}

/** References may come from imported JSON: only render http(s) URLs as links. */
function SafeLink({ href }: { href: string }) {
  let ok = false
  try {
    const u = new URL(href)
    ok = u.protocol === 'https:' || u.protocol === 'http:'
  } catch {
    ok = false
  }
  if (!ok) return <span className="mono">{href}</span>
  const label = href.replace(/^https?:\/\//, '').replace(/\.html$/, '')
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {label}
    </a>
  )
}

function ManualThreatForm({ model, update }: Pick<StepProps, 'model' | 'update'>) {
  const [elementId, setElementId] = useState(model.elements[0]?.id ?? '')
  // Fall back to the first element if the selected one was removed meanwhile.
  const element = model.elements.find((e) => e.id === elementId) ?? model.elements[0]
  const categories = element ? applicableCategories(element) : []
  const [category, setCategory] = useState<StrideCategory>('S')
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [likelihood, setLikelihood] = useState(2)
  const [impact, setImpact] = useState(2)
  const effectiveCategory = categories.includes(category) ? category : (categories[0] ?? 'S')

  return (
    <details className="card">
      <summary className="tm-summary">Add a manual threat</summary>
      <form
        className="stack tm-mt"
        onSubmit={(e) => {
          e.preventDefault()
          if (!element || !title.trim()) return
          const threat: Threat = {
            id: newId(),
            elementId: element.id,
            category: effectiveCategory,
            title: title.trim(),
            description: description.trim(),
            likelihood,
            impact,
            status: 'open',
            mitigation: '',
            generated: false,
          }
          update((m) => ({ ...m, threats: [...m.threats, threat] }))
          setTitle('')
          setDescription('')
        }}
      >
        <p className="small muted">
          Generated rules cover common patterns; add what is specific to your business logic (e.g. "a seller can refund
          an order of another shop", "coupon codes can be stacked").
        </p>
        <div className="tm-form-grid">
          <label>
            Element
            <select value={element?.id ?? ''} onChange={(e) => setElementId(e.target.value)}>
              {model.elements.map((el) => (
                <option key={el.id} value={el.id}>
                  {displayName(model, el)} ({ELEMENT_TYPE_LABELS[el.type]})
                </option>
              ))}
            </select>
          </label>
          <label>
            STRIDE category (applicable to this element)
            <select value={effectiveCategory} onChange={(e) => setCategory(e.target.value as StrideCategory)}>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c} — {STRIDE_NAMES[c]}
                </option>
              ))}
            </select>
          </label>
          <ScoreSelect label="Likelihood" value={likelihood} labels={LIKELIHOOD_LABELS} onChange={setLikelihood} />
          <ScoreSelect label="Impact" value={impact} labels={IMPACT_LABELS} onChange={setImpact} />
        </div>
        <label>
          Title
          <input type="text" maxLength={LIMITS.text} value={title} onChange={(e) => setTitle(e.target.value)} required />
        </label>
        <label>
          Description — who is the attacker, what do they do, what is the consequence?
          <textarea maxLength={LIMITS.text} className="tm-prose tm-short" value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <div className="row">
          <button type="submit" className="btn btn-primary" disabled={!element || !title.trim()}>
            Add threat
          </button>
          <RiskBadge t={{ likelihood, impact }} />
        </div>
      </form>
    </details>
  )
}
