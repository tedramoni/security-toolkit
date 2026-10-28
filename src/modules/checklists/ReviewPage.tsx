import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { CopyButton } from '../../lib/CopyButton'
import { downloadJSON, downloadText, slugify } from '../../lib/download'
import { getChecklist } from './data'
import { applicableItems, computeProgress, filterChecklist, getResult, orphanResultIds, progressOf, refUrl } from './logic'
import type { StatusFilter } from './logic'
import { reviewToMarkdown, safeHttpUrl } from './report'
import { reviewExport, setItemNote, setItemStatus, updateReviewMeta, upsertReview } from './review'
import { StackPicker } from './StackPicker'
import type { Checklist, ChecklistCategory, ChecklistItem, ItemStatus, Review } from './types'
import { ITEM_STATUSES, STACK_LABELS, STATUS_LABELS } from './types'
import type { ReviewsStore } from './useReviews'

const STATUS_FILTERS: { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All items' },
  { value: 'unchecked', label: 'Not reviewed' },
  { value: 'fail', label: 'Failed' },
  { value: 'pass', label: 'Passed' },
  { value: 'na', label: 'N/A' },
]

function StatusControl({ item, status, onChange }: { item: ChecklistItem; status: ItemStatus; onChange: (s: ItemStatus) => void }) {
  return (
    <fieldset className="checklists-status">
      <legend>Status of: {item.text}</legend>
      {ITEM_STATUSES.map((s) => (
        <label key={s}>
          <input
            type="radio"
            name={`status-${item.id}`}
            value={s}
            aria-label={STATUS_LABELS[s]}
            checked={status === s}
            onChange={() => onChange(s)}
          />
          <span>{s === 'unchecked' ? '–' : STATUS_LABELS[s]}</span>
        </label>
      ))}
    </fieldset>
  )
}

function ItemRow({ item, review, onStatus, onNote }: {
  item: ChecklistItem
  review: Review
  onStatus: (id: string, s: ItemStatus) => void
  onNote: (id: string, note: string) => void
}) {
  const result = getResult(review, item.id)
  const [open, setOpen] = useState(false)
  const showNote = open || result.note !== '' || result.status === 'fail'
  const detailId = `checklists-detail-${item.id}`
  return (
    <li className="checklists-item" data-status={result.status}>
      <div className="checklists-item-main">
        <div>
          <p className="checklists-item-text">{item.text}</p>
          <div className="checklists-item-refs">
            {item.level && <span className="badge sev-info">L{item.level}</span>}
            {item.stacks?.map((s) => (
              <span key={s} className="badge sev-low">{STACK_LABELS[s]}</span>
            ))}
            {item.refs?.map((ref) => {
              const url = refUrl(ref)
              return url ? (
                <a key={ref} className="checklists-ref" href={url} target="_blank" rel="noreferrer noopener">{ref}</a>
              ) : (
                <span key={ref} className="checklists-ref">{ref.startsWith('v5.0.0-') ? `ASVS ${ref}` : ref}</span>
              )
            })}
          </div>
        </div>
        <div className="row">
          <StatusControl item={item} status={result.status} onChange={(s) => onStatus(item.id, s)} />
          <button
            type="button"
            className="btn btn-sm"
            aria-expanded={open}
            aria-controls={detailId}
            onClick={() => setOpen(!open)}
          >
            {open ? 'Hide details' : 'Details'}
          </button>
        </div>
      </div>
      {open && (
        <div id={detailId} className="checklists-detail">
          <p><strong>How to check:</strong> {item.detail}</p>
        </div>
      )}
      {showNote && (
        <label className="checklists-note">
          <span className="small">Note{result.status === 'fail' ? ' (what is wrong, where, suggested fix)' : ''}</span>
          <textarea
            value={result.note}
            maxLength={5000}
            rows={2}
            onChange={(e) => onNote(item.id, e.target.value)}
          />
        </label>
      )}
    </li>
  )
}

function CategorySection({ category, scopeItems, review, expanded, onToggle, onStatus, onNote }: {
  category: ChecklistCategory
  /** Items of this category in the review's stack scope (progress ignores search/status filters). */
  scopeItems: ChecklistItem[]
  review: Review
  expanded: boolean
  onToggle: () => void
  onStatus: (id: string, s: ItemStatus) => void
  onNote: (id: string, note: string) => void
}) {
  const p = progressOf(scopeItems, review)
  const bodyId = `checklists-cat-${category.id}`
  return (
    <section className="card checklists-category" aria-labelledby={`${bodyId}-title`}>
      {/* Heading wraps the button (not the reverse): headings inside a button lose their semantics. */}
      <h2 className="checklists-category-heading" id={`${bodyId}-title`}>
        <button type="button" className="checklists-category-head" aria-expanded={expanded} aria-controls={bodyId} onClick={onToggle}>
          <span className="checklists-chevron" aria-hidden="true">▸</span>
          <span className="checklists-category-title">{category.title}</span>
          <span className="small muted">{p.answered}/{p.total}</span>
          {p.fail > 0 && <span className="badge sev-critical">{p.fail} fail</span>}
        </button>
      </h2>
      {expanded && (
        <div id={bodyId} className="checklists-category-body">
          <p className="checklists-category-desc small muted">{category.description}</p>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {category.items.map((item) => (
              <ItemRow key={item.id} item={item} review={review} onStatus={onStatus} onNote={onNote} />
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}

function ReviewEditor({ review, checklist, store }: { review: Review; checklist: Checklist; store: ReviewsStore }) {
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})
  const [showPreview, setShowPreview] = useState(false)
  const [editingMeta, setEditingMeta] = useState(false)

  const save = (fn: (r: Review) => Review) =>
    store.update((list) => {
      const current = list.find((r) => r.id === review.id)
      return current ? upsertReview(list, fn(current)) : list
    })

  const progress = computeProgress(checklist, review)
  const scopeByCategory = new Map<string, ChecklistItem[]>()
  for (const { category, item } of applicableItems(checklist, review.stacks)) {
    scopeByCategory.set(category.id, [...(scopeByCategory.get(category.id) ?? []), item])
  }
  const visible = filterChecklist(checklist, review, { stacks: review.stacks, query, status: statusFilter })
  const visibleCount = visible.reduce((n, c) => n + c.items.length, 0)
  const markdown = useMemo(() => reviewToMarkdown(review, checklist), [review, checklist])
  const orphans = orphanResultIds(checklist, review)
  const versionChanged = review.checklistVersion !== '' && review.checklistVersion !== checklist.version
  const filtering = query.trim() !== '' || statusFilter !== 'all'
  const link = safeHttpUrl(review.link)
  const fileBase = `review-${slugify(review.name)}`

  const onStatus = (id: string, s: ItemStatus) => save((r) => setItemStatus(r, id, s))
  const onNote = (id: string, note: string) => save((r) => setItemNote(r, id, note))
  const setAll = (value: boolean) =>
    setCollapsed(Object.fromEntries(checklist.categories.map((c) => [c.id, value])))

  return (
    <>
      <header className="page-header">
        <p className="small"><Link to="..">← All checklists and reviews</Link></p>
        <div className="checklists-review-title">
          <h1 style={{ margin: 0 }}>{review.name}</h1>
          <button type="button" className="btn btn-sm" aria-expanded={editingMeta} onClick={() => setEditingMeta(!editingMeta)}>
            {editingMeta ? 'Done editing' : 'Edit name, link & scope'}
          </button>
        </div>
        <p>
          {checklist.title}
          {link && (
            <>
              {' · '}
              <a href={link} target="_blank" rel="noreferrer noopener">{review.link}</a>
            </>
          )}
          {!link && review.link && <> · {review.link}</>}
          {review.stacks.length > 0 && <> · Scope: {review.stacks.map((s) => STACK_LABELS[s]).join(', ')}</>}
        </p>
      </header>

      {editingMeta && (
        <div className="card stack">
          <label>
            Review name
            <input type="text" defaultValue={review.name} maxLength={200} onBlur={(e) => {
                // An empty name is rejected by updateReviewMeta: restore the field so it shows what is saved.
                if (e.target.value.trim() === '') e.target.value = review.name
                else if (e.target.value !== review.name) save((r) => updateReviewMeta(r, { name: e.target.value }))
              }}
            />
          </label>
          <label>
            Link
            <input type="text" inputMode="url" defaultValue={review.link} maxLength={2000} onBlur={(e) => {
                if (e.target.value !== review.link) save((r) => updateReviewMeta(r, { link: e.target.value }))
              }}
            />
          </label>
          <StackPicker value={review.stacks} onChange={(stacks) => save((r) => updateReviewMeta(r, { stacks }))} />
        </div>
      )}

      {(orphans.length > 0 || versionChanged) && (
        <div className="callout warn" style={{ margin: '1rem 0' }}>
          {versionChanged &&
            `This review was created with checklist version ${review.checklistVersion}; the current version is ${checklist.version}.`}
          {orphans.length > 0 &&
            ` ${orphans.length} saved answer(s) refer to items that no longer exist in this checklist and are ignored.`}
        </div>
      )}

      <div className="card checklists-summary" style={{ marginTop: '1rem' }}>
        <div className="row">
          <strong>{progress.answered}/{progress.total} reviewed ({progress.percent}%)</strong>
          <span className="spacer" />
          <div className="checklists-counts" aria-label="Result counts">
            <span className={`badge ${progress.fail > 0 ? 'sev-critical' : 'sev-info'}`}>{progress.fail} fail</span>
            <span className="badge sev-pass">{progress.pass} pass</span>
            <span className="badge sev-info">{progress.na} N/A</span>
            <span className="badge sev-medium">{progress.unchecked} to review</span>
          </div>
        </div>
        <div className="progress" role="progressbar" aria-label="Review progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress.percent}>
          <span style={{ width: `${progress.percent}%` }} />
        </div>
        <div className="row">
          <CopyButton text={markdown} label="Copy as PR comment" />
          <button type="button" className="btn" onClick={() => downloadText(`${fileBase}.md`, markdown, 'text/markdown')}>
            Download Markdown
          </button>
          <button type="button" className="btn" onClick={() => downloadJSON(`${fileBase}.json`, reviewExport(review, checklist))}>
            Export JSON
          </button>
          <button type="button" className="btn" aria-expanded={showPreview} onClick={() => setShowPreview(!showPreview)}>
            {showPreview ? 'Hide preview' : 'Preview Markdown'}
          </button>
        </div>
        {showPreview && (
          <pre className="codeblock checklists-preview" aria-label="Markdown preview">{markdown}</pre>
        )}
      </div>

      <div className="checklists-toolbar" style={{ margin: '1rem 0' }}>
        <label>
          Search items
          <input
            type="search"
            value={query}
            placeholder="e.g. CORS, CWE-89, token…"
            onChange={(e) => {
              setQuery(e.target.value)
              setCollapsed({})
            }}
          />
        </label>
        <div className="row">
          <label>
            Show
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value as StatusFilter)
                setCollapsed({})
              }}
            >
              {STATUS_FILTERS.map((f) => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
          </label>
          <button type="button" className="btn btn-sm" onClick={() => setAll(false)} style={{ alignSelf: 'end' }}>Expand all</button>
          <button type="button" className="btn btn-sm" onClick={() => setAll(true)} style={{ alignSelf: 'end' }}>Collapse all</button>
        </div>
      </div>

      {filtering && (
        <p className="small muted" role="status">
          {visibleCount} matching item{visibleCount === 1 ? '' : 's'}
        </p>
      )}

      {visible.length === 0 ? (
        <p className="muted">No items match the current filters.</p>
      ) : (
        <div className="stack">
          {visible.map((cat) => (
            <CategorySection
              key={cat.id}
              category={cat}
              scopeItems={scopeByCategory.get(cat.id) ?? []}
              review={review}
              expanded={!collapsed[cat.id]}
              onToggle={() => setCollapsed((c) => ({ ...c, [cat.id]: !c[cat.id] }))}
              onStatus={onStatus}
              onNote={onNote}
            />
          ))}
        </div>
      )}
    </>
  )
}

export function ReviewPage({ store }: { store: ReviewsStore }) {
  const { id } = useParams()
  const review = store.reviews.find((r) => r.id === id)
  const checklist = review ? getChecklist(review.checklistId) : undefined

  if (!review || !checklist) {
    return (
      <>
        <header className="page-header">
          <h1>Review not found</h1>
          <p>{review ? `This review uses an unknown checklist (“${review.checklistId}”).` : 'It may have been deleted, or it was saved in another browser.'}</p>
        </header>
        <Link to=".." className="btn">Back to checklists</Link>
      </>
    )
  }
  return <ReviewEditor key={review.id} review={review} checklist={checklist} store={store} />
}
