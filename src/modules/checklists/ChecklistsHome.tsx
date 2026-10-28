import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { downloadJSON, readFileText, slugify } from '../../lib/download'
import { newId } from '../../lib/storage'
import { CHECKLISTS, getChecklist } from './data'
import { computeProgress } from './logic'
import {
  createReview,
  defaultReviewName,
  duplicateReview,
  importReview,
  removeReview,
  renameReview,
  reviewExport,
  sortReviews,
  upsertReview,
} from './review'
import { StackPicker } from './StackPicker'
import type { Checklist, Review, Stack } from './types'
import type { ReviewsStore } from './useReviews'

function itemCount(c: Checklist): number {
  return c.categories.reduce((n, cat) => n + cat.items.length, 0)
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function NewReviewForm({ checklist, onCreate, onCancel }: {
  checklist: Checklist
  onCreate: (r: Review) => void
  onCancel: () => void
}) {
  const [name, setName] = useState('')
  const [link, setLink] = useState('')
  const [stacks, setStacks] = useState<Stack[]>([])
  const submit = (e: FormEvent) => {
    e.preventDefault()
    onCreate(createReview({ name, link, checklist, stacks }, { id: newId() }))
  }
  return (
    <form className="card stack" onSubmit={submit} aria-label={`New review with ${checklist.title}`}>
      <h2>New review — {checklist.title}</h2>
      <label>
        Review name
        <input
          type="text"
          value={name}
          autoFocus
          maxLength={200}
          placeholder={`e.g. PR #123 — payment API (default: ${defaultReviewName(checklist)})`}
          onChange={(e) => setName(e.target.value)}
        />
      </label>
      <label>
        Link (optional — PR, ticket, design doc)
        <input type="text" inputMode="url" value={link} maxLength={2000} placeholder="https://github.com/org/repo/pull/123" onChange={(e) => setLink(e.target.value)} />
      </label>
      <StackPicker value={stacks} onChange={setStacks} />
      <div className="row">
        <button type="submit" className="btn btn-primary">Start review</button>
        <button type="button" className="btn" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  )
}

function SavedReviewRow({ review, store }: { review: Review; store: ReviewsStore }) {
  const navigate = useNavigate()
  const [renaming, setRenaming] = useState(false)
  const [draft, setDraft] = useState(review.name)
  const checklist = getChecklist(review.checklistId)
  const progress = checklist ? computeProgress(checklist, review) : null

  const commitRename = () => {
    // Apply to the latest stored copy (another tab may have changed results since this row rendered).
    store.update((list) => list.map((r) => (r.id === review.id ? renameReview(r, draft) : r)))
    setRenaming(false)
  }

  return (
    <tr>
      <td>
        {renaming ? (
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault()
              commitRename()
            }}
          >
            <label className="spacer">
              <span className="small">New name</span>
              <input
                type="text"
                value={draft}
                maxLength={200}
                autoFocus
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Escape') setRenaming(false)
                }}
              />
            </label>
            <button type="submit" className="btn btn-sm btn-primary">Save</button>
            <button type="button" className="btn btn-sm" onClick={() => setRenaming(false)}>Cancel</button>
          </form>
        ) : (
          <>
            <Link to={`review/${encodeURIComponent(review.id)}`}>{review.name}</Link>
            {review.link && <div className="small muted">{review.link}</div>}
          </>
        )}
      </td>
      <td className="small">{checklist?.title ?? <span className="sev-high">Unknown checklist</span>}</td>
      <td className="checklists-progress-cell">
        {progress && (
          <>
            <div
              className="progress"
              role="progressbar"
              aria-label={`Progress of ${review.name}`}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={progress.percent}
            >
              <span style={{ width: `${progress.percent}%` }} />
            </div>
            <div className="small muted">
              {progress.answered}/{progress.total}
              {progress.fail > 0 && (
                <>
                  {' '}· <span className="badge sev-critical">{progress.fail} fail</span>
                </>
              )}
            </div>
          </>
        )}
      </td>
      <td className="small muted">{formatDate(review.updatedAt)}</td>
      <td>
        <div className="row">
          <button type="button" className="btn btn-sm" onClick={() => navigate(`review/${encodeURIComponent(review.id)}`)}>
            Open
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              setDraft(review.name)
              setRenaming(true)
            }}
          >
            Rename
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              const id = newId()
              store.update((list) => {
                const current = list.find((r) => r.id === review.id)
                return current ? upsertReview(list, duplicateReview(current, { id })) : list
              })
            }}
          >
            Duplicate
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => downloadJSON(`review-${slugify(review.name)}.json`, reviewExport(review, checklist))}
          >
            Export JSON
          </button>
          <button
            type="button"
            className="btn btn-sm btn-danger"
            onClick={() => {
              if (window.confirm(`Delete review "${review.name}"? This cannot be undone.`)) {
                store.update((list) => removeReview(list, review.id))
              }
            }}
          >
            Delete
          </button>
        </div>
      </td>
    </tr>
  )
}

export function ChecklistsHome({ store }: { store: ReviewsStore }) {
  const navigate = useNavigate()
  const [selected, setSelected] = useState<string | null>(null)
  const [importMsg, setImportMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const selectedChecklist = selected ? getChecklist(selected) : undefined
  const reviews = sortReviews(store.reviews)

  const onImport = async (file: File | undefined) => {
    if (!file) return
    try {
      if (file.size > 2_000_000) throw new Error('File is larger than 2 MB')
      const review = importReview(
        await readFileText(file),
        store.reviews,
        CHECKLISTS.map((c) => c.id),
        { newId },
      )
      store.update((list) => upsertReview(list, review))
      setImportMsg({ ok: true, text: `Imported "${review.name}".` })
    } catch (err) {
      setImportMsg({ ok: false, text: `Import failed: ${err instanceof Error ? err.message : String(err)}` })
    } finally {
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  return (
    <>
      <header className="page-header">
        <h1>Review Checklists</h1>
        <p>
          Run a structured security review of a pull request, feature or service against OWASP checklists, record
          pass / fail / N/A with notes, and paste the summary straight into the PR. Everything stays in this browser.
        </p>
      </header>

      <section aria-labelledby="checklists-pick" className="stack">
        <h2 id="checklists-pick">Start a review</h2>
        <div className="grid">
          {CHECKLISTS.map((c) => (
            <article key={c.id} className="card checklists-card" data-selected={selected === c.id}>
              <h3>{c.title}</h3>
              <div className="checklists-card-meta">
                <span>{c.categories.length} categories</span>
                <span>{itemCount(c)} items</span>
                <a href={c.source} target="_blank" rel="noreferrer noopener">Source</a>
              </div>
              <p className="small">{c.description}</p>
              <div>
                <button
                  type="button"
                  className={selected === c.id ? 'btn btn-primary' : 'btn'}
                  aria-expanded={selected === c.id}
                  onClick={() => setSelected(selected === c.id ? null : c.id)}
                >
                  Use this checklist
                </button>
              </div>
            </article>
          ))}
        </div>
        {selectedChecklist && (
          <NewReviewForm
            key={selectedChecklist.id}
            checklist={selectedChecklist}
            onCancel={() => setSelected(null)}
            onCreate={(r) => {
              store.update((list) => upsertReview(list, r))
              navigate(`review/${encodeURIComponent(r.id)}`)
            }}
          />
        )}
      </section>

      <section aria-labelledby="checklists-saved" className="stack" style={{ marginTop: '2rem' }}>
        <div className="row">
          <h2 id="checklists-saved" style={{ margin: 0 }}>Saved reviews ({reviews.length})</h2>
          <span className="spacer" />
          <label className="btn checklists-file-label">
            Import review JSON
            <input
              ref={fileRef}
              type="file"
              accept="application/json,.json"
              className="checklists-hidden-file"
              onChange={(e) => void onImport(e.target.files?.[0])}
            />
          </label>
        </div>
        {importMsg && (
          <div className={importMsg.ok ? 'callout' : 'callout error'} role="status">
            {importMsg.text}
          </div>
        )}
        {reviews.length === 0 ? (
          <p className="muted">No saved reviews yet. Pick a checklist above to start one.</p>
        ) : (
          <div className="card" style={{ overflowX: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Review</th>
                  <th scope="col">Checklist</th>
                  <th scope="col">Progress</th>
                  <th scope="col">Updated</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {reviews.map((r) => (
                  <SavedReviewRow key={r.id} review={r} store={store} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}
