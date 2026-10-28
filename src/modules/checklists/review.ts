import type { Checklist, ItemResult, ItemStatus, Review, Stack } from './types'
import { ITEM_STATUSES, REVIEW_SCHEMA_VERSION, STACKS } from './types'

export const MAX_NAME_LENGTH = 200
export const MAX_LINK_LENGTH = 2000
export const MAX_NOTE_LENGTH = 5000

export interface Clock {
  now?: Date
}

function iso(opts: Clock | undefined): string {
  return (opts?.now ?? new Date()).toISOString()
}

export interface NewReviewInput {
  name: string
  link?: string
  checklist: Pick<Checklist, 'id' | 'version' | 'title'>
  stacks?: readonly Stack[]
}

export function defaultReviewName(checklist: Pick<Checklist, 'title'>, now = new Date()): string {
  return `${checklist.title} — ${now.toISOString().slice(0, 10)}`
}

export function createReview(input: NewReviewInput, opts: Clock & { id: string }): Review {
  const ts = iso(opts)
  const name = input.name.trim().slice(0, MAX_NAME_LENGTH) || defaultReviewName(input.checklist, opts.now)
  return {
    schemaVersion: REVIEW_SCHEMA_VERSION,
    id: opts.id,
    name,
    link: (input.link ?? '').trim().slice(0, MAX_LINK_LENGTH),
    checklistId: input.checklist.id,
    checklistVersion: input.checklist.version,
    stacks: normalizeStacks(input.stacks ?? []),
    results: {},
    createdAt: ts,
    updatedAt: ts,
  }
}

/** Dedupe, drop unknown values, keep canonical STACKS order. */
export function normalizeStacks(stacks: readonly unknown[]): Stack[] {
  return STACKS.filter((s) => stacks.includes(s))
}

function withResult(review: Review, itemId: string, next: ItemResult, opts?: Clock): Review {
  const results = { ...review.results }
  if (next.status === 'unchecked' && next.note === '') delete results[itemId]
  else results[itemId] = next
  return { ...review, results, updatedAt: iso(opts) }
}

export function setItemStatus(review: Review, itemId: string, status: ItemStatus, opts?: Clock): Review {
  const prev = Object.hasOwn(review.results, itemId) ? review.results[itemId] : undefined
  return withResult(review, itemId, { status, note: prev?.note ?? '' }, opts)
}

export function setItemNote(review: Review, itemId: string, note: string, opts?: Clock): Review {
  const prev = Object.hasOwn(review.results, itemId) ? review.results[itemId] : undefined
  return withResult(review, itemId, { status: prev?.status ?? 'unchecked', note: note.slice(0, MAX_NOTE_LENGTH) }, opts)
}

export interface ReviewMetaPatch {
  name?: string
  link?: string
  stacks?: readonly Stack[]
}

export function updateReviewMeta(review: Review, patch: ReviewMetaPatch, opts?: Clock): Review {
  const next: Review = { ...review, updatedAt: iso(opts) }
  if (patch.name !== undefined) {
    const name = patch.name.trim().slice(0, MAX_NAME_LENGTH)
    if (name) next.name = name
  }
  if (patch.link !== undefined) next.link = patch.link.trim().slice(0, MAX_LINK_LENGTH)
  if (patch.stacks !== undefined) next.stacks = normalizeStacks(patch.stacks)
  return next
}

export function renameReview(review: Review, name: string, opts?: Clock): Review {
  return updateReviewMeta(review, { name }, opts)
}

export function duplicateReview(review: Review, opts: Clock & { id: string }): Review {
  const ts = iso(opts)
  const results: Record<string, ItemResult> = {}
  for (const [k, v] of Object.entries(review.results)) results[k] = { ...v }
  return {
    ...review,
    id: opts.id,
    name: `${review.name} (copy)`.slice(0, MAX_NAME_LENGTH),
    stacks: [...review.stacks],
    results,
    createdAt: ts,
    updatedAt: ts,
  }
}

/** Replace the review with the same id, or add it at the front. */
export function upsertReview(list: readonly Review[], review: Review): Review[] {
  const idx = list.findIndex((r) => r.id === review.id)
  if (idx === -1) return [review, ...list]
  const out = [...list]
  out[idx] = review
  return out
}

export function removeReview(list: readonly Review[], id: string): Review[] {
  return list.filter((r) => r.id !== id)
}

/** Most recently updated first. */
export function sortReviews(list: readonly Review[]): Review[] {
  return [...list].sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0))
}

/* ---------------- Validation of untrusted JSON (localStorage, imported files) ---------------- */

/** Item ids are simple slugs; this also rules out keys such as "__proto__". */
export const ITEM_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function str(v: unknown, field: string, max: number, required = true): string {
  if (typeof v !== 'string') {
    if (!required && v === undefined) return ''
    throw new Error(`Invalid review: "${field}" must be a string`)
  }
  return v.slice(0, max)
}

function isoDate(v: unknown, fallback: string): string {
  return typeof v === 'string' && !Number.isNaN(Date.parse(v)) ? new Date(v).toISOString() : fallback
}

/**
 * Validate and normalize an unknown value into a Review. Unknown fields are dropped, invalid result
 * entries are skipped, and results for item ids that are no longer in the checklist are kept in
 * storage (so they come back if the item returns) but ignored by progress and exports.
 * Throws an Error with a human-readable message if the value is not a usable review.
 */
export function parseReview(data: unknown): Review {
  if (!isRecord(data)) throw new Error('Invalid review: expected a JSON object')
  if (data.schemaVersion !== REVIEW_SCHEMA_VERSION) {
    throw new Error(`Unsupported review schemaVersion: ${JSON.stringify(data.schemaVersion)} (expected ${REVIEW_SCHEMA_VERSION})`)
  }
  const id = str(data.id, 'id', 100)
  if (!id) throw new Error('Invalid review: "id" must not be empty')
  const checklistId = str(data.checklistId, 'checklistId', 100)
  const now = new Date().toISOString()
  const createdAt = isoDate(data.createdAt, now)

  const results: Record<string, ItemResult> = {}
  if (isRecord(data.results)) {
    for (const [itemId, raw] of Object.entries(data.results)) {
      if (!isRecord(raw) || !ITEM_ID_RE.test(itemId)) continue
      const status = raw.status
      if (typeof status !== 'string' || !(ITEM_STATUSES as readonly string[]).includes(status)) continue
      const note = typeof raw.note === 'string' ? raw.note.slice(0, MAX_NOTE_LENGTH) : ''
      if (status === 'unchecked' && note === '') continue
      results[itemId] = { status: status as ItemStatus, note }
    }
  }

  return {
    schemaVersion: REVIEW_SCHEMA_VERSION,
    id,
    name: str(data.name, 'name', MAX_NAME_LENGTH).trim() || 'Untitled review',
    link: str(data.link, 'link', MAX_LINK_LENGTH, false),
    checklistId,
    checklistVersion: str(data.checklistVersion, 'checklistVersion', 50, false),
    stacks: Array.isArray(data.stacks) ? normalizeStacks(data.stacks) : [],
    results,
    createdAt,
    updatedAt: isoDate(data.updatedAt, createdAt),
  }
}

/** Load a persisted list, silently dropping entries that are not valid reviews. */
export function sanitizeReviews(data: unknown): Review[] {
  if (!Array.isArray(data)) return []
  const out: Review[] = []
  const seen = new Set<string>()
  for (const entry of data) {
    try {
      const r = parseReview(entry)
      if (seen.has(r.id)) continue
      seen.add(r.id)
      out.push(r)
    } catch {
      // skip corrupt entry
    }
  }
  return out
}

/**
 * Entries written by a newer version of the app (higher schemaVersion). They cannot be read by this
 * version, but must not be silently deleted when this version saves the list (e.g. after a rollback).
 */
export function futureVersionEntries(data: unknown): unknown[] {
  if (!Array.isArray(data)) return []
  return data.filter(
    (e) => isRecord(e) && typeof e.schemaVersion === 'number' && e.schemaVersion > REVIEW_SCHEMA_VERSION,
  )
}

/** Exported file format: the review plus human-friendly checklist metadata (ignored on import). */
export function reviewExport(review: Review, checklist?: Pick<Checklist, 'title' | 'version' | 'source'>) {
  return {
    ...review,
    checklist: checklist ? { title: checklist.title, version: checklist.version, source: checklist.source } : undefined,
    exportedBy: 'Security Champion Toolkit',
  }
}

/**
 * Parse an exported review file. The checklist must exist in this app. If the id collides with an
 * existing review, a fresh id is assigned so the import never overwrites local work.
 */
export function importReview(
  text: string,
  existing: readonly Review[],
  knownChecklistIds: readonly string[],
  opts: { newId: () => string },
): Review {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    throw new Error('File is not valid JSON')
  }
  const review = parseReview(data)
  if (!knownChecklistIds.includes(review.checklistId)) {
    throw new Error(`Unknown checklist "${review.checklistId}"`)
  }
  if (existing.some((r) => r.id === review.id)) return { ...review, id: opts.newId() }
  return review
}
