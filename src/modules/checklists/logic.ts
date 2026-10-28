import type {
  Checklist,
  ChecklistCategory,
  ChecklistItem,
  ItemResult,
  ItemStatus,
  Review,
  Stack,
} from './types'

export const EMPTY_RESULT: ItemResult = Object.freeze({ status: 'unchecked', note: '' }) as ItemResult

/** Items without stacks apply everywhere; an empty selection means "no filter". */
export function itemMatchesStacks(item: ChecklistItem, stacks: readonly Stack[]): boolean {
  if (!item.stacks || item.stacks.length === 0 || stacks.length === 0) return true
  return item.stacks.some((s) => stacks.includes(s))
}

export interface ItemRef {
  category: ChecklistCategory
  item: ChecklistItem
}

/** Items in scope for a review (stack filter only — the search box never changes progress). */
export function applicableItems(checklist: Checklist, stacks: readonly Stack[]): ItemRef[] {
  const out: ItemRef[] = []
  for (const category of checklist.categories) {
    for (const item of category.items) {
      if (itemMatchesStacks(item, stacks)) out.push({ category, item })
    }
  }
  return out
}

export function getResult(review: Pick<Review, 'results'>, itemId: string): ItemResult {
  const r = Object.hasOwn(review.results, itemId) ? review.results[itemId] : undefined
  return r ?? EMPTY_RESULT
}

export interface Progress {
  total: number
  answered: number
  pass: number
  fail: number
  na: number
  unchecked: number
  /** 0–100, integer. 0 when there are no items. */
  percent: number
}

export function progressOf(items: readonly ChecklistItem[], review: Pick<Review, 'results'>): Progress {
  const p: Progress = { total: items.length, answered: 0, pass: 0, fail: 0, na: 0, unchecked: 0, percent: 0 }
  for (const item of items) {
    const { status } = getResult(review, item.id)
    p[status]++
  }
  p.answered = p.pass + p.fail + p.na
  p.percent = p.total === 0 ? 0 : Math.floor((p.answered / p.total) * 100)
  return p
}

/**
 * Progress over the items currently in scope. Results stored for ids that no longer exist in the
 * checklist (data changed since the review was created) are ignored.
 */
export function computeProgress(checklist: Checklist, review: Pick<Review, 'results' | 'stacks'>): Progress {
  return progressOf(
    applicableItems(checklist, review.stacks).map((r) => r.item),
    review,
  )
}

/** Result ids stored in the review that do not match any item of the checklist. */
export function orphanResultIds(checklist: Checklist, review: Pick<Review, 'results'>): string[] {
  const known = new Set(checklist.categories.flatMap((c) => c.items.map((i) => i.id)))
  return Object.keys(review.results).filter((id) => !known.has(id))
}

/** Canonical URL for a reference id, or null when there is no stable per-id page. */
export function refUrl(ref: string): string | null {
  const m = /^CWE-(\d+)$/.exec(ref)
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null
}

export type StatusFilter = 'all' | ItemStatus

export interface FilterOptions {
  stacks: readonly Stack[]
  query?: string
  status?: StatusFilter
}

/** Lower-cased search terms; every term must match somewhere in the item. */
export function searchTerms(query: string): string[] {
  return query.toLowerCase().split(/\s+/).filter(Boolean)
}

export function itemMatchesQuery(
  item: ChecklistItem,
  category: ChecklistCategory,
  terms: readonly string[],
  note = '',
): boolean {
  if (terms.length === 0) return true
  const haystack = [item.id, item.text, item.detail, category.title, note, ...(item.refs ?? [])]
    .join('\n')
    .toLowerCase()
  return terms.every((t) => haystack.includes(t))
}

/** Categories with their visible items; categories left empty are dropped. */
export function filterChecklist(
  checklist: Checklist,
  review: Pick<Review, 'results'>,
  { stacks, query = '', status = 'all' }: FilterOptions,
): ChecklistCategory[] {
  const terms = searchTerms(query)
  const out: ChecklistCategory[] = []
  for (const category of checklist.categories) {
    const items = category.items.filter((item) => {
      if (!itemMatchesStacks(item, stacks)) return false
      const result = getResult(review, item.id)
      if (status !== 'all' && result.status !== status) return false
      return itemMatchesQuery(item, category, terms, result.note)
    })
    if (items.length > 0) out.push({ ...category, items })
  }
  return out
}
