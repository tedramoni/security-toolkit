import { describe, expect, it } from 'vitest'
import {
  MAX_NAME_LENGTH,
  MAX_NOTE_LENGTH,
  createReview,
  defaultReviewName,
  duplicateReview,
  futureVersionEntries,
  importReview,
  normalizeStacks,
  parseReview,
  removeReview,
  renameReview,
  reviewExport,
  sanitizeReviews,
  setItemNote,
  setItemStatus,
  sortReviews,
  updateReviewMeta,
  upsertReview,
} from './review'
import { fixture, makeReview } from './testFixture'

const T0 = new Date('2026-03-01T10:00:00.000Z')
const T1 = new Date('2026-03-02T10:00:00.000Z')

describe('createReview', () => {
  it('builds a versioned, JSON-serializable review', () => {
    const r = createReview(
      { name: '  PR #123 — payment API ', link: ' https://github.com/o/r/pull/123 ', checklist: fixture, stacks: ['infra', 'web', 'web'] },
      { id: 'abc', now: T0 },
    )
    expect(r).toEqual({
      schemaVersion: 1,
      id: 'abc',
      name: 'PR #123 — payment API',
      link: 'https://github.com/o/r/pull/123',
      checklistId: 'fx',
      checklistVersion: '1',
      stacks: ['web', 'infra'],
      results: {},
      createdAt: T0.toISOString(),
      updatedAt: T0.toISOString(),
    })
    expect(JSON.parse(JSON.stringify(r))).toEqual(r)
  })

  it('falls back to a default name and truncates long names', () => {
    expect(createReview({ name: '   ', checklist: fixture }, { id: 'x', now: T0 }).name).toBe(defaultReviewName(fixture, T0))
    expect(defaultReviewName(fixture, T0)).toBe('Fixture — 2026-03-01')
    expect(createReview({ name: 'a'.repeat(500), checklist: fixture }, { id: 'x' }).name).toHaveLength(MAX_NAME_LENGTH)
  })
})

describe('normalizeStacks', () => {
  it('dedupes, drops unknown values and uses canonical order', () => {
    expect(normalizeStacks(['infra', 'bogus', 'web', 'infra', 42])).toEqual(['web', 'infra'])
    expect(normalizeStacks([])).toEqual([])
  })
})

describe('setItemStatus / setItemNote', () => {
  it('sets status immutably and bumps updatedAt', () => {
    const r = makeReview()
    const r2 = setItemStatus(r, 'i1', 'fail', { now: T1 })
    expect(r.results).toEqual({})
    expect(r2.results.i1).toEqual({ status: 'fail', note: '' })
    expect(r2.updatedAt).toBe(T1.toISOString())
  })

  it('keeps the note when the status changes and vice versa', () => {
    let r = setItemNote(makeReview(), 'i1', 'missing check in handler')
    expect(r.results.i1).toEqual({ status: 'unchecked', note: 'missing check in handler' })
    r = setItemStatus(r, 'i1', 'fail')
    expect(r.results.i1).toEqual({ status: 'fail', note: 'missing check in handler' })
    r = setItemNote(r, 'i1', 'fixed in abc123')
    expect(r.results.i1).toEqual({ status: 'fail', note: 'fixed in abc123' })
  })

  it('removes the entry when it returns to the default state', () => {
    let r = setItemStatus(makeReview(), 'i1', 'pass')
    r = setItemStatus(r, 'i1', 'unchecked')
    expect(r.results).toEqual({})
    r = setItemNote(r, 'i2', 'x')
    r = setItemNote(r, 'i2', '')
    expect(r.results).toEqual({})
  })

  it('caps very long notes', () => {
    const r = setItemNote(makeReview(), 'i1', 'n'.repeat(MAX_NOTE_LENGTH + 10))
    expect(r.results.i1.note).toHaveLength(MAX_NOTE_LENGTH)
  })
})

describe('updateReviewMeta / renameReview', () => {
  it('renames with trimming and ignores empty names', () => {
    const r = makeReview({ name: 'Old' })
    expect(renameReview(r, '  New  ').name).toBe('New')
    expect(renameReview(r, '   ').name).toBe('Old')
  })

  it('updates link and stacks, leaving other fields untouched', () => {
    const r = makeReview({ results: { i1: { status: 'pass', note: '' } } })
    const r2 = updateReviewMeta(r, { link: ' https://x.test ', stacks: ['api', 'web'] }, { now: T1 })
    expect(r2.link).toBe('https://x.test')
    expect(r2.stacks).toEqual(['web', 'api'])
    expect(r2.results).toBe(r.results)
    expect(r2.updatedAt).toBe(T1.toISOString())
    expect(r2.name).toBe(r.name)
  })
})

describe('duplicateReview', () => {
  it('copies results deeply with a new id, name and timestamps', () => {
    const r = makeReview({ name: 'PR 1', stacks: ['web'], results: { i1: { status: 'fail', note: 'n' } } })
    const d = duplicateReview(r, { id: 'copy', now: T1 })
    expect(d).toMatchObject({ id: 'copy', name: 'PR 1 (copy)', createdAt: T1.toISOString(), updatedAt: T1.toISOString() })
    expect(d.results).toEqual(r.results)
    expect(d.results).not.toBe(r.results)
    expect(d.results.i1).not.toBe(r.results.i1)
    expect(d.stacks).not.toBe(r.stacks)
  })
})

describe('list helpers', () => {
  const a = makeReview({ id: 'a', updatedAt: '2026-01-01T00:00:00.000Z' })
  const b = makeReview({ id: 'b', updatedAt: '2026-02-01T00:00:00.000Z' })

  it('upsert adds new reviews at the front and replaces existing ones in place', () => {
    expect(upsertReview([a], b).map((r) => r.id)).toEqual(['b', 'a'])
    const a2 = { ...a, name: 'changed' }
    const list = upsertReview([b, a], a2)
    expect(list.map((r) => r.id)).toEqual(['b', 'a'])
    expect(list[1].name).toBe('changed')
  })

  it('removes by id', () => {
    expect(removeReview([a, b], 'a')).toEqual([b])
    expect(removeReview([a, b], 'zzz')).toEqual([a, b])
  })

  it('sorts by updatedAt descending without mutating', () => {
    const list = [a, b]
    expect(sortReviews(list).map((r) => r.id)).toEqual(['b', 'a'])
    expect(list.map((r) => r.id)).toEqual(['a', 'b'])
  })
})

describe('parseReview', () => {
  const valid = makeReview({ results: { i1: { status: 'fail', note: 'n' } } })

  it('round-trips a valid review', () => {
    expect(parseReview(JSON.parse(JSON.stringify(valid)))).toEqual(valid)
  })

  it('rejects non-objects and wrong schema versions', () => {
    expect(() => parseReview(null)).toThrow(/JSON object/)
    expect(() => parseReview([])).toThrow(/JSON object/)
    expect(() => parseReview({ ...valid, schemaVersion: 2 })).toThrow(/schemaVersion/)
    expect(() => parseReview({ ...valid, schemaVersion: undefined })).toThrow(/schemaVersion/)
  })

  it('rejects missing required strings', () => {
    expect(() => parseReview({ ...valid, id: 5 })).toThrow(/"id"/)
    expect(() => parseReview({ ...valid, id: '' })).toThrow(/"id"/)
    expect(() => parseReview({ ...valid, checklistId: undefined })).toThrow(/checklistId/)
    expect(() => parseReview({ ...valid, name: {} })).toThrow(/"name"/)
  })

  it('drops invalid results, unknown stacks, extra fields and dangerous keys', () => {
    const raw = JSON.parse(
      JSON.stringify({ ...valid, extra: 'x', stacks: ['web', 'cobol'] }).replace(
        '"results":{',
        '"results":{"__proto__":{"status":"fail","note":"p"},"bad":{"status":"maybe"},"n":5,"blank":{"status":"unchecked","note":""},"noteonly":{"status":"unchecked","note":"keep"},"nonote":{"status":"pass"},',
      ),
    )
    const r = parseReview(raw)
    expect(r).not.toHaveProperty('extra')
    expect(r.stacks).toEqual(['web'])
    expect(Object.keys(r.results).sort()).toEqual(['i1', 'nonote', 'noteonly'])
    expect(r.results.nonote).toEqual({ status: 'pass', note: '' })
    expect(Object.getPrototypeOf(r.results)).toBe(Object.prototype)
    expect(({} as Record<string, unknown>).status).toBeUndefined()
  })

  it('defaults optional fields and repairs dates', () => {
    const r = parseReview({ schemaVersion: 1, id: 'x', name: '  ', checklistId: 'fx', createdAt: 'garbage', updatedAt: 3 })
    expect(r.name).toBe('Untitled review')
    expect(r.link).toBe('')
    expect(r.checklistVersion).toBe('')
    expect(r.stacks).toEqual([])
    expect(r.results).toEqual({})
    expect(Number.isNaN(Date.parse(r.createdAt))).toBe(false)
    expect(r.updatedAt).toBe(r.createdAt)
  })
})

describe('sanitizeReviews', () => {
  it('returns [] for non-arrays and skips corrupt or duplicate entries', () => {
    expect(sanitizeReviews(null)).toEqual([])
    expect(sanitizeReviews({})).toEqual([])
    const a = makeReview({ id: 'a' })
    const out = sanitizeReviews([a, 'junk', { schemaVersion: 9 }, { ...a, name: 'dupe' }])
    expect(out).toEqual([a])
  })
})

describe('futureVersionEntries', () => {
  it('keeps only entries from a newer schema so saving does not delete them', () => {
    const future = { schemaVersion: 2, id: 'f', extra: true }
    expect(futureVersionEntries([makeReview(), future, { schemaVersion: 0 }, { schemaVersion: '2' }, 'junk', null])).toEqual([
      future,
    ])
    expect(futureVersionEntries({ schemaVersion: 2 })).toEqual([])
    expect(futureVersionEntries(undefined)).toEqual([])
  })
})

describe('export / import', () => {
  const r = makeReview({ id: 'r1', results: { i1: { status: 'pass', note: '' } } })

  it('exports with checklist metadata and imports back', () => {
    const json = JSON.stringify(reviewExport(r, fixture))
    expect(JSON.parse(json).checklist).toEqual({ title: 'Fixture', version: '1', source: 'https://example.com/fx' })
    const imported = importReview(json, [], ['fx'], { newId: () => 'new' })
    expect(imported).toEqual(r)
  })

  it('assigns a new id when the id already exists locally', () => {
    const json = JSON.stringify(reviewExport(r))
    expect(importReview(json, [r], ['fx'], { newId: () => 'new' }).id).toBe('new')
  })

  it('rejects invalid JSON and unknown checklists', () => {
    expect(() => importReview('{nope', [], ['fx'], { newId: () => 'n' })).toThrow(/valid JSON/)
    expect(() => importReview(JSON.stringify(r), [], ['other'], { newId: () => 'n' })).toThrow(/Unknown checklist/)
  })
})
