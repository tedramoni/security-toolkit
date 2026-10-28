import { describe, expect, it } from 'vitest'
import {
  applicableItems,
  computeProgress,
  filterChecklist,
  getResult,
  itemMatchesStacks,
  orphanResultIds,
  progressOf,
  refUrl,
  searchTerms,
} from './logic'
import { fixture, makeReview as review } from './testFixture'

describe('itemMatchesStacks', () => {
  const item = fixture.categories[0].items[1]
  it('shows items without stacks for any selection', () => {
    expect(itemMatchesStacks(fixture.categories[0].items[0], ['infra'])).toBe(true)
  })
  it('treats an empty selection as no filter', () => {
    expect(itemMatchesStacks(item, [])).toBe(true)
  })
  it('matches on any overlap', () => {
    expect(itemMatchesStacks(item, ['api'])).toBe(true)
    expect(itemMatchesStacks(item, ['infra', 'web'])).toBe(true)
    expect(itemMatchesStacks(item, ['infra'])).toBe(false)
  })
  it('treats an empty stacks array on the item like no stacks', () => {
    expect(itemMatchesStacks({ ...item, stacks: [] }, ['java'])).toBe(true)
  })
})

describe('applicableItems', () => {
  it('returns all items without filter, in order', () => {
    expect(applicableItems(fixture, []).map((r) => r.item.id)).toEqual(['i1', 'i2', 'i3', 'i4'])
  })
  it('filters by stack and keeps the category reference', () => {
    const refs = applicableItems(fixture, ['web'])
    expect(refs.map((r) => r.item.id)).toEqual(['i1', 'i2'])
    expect(refs[1].category.id).toBe('c1')
  })
})

describe('getResult', () => {
  it('returns a default for missing entries', () => {
    expect(getResult(review(), 'i1')).toEqual({ status: 'unchecked', note: '' })
  })
  it('does not read inherited properties', () => {
    expect(getResult(review(), 'toString')).toEqual({ status: 'unchecked', note: '' })
    expect(getResult(review(), '__proto__')).toEqual({ status: 'unchecked', note: '' })
  })
})

describe('computeProgress', () => {
  it('handles an empty review', () => {
    expect(computeProgress(fixture, review())).toEqual({
      total: 4, answered: 0, pass: 0, fail: 0, na: 0, unchecked: 4, percent: 0,
    })
  })

  it('counts statuses and floors the percentage', () => {
    const r = review({
      results: {
        i1: { status: 'pass', note: '' },
        i2: { status: 'fail', note: 'x' },
        i3: { status: 'unchecked', note: 'only a note' },
      },
    })
    expect(computeProgress(fixture, r)).toEqual({
      total: 4, answered: 2, pass: 1, fail: 1, na: 0, unchecked: 2, percent: 50,
    })
    const r2 = review({ results: { i1: { status: 'na', note: '' } }, stacks: ['web'] })
    // stacks=['web'] → i1, i2 in scope
    expect(computeProgress(fixture, r2)).toMatchObject({ total: 2, answered: 1, na: 1, percent: 50 })
  })

  it('reaches 100% when everything is answered', () => {
    const results = Object.fromEntries(['i1', 'i2', 'i3', 'i4'].map((id) => [id, { status: 'na' as const, note: '' }]))
    expect(computeProgress(fixture, review({ results })).percent).toBe(100)
  })

  it('ignores results for unknown or out-of-scope items', () => {
    const r = review({
      stacks: ['web'],
      results: {
        gone: { status: 'fail', note: 'removed item' },
        i3: { status: 'fail', note: 'out of scope' },
      },
    })
    expect(computeProgress(fixture, r)).toMatchObject({ total: 2, fail: 0, answered: 0 })
  })

  it('returns 0% for an empty item list', () => {
    expect(progressOf([], review()).percent).toBe(0)
  })

  it('floors e.g. 1/3 to 33', () => {
    const items = fixture.categories[0].items.concat(fixture.categories[1].items[0])
    expect(progressOf(items, review({ results: { i1: { status: 'pass', note: '' } } })).percent).toBe(33)
  })
})

describe('orphanResultIds', () => {
  it('lists result ids not present in the checklist', () => {
    const r = review({ results: { i1: { status: 'pass', note: '' }, old: { status: 'fail', note: '' } } })
    expect(orphanResultIds(fixture, r)).toEqual(['old'])
  })
})

describe('searchTerms', () => {
  it('splits, lowercases and drops empties', () => {
    expect(searchTerms('  CORS   Origin ')).toEqual(['cors', 'origin'])
    expect(searchTerms('')).toEqual([])
  })
})

describe('filterChecklist', () => {
  it('returns everything for empty options', () => {
    const cats = filterChecklist(fixture, review(), { stacks: [] })
    expect(cats.map((c) => c.items.length)).toEqual([2, 2])
  })

  it('drops categories that become empty and does not mutate the source', () => {
    const cats = filterChecklist(fixture, review(), { stacks: ['web'] })
    expect(cats.map((c) => c.id)).toEqual(['c1'])
    expect(fixture.categories[0].items).toHaveLength(2)
  })

  it('searches text, detail, refs, category title and notes, case-insensitively, all terms required', () => {
    const r = review({ results: { i4: { status: 'unchecked', note: 'Dependabot pending' } } })
    const ids = (q: string) => filterChecklist(fixture, r, { stacks: [], query: q }).flatMap((c) => c.items.map((i) => i.id))
    expect(ids('cors')).toEqual(['i2'])
    expect(ids('USER directive')).toEqual(['i3'])
    expect(ids('cwe-862')).toEqual(['i1'])
    expect(ids('infra')).toEqual(['i3', 'i4'])
    expect(ids('dependabot')).toEqual(['i4'])
    expect(ids('cors nothing-matches')).toEqual([])
  })

  it('filters by status', () => {
    const r = review({ results: { i2: { status: 'fail', note: '' }, i3: { status: 'pass', note: '' } } })
    const ids = (status: 'all' | 'fail' | 'unchecked') =>
      filterChecklist(fixture, r, { stacks: [], status }).flatMap((c) => c.items.map((i) => i.id))
    expect(ids('fail')).toEqual(['i2'])
    expect(ids('unchecked')).toEqual(['i1', 'i4'])
    expect(ids('all')).toHaveLength(4)
  })
})

describe('refUrl', () => {
  it('links CWE ids to MITRE and nothing else', () => {
    expect(refUrl('CWE-89')).toBe('https://cwe.mitre.org/data/definitions/89.html')
    expect(refUrl('v5.0.0-1.2.4')).toBeNull()
    expect(refUrl('CWE-89x')).toBeNull()
  })
})
