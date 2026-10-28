import { describe, expect, it } from 'vitest'
import type { Threat } from './model.ts'
import { createModel, createNode } from './model.ts'
import { DEFAULT_FILTER, groupThreats, matchesFilter } from './view.ts'

const t = (over: Partial<Threat>): Threat => ({
  id: 'x',
  elementId: 'a',
  category: 'S',
  title: 'Title',
  description: 'Desc',
  likelihood: 1,
  impact: 1,
  status: 'open',
  mitigation: '',
  generated: true,
  ruleId: 'R',
  ...over,
})

describe('matchesFilter', () => {
  it('default filter matches everything', () => {
    expect(matchesFilter(t({ stale: true }), DEFAULT_FILTER)).toBe(true)
  })
  it('filters by status', () => {
    expect(matchesFilter(t({ status: 'mitigated' }), { ...DEFAULT_FILTER, status: 'open' })).toBe(false)
    expect(matchesFilter(t({ status: 'mitigated' }), { ...DEFAULT_FILTER, status: 'mitigated' })).toBe(true)
  })
  it('filters by risk level and high+', () => {
    const crit = t({ likelihood: 3, impact: 3 })
    const med = t({ likelihood: 2, impact: 2 })
    expect(matchesFilter(crit, { ...DEFAULT_FILTER, risk: 'high+' })).toBe(true)
    expect(matchesFilter(med, { ...DEFAULT_FILTER, risk: 'high+' })).toBe(false)
    expect(matchesFilter(med, { ...DEFAULT_FILTER, risk: 'medium' })).toBe(true)
    expect(matchesFilter(crit, { ...DEFAULT_FILTER, risk: 'high' })).toBe(false)
  })
  it('can hide stale threats', () => {
    expect(matchesFilter(t({ stale: true }), { ...DEFAULT_FILTER, includeStale: false })).toBe(false)
    expect(matchesFilter(t({}), { ...DEFAULT_FILTER, includeStale: false })).toBe(true)
  })
  it('searches title, description, mitigation, owner and ticket case-insensitively', () => {
    const th = t({ owner: 'Alice', ticket: 'SEC-42', mitigation: 'Use argon2id' })
    for (const q of ['title', 'DESC', 'argon', 'alice', 'sec-42']) expect(matchesFilter(th, { ...DEFAULT_FILTER, text: q })).toBe(true)
    expect(matchesFilter(th, { ...DEFAULT_FILTER, text: 'nothing' })).toBe(false)
    expect(matchesFilter(th, { ...DEFAULT_FILTER, text: '   ' })).toBe(true)
  })
})

describe('groupThreats', () => {
  const m = createModel('m', 'x', '2026-01-01T00:00:00.000Z')
  m.elements = [createNode('a', 'process', 'API'), createNode('b', 'datastore', 'DB'), createNode('c', 'external', 'Unused')]
  const threats = [
    t({ id: '1', elementId: 'b', category: 'I', likelihood: 1, impact: 1 }),
    t({ id: '2', elementId: 'a', category: 'T', likelihood: 3, impact: 3 }),
    t({ id: '3', elementId: 'a', category: 'S', likelihood: 1, impact: 2 }),
    t({ id: '4', elementId: 'ghost', category: 'D' }),
  ]

  it('groups by element in model order, highest risk first, skipping empty groups', () => {
    const g = groupThreats(m, threats, 'element')
    expect(g.map((x) => x.title)).toEqual(['API', 'DB', 'Unknown element'])
    expect(g[0].threats.map((x) => x.id)).toEqual(['2', '3'])
    expect(g[0].subtitle).toBe('Process')
  })

  it('groups by STRIDE category in STRIDE order', () => {
    const g = groupThreats(m, threats, 'category')
    expect(g.map((x) => x.key)).toEqual(['S', 'T', 'I', 'D'])
    expect(g[0].title).toBe('S — Spoofing')
  })

  it('returns no groups for no threats', () => {
    expect(groupThreats(m, [], 'element')).toEqual([])
    expect(groupThreats(m, [], 'category')).toEqual([])
  })
})
