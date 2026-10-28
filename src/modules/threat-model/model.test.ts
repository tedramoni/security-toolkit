import { describe, expect, it } from 'vitest'
import { exampleModel } from './example.ts'
import type { Threat, ThreatModel } from './model.ts'
import {
  createFlow,
  createModel,
  createNode,
  displayName,
  duplicateModel,
  flowsOf,
  nodesOf,
  parseImport,
  partitionStored,
  removalImpact,
  removeElement,
  sanitizeStored,
  tagsForType,
  touch,
  updateThreat,
  upsertElement,
  validateModel,
} from './model.ts'
import { refreshThreats } from './stride.ts'

const NOW = '2026-01-01T00:00:00.000Z'
let n = 0
const ids = () => `id-${++n}`

function sample(): ThreatModel {
  const m = createModel('m1', 'Shop', NOW)
  m.elements = [
    createNode('a', 'external', 'User'),
    createNode('b', 'process', 'API', ['internet-facing']),
    createNode('c', 'datastore', 'DB'),
    createFlow('f1', 'a', 'b', { protocol: 'HTTPS', crossesTrustBoundary: true }),
    createFlow('f2', 'b', 'c', { protocol: 'TLS' }),
  ]
  return refreshThreats(m, ids).model
}

const threat = (over: Partial<Threat> = {}): Threat => ({
  id: 't1',
  elementId: 'b',
  category: 'S',
  title: 'x',
  description: '',
  likelihood: 2,
  impact: 2,
  status: 'open',
  mitigation: '',
  generated: false,
  ...over,
})

describe('factories', () => {
  it('createModel produces an empty v1 model', () => {
    expect(createModel('x', 'Name', NOW)).toEqual({
      schemaVersion: 1,
      id: 'x',
      name: 'Name',
      description: '',
      owner: '',
      createdAt: NOW,
      updatedAt: NOW,
      assumptions: [],
      elements: [],
      threats: [],
    })
  })

  it('createFlow has safe defaults', () => {
    expect(createFlow('f', 'a', 'b')).toMatchObject({ type: 'dataflow', protocol: '', crossesTrustBoundary: false, dataClassification: 'internal', tags: [] })
  })

  it('createNode copies tags', () => {
    const tags = ['admin']
    const el = createNode('n', 'process', 'P', tags)
    tags.push('x')
    expect(el.tags).toEqual(['admin'])
  })

  it('tagsForType filters tags by element type', () => {
    expect(tagsForType('datastore').map((t) => t.id)).toContain('stores-credentials')
    expect(tagsForType('process').map((t) => t.id)).not.toContain('stores-credentials')
    expect(tagsForType('dataflow')).toEqual([])
  })

  it('nodesOf / flowsOf split elements', () => {
    const m = sample()
    expect(nodesOf(m).map((e) => e.id)).toEqual(['a', 'b', 'c'])
    expect(flowsOf(m).map((e) => e.id)).toEqual(['f1', 'f2'])
  })

  it('displayName falls back to endpoints for unnamed flows', () => {
    const m = sample()
    expect(displayName(m, m.elements[3])).toBe('User → API')
    expect(displayName(m, { ...m.elements[3], name: 'Login' })).toBe('Login')
    expect(displayName(m, { ...m.elements[0], name: '  ' })).toBe('(unnamed)')
    expect(displayName(m, createFlow('z', 'ghost', 'b'))).toBe('? → API')
  })

  it('touch bumps updatedAt only', () => {
    const m = sample()
    const t = touch(m, '2027-01-01T00:00:00.000Z')
    expect(t.updatedAt).toBe('2027-01-01T00:00:00.000Z')
    expect(t.createdAt).toBe(NOW)
    expect(m.updatedAt).toBe(NOW)
  })

  it('duplicateModel deep-copies with a new id and name', () => {
    const m = sample()
    const d = duplicateModel(m, 'm2', '2027-01-01T00:00:00.000Z')
    expect(d.id).toBe('m2')
    expect(d.name).toBe('Copy of Shop')
    expect(d.createdAt).toBe('2027-01-01T00:00:00.000Z')
    expect(d.elements).toEqual(m.elements)
    expect(d.elements).not.toBe(m.elements)
    d.elements[0].name = 'changed'
    expect(m.elements[0].name).toBe('User')
  })

  it('upsertElement inserts and replaces', () => {
    const m = sample()
    const added = upsertElement(m, createNode('d', 'process', 'Worker'))
    expect(added.elements).toHaveLength(6)
    const replaced = upsertElement(added, createNode('d', 'process', 'Worker 2'))
    expect(replaced.elements).toHaveLength(6)
    expect(replaced.elements.find((e) => e.id === 'd')?.name).toBe('Worker 2')
  })

  it('updateThreat patches one threat and never changes its id', () => {
    const m = { ...sample(), threats: [threat(), threat({ id: 't2' })] }
    const out = updateThreat(m, 't1', { status: 'mitigated', id: 'hijack' })
    expect(out.threats[0]).toMatchObject({ id: 't1', status: 'mitigated' })
    expect(out.threats[1].status).toBe('open')
  })
})

describe('cascade delete', () => {
  it('removalImpact lists attached flows and threats', () => {
    const m = sample()
    const impact = removalImpact(m, 'b')
    expect(impact.flows.map((f) => f.id).sort()).toEqual(['f1', 'f2'])
    expect(impact.elementIds.sort()).toEqual(['b', 'f1', 'f2'])
    expect(impact.threatCount).toBe(m.threats.filter((t) => ['b', 'f1', 'f2'].includes(t.elementId)).length)
    expect(impact.threatCount).toBeGreaterThan(0)
  })

  it('removing a node removes its flows and all their threats', () => {
    const m = sample()
    const out = removeElement(m, 'b')
    expect(out.elements.map((e) => e.id)).toEqual(['a', 'c'])
    expect(out.threats.every((t) => ['a', 'c'].includes(t.elementId))).toBe(true)
    expect(validateModel(out).ok).toBe(true)
  })

  it('removing a flow does not remove its endpoints', () => {
    const m = sample()
    expect(removalImpact(m, 'f1').flows).toEqual([])
    const out = removeElement(m, 'f1')
    expect(out.elements.map((e) => e.id)).toEqual(['a', 'b', 'c', 'f2'])
    expect(out.threats.some((t) => t.elementId === 'f1')).toBe(false)
  })

  it('removing an unknown id is a no-op', () => {
    const m = sample()
    expect(removeElement(m, 'nope')).toEqual(m)
  })
})

describe('validateModel', () => {
  it('accepts valid models (sample and example, round-tripped through JSON)', () => {
    for (const m of [sample(), refreshThreats(exampleModel('ex', NOW), ids).model]) {
      const res = validateModel(JSON.parse(JSON.stringify(m)))
      expect(res.ok).toBe(true)
      if (res.ok) expect(res.model).toEqual(m)
    }
  })

  it.each([null, 42, 'str', [], true])('rejects non-object %p', (v) => {
    const res = validateModel(v)
    expect(res.ok).toBe(false)
  })

  it('rejects wrong or missing schemaVersion with a helpful message', () => {
    const res = validateModel({ ...sample(), schemaVersion: 2 })
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.errors[0]).toMatch(/schemaVersion.*expected 1/)
    const res2 = validateModel({ foo: 'bar' })
    if (!res2.ok) expect(res2.errors[0]).toMatch(/threat model export/)
  })

  it('reports paths of invalid fields', () => {
    const bad = JSON.parse(JSON.stringify(sample()))
    bad.elements[1].type = 'robot'
    bad.threats[0].likelihood = 7
    bad.threats[1].status = 'done'
    bad.assumptions = [1]
    const res = validateModel(bad)
    expect(res.ok).toBe(false)
    if (!res.ok) {
      expect(res.errors).toEqual(
        expect.arrayContaining([
          expect.stringContaining('model.elements[1].type'),
          expect.stringContaining('model.threats[0].likelihood'),
          expect.stringContaining('model.threats[1].status'),
          expect.stringContaining('model.assumptions[0]'),
        ]),
      )
    }
  })

  it('rejects non-integer scores', () => {
    const bad = JSON.parse(JSON.stringify(sample()))
    bad.threats[0].impact = 2.5
    expect(validateModel(bad).ok).toBe(false)
  })

  it('rejects dangling flow references and flows pointing at flows', () => {
    const bad = JSON.parse(JSON.stringify(sample()))
    bad.elements[3].fromId = 'ghost'
    bad.elements[4].toId = 'f1'
    const res = validateModel(bad)
    expect(res.ok).toBe(false)
    if (!res.ok) {
      expect(res.errors.join('\n')).toMatch(/unknown element "ghost"/)
      expect(res.errors.join('\n')).toMatch(/not a data flow/)
    }
  })

  it('rejects threats on unknown elements and duplicate ids', () => {
    const bad = JSON.parse(JSON.stringify(sample()))
    bad.threats[0].elementId = 'ghost'
    bad.threats[1].id = bad.threats[2].id
    bad.elements[2].id = 'a'
    const res = validateModel(bad)
    expect(res.ok).toBe(false)
    if (!res.ok) {
      const all = res.errors.join('\n')
      expect(all).toMatch(/threats\[0\]\.elementId/)
      expect(all).toMatch(/duplicate id/)
    }
  })

  it('rejects wrong types', () => {
    const bad = JSON.parse(JSON.stringify(sample()))
    bad.name = 5
    bad.elements = 'nope'
    const res = validateModel(bad)
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.errors).toEqual(expect.arrayContaining(['model.name: must be a string', 'model.elements: must be an array']))
  })

  it('rejects oversized strings', () => {
    const bad = JSON.parse(JSON.stringify(sample()))
    bad.description = 'x'.repeat(20_001)
    expect(validateModel(bad).ok).toBe(false)
  })

  it('fills optional fields with defaults and drops unknown keys (incl. __proto__)', () => {
    const raw = JSON.parse(
      '{"schemaVersion":1,"id":"m","name":"N","elements":[{"id":"p","name":"P","type":"process","__proto__":{"polluted":true},"extra":1},{"id":"q","name":"Q","type":"datastore"},{"id":"f","type":"dataflow","fromId":"p","toId":"q"}],"evil":true}',
    )
    const res = validateModel(raw)
    expect(res.ok).toBe(true)
    if (!res.ok) return
    expect(res.model.description).toBe('')
    expect(res.model.assumptions).toEqual([])
    expect(res.model.threats).toEqual([])
    expect(Object.keys(res.model)).not.toContain('evil')
    expect(Object.keys(res.model.elements[0])).not.toContain('extra')
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
    expect(res.model.elements[2]).toMatchObject({ protocol: '', crossesTrustBoundary: false, dataClassification: 'internal', tags: [] })
  })

  it('caps the number of reported errors', () => {
    const bad = JSON.parse(JSON.stringify(sample()))
    bad.elements = Array.from({ length: 200 }, () => ({ type: 'nope' }))
    const res = validateModel(bad)
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.errors.length).toBeLessThanOrEqual(50)
  })
})

describe('parseImport', () => {
  it('rejects invalid JSON with a clear error', () => {
    const res = parseImport('{not json', [], ids)
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.errors[0]).toMatch(/^Not valid JSON/)
  })

  it('rejects an empty list', () => {
    expect(parseImport('[]', [], ids).ok).toBe(false)
  })

  it('accepts a single model or an array', () => {
    const m = sample()
    const one = parseImport(JSON.stringify(m), [], ids)
    expect(one.ok && one.models).toHaveLength(1)
    const many = parseImport(JSON.stringify([m, { ...m, id: 'm2' }]), [], ids)
    expect(many.ok && many.models.map((x) => x.id)).toEqual(['m1', 'm2'])
  })

  it('re-ids models that collide with existing or each other', () => {
    const m = sample()
    const res = parseImport(JSON.stringify([m, m]), ['m1'], () => 'fresh-' + ++n)
    expect(res.ok).toBe(true)
    if (res.ok) {
      expect(res.models[0].id).not.toBe('m1')
      expect(res.models[1].id).not.toBe('m1')
      expect(res.models[0].id).not.toBe(res.models[1].id)
    }
  })

  it('re-ids models whose id is not URL-safe', () => {
    const m = { ...sample(), id: '../../evil?x=1' }
    const res = parseImport(JSON.stringify(m), [], () => 'safe')
    expect(res.ok && res.models[0].id).toBe('safe')
  })

  it('is all-or-nothing and prefixes errors with the array index', () => {
    const res = parseImport(JSON.stringify([sample(), { schemaVersion: 1, id: 'x' }]), [], ids)
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.errors.some((e) => e.startsWith('[1]'))).toBe(true)
  })

  it('rejects other kinds of JSON (e.g. a backup or a checklist)', () => {
    expect(parseImport('{"scp:reviews":[]}', [], ids).ok).toBe(false)
    expect(parseImport('"hello"', [], ids).ok).toBe(false)
    expect(parseImport('null', [], ids).ok).toBe(false)
  })
})

describe('sanitizeStored', () => {
  it('keeps valid models and drops garbage', () => {
    const m = sample()
    expect(sanitizeStored([m, null, { foo: 1 }, 'x'])).toEqual([m])
  })
  it('returns [] for non-arrays', () => {
    expect(sanitizeStored(null)).toEqual([])
    expect(sanitizeStored({})).toEqual([])
  })
})

describe('review regressions', () => {
  it('partitionStored keeps unreadable entries instead of dropping them', () => {
    const m = sample()
    const broken = { ...m, id: 'm2', name: 'x'.repeat(30_000) }
    const p = partitionStored([m, broken, null])
    expect(p.models).toEqual([m])
    expect(p.invalid).toEqual([broken, null])
  })

  it('partitionStored treats a repeated model id as unreadable (no silent merge)', () => {
    const m = sample()
    const p = partitionStored([m, { ...m, name: 'other' }])
    expect(p.models).toHaveLength(1)
    expect(p.invalid).toHaveLength(1)
  })

  it('partitionStored keeps a non-array value as one unreadable entry, ignores null', () => {
    expect(partitionStored({ a: 1 })).toEqual({ models: [], invalid: [{ a: 1 }] })
    expect(partitionStored(null)).toEqual({ models: [], invalid: [] })
  })

  it('rejects non-date timestamps and normalises valid ones', () => {
    const m = sample()
    const bad = validateModel({ ...m, updatedAt: '<img src=x onerror=alert(1)>' })
    expect(bad.ok).toBe(false)
    if (!bad.ok) expect(bad.errors.join()).toContain('updatedAt')
    const good = validateModel({ ...m, createdAt: '2026-02-03', updatedAt: undefined })
    expect(good.ok).toBe(true)
    if (good.ok) {
      expect(good.model.createdAt).toBe('2026-02-03T00:00:00.000Z')
      expect(good.model.updatedAt).toBe('2026-02-03T00:00:00.000Z')
    }
  })

  it('validates recorded rule scores', () => {
    const m = sample()
    const res = validateModel({ ...m, threats: [{ ...m.threats[0], ruleImpact: 7 }] })
    expect(res.ok).toBe(false)
  })

  it('truncates huge schemaVersion values in the error message', () => {
    const res = validateModel({ schemaVersion: 'x'.repeat(10_000) })
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.errors[0].length).toBeLessThan(200)
  })
})
