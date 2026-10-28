import { describe, expect, it } from 'vitest'
import { STACKS } from '../types'
import { CHECKLISTS, getChecklist } from './index'

const CWE_RE = /^CWE-[1-9]\d*$/
const ASVS_RE = /^v5\.0\.0-([1-9]\d?)\.([1-9]\d?)\.([1-9]\d?)$/
const ITEM_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/

describe('checklist data integrity', () => {
  it('has unique checklist ids and resolves them', () => {
    const ids = CHECKLISTS.map((c) => c.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const id of ids) expect(getChecklist(id)?.id).toBe(id)
    expect(getChecklist('nope')).toBeUndefined()
  })

  for (const checklist of CHECKLISTS) {
    describe(checklist.title, () => {
      it('has metadata and an https source', () => {
        expect(checklist.title.trim()).not.toBe('')
        expect(checklist.version.trim()).not.toBe('')
        expect(checklist.description.trim()).not.toBe('')
        expect(new URL(checklist.source).protocol).toBe('https:')
      })

      it('has unique category ids and every category has items', () => {
        const ids = checklist.categories.map((c) => c.id)
        expect(new Set(ids).size).toBe(ids.length)
        expect(checklist.categories.length).toBeGreaterThan(0)
        for (const c of checklist.categories) {
          expect(c.title.trim(), c.id).not.toBe('')
          expect(c.description.trim(), c.id).not.toBe('')
          expect(c.items.length, c.id).toBeGreaterThan(0)
        }
      })

      it('has unique, well-formed item ids', () => {
        const ids = checklist.categories.flatMap((c) => c.items.map((i) => i.id))
        const dupes = ids.filter((id, i) => ids.indexOf(id) !== i)
        expect(dupes).toEqual([])
        for (const id of ids) expect(id).toMatch(ITEM_ID_RE)
      })

      it('has non-empty text and detail, valid stacks and refs', () => {
        for (const c of checklist.categories) {
          for (const item of c.items) {
            expect(item.text.trim().length, item.id).toBeGreaterThan(10)
            expect(item.detail.trim().length, item.id).toBeGreaterThan(20)
            if (item.stacks) {
              expect(item.stacks.length, item.id).toBeGreaterThan(0)
              expect(new Set(item.stacks).size, item.id).toBe(item.stacks.length)
              for (const s of item.stacks) expect(STACKS, item.id).toContain(s)
            }
            for (const ref of item.refs ?? []) {
              expect(CWE_RE.test(ref) || ASVS_RE.test(ref), `${item.id}: ${ref}`).toBe(true)
            }
            if (item.refs) expect(new Set(item.refs).size, item.id).toBe(item.refs.length)
          }
        }
      })
    })
  }

  it('OWASP Top 10 uses the 2025 categories A01..A10 in order', () => {
    const c = getChecklist('owasp-top10-2025')!
    expect(c.categories.map((x) => x.id)).toEqual(['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'])
    expect(c.categories.map((x) => x.title.split(' – ')[1])).toEqual([
      'Broken Access Control',
      'Security Misconfiguration',
      'Software Supply Chain Failures',
      'Cryptographic Failures',
      'Injection',
      'Insecure Design',
      'Authentication Failures',
      'Software or Data Integrity Failures',
      'Security Logging and Alerting Failures',
      'Mishandling of Exceptional Conditions',
    ])
    for (const cat of c.categories) {
      expect(cat.items.length).toBeGreaterThanOrEqual(4)
      expect(cat.items.length).toBeLessThanOrEqual(8)
    }
  })

  it('API Top 10 uses the exact 2023 titles', () => {
    const c = getChecklist('owasp-api-2023')!
    expect(c.categories.map((x) => x.title)).toEqual([
      'API1:2023 – Broken Object Level Authorization',
      'API2:2023 – Broken Authentication',
      'API3:2023 – Broken Object Property Level Authorization',
      'API4:2023 – Unrestricted Resource Consumption',
      'API5:2023 – Broken Function Level Authorization',
      'API6:2023 – Unrestricted Access to Sensitive Business Flows',
      'API7:2023 – Server Side Request Forgery',
      'API8:2023 – Security Misconfiguration',
      'API9:2023 – Improper Inventory Management',
      'API10:2023 – Unsafe Consumption of APIs',
    ])
    for (const cat of c.categories) {
      expect(cat.items.length).toBeGreaterThanOrEqual(3)
      expect(cat.items.length).toBeLessThanOrEqual(6)
    }
  })

  it('ASVS items carry a level, an ASVS ref matching their id and their chapter', () => {
    const c = getChecklist('asvs-5-subset')!
    const items = c.categories.flatMap((cat) => cat.items.map((item) => ({ cat, item })))
    expect(items.length).toBeGreaterThanOrEqual(40)
    expect(items.length).toBeLessThanOrEqual(70)
    for (const { cat, item } of items) {
      expect([1, 2]).toContain(item.level)
      const num = item.id.replace(/^asvs-/, '')
      expect(item.refs?.[0]).toBe(`v5.0.0-${num}`)
      expect(cat.id).toBe(`V${num.split('.')[0]}`)
    }
  })

  it('PR quick review has 15-20 items', () => {
    const c = getChecklist('pr-quick')!
    const n = c.categories.reduce((a, cat) => a + cat.items.length, 0)
    expect(n).toBeGreaterThanOrEqual(15)
    expect(n).toBeLessThanOrEqual(20)
  })
})
