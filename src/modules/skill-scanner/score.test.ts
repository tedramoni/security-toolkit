import { describe, expect, it } from 'vitest'
import { FAIL_SCORE, SCORE_FORMULA, scoreFindings } from './score'
import type { Category, Finding, Sev } from './types'

let n = 0
function f(severity: Sev, ruleId = `SS-XX-${String(n++).padStart(3, '0')}`, extra: Partial<Finding> = {}): Finding {
  return {
    ruleId,
    category: 'supply-chain' as Category,
    severity,
    baseSeverity: severity,
    title: 't',
    message: 'm',
    path: 'p',
    line: 1,
    column: 1,
    endColumn: 2,
    fingerprint: `${ruleId}:${n}`,
    ...extra,
  }
}

describe('scoreFindings', () => {
  it('empty → PASS 0', () => {
    const s = scoreFindings([])
    expect(s).toMatchObject({ score: 0, verdict: 'PASS' })
    expect(s.reasons[0]).toMatch(/no findings/)
  })

  it('any firm critical → FAIL', () => {
    expect(scoreFindings([f('critical')]).verdict).toBe('FAIL')
  })

  it('a single high or medium → REVIEW', () => {
    expect(scoreFindings([f('high')])).toMatchObject({ verdict: 'REVIEW', score: 15 })
    expect(scoreFindings([f('medium')])).toMatchObject({ verdict: 'REVIEW', score: 6 })
  })

  it('low/info only → PASS while under the review threshold', () => {
    expect(scoreFindings([f('low'), f('low'), f('info')])).toMatchObject({ verdict: 'PASS', score: 4 })
    expect(scoreFindings(Array.from({ length: 5 }, () => f('low'))).verdict).toBe('REVIEW')
  })

  it('repeat occurrences of one rule add 25% each, capped at 2×', () => {
    expect(scoreFindings([f('high', 'SS-A'), f('high', 'SS-A')]).score).toBe(Math.round(15 * 1.25))
    expect(scoreFindings(Array.from({ length: 20 }, () => f('high', 'SS-B'))).score).toBe(30)
  })

  it('possible false positives count half and do not drive the verdict', () => {
    const fp = f('medium', 'SS-C', { baseSeverity: 'high', possibleFalsePositive: 'docs' })
    expect(scoreFindings([fp])).toMatchObject({ score: 3, verdict: 'PASS' })
  })

  it('score ≥ FAIL threshold fails even without criticals; score is capped at 100', () => {
    const many = Array.from({ length: 4 }, () => f('high'))
    expect(scoreFindings(many).score).toBe(60)
    expect(scoreFindings(many).verdict).toBe(60 >= FAIL_SCORE ? 'FAIL' : 'REVIEW')
    expect(scoreFindings(Array.from({ length: 10 }, () => f('critical'))).score).toBe(100)
  })

  it('category breakdown sums rule points', () => {
    const s = scoreFindings([f('high', 'SS-D', { category: 'exfiltration' }), f('low', 'SS-E', { category: 'secrets' })])
    expect(s.byCategory).toEqual([
      { category: 'exfiltration', points: 15, count: 1 },
      { category: 'secrets', points: 2, count: 1 },
    ])
  })

  it('documents the formula', () => {
    expect(SCORE_FORMULA.join(' ')).toMatch(/critical 40/)
  })
})
