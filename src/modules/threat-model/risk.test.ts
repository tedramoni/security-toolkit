import { describe, expect, it } from 'vitest'
import { clampScore, compareRisk, riskClass, riskLevel, riskOf, riskScore } from './risk.ts'

describe('risk', () => {
  it('computes likelihood x impact', () => {
    expect(riskScore(1, 1)).toBe(1)
    expect(riskScore(2, 3)).toBe(6)
    expect(riskScore(3, 3)).toBe(9)
  })

  it.each([
    [1, 'low'],
    [2, 'low'],
    [3, 'medium'],
    [4, 'medium'],
    [6, 'high'],
    [9, 'critical'],
  ] as const)('score %i -> %s', (score, level) => {
    expect(riskLevel(score)).toBe(level)
  })

  it('maps every 3x3 combination to the documented label', () => {
    const grid = [1, 2, 3].map((l) => [1, 2, 3].map((i) => riskOf({ likelihood: l, impact: i })))
    expect(grid).toEqual([
      ['low', 'low', 'medium'],
      ['low', 'medium', 'high'],
      ['medium', 'high', 'critical'],
    ])
  })

  it('clamps out-of-range and non-finite input', () => {
    expect(clampScore(0)).toBe(1)
    expect(clampScore(7)).toBe(3)
    expect(clampScore(2.4)).toBe(2)
    expect(clampScore(Number.NaN)).toBe(1)
    expect(clampScore(Infinity)).toBe(1)
    expect(riskScore(10, 10)).toBe(9)
  })

  it('returns the design-system class', () => {
    expect(riskClass('critical')).toBe('sev-critical')
    expect(riskClass('low')).toBe('sev-low')
  })

  it('sorts highest risk first', () => {
    const list = [
      { likelihood: 1, impact: 1 },
      { likelihood: 3, impact: 3 },
      { likelihood: 2, impact: 2 },
    ]
    expect([...list].sort(compareRisk).map((t) => t.likelihood * t.impact)).toEqual([9, 4, 1])
  })
})
