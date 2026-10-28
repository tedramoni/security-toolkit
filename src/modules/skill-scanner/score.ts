import type { Category, Finding, Sev } from './types'

export const SEVERITY_WEIGHT: Record<Sev, number> = { critical: 40, high: 15, medium: 6, low: 2, info: 0 }
export const REPEAT_FACTOR = 0.25
export const FP_FACTOR = 0.5
export const RULE_CAP_FACTOR = 2
export const FAIL_SCORE = 50
export const REVIEW_SCORE = 10

export type Verdict = 'PASS' | 'REVIEW' | 'FAIL'

export interface ScoreResult {
  score: number
  verdict: Verdict
  /** Why the verdict was reached (human readable). */
  reasons: string[]
  byCategory: { category: Category; points: number; count: number }[]
  byRule: { ruleId: string; points: number; count: number }[]
}

/** Transparent formula, rendered verbatim in the UI. */
export const SCORE_FORMULA = [
  `Weights: critical ${SEVERITY_WEIGHT.critical}, high ${SEVERITY_WEIGHT.high}, medium ${SEVERITY_WEIGHT.medium}, low ${SEVERITY_WEIGHT.low}, info ${SEVERITY_WEIGHT.info}.`,
  `Per rule: the most severe occurrence counts its full weight; every further occurrence adds ${REPEAT_FACTOR * 100}% of its weight; a rule contributes at most ${RULE_CAP_FACTOR}× its top weight.`,
  `Findings marked "possible false positive" are already one severity lower and count ${FP_FACTOR * 100}%. Suppressed findings count 0.`,
  `Score = min(100, sum over rules), rounded.`,
  `Verdict: FAIL if any critical finding (not a possible false positive) or score ≥ ${FAIL_SCORE}; REVIEW if any high/medium finding (not a possible false positive) or score ≥ ${REVIEW_SCORE}; otherwise PASS.`,
]

export function scoreFindings(findings: readonly Finding[]): ScoreResult {
  const byRule = new Map<string, Finding[]>()
  for (const f of findings) byRule.set(f.ruleId, [...(byRule.get(f.ruleId) ?? []), f])
  const ruleRows: ScoreResult['byRule'] = []
  const cat = new Map<Category, { points: number; count: number }>()
  let total = 0
  for (const [ruleId, list] of byRule) {
    const weighted = list
      .map((f) => SEVERITY_WEIGHT[f.severity] * (f.possibleFalsePositive ? FP_FACTOR : 1))
      .sort((a, b) => b - a)
    const top = weighted[0] ?? 0
    let pts = top
    for (let i = 1; i < weighted.length; i++) pts += weighted[i] * REPEAT_FACTOR
    pts = Math.min(pts, top * RULE_CAP_FACTOR)
    total += pts
    ruleRows.push({ ruleId, points: pts, count: list.length })
    const c = cat.get(list[0].category) ?? { points: 0, count: 0 }
    c.points += pts
    c.count += list.length
    cat.set(list[0].category, c)
  }
  const score = Math.min(100, Math.round(total))
  const firm = findings.filter((f) => !f.possibleFalsePositive)
  const crit = firm.filter((f) => f.severity === 'critical').length
  const highMed = firm.filter((f) => f.severity === 'high' || f.severity === 'medium').length
  const reasons: string[] = []
  let verdict: Verdict = 'PASS'
  if (crit > 0 || score >= FAIL_SCORE) {
    verdict = 'FAIL'
    if (crit > 0) reasons.push(`${crit} critical finding${crit > 1 ? 's' : ''}`)
    if (score >= FAIL_SCORE) reasons.push(`score ${score} ≥ ${FAIL_SCORE}`)
  } else if (highMed > 0 || score >= REVIEW_SCORE) {
    verdict = 'REVIEW'
    if (highMed > 0) reasons.push(`${highMed} high/medium finding${highMed > 1 ? 's' : ''}`)
    if (score >= REVIEW_SCORE) reasons.push(`score ${score} ≥ ${REVIEW_SCORE}`)
  } else {
    reasons.push(findings.length === 0 ? 'no findings' : 'only low/info findings or possible false positives')
  }
  return {
    score,
    verdict,
    reasons,
    byCategory: [...cat.entries()].map(([category, v]) => ({ category, ...v })).sort((a, b) => b.points - a.points || b.count - a.count),
    byRule: ruleRows.sort((a, b) => b.points - a.points),
  }
}
