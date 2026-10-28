/** Qualitative risk = likelihood (1-3) x impact (1-3). */

export const RISK_LEVELS = ['low', 'medium', 'high', 'critical'] as const
export type RiskLevel = (typeof RISK_LEVELS)[number]

export const RISK_LABELS: Record<RiskLevel, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}

export const LIKELIHOOD_LABELS: Record<number, string> = {
  1: '1 – Unlikely (needs insider access or rare conditions)',
  2: '2 – Possible (skilled attacker, some preconditions)',
  3: '3 – Likely (well-known technique, easy to reach)',
}

export const IMPACT_LABELS: Record<number, string> = {
  1: '1 – Minor (limited, easily recoverable)',
  2: '2 – Significant (one customer / partial outage / internal data)',
  3: '3 – Severe (many users, regulated data, money, full compromise)',
}

/** Clamp to the 1..3 integer scale (defensive: values may come from imported JSON or form input). */
export function clampScore(n: number): number {
  if (!Number.isFinite(n)) return 1
  return Math.min(3, Math.max(1, Math.round(n)))
}

export function riskScore(likelihood: number, impact: number): number {
  return clampScore(likelihood) * clampScore(impact)
}

/** 1-2 low, 3-4 medium, 6 high, 9 critical. */
export function riskLevel(score: number): RiskLevel {
  if (score >= 9) return 'critical'
  if (score >= 6) return 'high'
  if (score >= 3) return 'medium'
  return 'low'
}

export function riskOf(t: { likelihood: number; impact: number }): RiskLevel {
  return riskLevel(riskScore(t.likelihood, t.impact))
}

/** CSS class from the global design system. */
export function riskClass(level: RiskLevel): string {
  return `sev-${level}`
}

/** Higher first. */
export function compareRisk(a: { likelihood: number; impact: number }, b: { likelihood: number; impact: number }): number {
  return riskScore(b.likelihood, b.impact) - riskScore(a.likelihood, a.impact)
}
