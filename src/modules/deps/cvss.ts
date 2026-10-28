/**
 * CVSS v3.0 / v3.1 base score calculator.
 * Spec: https://www.first.org/cvss/v3.1/specification-document (section 7 "Equations" and Appendix A "Roundup").
 */

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 }, // privileges required weigh differently when scope changes
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const

const ALLOWED: Record<string, readonly string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
}

/** CVSS v3.1 Roundup (Appendix A): avoids floating point artefacts such as 4.000000000001 -> 4.1. */
export function roundUp31(x: number): number {
  const i = Math.round(x * 100000)
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10
}

/** CVSS v3.0 round up: smallest number with one decimal >= x. */
export function roundUp30(x: number): number {
  return Math.ceil(x * 10) / 10
}

export interface Cvss3 {
  version: '3.0' | '3.1'
  metrics: Record<string, string>
  baseScore: number
}

/** Parse a CVSS v3.x vector and compute its base score. Returns null for anything that is not a valid v3 vector. */
export function parseCvss3(vector: string): Cvss3 | null {
  const parts = vector.trim().split('/')
  const head = /^CVSS:(3\.[01])$/.exec(parts[0] ?? '')
  if (!head) return null
  const version = head[1] as '3.0' | '3.1'
  const metrics: Record<string, string> = {}
  for (const part of parts.slice(1)) {
    const [k, v, extra] = part.split(':')
    if (!k || v === undefined || extra !== undefined) return null
    if (k in metrics) return null // duplicate metric is invalid
    metrics[k] = v
  }
  for (const [k, allowed] of Object.entries(ALLOWED)) {
    if (!allowed.includes(metrics[k])) return null // every base metric is mandatory
  }
  return { version, metrics, baseScore: baseScore(metrics, version) }
}

function baseScore(m: Record<string, string>, version: '3.0' | '3.1'): number {
  const roundUp = version === '3.1' ? roundUp31 : roundUp30
  const changed = m.S === 'C'
  const iss =
    1 -
    (1 - W.CIA[m.C as 'H' | 'L' | 'N']) * (1 - W.CIA[m.I as 'H' | 'L' | 'N']) * (1 - W.CIA[m.A as 'H' | 'L' | 'N'])
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss
  const pr = (changed ? W.PR_C : W.PR_U)[m.PR as 'N' | 'L' | 'H']
  const exploitability =
    8.22 * W.AV[m.AV as 'N' | 'A' | 'L' | 'P'] * W.AC[m.AC as 'L' | 'H'] * pr * W.UI[m.UI as 'N' | 'R']
  if (impact <= 0) return 0
  return changed ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10))
}

/** Qualitative severity rating scale (CVSS v3.1 spec, section 5). */
export function cvssRating(score: number): 'none' | 'low' | 'medium' | 'high' | 'critical' {
  if (score === 0) return 'none'
  if (score < 4) return 'low'
  if (score < 7) return 'medium'
  if (score < 9) return 'high'
  return 'critical'
}
