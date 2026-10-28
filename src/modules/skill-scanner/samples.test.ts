import { describe, expect, it } from 'vitest'
import { scanFilesSync } from './engine'
import { SAMPLES } from './samples'
import { scoreFindings } from './score'

const run = (id: string) => {
  const s = SAMPLES.find((x) => x.id === id)!
  const r = scanFilesSync(s.files)
  return { ...r, score: scoreFindings(r.findings), ids: new Set(r.findings.map((f) => f.ruleId)) }
}

describe('built-in samples', () => {
  it('benign sample passes; its mentions of dangerous commands are possible false positives', () => {
    const r = run('benign')
    expect(r.score.verdict).toBe('PASS')
    expect(r.findings.every((f) => f.possibleFalsePositive || f.severity === 'low' || f.severity === 'info')).toBe(true)
  })

  it('malicious sample fails with the headline techniques detected', () => {
    const r = run('malicious')
    expect(r.score.verdict).toBe('FAIL')
    for (const id of ['SS-UC-001', 'SS-PI-001', 'SS-EX-009', 'SS-SC-001', 'SS-SC-002', 'SS-RA-002', 'SS-MC-001', 'SS-MC-005', 'SS-PI-007', 'SS-CS-001', 'SS-CS-004', 'SS-BN-001', 'SS-TR-001', 'SS-PM-001', 'SS-HC-004']) {
      expect(r.ids.has(id), id).toBe(true)
    }
    const tag = r.findings.find((f) => f.ruleId === 'SS-UC-001')!
    expect(tag.message).toContain('webhook.site')
  })

  it('subtle sample needs review or fails, with the subtle tricks detected', () => {
    const r = run('subtle')
    expect(['REVIEW', 'FAIL']).toContain(r.score.verdict)
    for (const id of ['SS-UC-005', 'SS-HC-002', 'SS-HC-004', 'SS-EX-008', 'SS-UC-003', 'SS-TM-002', 'SS-SC-005']) expect(r.ids.has(id), id).toBe(true)
  })
})
