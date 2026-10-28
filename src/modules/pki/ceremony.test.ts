import { describe, expect, it } from 'vitest'
import { analyzeQuorum, binomial, ceremonyMarkdown, EMPTY_CEREMONY, sanitizeDraft } from './ceremony'
import { cpsMarkdown, EMPTY_CPS, parsePolicyOids, RFC3647_OUTLINE, sanitizeCps } from './cps'

describe('M-of-N math', () => {
  it('binomial coefficients', () => {
    expect(binomial(5, 3)).toBe(10)
    expect(binomial(15, 7)).toBe(6435)
    expect(binomial(15, 15)).toBe(1)
    expect(binomial(7, 0)).toBe(1)
    expect(binomial(3, 4)).toBe(0)
  })
  it('3-of-5 is a good balance', () => {
    const q = analyzeQuorum(3, 5)
    expect(q).toMatchObject({ lossTolerance: 2, collusionThreshold: 3, quorums: 10 })
    expect(q.warnings).toEqual([])
    expect(q.recommendation).toContain('Good balance')
  })
  it('warns on M=1, M=N and M ≤ N/2', () => {
    expect(analyzeQuorum(1, 5).warnings.map((w) => w.text).join()).toContain('M = 1')
    expect(analyzeQuorum(4, 4).warnings.map((w) => w.text).join()).toContain('M = N')
    expect(analyzeQuorum(2, 6).warnings.map((w) => w.text).join()).toContain('M ≤ N/2')
    expect(analyzeQuorum(1, 1).recommendation).toContain('Not recommended')
  })
  it('clamps out-of-range input', () => {
    expect(analyzeQuorum(20, 30)).toMatchObject({ m: 15, n: 15 })
    expect(analyzeQuorum(0, 0)).toMatchObject({ m: 1, n: 1 })
    expect(analyzeQuorum(9, 4)).toMatchObject({ m: 4, n: 4 })
  })
})

describe('ceremony runbook', () => {
  it('contains every section and escapes untrusted text', () => {
    const md = ceremonyMarkdown({
      ...EMPTY_CEREMONY,
      caName: 'Acme <script>alert(1)</script> Root',
      m: 2,
      n: 3,
      participants: [
        { id: '1', name: 'Alice | Admin', role: 'Ceremony Administrator', organization: 'Acme' },
        { id: '2', name: 'Bob', role: 'Key Custodian', organization: '' },
      ],
    })
    for (const h of ['Preparation checklist', 'Participants and roles', 'tamper-evident bag serials', 'identity verification', 'HSM initialization', 'Key generation', 'M-of-N split (2-of-3)', 'self-signing', 'Verification of fingerprints', 'Secure storage', 'Exception log', 'Sign-off']) {
      expect(md).toContain(h)
    }
    expect(md).not.toContain('<script>')
    expect(md).toContain('&lt;script&gt;')
    expect(md).toContain('Alice \\| Admin')
    expect(md).toContain('| Card 1 of 3 | Bob |')
  })
  it('sanitizes persisted drafts', () => {
    const d = sanitizeDraft({ caName: 42, m: 'x', participants: [{ name: 'A' }, null], notes: 'n' })
    expect(d.caName).toBe('')
    expect(d.m).toBe(3)
    expect(d.participants).toHaveLength(2)
    expect(d.participants[1].role).toBe('Key Custodian')
    expect(sanitizeDraft(null)).toEqual({ ...EMPTY_CEREMONY })
  })
})

describe('CPS outline (RFC 3647 §6)', () => {
  it('has the 9 top-level sections and the expected subsections', () => {
    const top = RFC3647_OUTLINE.filter(([n]) => !n.includes('.')).map(([, t]) => t)
    expect(top).toEqual([
      'Introduction',
      'Publication and repository responsibilities',
      'Identification and authentication',
      'Certificate life-cycle operational requirements',
      'Facility, management, and operational controls',
      'Technical security controls',
      'Certificate, CRL, and OCSP profiles',
      'Compliance audit and other assessments',
      'Other business and legal matters',
    ])
    const nums = RFC3647_OUTLINE.map(([n]) => n)
    expect(new Set(nums).size).toBe(nums.length)
    expect(nums).toContain('4.9.16')
    expect(nums).toContain('6.2.11')
    expect(nums).toContain('9.17')
    expect(nums.filter((n) => n.startsWith('4.9.'))).toHaveLength(16)
  })
  it('pre-fills fields and exports Markdown', () => {
    const md = cpsMarkdown({ ...EMPTY_CPS, caName: 'Acme Root CA', orgName: 'Acme', policyOids: '1.3.6.1.4.1.99999.1.1, bad.oid', contactEmail: 'pki@acme.example', repositoryUrl: 'javascript:alert(1)' })
    expect(md).toContain('# Acme Root CA — Certification Practice Statement')
    expect(md).toContain('## 1. INTRODUCTION')
    expect(md).toContain('#### 4.9.16 Limits on suspension period')
    expect(md).toContain('`1.3.6.1.4.1.99999.1.1`')
    expect(md).not.toContain('bad.oid')
    expect(md).not.toContain('javascript:')
    expect(md).toContain('pki@acme.example')
    expect(parsePolicyOids('1.2.3 4.5 2.999').invalid).toEqual(['4.5'])
  })
  it('sanitizes persisted CPS drafts', () => {
    const d = sanitizeCps({ docType: 'X', sections: { '1.1': 'ok', 'evil key': 'x', '2.1': 5 } })
    expect(d.docType).toBe('CPS')
    expect(d.sections).toEqual({ '1.1': 'ok' })
  })
})
