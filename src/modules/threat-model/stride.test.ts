import { describe, expect, it } from 'vitest'
import { exampleModel } from './example.ts'
import type { ModelElement, ThreatModel } from './model.ts'
import { createFlow, createModel, createNode, removeElement, STRIDE, upsertElement } from './model.ts'
import {
  applicableCategories,
  buildContext,
  generateCandidates,
  impactForClassification,
  mergeThreats,
  refreshThreats,
  removeStaleThreats,
  RULES,
  suggestedMitigationText,
  transportSecurity,
} from './stride.ts'

let seq = 0
const ids = () => `t${++seq}`

function model(elements: ModelElement[]): ThreatModel {
  const m = createModel('m1', 'Test', '2026-01-01T00:00:00.000Z')
  m.elements = elements
  return m
}

const rulesFor = (m: ThreatModel, elementId: string) =>
  generateCandidates(m)
    .filter((c) => c.elementId === elementId)
    .map((c) => c.ruleId)

const candidate = (m: ThreatModel, elementId: string, ruleId: string) =>
  generateCandidates(m).find((c) => c.elementId === elementId && c.ruleId === ruleId)

describe('applicableCategories (STRIDE per element)', () => {
  it('follows the Microsoft SDL chart', () => {
    expect(applicableCategories({ type: 'external', tags: [] })).toEqual(['S', 'R'])
    expect(applicableCategories({ type: 'process', tags: [] })).toEqual(['S', 'T', 'R', 'I', 'D', 'E'])
    expect(applicableCategories({ type: 'datastore', tags: [] })).toEqual(['T', 'I', 'D'])
    expect(applicableCategories({ type: 'dataflow', tags: [] })).toEqual(['T', 'I', 'D'])
  })
  it('adds Repudiation for log / audit stores', () => {
    expect(applicableCategories({ type: 'datastore', tags: ['logs'] })).toEqual(['T', 'R', 'I', 'D'])
  })
})

describe('rule catalogue', () => {
  it('has 30+ rules with unique ids', () => {
    expect(RULES.length).toBeGreaterThanOrEqual(30)
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length)
  })

  it('every rule has actionable mitigations and https references', () => {
    for (const r of RULES) {
      expect(r.mitigations.length, r.id).toBeGreaterThanOrEqual(2)
      for (const m of r.mitigations) expect(m.length, r.id).toBeGreaterThan(20)
      expect(r.references.length, r.id).toBeGreaterThanOrEqual(1)
      for (const ref of r.references) expect(ref, r.id).toMatch(/^https:\/\/\S+$/)
    }
  })

  it('rule ids encode element type and category consistently', () => {
    const prefix = { external: 'EXT', process: 'PROC', datastore: 'DS', dataflow: 'DF' }
    for (const r of RULES) expect(r.id.startsWith(`${prefix[r.appliesTo]}-${r.category}-`), r.id).toBe(true)
  })

  it('each rule category is allowed for its element type (R on data stores only for logs)', () => {
    for (const r of RULES) {
      const tags = r.appliesTo === 'datastore' && r.category === 'R' ? ['logs'] : []
      expect(applicableCategories({ type: r.appliesTo, tags }), r.id).toContain(r.category)
    }
  })
})

describe('transportSecurity', () => {
  it.each([
    ['HTTPS', 'encrypted'],
    ['https', 'encrypted'],
    ['gRPC over TLS', 'encrypted'],
    ['PostgreSQL over TLS', 'encrypted'],
    ['TLS syslog', 'encrypted'],
    ['SFTP', 'encrypted'],
    ['wss', 'encrypted'],
    ['mTLS', 'encrypted'],
    ['HTTP', 'plaintext'],
    ['http/1.1', 'plaintext'],
    ['FTP', 'plaintext'],
    ['telnet', 'plaintext'],
    ['plain TCP', 'plaintext'],
    ['ws', 'plaintext'],
    ['SMTP', 'plaintext'],
    ['PostgreSQL', 'unknown'],
    ['Kafka', 'unknown'],
    ['', 'unknown'],
    [undefined, 'unknown'],
  ] as const)('%s -> %s', (proto, expected) => {
    expect(transportSecurity(proto)).toBe(expected)
  })

  it('does not confuse https with http', () => {
    expect(transportSecurity('HTTPS/2')).toBe('encrypted')
  })
})

describe('impactForClassification', () => {
  it('maps public→1, internal→2, confidential/secret→3', () => {
    expect(impactForClassification('public')).toBe(1)
    expect(impactForClassification('internal')).toBe(2)
    expect(impactForClassification('confidential')).toBe(3)
    expect(impactForClassification('secret')).toBe(3)
    expect(impactForClassification(undefined)).toBe(2)
  })
})

describe('generateCandidates — specific rules', () => {
  const user = createNode('u', 'external', 'User', ['human'])
  const api = createNode('api', 'process', 'API')
  const db = createNode('db', 'datastore', 'DB')

  it('flags cleartext flows crossing a trust boundary as likely info disclosure and tampering', () => {
    const f = createFlow('f', 'u', 'api', { protocol: 'HTTP', crossesTrustBoundary: true, dataClassification: 'confidential' })
    const m = model([user, api, f])
    const i = candidate(m, 'f', 'DF-I-01')
    const t = candidate(m, 'f', 'DF-T-01')
    expect(i).toMatchObject({ category: 'I', likelihood: 3, impact: 3 })
    expect(t).toMatchObject({ category: 'T', likelihood: 3 })
    expect(i?.title).toContain('User → API')
  })

  it('raises impact with data classification', () => {
    const pub = createFlow('f', 'u', 'api', { protocol: 'ftp', crossesTrustBoundary: true, dataClassification: 'public' })
    const sec = createFlow('f', 'u', 'api', { protocol: 'ftp', crossesTrustBoundary: true, dataClassification: 'secret' })
    expect(candidate(model([user, api, pub]), 'f', 'DF-I-01')?.impact).toBe(1)
    expect(candidate(model([user, api, sec]), 'f', 'DF-I-01')?.impact).toBe(3)
  })

  it('does not flag cleartext rules for HTTPS flows; checks TLS config for sensitive ones instead', () => {
    const f = createFlow('f', 'u', 'api', { protocol: 'HTTPS', crossesTrustBoundary: true, dataClassification: 'confidential' })
    const rules = rulesFor(model([user, api, f]), 'f')
    expect(rules).not.toContain('DF-I-01')
    expect(rules).not.toContain('DF-T-01')
    expect(rules).toContain('DF-I-04')
    expect(rules).toContain('DF-T-02')
    expect(rules).toContain('DF-D-01')
  })

  it('asks to confirm encryption when the protocol is ambiguous across a boundary', () => {
    const f = createFlow('f', 'api', 'db', { protocol: 'PostgreSQL', crossesTrustBoundary: true })
    expect(rulesFor(model([api, db, f]), 'f')).toContain('DF-I-03')
  })

  it('flags internal cleartext only when the data is sensitive', () => {
    const internal = createFlow('f', 'api', 'db', { protocol: 'tcp', dataClassification: 'internal' })
    const conf = createFlow('f', 'api', 'db', { protocol: 'tcp', dataClassification: 'confidential' })
    expect(rulesFor(model([api, db, internal]), 'f')).not.toContain('DF-I-02')
    expect(rulesFor(model([api, db, conf]), 'f')).toContain('DF-I-02')
  })

  it('internal HTTPS flow with internal data produces no flow threats', () => {
    const f = createFlow('f', 'api', 'db', { protocol: 'HTTPS', dataClassification: 'internal' })
    expect(rulesFor(model([api, db, f]), 'f')).toEqual([])
  })

  it('secret data in transit triggers the secrets-in-URL rule', () => {
    const f = createFlow('f', 'api', 'db', { protocol: 'HTTPS', dataClassification: 'secret' })
    expect(rulesFor(model([api, db, f]), 'f')).toContain('DF-I-05')
  })

  it('credential stores get a credential-theft threat recommending argon2id and KMS', () => {
    const creds = createNode('db', 'datastore', 'Users DB', ['stores-credentials'])
    const c = candidate(model([creds]), 'db', 'DS-I-02')
    expect(c).toBeDefined()
    expect(c?.impact).toBe(3)
    expect(c?.mitigations.join(' ')).toMatch(/Argon2id/)
    expect(c?.mitigations.join(' ')).toMatch(/KMS/)
  })

  it('internet-facing processes get DoS and account-takeover threats', () => {
    const web = createNode('web', 'process', 'Web', ['internet-facing'])
    const rules = rulesFor(model([web]), 'web')
    expect(rules).toEqual(expect.arrayContaining(['PROC-D-01', 'PROC-S-02', 'PROC-T-02', 'PROC-E-04']))
    expect(candidate(model([web]), 'web', 'PROC-S-02')?.likelihood).toBe(3)
    const dos = candidate(model([web]), 'web', 'PROC-D-01')
    expect(dos?.mitigations.join(' ')).toMatch(/rate limiting/i)
  })

  it('a plain internal process does not get internet-only threats', () => {
    const worker = createNode('w', 'process', 'Worker')
    const rules = rulesFor(model([worker]), 'w')
    expect(rules).not.toContain('PROC-D-01')
    expect(rules).not.toContain('PROC-S-02')
    expect(rules).toEqual(expect.arrayContaining(['PROC-S-01', 'PROC-R-01', 'PROC-I-01', 'PROC-E-01', 'PROC-E-03', 'PROC-T-04']))
  })

  it('admin processes get an elevation-of-privilege threat', () => {
    const admin = createNode('a', 'process', 'Back office', ['admin'])
    const c = candidate(model([admin]), 'a', 'PROC-E-02')
    expect(c).toMatchObject({ category: 'E', impact: 3, likelihood: 2 })
    const exposed = createNode('a', 'process', 'Back office', ['admin', 'internet-facing'])
    expect(candidate(model([exposed]), 'a', 'PROC-E-02')?.likelihood).toBe(3)
  })

  it('auth-handling processes get token/session and lockout threats', () => {
    const idp = createNode('idp', 'process', 'Auth', ['handles-auth'])
    expect(rulesFor(model([idp]), 'idp')).toEqual(expect.arrayContaining(['PROC-S-02', 'PROC-S-03', 'PROC-D-03']))
  })

  it('third-party externals that send data get webhook-spoofing threats; process gets untrusted-data threat', () => {
    const psp = createNode('psp', 'external', 'Stripe', ['third-party'])
    const inbound = createFlow('f', 'psp', 'api', { protocol: 'HTTPS', crossesTrustBoundary: true })
    const m = model([psp, api, inbound])
    const c = candidate(m, 'psp', 'EXT-S-02')
    expect(c?.mitigations.join(' ')).toMatch(/signature/i)
    expect(rulesFor(m, 'psp')).toContain('EXT-S-03')
    expect(candidate(m, 'api', 'PROC-T-03')?.title).toContain('Stripe')
  })

  it('third-party externals that only receive data do not get the webhook rule', () => {
    const psp = createNode('psp', 'external', 'Vendor', ['third-party'])
    const out = createFlow('f', 'api', 'psp', { protocol: 'HTTPS' })
    const m = model([psp, api, out])
    expect(rulesFor(m, 'psp')).not.toContain('EXT-S-02')
    // the calling process gets SSRF and leaked-credential threats
    expect(rulesFor(m, 'api')).toEqual(expect.arrayContaining(['PROC-I-03', 'PROC-I-04']))
  })

  it('log stores get Repudiation (tamper-evident) and the flow into them gets log injection', () => {
    const logs = createNode('l', 'datastore', 'Audit log', ['logs'])
    const f = createFlow('f', 'api', 'l', { protocol: 'HTTPS' })
    const m = model([api, logs, f])
    const r = candidate(m, 'l', 'DS-R-01')
    expect(r?.category).toBe('R')
    expect(r?.mitigations.join(' ')).toMatch(/append-only/i)
    expect(rulesFor(m, 'f')).toContain('DF-T-03')
  })

  it('non-log data stores never get Repudiation threats', () => {
    const m = model([db])
    expect(generateCandidates(m).some((c) => c.category === 'R')).toBe(false)
  })

  it('PII stores get privacy threats with high impact', () => {
    const pii = createNode('p', 'datastore', 'Customers', ['stores-pii'])
    expect(candidate(model([pii]), 'p', 'DS-I-03')?.impact).toBe(3)
    expect(candidate(model([pii]), 'p', 'DS-I-01')?.impact).toBe(3)
  })

  it('uses the highest classification of attached flows for element impact', () => {
    const f1 = createFlow('f1', 'api', 'db', { dataClassification: 'public', protocol: 'HTTPS' })
    const f2 = createFlow('f2', 'api', 'db', { dataClassification: 'confidential', protocol: 'HTTPS' })
    const ctx = buildContext(model([api, db, f1, f2]))
    expect(ctx.maxClassification('db')).toBe('confidential')
    expect(ctx.maxClassification('nope')).toBe('internal')
    const only = buildContext(model([api, db, f1]))
    expect(only.maxClassification('db')).toBe('public')
  })

  it('tolerates dangling flow references', () => {
    const f = createFlow('f', 'ghost', 'api', { protocol: 'HTTP', crossesTrustBoundary: true })
    expect(() => generateCandidates(model([api, f]))).not.toThrow()
    expect(candidate(model([api, f]), 'f', 'DF-I-01')?.title).toContain('? → API')
  })
})

describe('generateCandidates — on the example model', () => {
  const m = exampleModel('ex', '2026-01-01T00:00:00.000Z')
  const cands = generateCandidates(m)

  it('only produces categories applicable to each element', () => {
    for (const c of cands) {
      const el = m.elements.find((e) => e.id === c.elementId)!
      expect(applicableCategories(el), c.ruleId).toContain(c.category)
    }
  })

  it('produces at most one threat per (rule, element)', () => {
    const keys = cands.map((c) => `${c.ruleId}|${c.elementId}`)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('covers every node with at least one threat and all STRIDE categories overall', () => {
    for (const el of m.elements.filter((e) => e.type !== 'dataflow')) {
      expect(cands.some((c) => c.elementId === el.id), el.name).toBe(true)
    }
    for (const c of STRIDE) expect(cands.some((x) => x.category === c)).toBe(true)
  })

  it('flags the legacy HTTP CDN flow', () => {
    expect(cands.find((c) => c.elementId === 'ex-f7' && c.ruleId === 'DF-T-01')).toBeDefined()
  })

  it('scores stay in 1..3 and text has no unresolved placeholders', () => {
    for (const c of cands) {
      expect(c.likelihood).toBeGreaterThanOrEqual(1)
      expect(c.likelihood).toBeLessThanOrEqual(3)
      expect(c.impact).toBeGreaterThanOrEqual(1)
      expect(c.impact).toBeLessThanOrEqual(3)
      expect(c.title).not.toMatch(/undefined|\[object/)
      expect(c.description).not.toMatch(/undefined|\[object/)
    }
  })

  it('is deterministic', () => {
    expect(generateCandidates(m)).toEqual(cands)
  })
})

describe('mergeThreats / refreshThreats', () => {
  const user = createNode('u', 'external', 'User', ['human'])
  const api = createNode('api', 'process', 'API', ['internet-facing'])
  const flow = createFlow('f', 'u', 'api', { protocol: 'HTTP', crossesTrustBoundary: true, dataClassification: 'confidential' })
  const base = () => model([user, api, flow])

  it('first run adds every candidate as open with prefilled mitigation', () => {
    const m = base()
    const { model: out, stats } = refreshThreats(m, ids)
    const n = generateCandidates(m).length
    expect(stats).toEqual({ added: n, refreshed: 0, unchanged: 0, newlyStale: 0, revived: 0 })
    expect(out.threats).toHaveLength(n)
    for (const t of out.threats) {
      expect(t.status).toBe('open')
      expect(t.generated).toBe(true)
      expect(t.ruleId).toBeTruthy()
      expect(t.mitigation).toBe(suggestedMitigationText(t.suggestedMitigations!))
      expect(t.mitigation.startsWith('- ')).toBe(true)
    }
  })

  it('is idempotent: a second run changes nothing', () => {
    const once = refreshThreats(base(), ids).model
    const twice = refreshThreats(once, ids)
    expect(twice.model).toEqual(once)
    expect(twice.stats.added).toBe(0)
    expect(twice.stats.unchanged).toBe(once.threats.length)
    // unchanged threats keep object identity (cheap React re-renders)
    twice.model.threats.forEach((t, i) => expect(t).toBe(once.threats[i]))
  })

  it('keeps user edits on existing generated threats', () => {
    const once = refreshThreats(base(), ids).model
    const target = once.threats.find((t) => t.ruleId === 'DF-I-01')!
    const edited: ThreatModel = {
      ...once,
      threats: once.threats.map((t) =>
        t.id === target.id ? { ...t, status: 'mitigated', mitigation: 'Moved to HTTPS in PR #12', likelihood: 1, impact: 2, owner: 'alice', ticket: 'SEC-1' } : t,
      ),
    }
    const again = refreshThreats(edited, ids).model
    const t = again.threats.find((x) => x.id === target.id)!
    expect(t).toMatchObject({ status: 'mitigated', mitigation: 'Moved to HTTPS in PR #12', likelihood: 1, impact: 2, owner: 'alice', ticket: 'SEC-1' })
    expect(again.threats).toHaveLength(once.threats.length)
  })

  it('refreshes rule-owned wording when an element is renamed, keeping the same threat id and status', () => {
    const once = refreshThreats(base(), ids).model
    const t0 = once.threats.find((t) => t.ruleId === 'PROC-D-01')!
    const withStatus: ThreatModel = { ...once, threats: once.threats.map((t) => (t.id === t0.id ? { ...t, status: 'accepted' } : t)) }
    const renamed = upsertElement(withStatus, { ...api, name: 'Orders API' })
    const { model: out, stats } = refreshThreats(renamed, ids)
    const t1 = out.threats.find((t) => t.id === t0.id)!
    expect(t1.title).toContain('Orders API')
    expect(t1.status).toBe('accepted')
    expect(stats.refreshed).toBeGreaterThan(0)
    expect(stats.added).toBe(0)
  })

  it('flags (does not delete) generated threats whose rule no longer applies, keeping status', () => {
    const once = refreshThreats(base(), ids).model
    const cleartext = once.threats.find((t) => t.ruleId === 'DF-I-01')!
    const accepted: ThreatModel = { ...once, threats: once.threats.map((t) => (t.id === cleartext.id ? { ...t, status: 'accepted' } : t)) }
    const fixed = upsertElement(accepted, { ...flow, protocol: 'HTTPS' })
    const { model: out, stats } = refreshThreats(fixed, ids)
    const stale = out.threats.find((t) => t.id === cleartext.id)!
    expect(stale.stale).toBe(true)
    expect(stale.status).toBe('accepted')
    expect(stats.newlyStale).toBe(2) // DF-I-01 and DF-T-01
    // HTTPS + confidential + boundary now triggers the TLS-config rule
    expect(out.threats.some((t) => t.ruleId === 'DF-I-04' && t.elementId === 'f')).toBe(true)

    // Running again: stale threats are not re-counted and nothing else changes
    const again = refreshThreats(out, ids)
    expect(again.model).toEqual(out)
    expect(again.stats.newlyStale).toBe(0)
  })

  it('revives a stale threat when its rule applies again, clearing the marker', () => {
    const once = refreshThreats(base(), ids).model
    const fixed = refreshThreats(upsertElement(once, { ...flow, protocol: 'HTTPS' }), ids).model
    const broken = refreshThreats(upsertElement(fixed, { ...flow, protocol: 'HTTP' }), ids)
    const t = broken.model.threats.find((x) => x.ruleId === 'DF-I-01')!
    expect(t.stale).toBeUndefined()
    expect('stale' in t).toBe(false)
    expect(broken.stats.revived).toBe(2)
    expect(broken.model.threats.filter((x) => x.ruleId === 'DF-I-01')).toHaveLength(1)
  })

  it('never touches manual threats', () => {
    const once = refreshThreats(base(), ids).model
    const manual = { id: 'manual', elementId: 'api', category: 'E' as const, title: 'Refund abuse', description: 'x', likelihood: 2, impact: 3, status: 'open' as const, mitigation: '', generated: false }
    const withManual: ThreatModel = { ...once, threats: [...once.threats, manual] }
    const out = refreshThreats(model([]), ids)
    expect(out.model.threats).toEqual([])
    const merged = mergeThreats(withManual.threats, [], ids)
    expect(merged.threats.find((t) => t.id === 'manual')).toBe(manual)
    expect(merged.threats.filter((t) => t.generated).every((t) => t.stale)).toBe(true)
  })

  it('treats a generated threat without ruleId like a manual one', () => {
    const odd = { id: 'x', elementId: 'api', category: 'S' as const, title: 'T', description: '', likelihood: 1, impact: 1, status: 'open' as const, mitigation: '', generated: true }
    const res = mergeThreats([odd], [], ids)
    expect(res.threats[0]).toBe(odd)
  })

  it('adds threats for newly added elements and appends them after existing ones', () => {
    const once = refreshThreats(base(), ids).model
    const db = createNode('db', 'datastore', 'DB', ['stores-credentials'])
    const grown = upsertElement(once, db)
    const { model: out, stats } = refreshThreats(grown, ids)
    expect(stats.added).toBe(generateCandidates(grown).filter((c) => c.elementId === 'db').length)
    expect(out.threats.slice(0, once.threats.length)).toEqual(once.threats)
    expect(out.threats.slice(once.threats.length).every((t) => t.elementId === 'db')).toBe(true)
  })

  it('matches by ruleId AND elementId', () => {
    const api2 = createNode('api2', 'process', 'API 2', ['internet-facing'])
    const m = model([user, api, api2, flow])
    const out = refreshThreats(m, ids).model
    const dos = out.threats.filter((t) => t.ruleId === 'PROC-D-01')
    expect(dos.map((t) => t.elementId).sort()).toEqual(['api', 'api2'])
  })

  it('handles duplicate candidates and duplicate existing threats without crashing or duplicating', () => {
    const c = generateCandidates(base())[0]
    const res = mergeThreats([], [c, { ...c }], ids)
    expect(res.threats).toHaveLength(1)
    const dupExisting = [res.threats[0], { ...res.threats[0], id: 'dup' }]
    const res2 = mergeThreats(dupExisting, [c], ids)
    expect(res2.threats).toHaveLength(2)
    expect(res2.stats.added).toBe(0)
  })

  it('after cascade delete, only remaining elements can have stale threats (context changed)', () => {
    const once = refreshThreats(base(), ids).model
    const removed = removeElement(once, 'u')
    expect(removed.threats.some((t) => t.elementId === 'u' || t.elementId === 'f')).toBe(false)
    const { model: out } = refreshThreats(removed, ids)
    const stale = out.threats.filter((t) => t.stale)
    expect(stale.every((t) => t.elementId === 'api')).toBe(true)
    // the API lost its only confidential flow, so the sensitive-data rule no longer applies
    expect(stale.map((t) => t.ruleId)).toEqual(['PROC-I-02'])
  })

  it('removeStaleThreats only deletes stale ones', () => {
    const once = refreshThreats(base(), ids).model
    const out = refreshThreats(upsertElement(once, { ...flow, protocol: 'HTTPS' }), ids).model
    const cleaned = removeStaleThreats(out)
    expect(cleaned.threats.some((t) => t.stale)).toBe(false)
    expect(cleaned.threats).toHaveLength(out.threats.length - 2)
  })
})

describe('review regressions', () => {
  it.each([
    ['HTTP (no TLS)', 'plaintext'],
    ['non-TLS HTTP', 'plaintext'],
    ['TCP without TLS', 'plaintext'],
    ['TLS disabled', 'plaintext'],
    ['SSL off', 'plaintext'],
    ['HTTPS, but unencrypted fallback', 'plaintext'],
    ['cleartext gRPC', 'plaintext'],
    ['PostgreSQL, TLS optional', 'plaintext'],
    ['HTTPS (no client cert)', 'encrypted'],
    ['Kafka over TLS', 'encrypted'],
  ] as const)('transportSecurity handles negation: %s -> %s', (proto, expected) => {
    expect(transportSecurity(proto)).toBe(expected)
  })

  it('flags a boundary-crossing "no TLS" flow as cleartext', () => {
    const m = model([
      createNode('a', 'external', 'A'),
      createNode('b', 'process', 'B'),
      createFlow('f', 'a', 'b', { protocol: 'HTTP (no TLS)', crossesTrustBoundary: true }),
    ])
    expect(rulesFor(m, 'f')).toContain('DF-I-01')
  })

  const user = createNode('u', 'external', 'User', ['human'])
  const api = createNode('api', 'process', 'API', ['internet-facing'])
  const flow = createFlow('f', 'u', 'api', { protocol: 'HTTP', crossesTrustBoundary: true, dataClassification: 'public' })

  it('records the rule default scores on new generated threats', () => {
    const out = refreshThreats(model([user, api, flow]), ids).model
    for (const t of out.threats) {
      expect(t.ruleLikelihood).toBe(t.likelihood)
      expect(t.ruleImpact).toBe(t.impact)
    }
  })

  it('updates untouched scores when the model makes the rule score higher (e.g. flow becomes secret)', () => {
    const once = refreshThreats(model([user, api, flow]), ids).model
    const before = once.threats.find((t) => t.ruleId === 'DF-I-01' && t.elementId === 'f')!
    expect(before.impact).toBe(1)
    const secret = upsertElement(once, { ...flow, dataClassification: 'secret' })
    const { model: out, stats } = refreshThreats(secret, ids)
    const after = out.threats.find((t) => t.id === before.id)!
    expect(after.impact).toBe(3)
    expect(after.ruleImpact).toBe(3)
    expect(stats.refreshed).toBeGreaterThan(0)
    // and it stays idempotent
    expect(refreshThreats(out, ids).model).toEqual(out)
  })

  it('never overrides a score the user changed', () => {
    const once = refreshThreats(model([user, api, flow]), ids).model
    const target = once.threats.find((t) => t.ruleId === 'DF-I-01' && t.elementId === 'f')!
    const edited: ThreatModel = { ...once, threats: once.threats.map((t) => (t.id === target.id ? { ...t, impact: 2, likelihood: 1 } : t)) }
    const secret = upsertElement(edited, { ...flow, dataClassification: 'secret' })
    const after = refreshThreats(secret, ids).model.threats.find((t) => t.id === target.id)!
    expect(after.impact).toBe(2)
    expect(after.likelihood).toBe(1)
    expect(after.ruleImpact).toBe(3)
  })

  it('keeps scores of legacy threats without recorded defaults, then records them', () => {
    const once = refreshThreats(model([user, api, flow]), ids).model
    const legacy: ThreatModel = {
      ...once,
      threats: once.threats.map((t) => {
        const copy = { ...t, impact: 2 }
        delete copy.ruleImpact
        delete copy.ruleLikelihood
        return copy
      }),
    }
    const out = refreshThreats(legacy, ids).model
    expect(out.threats.every((t) => t.impact === 2)).toBe(true)
    expect(out.threats.every((t) => t.ruleImpact !== undefined && t.ruleLikelihood !== undefined)).toBe(true)
    expect(refreshThreats(out, ids).model).toEqual(out)
  })
})
