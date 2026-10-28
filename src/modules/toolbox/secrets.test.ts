import { describe, expect, it } from 'vitest'
import { SECRET_RULES, isPlaceholder, redact, scanSecrets, shannonEntropy } from './secrets'

/*
 * Fixtures are assembled at runtime from pieces so that this file never contains a
 * literal token that GitHub push protection / secret scanners would block. None are real.
 */
const j = (...parts: string[]) => parts.join('')
const ALNUM = 'aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz'
const rep = (n: number, alphabet = ALNUM) => Array.from({ length: n }, (_, i) => alphabet[(i * 7) % alphabet.length]).join('')
const HEX = '0123456789abcdef'

interface Case {
  rule: string
  positive: string
  negative: string
}

const CASES: Case[] = [
  { rule: 'private-key', positive: j('-----BEGIN RSA ', 'PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----'), negative: '-----BEGIN PUBLIC KEY-----\nMIIBIjAN' },
  { rule: 'aws-access-key-id', positive: j('key = "AKIA', 'QYLPMN5HHHFPZAM2', '"'), negative: j('AKIA', 'IOSFODNN7EXAMPLE') },
  { rule: 'aws-secret-access-key', positive: j('aws_secret_access_key = ', rep(40, 'wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY/+')), negative: j('aws_secret_access_key = ', '${AWS_SECRET}') },
  { rule: 'github-token', positive: j('token: gh', 'p_', rep(36)), negative: j('gh', 'p_', 'short') },
  { rule: 'github-fine-grained-pat', positive: j('github', '_pat_', rep(22), '_', rep(59)), negative: 'github_pat_tooShort' },
  { rule: 'gitlab-pat', positive: j('glp', 'at-', rep(20)), negative: j('glp', 'at-', 'abc') },
  { rule: 'slack-token', positive: j('xo', 'xb-', '1234567890-1234567890123-', rep(24)), negative: 'xoxz-1234567890' },
  { rule: 'slack-webhook', positive: j('https://hooks.slack', '.com/services/', 'T00000000/B00000000/', rep(24)), negative: 'https://hooks.slack.com/' },
  { rule: 'stripe-live-key', positive: j('sk', '_live_', rep(24)), negative: j('sk', '_test_', rep(24)) },
  { rule: 'google-api-key', positive: j('AI', 'za', rep(35)), negative: j('AI', 'za', rep(10)) },
  { rule: 'azure-storage-key', positive: j('DefaultEndpointsProtocol=https;AccountName=x;Account', 'Key=', rep(86, 'Ab0+/9zZ'), '==;'), negative: 'AccountKey=<your-key>' },
  { rule: 'npm-token', positive: j('//registry.npmjs.org/:_authToken=np', 'm_', rep(36)), negative: 'npm_install_script' },
  { rule: 'twilio-api-key', positive: j('S', 'K', rep(32, HEX)), negative: j('S', 'K', rep(31, HEX), 'z') },
  { rule: 'sendgrid-api-key', positive: j('S', 'G.', rep(22), '.', rep(43)), negative: 'SG.short.key' },
  { rule: 'jwt', positive: j('Authorization: Bearer ey', 'JhbGciOiJIUzI1NiJ9.ey', 'JzdWIiOiIxMjM0NTY3ODkwIn0.', rep(20)), negative: 'eyJhbGci only header' },
  { rule: 'connection-string', positive: j('DATABASE_URL=postgres://admin:', 'S3cr3tPw', '@db.internal:5432/app'), negative: 'postgres://admin:${DB_PASSWORD}@db.internal/app' },
  { rule: 'generic-assignment', positive: j('const dbPassword = "', 'Tr0ub4dor&3', '"'), negative: 'const password = "changeme"' },
  { rule: 'generic-env', positive: j('API_', 'SECRET=', 'q8Zr2LmW9xT'), negative: 'API_SECRET=${API_SECRET}' },
]

describe('secret rules', () => {
  it('every rule has a positive and a negative test case', () => {
    expect(CASES.map((c) => c.rule).sort()).toEqual(SECRET_RULES.map((r) => r.id).sort())
  })
  it('rule ids are unique and patterns are not global', () => {
    expect(new Set(SECRET_RULES.map((r) => r.id)).size).toBe(SECRET_RULES.length)
    for (const r of SECRET_RULES) expect(r.pattern.global).toBe(false)
  })
  it.each(CASES)('$rule: detects positive sample', ({ rule, positive }) => {
    expect(scanSecrets(positive).map((f) => f.ruleId)).toContain(rule)
  })
  it.each(CASES)('$rule: ignores negative sample', ({ rule, negative }) => {
    expect(scanSecrets(negative).map((f) => f.ruleId)).not.toContain(rule)
  })
})

describe('scanSecrets', () => {
  it('reports line and column (1-based)', () => {
    const text = j('line one\n\n  token = gh', 'p_', rep(36), '\n')
    const [f] = scanSecrets(text)
    expect(f.line).toBe(3)
    expect(f.column).toBe(11)
  })
  it('never returns the raw secret', () => {
    const secret = j('sk', '_live_', rep(30))
    const [f] = scanSecrets(`stripe = "${secret}"`)
    expect(f.redacted).toBe('sk_l****')
    expect(JSON.stringify(scanSecrets(`stripe = "${secret}"`))).not.toContain(secret.slice(8))
  })
  it('prefers the specific rule over generic assignment for the same value', () => {
    const f = scanSecrets(j('GITHUB_TOKEN = "gh', 'p_', rep(36), '"'))
    expect(f).toHaveLength(1)
    expect(f[0].ruleId).toBe('github-token')
  })
  it('shows a safe display for private keys', () => {
    const [f] = scanSecrets(j('-----BEGIN OPENSSH ', 'PRIVATE KEY-----\nb3Blbn'))
    expect(f.redacted).toBe('-----BEGIN OPENSSH PRIVATE KEY----- (key body hidden)')
    expect(f.severity).toBe('critical')
  })
  it('finds multiple secrets sorted by position', () => {
    const text = j('a = "AKIA', 'QYLPMN5HHHFPZAM2"\nb: ', 'gl', 'pat-', rep(20))
    expect(scanSecrets(text).map((f) => [f.ruleId, f.line])).toEqual([
      ['aws-access-key-id', 1],
      ['gitlab-pat', 2],
    ])
  })
  it('handles JSON and YAML generic assignments', () => {
    expect(scanSecrets('{"client_secret": "9f8e7d6c5b4a"}')[0]?.ruleId).toBe('generic-assignment')
    expect(scanSecrets("api_key: 'Zx81LmQp20aa'")[0]?.ruleId).toBe('generic-assignment')
  })
  it('returns nothing for clean code and empty input', () => {
    expect(scanSecrets('')).toEqual([])
    expect(scanSecrets('const user = getUser(id)\nconst token = req.headers.authorization\n')).toEqual([])
  })
  it('stays fast on pathological input', () => {
    const t0 = performance.now()
    scanSecrets('_'.repeat(50_000) + 'a'.repeat(50_000), { entropy: true })
    expect(performance.now() - t0).toBeLessThan(2000)
  })
})

describe('entropy check', () => {
  const RANDOM = 'q7Xv2Lp9Rz4Kt8Wn3Bm6Yc1Hd5Fg0Js'
  it('is off by default', () => {
    expect(scanSecrets(`x = ${RANDOM}`)).toEqual([])
  })
  it('flags long high-entropy strings when enabled', () => {
    const f = scanSecrets(`x = ${RANDOM}`, { entropy: true })
    expect(f).toHaveLength(1)
    expect(f[0].ruleId).toBe('high-entropy')
    expect(f[0].severity).toBe('low')
    expect(f[0].redacted).toBe('q7Xv****')
  })
  it('ignores low-entropy, letter-only, short and SRI hash strings', () => {
    expect(scanSecrets('aaaaaaaaaaaaaaaaaaaaaaaaaaaa1111', { entropy: true })).toEqual([])
    expect(scanSecrets('ThisIsAVeryLongIdentifierNameWithoutDigits', { entropy: true })).toEqual([])
    expect(scanSecrets('q7Xv2Lp9Rz4K', { entropy: true })).toEqual([])
    expect(scanSecrets(`integrity="sha512-${RANDOM}${RANDOM}"`, { entropy: true })).toEqual([])
  })
  it('does not double-report values already matched by a rule', () => {
    const f = scanSecrets(j('gh', 'p_', rep(36)), { entropy: true })
    expect(f.map((x) => x.ruleId)).toEqual(['github-token'])
  })
  it('does not flag private key bodies line by line', () => {
    const key = j('-----BEGIN ', 'PRIVATE KEY-----\n', RANDOM, RANDOM, '\n', RANDOM, '\n-----END PRIVATE KEY-----')
    expect(scanSecrets(key, { entropy: true }).map((x) => x.ruleId)).toEqual(['private-key'])
  })
})

describe('helpers', () => {
  it('shannonEntropy', () => {
    expect(shannonEntropy('')).toBe(0)
    expect(shannonEntropy('aaaa')).toBe(0)
    expect(shannonEntropy('ab')).toBe(1)
    expect(shannonEntropy('0123456789abcdef')).toBe(4)
  })
  it('redact', () => {
    expect(redact('abcdefgh')).toBe('abcd****')
    expect(redact('ab')).toBe('ab****')
  })
  it('isPlaceholder', () => {
    for (const p of ['${X}', '{{ secret }}', '<password>', '%PASS%', 'xxxxxx', '******', 'changeme', 'your-api-key', 'process.env.TOKEN', '$DB_PASS']) {
      expect(isPlaceholder(p)).toBe(true)
    }
    expect(isPlaceholder('Tr0ub4dor&3')).toBe(false)
  })
})

describe('review regressions', () => {
  const timed = (input: string) => {
    const t0 = performance.now()
    scanSecrets(input, { entropy: true })
    return performance.now() - t0
  }
  it('does not go quadratic on many blank lines (.env rule anchored with a whitespace class under the m flag)', () => {
    expect(timed('\n'.repeat(200_000) + 'x')).toBeLessThan(1500)
  })
  it('does not go quadratic on long runs of keyword-like identifiers', () => {
    expect(timed('token'.repeat(40_000))).toBeLessThan(1500)
    expect(timed('TOKEN'.repeat(40_000))).toBeLessThan(1500)
    expect(timed('eyJ-'.repeat(40_000))).toBeLessThan(1500)
    expect(timed(j('glp', 'at-').repeat(30_000))).toBeLessThan(1500)
    expect(timed(j('xo', 'xb-').repeat(30_000))).toBeLessThan(1500)
    expect(timed('-----BEGIN ' + 'PRIVATE KEY '.repeat(20_000))).toBeLessThan(1500)
  })
  it('reports the column of the secret group, not an earlier identical substring', () => {
    // The value also appears inside the variable name; the column must point at the quoted literal.
    const secret = 'tokenAb12Cd34'
    const line = `my_${secret}_token = "${secret}"`
    const f = scanSecrets(line).find((x) => x.ruleId === 'generic-assignment')
    expect(f?.column).toBe(line.indexOf(`"${secret}"`) + 2)
  })
  it('still detects .env secrets after the anchoring change', () => {
    expect(scanSecrets('\n\n  export DB_PASSWORD=Zq81LmQp20aa')[0]).toMatchObject({ ruleId: 'generic-env', line: 3 })
  })
})
