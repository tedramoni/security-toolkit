import type { Severity } from './types'

/*
 * Regex-based secret scanner. Patterns are adapted from public token format documentation and
 * the gitleaks default ruleset: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
 * Everything runs locally; matches are only ever returned redacted.
 */

export interface SecretRule {
  id: string
  name: string
  severity: Severity
  /** Pattern WITHOUT the g flag. If it has a capture group named "secret", that group is reported. */
  pattern: RegExp
  description: string
  /** Optional filter to drop false positives (receives the secret part). */
  accept?: (secret: string) => boolean
  /** Rule ids processed later than specific rules: they skip ranges already reported. */
  generic?: boolean
  /** Custom safe display instead of first-4-chars redaction. */
  display?: (secret: string) => string
}

/** Values that are obviously placeholders, not real secrets. */
const PLACEHOLDER =
  /^(?:\$\{[^}]*\}|\$\(.*\)|\{\{.*\}\}|<[^>]*>|%[^%]*%|\$[A-Z_][A-Z0-9_]*|x{3,}.*|\*{3,}|\.{3,}|changeme|change_me|password|passwd|secret|example|sample|dummy|test|testing|placeholder|redacted|your[_-].*|null|none|undefined|true|false|process\.env\..*|os\.environ.*|env\(.*\))$/i

export function isPlaceholder(v: string): boolean {
  return PLACEHOLDER.test(v.trim())
}

export const SECRET_RULES: readonly SecretRule[] = [
  {
    id: 'private-key',
    name: 'Private key block',
    severity: 'critical',
    pattern: /-----BEGIN (?<secret>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----/,
    description: 'PEM / OpenSSH / PGP private key.',
    display: (s) => `-----BEGIN ${s}----- (key body hidden)`,
  },
  {
    id: 'aws-access-key-id',
    name: 'AWS access key ID',
    severity: 'critical',
    pattern: /\b(?<secret>(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/,
    description: 'AKIA = long-term IAM user key, ASIA = temporary STS key. Usually paired with a secret access key.',
    // AWS documentation examples (AKIAIOSFODNN7EXAMPLE) are not real keys.
    accept: (s) => !s.endsWith('EXAMPLE'),
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS secret access key',
    severity: 'critical',
    pattern: /(?:aws[_.-]?)?secret[_.-]?(?:access[_.-]?)?key["']?\s*(?:[:=]|=>)\s*["']?(?<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/i,
    description: '40-character secret assigned to an aws_secret_access_key-like name.',
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    severity: 'critical',
    pattern: /\b(?<secret>gh[pousr]_[A-Za-z0-9]{36,251})\b/,
    description: 'ghp_ = classic PAT, gho_ = OAuth, ghu_ = user-to-server, ghs_ = server-to-server, ghr_ = refresh token.',
  },
  {
    id: 'github-fine-grained-pat',
    name: 'GitHub fine-grained PAT',
    severity: 'critical',
    pattern: /\b(?<secret>github_pat_[A-Za-z0-9_]{50,255})\b/,
    description: 'Fine-grained personal access token.',
  },
  {
    id: 'gitlab-pat',
    name: 'GitLab personal access token',
    severity: 'critical',
    pattern: /(?<![A-Za-z0-9_.-])(?<secret>glpat-[A-Za-z0-9_.-]{20,255})/,
    description: 'GitLab personal / project / group access token.',
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    severity: 'high',
    pattern: /(?<![A-Za-z0-9_-])(?<secret>xox[baprs]-[A-Za-z0-9-]{10,255})/,
    description: 'xoxb = bot, xoxp = user, xoxa/xoxr = app/refresh, xoxs = session token.',
  },
  {
    id: 'slack-webhook',
    name: 'Slack incoming webhook',
    severity: 'high',
    pattern: /(?<secret>https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_/+-]{20,512})/,
    description: 'Anyone with the URL can post messages into the channel (phishing from a trusted source).',
  },
  {
    id: 'stripe-live-key',
    name: 'Stripe live secret / restricted key',
    severity: 'critical',
    pattern: /\b(?<secret>(?:sk|rk)_live_[A-Za-z0-9]{20,247})\b/,
    description: 'Live-mode Stripe key: can create charges, refunds and read customer data.',
  },
  {
    id: 'google-api-key',
    name: 'Google API key',
    severity: 'high',
    pattern: /\b(?<secret>AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/,
    description: 'Google Cloud / Firebase / Maps API key. Browser keys are public by design but must be restricted (HTTP referrer + API restrictions) to avoid billing abuse.',
  },
  {
    id: 'azure-storage-key',
    name: 'Azure Storage account key',
    severity: 'critical',
    pattern: /AccountKey=(?<secret>[A-Za-z0-9+/]{86}==)/,
    description: 'Full access to the storage account. Prefer Entra ID (managed identity) or short-lived SAS tokens.',
  },
  {
    id: 'npm-token',
    name: 'npm access token',
    severity: 'critical',
    pattern: /\b(?<secret>npm_[A-Za-z0-9]{36})\b/,
    description: 'Can publish packages under your account (supply-chain attack).',
  },
  {
    id: 'twilio-api-key',
    name: 'Twilio API key',
    severity: 'high',
    pattern: /\b(?<secret>SK[0-9a-fA-F]{32})\b/,
    description: 'Twilio API key SID (SK + 32 hex). Paired with an API secret.',
  },
  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API key',
    severity: 'high',
    pattern: /\b(?<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/,
    description: 'Can send email as your domain (phishing).',
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    severity: 'medium',
    // Lookbehind (not \b) so "eyJ-eyJ-…" runs get one match attempt, not one per segment (quadratic).
    pattern: /(?<![A-Za-z0-9_-])(?<secret>eyJ[A-Za-z0-9_-]{10,8192}\.eyJ[A-Za-z0-9_-]{10,16384}\.[A-Za-z0-9_-]{0,4096})/,
    description: 'A bearer token — usable by whoever holds it until it expires. Decode it in the JWT tab to check exp.',
  },
  {
    id: 'connection-string',
    name: 'Credentials in connection string / URL',
    severity: 'high',
    pattern: /\b(?<secret>[a-z][a-z0-9+.-]{1,30}:\/\/[^\s:@/'"`]{1,128}:(?<pw>[^\s@/'"`]{1,256})@[^\s'"`/]+)/i,
    description: 'scheme://user:password@host — database, broker or HTTP URL with an embedded password.',
    accept: (s) => {
      const pw = /:\/\/[^:]*:([^@]*)@/.exec(s)?.[1] ?? ''
      return pw !== '' && !isPlaceholder(pw)
    },
  },
  {
    id: 'generic-assignment',
    name: 'Hard-coded secret assignment',
    severity: 'medium',
    pattern:
      /(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]{0,40}(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]{0,40}["']?\s*(?::=|=>|[:=])\s*(?<q>["'`])(?<secret>[^"'`\s]{6,256})\k<q>/i,
    description: 'A quoted literal assigned to a password/secret/token-like name.',
    accept: (s) => !isPlaceholder(s),
    generic: true,
  },
  {
    id: 'generic-env',
    name: 'Secret in .env-style assignment',
    severity: 'medium',
    // [ \t] instead of \s: with the m flag, ^\s* spans blank lines and went quadratic on large inputs.
    pattern: /^[ \t]*(?:export[ \t]+)?[A-Z0-9_]{0,40}(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)[A-Z0-9_]{0,40}[ \t]*=[ \t]*(?<secret>[^\s'"#`]{6,256})/m,
    description: 'Unquoted KEY=value line, typical of committed .env files.',
    accept: (s) => !isPlaceholder(s),
    generic: true,
  },
]

export const ENTROPY_RULE: Pick<SecretRule, 'id' | 'name' | 'severity' | 'description'> = {
  id: 'high-entropy',
  name: 'High-entropy string',
  severity: 'low',
  description: 'Long random-looking string. Could be a key, or a harmless hash/ID — review manually.',
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

export function redact(secret: string): string {
  return secret.slice(0, 4) + '****'
}

export interface SecretFinding {
  ruleId: string
  ruleName: string
  severity: Severity
  line: number
  column: number
  /** Redacted match — the raw secret is never returned. */
  redacted: string
  description: string
}

export interface ScanOptions {
  entropy?: boolean
  /** Minimum length for entropy candidates (default 20). */
  entropyMinLength?: number
}

function lineIndex(text: string): number[] {
  const starts = [0]
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1)
  return starts
}

function position(starts: number[], offset: number): { line: number; column: number } {
  let lo = 0
  let hi = starts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (starts[mid] <= offset) lo = mid
    else hi = mid - 1
  }
  return { line: lo + 1, column: offset - starts[lo] + 1 }
}

export function scanSecrets(text: string, options: ScanOptions = {}): SecretFinding[] {
  const starts = lineIndex(text)
  const covered: [number, number][] = []
  const overlaps = (s: number, e: number) => covered.some(([a, b]) => s < b && e > a)
  const out: SecretFinding[] = []

  const ordered = [...SECRET_RULES.filter((r) => !r.generic), ...SECRET_RULES.filter((r) => r.generic)]
  for (const rule of ordered) {
    // 'd' gives the exact offset of the secret group (indexOf could hit an earlier identical substring).
    const flags = [...new Set(rule.pattern.flags + 'gd')].join('')
    const re = new RegExp(rule.pattern.source, flags)
    for (const m of text.matchAll(re)) {
      const secret = m.groups?.secret ?? m[0]
      const start = m.indices?.groups?.secret?.[0] ?? m.index ?? 0
      const end = start + secret.length
      if (rule.accept && !rule.accept(secret)) continue
      if (overlaps(start, end)) continue
      covered.push([start, end])
      out.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        ...position(starts, start),
        redacted: rule.display ? rule.display(secret) : redact(secret),
        description: rule.description,
      })
    }
  }

  // Skip private key bodies for the entropy check.
  for (const m of text.matchAll(/-----BEGIN [A-Z ]{0,40}PRIVATE KEY[A-Z ]{0,40}-----[\s\S]*?(?:-----END [A-Z ]{0,40}PRIVATE KEY[A-Z ]{0,40}-----|$)/g)) {
    covered.push([m.index ?? 0, (m.index ?? 0) + m[0].length])
  }

  if (options.entropy) {
    const min = options.entropyMinLength ?? 20
    const re = new RegExp(`[A-Za-z0-9+/=_-]{${min},}`, 'g')
    for (const m of text.matchAll(re)) {
      const token = m[0].replace(/=+$/, '')
      const start = m.index ?? 0
      if (token.length < min) continue
      if (overlaps(start, start + m[0].length)) continue
      // Subresource-integrity / lockfile hashes are not secrets.
      if (/(?:sha(?:1|256|384|512)-|integrity)\W*$/i.test(text.slice(Math.max(0, start - 20), start))) continue
      if (!/[0-9]/.test(token) || !/[A-Za-z]/.test(token)) continue
      const isHex = /^[0-9a-f]+$/i.test(token)
      const threshold = isHex ? 3.0 : 4.0
      if (shannonEntropy(token) < threshold) continue
      covered.push([start, start + m[0].length])
      out.push({
        ruleId: ENTROPY_RULE.id,
        ruleName: ENTROPY_RULE.name,
        severity: ENTROPY_RULE.severity,
        ...position(starts, start),
        redacted: redact(token),
        description: `${ENTROPY_RULE.description} (entropy ${shannonEntropy(token).toFixed(2)} bits/char, length ${token.length})`,
      })
    }
  }

  return out.sort((a, b) => a.line - b.line || a.column - b.column)
}
