import { base64ToBytes, bytesToUtf8 } from './encoders'
import type { Finding } from './types'

/*
 * JWT decoding & linting. Decoding is purely local; the signature is NEVER verified here
 * (verification needs the key and must happen on the server that trusts the token).
 * References: RFC 7519 (JWT), RFC 7515 (JWS), RFC 7516 (JWE), RFC 8725 (JWT Best Current Practices).
 */

export const JWT_BCP = 'https://www.rfc-editor.org/rfc/rfc8725'
const OWASP_JWT = 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'
const PORTSWIGGER_JWT = 'https://portswigger.net/web-security/jwt'

export class JwtError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'JwtError'
  }
}

export type JsonObject = Record<string, unknown>

export interface DecodedJwt {
  kind: 'JWS' | 'JWE'
  header: JsonObject
  /** Parsed JSON payload (JWS only, when the payload is JSON). */
  payload?: unknown
  /** Raw payload text when it is not JSON (JWS only). */
  payloadText?: string
  signaturePresent: boolean
  /** Signature length in bytes (JWS only). */
  signatureBytes: number
  parts: string[]
}

const B64URL = /^[A-Za-z0-9_-]*$/

function decodeSegment(seg: string, what: string): string {
  if (!B64URL.test(seg)) {
    throw new JwtError(`${what} is not valid Base64URL (JWTs use the URL-safe alphabet A-Z a-z 0-9 - _ without padding)`)
  }
  try {
    return bytesToUtf8(base64ToBytes(seg))
  } catch (e) {
    throw new JwtError(`${what} could not be decoded: ${(e as Error).message}`)
  }
}

/** Max JSON nesting accepted. Deeper input would overflow the stack in the recursive lint / JSON.stringify. */
export const MAX_JSON_DEPTH = 64

/** Maximum nesting depth of a JSON text (brackets inside strings are ignored). Linear scan, no recursion. */
export function jsonDepth(text: string): number {
  let depth = 0
  let max = 0
  let inString = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (inString) {
      if (c === '\\') i++
      else if (c === '"') inString = false
    } else if (c === '"') inString = true
    else if (c === '{' || c === '[') max = Math.max(max, ++depth)
    else if (c === '}' || c === ']') depth--
  }
  return max
}

function parseJsonLimited(text: string, what: string): unknown {
  if (jsonDepth(text) > MAX_JSON_DEPTH) throw new JwtError(`${what} JSON is nested more than ${MAX_JSON_DEPTH} levels deep — refusing to process it.`)
  return JSON.parse(text)
}

function isObject(v: unknown): v is JsonObject {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

export function decodeJwt(input: string): DecodedJwt {
  const token = input.trim().replace(/^(?:authorization:\s*)?bearer\s+/i, '').replace(/\s+/g, '').replace(/=+(?=\.|$)/g, '')
  if (token === '') throw new JwtError('Paste a token to decode it.')
  const parts = token.split('.')
  if (parts.length !== 3 && parts.length !== 5) {
    throw new JwtError(
      `A JWT has 3 dot-separated parts (JWS: header.payload.signature) or 5 (JWE). This input has ${parts.length}.`,
    )
  }
  if (parts[0] === '') throw new JwtError('The header segment is empty.')
  const headerText = decodeSegment(parts[0], 'Header')
  let header: unknown
  try {
    header = parseJsonLimited(headerText, 'Header')
  } catch (e) {
    if (e instanceof JwtError) throw e
    throw new JwtError('Header is not valid JSON.')
  }
  if (!isObject(header)) throw new JwtError('Header must be a JSON object.')

  if (parts.length === 5) {
    parts.slice(1).forEach((p, i) => {
      if (!B64URL.test(p)) throw new JwtError(`JWE segment ${i + 2} is not valid Base64URL.`)
    })
    return { kind: 'JWE', header, signaturePresent: false, signatureBytes: 0, parts }
  }

  const payloadText = decodeSegment(parts[1], 'Payload')
  let payload: unknown
  let isJson = true
  try {
    payload = parseJsonLimited(payloadText, 'Payload')
  } catch (e) {
    if (e instanceof JwtError) throw e
    isJson = false
  }
  if (!B64URL.test(parts[2])) throw new JwtError('Signature is not valid Base64URL.')
  let signatureBytes = 0
  if (parts[2] !== '') {
    try {
      signatureBytes = base64ToBytes(parts[2]).length
    } catch {
      throw new JwtError('Signature segment has an impossible Base64URL length (truncated token?).')
    }
  }
  return {
    kind: 'JWS',
    header,
    ...(isJson ? { payload } : { payloadText }),
    signaturePresent: parts[2] !== '',
    signatureBytes,
    parts,
  }
}

/* ---------- time helpers ---------- */

export function formatRelative(deltaSeconds: number): string {
  const abs = Math.abs(deltaSeconds)
  const units: [number, string][] = [
    [365 * 86400, 'year'],
    [30 * 86400, 'month'],
    [86400, 'day'],
    [3600, 'hour'],
    [60, 'minute'],
  ]
  let text = `${Math.round(abs)} second${Math.round(abs) === 1 ? '' : 's'}`
  for (const [size, name] of units) {
    if (abs >= size) {
      const n = Math.floor(abs / size)
      text = `${n} ${name}${n === 1 ? '' : 's'}`
      break
    }
  }
  if (abs < 1) return 'now'
  return deltaSeconds > 0 ? `in ${text}` : `${text} ago`
}

export function formatDuration(seconds: number): string {
  return formatRelative(seconds).replace(/^in /, '')
}

export interface TimeClaim {
  claim: 'iat' | 'nbf' | 'exp' | 'auth_time'
  label: string
  value: unknown
  iso?: string
  relative?: string
  valid: boolean
}

const TIME_LABELS: Record<TimeClaim['claim'], string> = {
  iat: 'Issued at',
  nbf: 'Not before',
  exp: 'Expires',
  auth_time: 'Authenticated at',
}

function isNumericDate(v: unknown): v is number {
  // NumericDate = seconds since epoch; reject milliseconds-looking values beyond year 10000.
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 && v < 253402300800
}

export function describeTimeClaims(payload: unknown, now: number): TimeClaim[] {
  if (!isObject(payload)) return []
  const out: TimeClaim[] = []
  for (const claim of ['iat', 'nbf', 'exp', 'auth_time'] as const) {
    if (!(claim in payload)) continue
    const value = payload[claim]
    if (isNumericDate(value)) {
      out.push({
        claim,
        label: TIME_LABELS[claim],
        value,
        iso: new Date(value * 1000).toISOString(),
        relative: formatRelative(value - now),
        valid: true,
      })
    } else {
      out.push({ claim, label: TIME_LABELS[claim], value, valid: false })
    }
  }
  return out
}

/* ---------- sensitive data detection ---------- */

const SENSITIVE_KEY =
  /pass(?:word|wd|phrase)?$|^pwd$|secret|ssn$|social.?security|credit.?card|card.?num|^cc.?num|^pan$|cvv|cvc|api.?key|private.?key|access.?key|client.?secret|^pin$|iban/i

function luhnValid(digits: string): boolean {
  let sum = 0
  let dbl = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48
    if (dbl) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
    dbl = !dbl
  }
  return sum % 10 === 0
}

function sensitiveValueReason(v: string): string | undefined {
  if (/^\d{3}-\d{2}-\d{4}$/.test(v)) return 'looks like a US Social Security Number'
  const digits = v.replace(/[ -]/g, '')
  if (/^\d{13,19}$/.test(digits) && /^[\d -]+$/.test(v) && luhnValid(digits)) return 'looks like a payment card number (passes Luhn check)'
  if (/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(v)) return 'contains a private key'
  if (/^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(v)) return 'looks like an AWS access key id'
  if (/^(?:gh[pousr]_|github_pat_|glpat-|xox[baprs]-|sk_live_|npm_)/.test(v)) return 'looks like an API token'
  return undefined
}

/** Recursively look for sensitive-looking claim names / values. Returns JSON paths with a reason. */
export function findSensitiveClaims(value: unknown, path = ''): { path: string; reason: string }[] {
  const out: { path: string; reason: string }[] = []
  if (Array.isArray(value)) {
    value.forEach((v, i) => out.push(...findSensitiveClaims(v, `${path}[${i}]`)))
  } else if (isObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      const p = path ? `${path}.${k}` : k
      // Numbers count too ("pin": 1234); booleans/null/empty strings ("has_password": true) do not.
      const meaningful = (typeof v === 'string' && v !== '') || typeof v === 'number' || isObject(v) || Array.isArray(v)
      if (SENSITIVE_KEY.test(k) && meaningful) {
        out.push({ path: p, reason: `claim name "${k}" suggests sensitive data` })
      } else {
        out.push(...findSensitiveClaims(v, p))
      }
    }
  } else if (typeof value === 'string') {
    const reason = sensitiveValueReason(value.trim())
    if (reason) out.push({ path: path || '(payload)', reason })
  } else if (typeof value === 'number' && Number.isSafeInteger(value) && /^[2-6]\d{14,15}$/.test(String(value))) {
    // Card numbers are sometimes serialised as JSON numbers. Require a card-like first digit (2-6) and 15-16 digits
    // so millisecond / microsecond timestamps (start with 1) are not mistaken for cards.
    const reason = sensitiveValueReason(String(value))
    if (reason) out.push({ path: path || '(payload)', reason })
  }
  return out
}

/* ---------- linting ---------- */

const SYMMETRIC = /^HS(256|384|512)$/i
const ASYMMETRIC = /^(RS|PS|ES)(256|384|512)$|^ES256K$|^EdDSA$|^Ed25519$|^Ed448$/i

export function lintJwt(jwt: DecodedJwt, now: number = Date.now() / 1000): Finding[] {
  const f: Finding[] = []
  const h = jwt.header
  const alg = typeof h.alg === 'string' ? h.alg : undefined

  // --- header checks common to JWS and JWE ---
  if ('jku' in h || 'x5u' in h) {
    const which = ['jku', 'x5u'].filter((k) => k in h).join(' and ')
    f.push({
      severity: 'info',
      title: `Header contains ${which} (key URL)`,
      detail: `${which} tells the verifier where to fetch the key. If the server follows this URL, an attacker can host their own key and forge tokens (header injection / SSRF).`,
      fix: 'Ignore key URLs from the token, or only accept exact URLs from a server-side allowlist. Prefer a pre-configured JWKS endpoint.',
      ref: PORTSWIGGER_JWT,
    })
  }
  if ('jwk' in h) {
    f.push({
      severity: 'high',
      title: 'Public key embedded in header (jwk)',
      detail: 'A token that carries its own verification key proves nothing: anyone can sign with their own private key and embed the matching public key (CVE-2018-0114 style attacks).',
      fix: 'Never trust a key supplied by the token. Verify against keys configured on the server only.',
      ref: PORTSWIGGER_JWT,
    })
  }
  if ('x5c' in h) {
    f.push({
      severity: 'info',
      title: 'Certificate chain embedded in header (x5c)',
      detail: 'If the verifier trusts the embedded certificate without validating it against a trusted root and pinning the expected subject, attackers can sign with a self-made certificate.',
      fix: 'Validate the x5c chain against a trust anchor and the expected subject, or ignore x5c and use configured keys.',
      ref: JWT_BCP,
    })
  }
  if ('kid' in h) {
    f.push({
      severity: 'info',
      title: `Key ID present (kid: ${JSON.stringify(h.kid)})`,
      detail: 'kid selects the verification key. It is attacker-controlled input: implementations that use it in file paths or SQL queries have been exploited (path traversal to /dev/null, SQL injection).',
      fix: 'Look kid up in a fixed key map / allowlist; never use it to build paths, queries or URLs.',
      ref: PORTSWIGGER_JWT,
    })
  }
  if ('crit' in h) {
    f.push({
      severity: 'info',
      title: 'crit header present',
      detail: `The verifier MUST understand and process these extensions or reject the token (RFC 7515 §4.1.11): ${JSON.stringify(h.crit)}.`,
    })
  }

  if (jwt.kind === 'JWE') {
    f.push({
      severity: 'info',
      title: 'Encrypted token (JWE)',
      detail: `5-part token: header is readable but the payload is encrypted (alg: ${String(h.alg)}, enc: ${String(h.enc)}). It cannot be decoded without the recipient's key.`,
    })
    if (alg === 'RSA1_5') {
      f.push({
        severity: 'medium',
        title: 'JWE uses RSA1_5 key encryption',
        detail: 'RSAES-PKCS1-v1_5 is vulnerable to padding-oracle (Bleichenbacher) attacks; RFC 8725 §3.2 advises avoiding it.',
        fix: 'Use RSA-OAEP-256 or ECDH-ES based key management.',
        ref: JWT_BCP,
      })
    }
    return f
  }

  // --- algorithm ---
  if (alg === undefined) {
    f.push({
      severity: 'high',
      title: 'Missing alg header',
      detail: 'Every JWS must declare its algorithm. Libraries may behave unpredictably with a missing alg.',
      fix: 'Reject tokens without alg; pin the expected algorithm on the verifier side.',
      ref: JWT_BCP,
    })
  } else if (alg.toLowerCase() === 'none') {
    f.push({
      severity: 'critical',
      title: 'alg is "none" — token is unsigned',
      detail: 'Anybody can create or modify this token. Verifiers that accept "none" (or are tricked by case variants like "NoNe") allow full authentication bypass.',
      fix: 'Reject alg "none" in every case variant. Configure the verifier with an explicit algorithm allowlist (e.g. only RS256/ES256).',
      ref: JWT_BCP,
    })
  } else if (SYMMETRIC.test(alg)) {
    f.push({
      severity: 'info',
      title: `Symmetric algorithm (${alg})`,
      detail: 'HMAC tokens are verified with the same secret that signs them: every service able to verify can also forge tokens. Weak secrets can be brute-forced offline from a single token (hashcat -m 16500).',
      fix: 'Use a random secret of at least 256 bits (32+ bytes from a CSPRNG), never share it between services, and store it in a secret manager. Prefer RS256/ES256/EdDSA when several services verify tokens. Pin the algorithm to prevent RS/HS confusion.',
      ref: JWT_BCP,
    })
  } else if (ASYMMETRIC.test(alg)) {
    f.push({
      severity: 'pass',
      title: `Asymmetric algorithm (${alg})`,
      detail: 'Verifiers only need the public key. Make sure the verifier pins this algorithm (prevents algorithm-confusion attacks where an attacker switches to HS256 using the public key as HMAC secret).',
    })
  } else {
    f.push({
      severity: 'medium',
      title: `Unusual algorithm "${alg}"`,
      detail: 'This is not a standard JWS algorithm name. Unknown algorithms are a sign of misconfiguration or tampering.',
      fix: 'Use a standard algorithm (RS256, PS256, ES256, EdDSA) and enforce an allowlist on the verifier.',
      ref: JWT_BCP,
    })
  }
  if (alg !== undefined && alg.toLowerCase() !== 'none' && !jwt.signaturePresent) {
    f.push({
      severity: 'high',
      title: 'Signature is empty',
      detail: `The header declares ${alg} but the signature segment is empty. A verifier that accepts this is not checking signatures at all.`,
      fix: 'Make sure the verifier rejects tokens with an empty or invalid signature.',
    })
  }
  if (alg !== undefined && alg.toLowerCase() === 'none' && jwt.signaturePresent) {
    f.push({
      severity: 'info',
      title: 'alg "none" with a non-empty signature',
      detail: 'Unsigned tokens must have an empty third segment; this token looks tampered with.',
    })
  }

  // --- payload claims ---
  const p = jwt.payload
  if (!isObject(p)) {
    f.push({
      severity: 'info',
      title: 'Payload is not a JSON claims object',
      detail: 'This JWS does not carry JWT claims, so expiry / issuer / audience cannot be checked.',
    })
    return f
  }

  const exp = p.exp
  const iat = p.iat
  const nbf = p.nbf
  if (!('exp' in p)) {
    f.push({
      severity: 'high',
      title: 'No expiration (exp claim missing)',
      detail: 'The token is valid forever: a leaked token (logs, browser history, proxy) can be replayed indefinitely.',
      fix: 'Always set exp. Access tokens: minutes (5-60 min). Use refresh tokens with rotation for long sessions.',
      ref: OWASP_JWT,
    })
  } else if (!isNumericDate(exp)) {
    f.push({
      severity: 'medium',
      title: 'exp is not a valid NumericDate',
      detail: `exp must be a number of seconds since the Unix epoch (got ${JSON.stringify(exp)}). Some libraries silently ignore invalid exp values.`,
      fix: 'Emit exp as an integer number of seconds (not milliseconds, not a string).',
    })
  } else if (exp <= now) {
    f.push({
      severity: 'medium',
      title: `Token expired ${formatRelative(exp - now)}`,
      detail: `exp = ${new Date(exp * 1000).toISOString()}. A server accepting this token is not validating expiry.`,
      fix: 'Ensure verification rejects expired tokens (small clock skew of ≤ 60 s is acceptable).',
    })
  } else {
    f.push({ severity: 'pass', title: `Not expired (expires ${formatRelative(exp - now)})`, detail: `exp = ${new Date(exp * 1000).toISOString()}` })
  }

  if ('nbf' in p) {
    if (!isNumericDate(nbf)) {
      f.push({ severity: 'low', title: 'nbf is not a valid NumericDate', detail: `Got ${JSON.stringify(nbf)}.` })
    } else if (nbf > now) {
      f.push({
        severity: 'low',
        title: `Not valid yet (nbf ${formatRelative(nbf - now)})`,
        detail: 'Verifiers must reject the token until this time. If unexpected, check the issuer clock.',
      })
    }
  }
  if (isNumericDate(iat) && iat > now + 60) {
    f.push({
      severity: 'low',
      title: `Issued in the future (iat ${formatRelative(iat - now)})`,
      detail: 'The issuer clock is ahead or the token was crafted. Verifiers may reject it.',
    })
  }

  const start = isNumericDate(iat) ? iat : isNumericDate(nbf) ? nbf : undefined
  if (isNumericDate(exp) && start !== undefined) {
    const lifetime = exp - start
    if (lifetime > 86400) {
      f.push({
        severity: 'medium',
        title: `Long lifetime (${formatDuration(lifetime)})`,
        detail: 'JWTs cannot easily be revoked; a long-lived token stays usable for that whole period if stolen.',
        fix: 'Keep access tokens short-lived (≤ 1 h) and use rotating refresh tokens, or add a server-side denylist (jti) for revocation.',
        ref: OWASP_JWT,
      })
    } else if (lifetime < 0) {
      f.push({ severity: 'low', title: 'exp is before iat/nbf', detail: 'The token was never valid.' })
    }
  }

  if (!('iss' in p)) {
    f.push({
      severity: 'low',
      title: 'No issuer (iss claim missing)',
      detail: 'Without iss, a verifier that trusts several issuers cannot tell who minted the token.',
      fix: 'Set iss and validate it against the expected issuer.',
      ref: JWT_BCP,
    })
  }
  if (!('aud' in p)) {
    f.push({
      severity: 'low',
      title: 'No audience (aud claim missing)',
      detail: 'Without aud, a token issued for service A can be replayed against service B that trusts the same issuer (substitution attack, RFC 8725 §2.7 / §3.9).',
      fix: 'Set aud to the intended API and have every service reject tokens not addressed to it.',
      ref: JWT_BCP,
    })
  }

  const sensitive = findSensitiveClaims(p)
  if (sensitive.length > 0) {
    f.push({
      severity: 'high',
      title: `Sensitive-looking data in payload (${sensitive.length})`,
      detail: `${sensitive.map((s) => `${s.path}: ${s.reason}`).join('; ')}. A JWS payload is only Base64URL-encoded, not encrypted — anyone holding the token (browser, logs, proxies) can read it.`,
      fix: 'Remove secrets and personal data from the token; reference them by an opaque id, or use JWE if the data must travel in the token.',
      ref: OWASP_JWT,
    })
  }

  return f
}

/** The classic jwt.io sample (HS256, no exp/iss/aud) — handy to demo the linter. */
export const SAMPLE_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
