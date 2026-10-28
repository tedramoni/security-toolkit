/**
 * STRIDE-per-element rule engine.
 *
 * Applicability follows the classic Microsoft SDL STRIDE-per-element chart
 * (https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats):
 *   external entity: S, R
 *   process:         S, T, R, I, D, E
 *   data store:      T, I, D  (+ R when it stores logs / audit trails)
 *   data flow:       T, I, D
 *
 * Each rule produces at most one threat per element, identified by (ruleId, elementId).
 * mergeThreats() makes regeneration idempotent and preserves user edits.
 */
import type { DataClassification, ElementType, ModelElement, StrideCategory, Threat, ThreatModel } from './model.ts'
import { displayName } from './model.ts'

// ---------------------------------------------------------------------------
// Applicability
// ---------------------------------------------------------------------------

export function applicableCategories(el: Pick<ModelElement, 'type' | 'tags'>): StrideCategory[] {
  switch (el.type) {
    case 'external':
      return ['S', 'R']
    case 'process':
      return ['S', 'T', 'R', 'I', 'D', 'E']
    case 'datastore':
      return el.tags.includes('logs') ? ['T', 'R', 'I', 'D'] : ['T', 'I', 'D']
    case 'dataflow':
      return ['T', 'I', 'D']
  }
}

// ---------------------------------------------------------------------------
// Transport / classification helpers
// ---------------------------------------------------------------------------

export type TransportSecurity = 'encrypted' | 'plaintext' | 'unknown'

const ENCRYPTED_TOKENS = new Set([
  'https', 'tls', 'mtls', 'ssl', 'ssh', 'sftp', 'scp', 'ftps', 'wss', 'ldaps', 'smtps', 'imaps', 'pop3s',
  'grpcs', 'ipsec', 'wireguard', 'vpn', 'amqps', 'mqtts', 'rediss', 'dot', 'doh', 'quic', 'http3', 'h3',
])
const PLAINTEXT_TOKENS = new Set([
  'http', 'ftp', 'telnet', 'tcp', 'udp', 'smtp', 'ldap', 'ws', 'mqtt', 'amqp', 'redis', 'memcached', 'snmp',
  'pop3', 'imap', 'syslog', 'nfs', 'smb', 'cifs', 'rsh', 'rlogin', 'tftp', 'vnc',
])

/**
 * Classify a free-text protocol. Any explicit encryption marker wins ("gRPC over TLS", "HTTPS", "Postgres+TLS");
 * a known cleartext protocol is plaintext ("HTTP/1.1", "FTP", "plain TCP"); anything else is unknown
 * (e.g. "postgres", "kafka" — whose encryption depends on configuration).
 */
/** Words that explicitly state there is no encryption, whatever else the text says. */
const EXPLICIT_CLEARTEXT = new Set(['plaintext', 'cleartext', 'unencrypted', 'insecure'])
/** "no TLS", "non-TLS", "without SSL" */
const NEGATION_BEFORE = new Set(['no', 'non', 'without', 'not', 'disabled', 'plain'])
/** "TLS disabled", "SSL off", "TLS optional" */
const NEGATION_AFTER = new Set(['disabled', 'off', 'optional', 'none', 'false'])

export function transportSecurity(protocol: string | undefined): TransportSecurity {
  const tokens = (protocol ?? '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)
  if (tokens.some((t) => EXPLICIT_CLEARTEXT.has(t))) return 'plaintext'
  const negated = (i: number) => NEGATION_BEFORE.has(tokens[i - 1] ?? '') || NEGATION_AFTER.has(tokens[i + 1] ?? '')
  const encrypted = tokens.filter((t, i) => ENCRYPTED_TOKENS.has(t) && !negated(i))
  if (encrypted.length) return 'encrypted'
  // An encryption marker that is explicitly negated ("HTTP, no TLS", "TLS disabled") means cleartext.
  if (tokens.some((t, i) => ENCRYPTED_TOKENS.has(t) && negated(i))) return 'plaintext'
  if (tokens.some((t) => PLAINTEXT_TOKENS.has(t))) return 'plaintext'
  return 'unknown'
}

const CLASS_RANK: Record<DataClassification, number> = { public: 0, internal: 1, confidential: 2, secret: 3 }

export function classificationRank(c: DataClassification | undefined): number {
  return CLASS_RANK[c ?? 'internal'] ?? 1
}

/** Default impact contributed by data sensitivity. */
export function impactForClassification(c: DataClassification | undefined): number {
  return [1, 2, 3, 3][classificationRank(c)]
}

function isSensitive(c: DataClassification | undefined): boolean {
  return classificationRank(c) >= 2
}

// ---------------------------------------------------------------------------
// Rule context
// ---------------------------------------------------------------------------

export interface RuleContext {
  model: ThreatModel
  byId: Map<string, ModelElement>
  flowsIn: (id: string) => ModelElement[]
  flowsOut: (id: string) => ModelElement[]
  /** Highest classification of any flow touching the element (internal if none). */
  maxClassification: (id: string) => DataClassification
  name: (el: ModelElement | undefined) => string
}

export function buildContext(model: ThreatModel): RuleContext {
  const byId = new Map(model.elements.map((e) => [e.id, e]))
  const flows = model.elements.filter((e) => e.type === 'dataflow')
  const flowsIn = (id: string) => flows.filter((f) => f.toId === id)
  const flowsOut = (id: string) => flows.filter((f) => f.fromId === id)
  const maxClassification = (id: string): DataClassification => {
    const touching = flows.filter((f) => f.fromId === id || f.toId === id)
    let best: DataClassification = 'internal'
    let found = false
    for (const f of touching) {
      const c = f.dataClassification ?? 'internal'
      if (!found || classificationRank(c) > classificationRank(best)) best = c
      found = true
    }
    return best
  }
  return {
    model,
    byId,
    flowsIn,
    flowsOut,
    maxClassification,
    name: (el) => (el ? displayName(model, el) : '?'),
  }
}

const has = (el: ModelElement, tag: string) => el.tags.includes(tag)

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export interface Rule {
  id: string
  category: StrideCategory
  appliesTo: ElementType
  when?: (el: ModelElement, ctx: RuleContext) => boolean
  title: (el: ModelElement, ctx: RuleContext) => string
  description: (el: ModelElement, ctx: RuleContext) => string
  mitigations: string[]
  references: string[]
  likelihood: number | ((el: ModelElement, ctx: RuleContext) => number)
  impact: number | ((el: ModelElement, ctx: RuleContext) => number)
}

const REF = {
  stride: 'https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats',
  authn: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
  mfa: 'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html',
  stuffing: 'https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html',
  session: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
  jwt: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
  jwtBcp: 'https://www.rfc-editor.org/rfc/rfc8725',
  injection: 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
  inputValidation: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
  massAssignment: 'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
  logging: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
  errors: 'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
  ssrf: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
  imds: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
  secrets: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
  dos: 'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
  authz: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
  idor: 'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
  apiTop10: 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/',
  deserialization: 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
  fileUpload: 'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
  docker: 'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html',
  database: 'https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html',
  cryptoStorage: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
  keyMgmt: 'https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html',
  passwords: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
  privacy: 'https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html',
  gdpr33: 'https://gdpr-info.eu/art-33-gdpr/',
  supplyChain: 'https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html',
  depMgmt: 'https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html',
  slsa: 'https://slsa.dev/',
  tls: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
  hsts: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
  microservices: 'https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html',
  ghWebhooks: 'https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries',
  stripeWebhooks: 'https://docs.stripe.com/webhooks',
  objectLock: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html',
  transactionAuth: 'https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html',
  cwe: (n: number) => `https://cwe.mitre.org/data/definitions/${n}.html`,
}

/** Is this flow's source an external entity tagged third-party? */
function fromThirdParty(ctx: RuleContext, el: ModelElement): ModelElement[] {
  return ctx
    .flowsIn(el.id)
    .map((f) => ctx.byId.get(f.fromId ?? ''))
    .filter((src): src is ModelElement => !!src && src.type === 'external' && has(src, 'third-party'))
}

function outboundToExternals(ctx: RuleContext, el: ModelElement): ModelElement[] {
  return ctx
    .flowsOut(el.id)
    .map((f) => ctx.byId.get(f.toId ?? ''))
    .filter((dst): dst is ModelElement => !!dst && dst.type === 'external')
}

function list(names: string[]): string {
  const uniq = [...new Set(names)]
  return uniq.length <= 1 ? (uniq[0] ?? '') : `${uniq.slice(0, -1).join(', ')} and ${uniq[uniq.length - 1]}`
}

function flowEnds(el: ModelElement, ctx: RuleContext): string {
  return `${ctx.name(ctx.byId.get(el.fromId ?? ''))} → ${ctx.name(ctx.byId.get(el.toId ?? ''))}`
}

function protoLabel(el: ModelElement): string {
  return el.protocol?.trim() || 'an unspecified protocol'
}

export const RULES: Rule[] = [
  // ======================= External entities (S, R) =======================
  {
    id: 'EXT-S-01',
    category: 'S',
    appliesTo: 'external',
    title: (el, ctx) => `Attacker impersonates ${ctx.name(el)}`,
    description: (el, ctx) =>
      `An attacker presents themselves as "${ctx.name(el)}" (stolen or guessed credentials, forged tokens, spoofed source IP) and is treated as the legitimate party by the system. Everything the system lets ${ctx.name(el)} do becomes available to the attacker.`,
    mitigations: [
      'Authenticate every request from this entity — OIDC/OAuth 2.0 for users, mTLS or signed client credentials for services; never rely on source IP or a static shared header alone.',
      'Require MFA for human users (phishing-resistant WebAuthn/passkeys for privileged accounts).',
      'Use short-lived credentials/tokens and rotate any long-lived secrets issued to this entity.',
    ],
    references: [REF.authn, REF.mfa, REF.cwe(290)],
    likelihood: (el) => (has(el, 'human') ? 3 : 2),
    impact: (el, ctx) => (has(el, 'admin') ? 3 : impactForClassification(ctx.maxClassification(el.id))),
  },
  {
    id: 'EXT-S-02',
    category: 'S',
    appliesTo: 'external',
    when: (el, ctx) => has(el, 'third-party') && ctx.flowsOut(el.id).some((f) => ctx.byId.get(f.toId ?? '')?.type === 'process'),
    title: (el, ctx) => `Forged or replayed callbacks/webhooks claiming to come from ${ctx.name(el)}`,
    description: (el, ctx) =>
      `${ctx.name(el)} is a third party that sends data into the system. Webhook/callback endpoints are usually public; if the payload is not cryptographically verified, anyone who discovers the URL can forge events (e.g. "payment succeeded") or replay a captured genuine event.`,
    mitigations: [
      "Verify the provider's signature (e.g. HMAC-SHA256 over the raw request body) with a constant-time comparison before parsing or acting on the payload.",
      'Reject events whose signed timestamp is outside a short tolerance window (e.g. 5 minutes) and de-duplicate by event id to stop replays.',
      'Treat the webhook as a notification only: re-fetch the authoritative state from the provider API before performing sensitive actions.',
      'Store the webhook signing secret in a secrets manager and rotate it; do not log it.',
    ],
    references: [REF.ghWebhooks, REF.stripeWebhooks, REF.cwe(345), REF.cwe(294)],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'EXT-S-03',
    category: 'S',
    appliesTo: 'external',
    when: (el) => has(el, 'third-party'),
    title: (el, ctx) => `Compromise of third party ${ctx.name(el)} is used to attack the system (supply chain)`,
    description: (el, ctx) =>
      `If ${ctx.name(el)} is breached, or its credentials issued to you leak, an attacker can act with the trust the system grants that vendor: sending malicious data, calling your APIs, or harvesting data you send to it.`,
    mitigations: [
      'Grant the vendor the narrowest possible API scopes and data; keep an inventory of what is shared with it.',
      'Validate everything received from the vendor as untrusted input (schema, size, types) — do not trust it more than user input.',
      'Monitor for anomalous vendor behaviour (volumes, new endpoints) and have a documented kill-switch to revoke its credentials quickly.',
      'Review the vendor security posture (SOC 2 / ISO 27001 report, breach-notification clause in the contract).',
    ],
    references: [REF.supplyChain, REF.cwe(345)],
    likelihood: 1,
    impact: 3,
  },
  {
    id: 'EXT-R-01',
    category: 'R',
    appliesTo: 'external',
    title: (el, ctx) => `${ctx.name(el)} denies having performed an action`,
    description: (el, ctx) =>
      `Without attributable, tamper-resistant records, ${ctx.name(el)} (or someone using its identity) can dispute actions such as orders, configuration changes or data deletion, and the team cannot prove what happened during an incident.`,
    mitigations: [
      'Log every security-relevant action with the authenticated principal id, timestamp (synchronised clock), source IP, request/correlation id and outcome.',
      'Send these logs to an append-only store outside the application’s control.',
      'For high-value operations (payments, privilege changes) keep signed receipts or require transaction confirmation (step-up auth).',
    ],
    references: [REF.logging, REF.transactionAuth, REF.cwe(778)],
    likelihood: 2,
    impact: (el) => (has(el, 'admin') ? 3 : 2),
  },

  // ======================= Processes (S, T, R, I, D, E) =======================
  {
    id: 'PROC-S-01',
    category: 'S',
    appliesTo: 'process',
    title: (el, ctx) => `Callers or downstream services are tricked into talking to a fake ${ctx.name(el)}`,
    description: (el, ctx) =>
      `A rogue service, DNS hijack or man-in-the-middle impersonates ${ctx.name(el)}. Clients then send it credentials and data, or accept forged responses. Internal service-to-service calls without authentication are particularly exposed once an attacker has a foothold in the network.`,
    mitigations: [
      'Serve only over TLS with certificates from a trusted CA; clients must validate the certificate and hostname (never disable verification).',
      'Authenticate service-to-service calls with workload identity (mTLS, SPIFFE/SPIRE, cloud IAM) instead of network location.',
      'Restrict who can create DNS records / ingress routes for this service.',
    ],
    references: [REF.microservices, REF.tls, REF.cwe(295)],
    likelihood: 1,
    impact: (el, ctx) => impactForClassification(ctx.maxClassification(el.id)),
  },
  {
    id: 'PROC-S-02',
    category: 'S',
    appliesTo: 'process',
    when: (el) => has(el, 'handles-auth') || has(el, 'internet-facing'),
    title: (el, ctx) => `Account takeover on ${ctx.name(el)} via credential stuffing, brute force or phishing`,
    description: (el, ctx) =>
      `Attackers replay leaked username/password pairs or guess passwords against the authentication of ${ctx.name(el)}, then act as the victim user. This is the most common way user accounts are compromised.`,
    mitigations: [
      'Offer and encourage MFA; require it for admin and high-risk actions (prefer WebAuthn/passkeys).',
      'Rate-limit and add progressive delays per account and per IP on login, password reset and MFA endpoints; alert on spikes.',
      'Reject known-breached passwords (e.g. k-anonymity check against Pwned Passwords) and enforce a minimum length of 8+ (15+ without MFA).',
      'Return identical errors and timing for "unknown user" and "wrong password"; notify users of new-device logins.',
    ],
    references: [REF.stuffing, REF.authn, REF.mfa, REF.cwe(307)],
    likelihood: (el) => (has(el, 'internet-facing') ? 3 : 2),
    impact: (el) => (has(el, 'admin') || has(el, 'processes-payments') ? 3 : 2),
  },
  {
    id: 'PROC-S-03',
    category: 'S',
    appliesTo: 'process',
    when: (el) => has(el, 'handles-auth'),
    title: (el, ctx) => `Forged, stolen or never-expiring sessions/tokens accepted by ${ctx.name(el)}`,
    description: (el, ctx) =>
      `${ctx.name(el)} issues or validates sessions or tokens. Typical failures: JWTs accepted with "alg: none" or the wrong key/algorithm, missing iss/aud/exp checks, session ids not rotated after login (fixation), tokens stored where XSS can read them, or no way to revoke a stolen token.`,
    mitigations: [
      'Validate JWTs with an explicit algorithm allowlist and the expected key; check iss, aud, exp and nbf on every request.',
      'Keep access tokens short-lived (minutes) and rotate refresh tokens on use, with reuse detection and server-side revocation.',
      'For cookie sessions: regenerate the session id on login/privilege change; set Secure, HttpOnly and SameSite=Lax/Strict; enforce idle and absolute timeouts.',
      'Invalidate all sessions on password change, MFA reset and logout.',
    ],
    references: [REF.jwt, REF.jwtBcp, REF.session, REF.cwe(287)],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'PROC-T-01',
    category: 'T',
    appliesTo: 'process',
    when: (el, ctx) => ctx.flowsIn(el.id).length > 0 || has(el, 'internet-facing'),
    title: (el, ctx) => `Injection through untrusted input processed by ${ctx.name(el)}`,
    description: (el, ctx) => {
      const sinks = ctx
        .flowsOut(el.id)
        .map((f) => ctx.byId.get(f.toId ?? ''))
        .filter((d): d is ModelElement => d?.type === 'datastore')
        .map((d) => ctx.name(d))
      return `Input reaching ${ctx.name(el)} is interpreted as code or commands: SQL/NoSQL injection, OS command injection, LDAP/XPath injection, template injection or stored XSS.${sinks.length ? ` Injected queries against ${list(sinks)} can read or modify data directly.` : ''}`
    },
    mitigations: [
      'Use parameterised queries / prepared statements or a safe ORM API for every database access — never build queries with string concatenation.',
      'Avoid invoking shells; if a subprocess is needed, pass arguments as an array with a fixed executable.',
      'Validate input at the boundary with an allowlist schema (type, length, format) and encode output for its context (HTML, JS, URL).',
      'Run SAST (e.g. Semgrep/CodeQL) in CI with injection rules enabled.',
    ],
    references: [REF.injection, REF.inputValidation, REF.cwe(89), REF.cwe(78)],
    likelihood: (el) => (has(el, 'internet-facing') ? 3 : 2),
    impact: (el, ctx) =>
      ctx.flowsOut(el.id).some((f) => ctx.byId.get(f.toId ?? '')?.type === 'datastore') ? 3 : impactForClassification(ctx.maxClassification(el.id)),
  },
  {
    id: 'PROC-T-02',
    category: 'T',
    appliesTo: 'process',
    when: (el) => has(el, 'internet-facing'),
    title: (el, ctx) => `Client-controlled parameters tampered with to change business logic in ${ctx.name(el)}`,
    description: (el, ctx) =>
      `Anything the client sends to ${ctx.name(el)} — prices, quantities, user ids, role fields, hidden form fields, feature flags — can be modified with a proxy. Binding request bodies directly onto domain objects (mass assignment) lets attackers set fields such as "isAdmin" or "balance".`,
    mitigations: [
      'Recompute security-relevant values (prices, totals, ownership) on the server; never trust them from the client.',
      'Bind requests to explicit DTOs with an allowlist of writable fields (no automatic binding to persistence entities).',
      'Enforce business invariants server-side (non-negative quantities, state-machine transitions, limits).',
    ],
    references: [REF.massAssignment, REF.apiTop10, REF.cwe(915)],
    likelihood: 2,
    impact: (el) => (has(el, 'processes-payments') ? 3 : 2),
  },
  {
    id: 'PROC-T-03',
    category: 'T',
    appliesTo: 'process',
    when: (el, ctx) => fromThirdParty(ctx, el).length > 0,
    title: (el, ctx) => `Malicious or malformed data from ${list(fromThirdParty(ctx, el).map((s) => ctx.name(s)))} corrupts ${ctx.name(el)}`,
    description: (el, ctx) =>
      `${ctx.name(el)} consumes data from third party ${list(fromThirdParty(ctx, el).map((s) => ctx.name(s)))}. Developers often trust vendor responses implicitly; a compromised or buggy vendor can deliver payloads that trigger injection, deserialization bugs, or corrupt stored state.`,
    mitigations: [
      'Validate third-party responses and webhook bodies against a strict schema; reject unexpected fields, types and sizes.',
      'Never deserialize vendor data into native objects with polymorphic type handling; parse JSON into plain data.',
      'Set timeouts and maximum response sizes on every outbound call.',
    ],
    references: [REF.inputValidation, REF.deserialization, REF.cwe(20)],
    likelihood: 2,
    impact: (el, ctx) => impactForClassification(ctx.maxClassification(el.id)),
  },
  {
    id: 'PROC-T-04',
    category: 'T',
    appliesTo: 'process',
    title: (el, ctx) => `Malicious code shipped in ${ctx.name(el)} through a compromised dependency or build pipeline`,
    description: (el, ctx) =>
      `The code running as ${ctx.name(el)} includes third-party packages, base images and CI actions. A typosquatted or hijacked package, a compromised CI secret, or an unpinned GitHub Action can inject code that runs with the full privileges of this process.`,
    mitigations: [
      'Commit lockfiles, install with `npm ci`/equivalent, and scan dependencies for known vulnerabilities (OSV, Dependabot) on every PR.',
      'Pin third-party GitHub Actions to a full commit SHA and give workflows a least-privilege `permissions:` block.',
      'Build in CI only, sign artifacts / generate provenance (SLSA) and deploy only signed, scanned images.',
      'Protect the default branch: required reviews, no direct pushes, secret scanning with push protection.',
    ],
    references: [REF.supplyChain, REF.depMgmt, REF.slsa, REF.cwe(1357)],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'PROC-R-01',
    category: 'R',
    appliesTo: 'process',
    title: (el, ctx) => `Security-relevant actions in ${ctx.name(el)} are not traceable`,
    description: (el, ctx) =>
      `If ${ctx.name(el)} does not record who did what and when, attacks go unnoticed, users can deny actions, and incident responders cannot establish scope (which accounts and records were touched).`,
    mitigations: [
      'Log authentication successes/failures, authorization failures, input-validation failures, admin actions and changes to sensitive data — with user id, timestamp, source IP, correlation id and outcome.',
      'Use structured (JSON) logs shipped to a central store the application cannot modify or delete.',
      'Define alerts for suspicious patterns (bursts of 401/403, many password resets, admin actions at odd hours) and test them.',
    ],
    references: [REF.logging, REF.cwe(778)],
    likelihood: 2,
    impact: (el) => (has(el, 'admin') || has(el, 'processes-payments') || has(el, 'handles-auth') ? 3 : 2),
  },
  {
    id: 'PROC-I-01',
    category: 'I',
    appliesTo: 'process',
    title: (el, ctx) => `${ctx.name(el)} leaks internals through error messages and debug features`,
    description: (el, ctx) =>
      `Stack traces, SQL errors, framework debug pages, verbose version headers or exposed actuator/metrics endpoints on ${ctx.name(el)} give attackers file paths, library versions, query structure and sometimes secrets — accelerating every other attack.`,
    mitigations: [
      'Return generic error responses with a correlation id; log details server-side only.',
      'Disable debug mode, directory listing and framework debug endpoints in production; restrict health/metrics endpoints to the internal network.',
      'Remove or genericise Server / X-Powered-By headers.',
    ],
    references: [REF.errors, REF.cwe(209)],
    likelihood: (el) => (has(el, 'internet-facing') ? 3 : 2),
    impact: 1,
  },
  {
    id: 'PROC-I-02',
    category: 'I',
    appliesTo: 'process',
    when: (el, ctx) => has(el, 'stores-pii') || isSensitive(ctx.maxClassification(el.id)),
    title: (el, ctx) => `Sensitive data handled by ${ctx.name(el)} exposed via API responses, logs or caches`,
    description: (el, ctx) =>
      `${ctx.name(el)} handles ${ctx.maxClassification(el.id)} data${has(el, 'stores-pii') ? ' including personal data' : ''}. Common leaks: endpoints returning whole database objects (excessive data exposure), tokens or PII written to application logs, sensitive responses cached by CDNs/browsers, and data copied to analytics or error-tracking tools.`,
    mitigations: [
      'Serialise responses through explicit view models that only include fields the caller is allowed to see.',
      'Redact secrets, tokens and PII in logs and error-tracking (central log filter + tests).',
      'Send `Cache-Control: no-store` on responses containing sensitive data.',
      'Review which third-party SDKs (analytics, APM, error tracking) receive request data.',
    ],
    references: [REF.apiTop10, REF.logging, REF.cwe(200), REF.cwe(532)],
    likelihood: 2,
    impact: (el, ctx) => (has(el, 'stores-pii') ? 3 : impactForClassification(ctx.maxClassification(el.id))),
  },
  {
    id: 'PROC-I-03',
    category: 'I',
    appliesTo: 'process',
    when: (el, ctx) => outboundToExternals(ctx, el).length > 0 || (has(el, 'internet-facing') && ctx.flowsOut(el.id).length > 0),
    title: (el, ctx) => `Server-side request forgery (SSRF) from ${ctx.name(el)}`,
    description: (el, ctx) =>
      `${ctx.name(el)} makes outbound network requests. If any part of a destination URL (host, path, redirect target, webhook URL, image URL to fetch) is influenced by a user, an attacker can make the server call internal services or the cloud metadata endpoint (169.254.169.254) and steal credentials.`,
    mitigations: [
      'Only call destinations from a server-side allowlist; never fetch arbitrary user-supplied URLs.',
      'If user URLs are unavoidable: resolve DNS once, block private, loopback and link-local ranges, disable redirects, and fetch through an egress proxy.',
      'Enforce IMDSv2 (session tokens) on cloud instances and apply egress network policies so the process can only reach what it needs.',
    ],
    references: [REF.ssrf, REF.imds, REF.cwe(918)],
    likelihood: (el) => (has(el, 'internet-facing') ? 2 : 1),
    impact: 3,
  },
  {
    id: 'PROC-I-04',
    category: 'I',
    appliesTo: 'process',
    when: (el, ctx) =>
      ctx.flowsOut(el.id).some((f) => {
        const dst = ctx.byId.get(f.toId ?? '')
        return dst?.type === 'datastore' || (dst?.type === 'external' && has(dst, 'third-party'))
      }),
    title: (el, ctx) => `Credentials used by ${ctx.name(el)} leak (source code, images, env dumps, logs)`,
    description: (el, ctx) => {
      const targets = ctx
        .flowsOut(el.id)
        .map((f) => ctx.byId.get(f.toId ?? ''))
        .filter((d): d is ModelElement => !!d && (d.type === 'datastore' || (d.type === 'external' && has(d, 'third-party'))))
        .map((d) => ctx.name(d))
      return `${ctx.name(el)} authenticates to ${list(targets)}. Database passwords and API keys committed to git, baked into container images, printed in CI logs or exposed via debug endpoints give an attacker direct access that bypasses the application.`
    },
    mitigations: [
      'Load secrets at runtime from a secrets manager (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) or use workload identity instead of static secrets.',
      'Enable secret scanning with push protection on the repository and scan container images for embedded secrets.',
      'Rotate credentials regularly and immediately when people leave or a leak is suspected; give each service its own credentials.',
    ],
    references: [REF.secrets, REF.cwe(798)],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'PROC-D-01',
    category: 'D',
    appliesTo: 'process',
    when: (el) => has(el, 'internet-facing'),
    title: (el, ctx) => `${ctx.name(el)} is made unavailable by request floods or expensive requests`,
    description: (el, ctx) =>
      `As an internet-facing component, ${ctx.name(el)} can be overwhelmed by volumetric attacks, scrapers, or a few expensive requests (huge payloads, unbounded pagination, complex GraphQL queries, regex backtracking). With autoscaling, the attack can turn into a large cloud bill instead.`,
    mitigations: [
      'Apply rate limiting per IP, per user/API key and per expensive endpoint (API gateway / reverse proxy), returning 429.',
      'Limit request body size, page size, query depth/complexity and upload size; set server and upstream timeouts.',
      'Put the service behind a CDN/WAF with DDoS protection.',
      'Cap autoscaling (max instances) and set budget alerts so an attack cannot cause unlimited spend.',
    ],
    references: [REF.dos, REF.apiTop10, REF.cwe(770), REF.cwe(400)],
    likelihood: 2,
    impact: (el) => (has(el, 'processes-payments') ? 3 : 2),
  },
  {
    id: 'PROC-D-02',
    category: 'D',
    appliesTo: 'process',
    when: (el, ctx) => ctx.flowsOut(el.id).length > 0,
    title: (el, ctx) => `A slow or failing dependency cascades into an outage of ${ctx.name(el)}`,
    description: (el, ctx) => {
      const deps = ctx.flowsOut(el.id).map((f) => ctx.name(ctx.byId.get(f.toId ?? '')))
      return `${ctx.name(el)} depends on ${list(deps)}. Without timeouts and isolation, one hanging dependency exhausts threads/connection pools and takes the whole service down — attackers can trigger this deliberately by targeting the weakest dependency.`
    },
    mitigations: [
      'Set connect and read timeouts on every outbound call and database query.',
      'Use bounded connection pools, circuit breakers and bulkheads per dependency; retry only idempotent calls, with exponential backoff and jitter.',
      'Degrade gracefully (cached/partial responses) and monitor dependency latency and error rates.',
    ],
    references: [REF.dos, REF.microservices],
    likelihood: 2,
    impact: 2,
  },
  {
    id: 'PROC-D-03',
    category: 'D',
    appliesTo: 'process',
    when: (el) => has(el, 'handles-auth'),
    title: (el, ctx) => `Login and password-reset flows of ${ctx.name(el)} abused to lock out users or exhaust CPU`,
    description: (el, ctx) =>
      `Hard account lockout lets anyone lock a victim out by entering wrong passwords; slow password hashing (by design) means a flood of login attempts on ${ctx.name(el)} consumes a lot of CPU; reset/OTP endpoints can be abused to spam users or run up SMS costs.`,
    mitigations: [
      'Prefer progressive delays, CAPTCHA or risk-based challenges over permanent lockout; unlock automatically after a period.',
      'Rate-limit login, reset and OTP endpoints per account and per IP before doing expensive hashing.',
      'Cap SMS/e-mail sends per user and per destination; monitor sending costs.',
    ],
    references: [REF.authn, REF.stuffing, REF.cwe(645)],
    likelihood: 2,
    impact: 2,
  },
  {
    id: 'PROC-E-01',
    category: 'E',
    appliesTo: 'process',
    title: (el, ctx) => `Missing or broken authorization checks in ${ctx.name(el)} (IDOR / BOLA, function-level)`,
    description: (el, ctx) =>
      `${ctx.name(el)} authenticates callers but may not check, on every request, that this caller may access this specific object or function. Changing an id in the URL (/invoices/1234 → 1235) or calling an admin route directly then exposes or modifies other users' data — the #1 issue in the OWASP API Security Top 10.`,
    mitigations: [
      'Deny by default: enforce authorization in one central place (middleware/policy engine) for every route, not ad hoc in handlers.',
      'Check object ownership/tenant on every read and write (scope queries by tenant/user id), including bulk and export endpoints.',
      'Prefer non-guessable ids (UUIDs) as defence in depth — but never as the only control.',
      'Add automated tests that call each endpoint as another user and as a lower-privileged role and expect 403/404.',
    ],
    references: [REF.authz, REF.idor, REF.apiTop10, REF.cwe(639), REF.cwe(285)],
    likelihood: (el) => (has(el, 'internet-facing') ? 3 : 2),
    impact: (el, ctx) => (has(el, 'stores-pii') || has(el, 'admin') ? 3 : impactForClassification(ctx.maxClassification(el.id))),
  },
  {
    id: 'PROC-E-02',
    category: 'E',
    appliesTo: 'process',
    when: (el) => has(el, 'admin'),
    title: (el, ctx) => `Privilege escalation through the administrative functions of ${ctx.name(el)}`,
    description: (el, ctx) =>
      `${ctx.name(el)} exposes admin operations (user management, configuration, data export, impersonation). An attacker who reaches them — via a phished admin, a missing role check, or CSRF against a logged-in admin — controls the whole system.`,
    mitigations: [
      'Do not expose the admin interface to the internet: separate host/route reachable only through VPN/zero-trust proxy.',
      'Require phishing-resistant MFA and step-up re-authentication for admin actions; keep admin sessions short.',
      'Use just-in-time, time-boxed admin access and four-eyes approval for the most dangerous operations.',
      'Audit-log every admin action to an append-only store and alert on role changes.',
    ],
    references: [REF.authz, REF.mfa, REF.apiTop10, REF.cwe(269)],
    likelihood: (el) => (has(el, 'internet-facing') ? 3 : 2),
    impact: 3,
  },
  {
    id: 'PROC-E-03',
    category: 'E',
    appliesTo: 'process',
    title: (el, ctx) => `Compromise of ${ctx.name(el)} grants more access than it needs (excessive privileges)`,
    description: (el, ctx) =>
      `If ${ctx.name(el)} runs as root, with a broad cloud IAM role, or with a database owner account, any code-execution or injection bug turns into a full environment compromise instead of a contained incident.`,
    mitigations: [
      'Run as a non-root user in a minimal image with a read-only root filesystem and dropped Linux capabilities.',
      'Give the workload its own IAM role scoped to the exact resources and actions it uses; no wildcard policies.',
      'Use a dedicated database user with only the required privileges (no DDL, no superuser) per service.',
    ],
    references: [REF.docker, REF.database, REF.cwe(250)],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'PROC-E-04',
    category: 'E',
    appliesTo: 'process',
    when: (el) => has(el, 'internet-facing'),
    title: (el, ctx) => `Remote code execution in ${ctx.name(el)} via unsafe deserialization, file upload or known CVEs`,
    description: (el, ctx) =>
      `Internet-facing code paths that deserialize untrusted data into native objects (Java/.NET/PHP/Python pickle), render user-controlled templates, process uploaded files (image/PDF/XML parsers, XXE) or run unpatched frameworks are the typical route to code execution on ${ctx.name(el)}.`,
    mitigations: [
      'Never deserialize untrusted data with native serializers; use JSON into plain data types with schema validation.',
      'For uploads: allowlist extensions and content types, re-encode images, store outside the web root with random names, scan for malware, disable XML external entities.',
      'Patch frameworks and OS packages on a defined SLA (e.g. critical CVEs within 7 days) and track them with dependency scanning.',
    ],
    references: [REF.deserialization, REF.fileUpload, REF.cwe(502), REF.cwe(434)],
    likelihood: 2,
    impact: 3,
  },

  // ======================= Data stores (T, I, D, +R for logs) =======================
  {
    id: 'DS-T-01',
    category: 'T',
    appliesTo: 'datastore',
    title: (el, ctx) => `Unauthorized modification or corruption of data in ${ctx.name(el)}`,
    description: (el, ctx) =>
      `An attacker with direct or indirect write access to ${ctx.name(el)} (shared credentials, over-privileged service account, network-reachable admin port, injection in a writing service) alters records — e.g. balances, roles, prices — without going through business logic.`,
    mitigations: [
      'Do not expose the store to the internet; restrict network access to the services that need it (private subnet, security groups).',
      'Give each writing service its own least-privilege account; humans use separate, audited, time-boxed access.',
      'Enforce integrity constraints in the store itself and keep point-in-time recovery enabled to undo corruption.',
    ],
    references: [REF.database, REF.cwe(284)],
    likelihood: 2,
    impact: (el, ctx) => (has(el, 'stores-credentials') ? 3 : impactForClassification(ctx.maxClassification(el.id))),
  },
  {
    id: 'DS-I-01',
    category: 'I',
    appliesTo: 'datastore',
    title: (el, ctx) => `Data in ${ctx.name(el)} read by unauthorized parties (breach / misconfiguration)`,
    description: (el, ctx) =>
      `Publicly reachable databases, public cloud buckets, default credentials and stolen service credentials are leading causes of data breaches. ${ctx.name(el)} holds ${ctx.maxClassification(el.id)} data${has(el, 'stores-pii') ? ', including personal data' : ''}.`,
    mitigations: [
      'Block public network access; require authentication and TLS for every connection.',
      'Encrypt at rest with keys managed in a KMS; restrict and audit who can use the key (separation from storage admins).',
      'Review access grants periodically and alert on unusual bulk reads/exports.',
      'Enable account-level "block public access" guardrails for object storage.',
    ],
    references: [REF.database, REF.cryptoStorage, REF.cwe(200)],
    likelihood: 2,
    impact: (el, ctx) => (has(el, 'stores-pii') || has(el, 'stores-credentials') ? 3 : impactForClassification(ctx.maxClassification(el.id))),
  },
  {
    id: 'DS-I-02',
    category: 'I',
    appliesTo: 'datastore',
    when: (el) => has(el, 'stores-credentials'),
    title: (el, ctx) => `Credential theft from ${ctx.name(el)}`,
    description: (el, ctx) =>
      `${ctx.name(el)} stores passwords, API keys, tokens or private keys. A dump of this store lets attackers crack weakly hashed passwords offline and reuse them elsewhere (credential stuffing), or use stored keys/tokens directly.`,
    mitigations: [
      'Hash user passwords with Argon2id (OWASP minimum: m=19 MiB, t=2, p=1), or scrypt (N=2^17, r=8, p=1); bcrypt (cost ≥ 10, 72-byte input limit) only for legacy systems; PBKDF2-HMAC-SHA256 with 600,000 iterations where FIPS-140 is required.',
      'Store API keys and tokens as hashes (e.g. SHA-256 of a high-entropy random key) and show the plaintext only once at creation.',
      'Encrypt secrets that must be recoverable with envelope encryption using KMS-managed keys (or an HSM); never store the key next to the data.',
      'Plan for rehash-on-login when upgrading algorithms or work factors.',
    ],
    references: [REF.passwords, REF.keyMgmt, REF.cryptoStorage, REF.cwe(916), REF.cwe(256)],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'DS-I-03',
    category: 'I',
    appliesTo: 'datastore',
    when: (el) => has(el, 'stores-pii'),
    title: (el, ctx) => `Personal data breach from ${ctx.name(el)} (GDPR / privacy impact)`,
    description: (el, ctx) =>
      `${ctx.name(el)} holds personal data. A breach is a reportable incident (GDPR Art. 33: notify the supervisory authority within 72 hours where feasible) and harms users; over-collected or over-retained data increases the blast radius.`,
    mitigations: [
      'Minimise: collect and keep only the fields you need, with a documented retention period and automated deletion.',
      'Pseudonymise or apply field-level encryption to the most sensitive fields (national ids, health, financial data).',
      'Mask personal data in non-production environments — never copy production dumps to dev/test.',
      'Log access to personal data and have a tested breach-response runbook.',
    ],
    references: [REF.privacy, REF.gdpr33, REF.cryptoStorage],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'DS-I-04',
    category: 'I',
    appliesTo: 'datastore',
    title: (el, ctx) => `Backups, snapshots or exports of ${ctx.name(el)} exposed`,
    description: (el, ctx) =>
      `Copies of ${ctx.name(el)} — database snapshots, backup files, CSV exports, replicas used for analytics — often get weaker protection than the primary store and are a frequent source of leaks (shared snapshots, public buckets, laptops).`,
    mitigations: [
      'Encrypt backups and snapshots with KMS keys and store them in a separate, restricted account/project.',
      'Prevent public sharing of snapshots and buckets with organisation-level policies.',
      'Inventory every copy/replica of the data and apply the same classification and access controls.',
    ],
    references: [REF.cryptoStorage, REF.database],
    likelihood: 1,
    impact: (el, ctx) => (has(el, 'stores-pii') || has(el, 'stores-credentials') ? 3 : impactForClassification(ctx.maxClassification(el.id))),
  },
  {
    id: 'DS-D-01',
    category: 'D',
    appliesTo: 'datastore',
    title: (el, ctx) => `${ctx.name(el)} becomes unavailable (exhaustion of storage, connections or IOPS)`,
    description: (el, ctx) =>
      `Unbounded writes, missing pagination, expensive unindexed queries or connection storms from scaled-out clients can exhaust ${ctx.name(el)}; every dependent service then fails.`,
    mitigations: [
      'Set connection-pool limits in clients and maximum connections / statement timeouts in the store.',
      'Enforce quotas and size limits on user-generated content; paginate all list queries.',
      'Monitor capacity (disk, connections, CPU, replication lag) with alerts before saturation; use replicas/HA for critical stores.',
    ],
    references: [REF.dos, REF.cwe(400)],
    likelihood: 2,
    impact: 2,
  },
  {
    id: 'DS-D-02',
    category: 'D',
    appliesTo: 'datastore',
    when: (el) => !has(el, 'third-party'),
    title: (el, ctx) => `Data in ${ctx.name(el)} destroyed or encrypted (ransomware, malicious or accidental deletion)`,
    description: (el, ctx) =>
      `An attacker with admin credentials (or a mistaken migration/script) deletes or encrypts ${ctx.name(el)} — and, if backups are reachable with the same credentials, the backups too.`,
    mitigations: [
      'Keep immutable/offline backups (object lock, separate backup account) that production credentials cannot delete.',
      'Enable deletion protection on databases/buckets and require approval for destructive migrations.',
      'Regularly test restores and measure RPO/RTO against business requirements.',
    ],
    references: [REF.objectLock, REF.database],
    likelihood: 1,
    impact: 3,
  },
  {
    id: 'DS-R-01',
    category: 'R',
    appliesTo: 'datastore',
    when: (el) => has(el, 'logs'),
    title: (el, ctx) => `Entries in ${ctx.name(el)} altered or deleted to cover an attacker's tracks`,
    description: (el, ctx) =>
      `${ctx.name(el)} is the audit trail. If the systems being audited (or their admins) can modify or delete entries, an attacker who compromises them erases the evidence, and legitimate users can repudiate their actions.`,
    mitigations: [
      'Write logs to append-only/WORM storage (e.g. S3 Object Lock in compliance mode, immutable log analytics tables) with a defined retention.',
      'Producers get write-only credentials; reading and administration are separate roles.',
      'Make tampering evident: hash-chain or sign log batches and forward a copy to a SIEM in a separate security account.',
      'Synchronise clocks (NTP) across all producers so timelines can be reconstructed.',
    ],
    references: [REF.logging, REF.objectLock],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'DS-I-05',
    category: 'I',
    appliesTo: 'datastore',
    when: (el) => has(el, 'logs'),
    title: (el, ctx) => `Secrets and personal data accumulate in ${ctx.name(el)}`,
    description: (el, ctx) =>
      `Logs routinely capture request bodies, headers (Authorization, cookies), tokens in URLs and personal data. ${ctx.name(el)} then becomes a high-value target that is usually readable by far more people than the production database.`,
    mitigations: [
      'Redact Authorization headers, cookies, passwords, tokens and card numbers before logging (central logging filter with tests).',
      'Do not put secrets or personal data in URLs / query strings — they end up in access logs.',
      'Restrict log access by role and set retention limits.',
    ],
    references: [REF.logging, REF.cwe(532), REF.cwe(598)],
    likelihood: 2,
    impact: 2,
  },
  {
    id: 'DS-D-03',
    category: 'D',
    appliesTo: 'datastore',
    when: (el) => has(el, 'logs'),
    title: (el, ctx) => `${ctx.name(el)} flooded so that real events are lost or logging stops`,
    description: (el, ctx) =>
      `An attacker generates huge volumes of log events (e.g. failed requests) to fill ${ctx.name(el)}, rotate away evidence, blow the logging budget or make producers block/crash when the log sink is unavailable.`,
    mitigations: [
      'Rate-limit/sample noisy events at the producer while always keeping security events.',
      'Alert on missing logs (heartbeat) and on sudden volume changes.',
      'Make logging asynchronous and non-blocking with bounded buffers; size storage and retention for attack volumes.',
    ],
    references: [REF.logging, REF.cwe(400)],
    likelihood: 1,
    impact: 2,
  },

  // ======================= Data flows (T, I, D) =======================
  {
    id: 'DF-I-01',
    category: 'I',
    appliesTo: 'dataflow',
    when: (el) => el.crossesTrustBoundary === true && transportSecurity(el.protocol) === 'plaintext',
    title: (el, ctx) => `Eavesdropping on ${el.dataClassification ?? 'internal'} data sent in cleartext (${protoLabel(el)}) across a trust boundary: ${flowEnds(el, ctx)}`,
    description: (el) =>
      `This flow uses ${protoLabel(el)}, which is not encrypted, and crosses a trust boundary. Anyone on the path (Wi-Fi, ISP, hosting provider, compromised network device) can read credentials, session tokens and ${el.dataClassification ?? 'internal'} data.`,
    mitigations: [
      'Switch to an encrypted protocol: HTTPS/TLS 1.2+ (prefer TLS 1.3), SFTP/FTPS instead of FTP, SSH instead of Telnet, TLS-enabled variants for databases/queues.',
      'Disable the plaintext listener (or redirect HTTP→HTTPS and send HSTS for browsers).',
      'Validate server certificates in every client; consider mTLS for service-to-service traffic.',
    ],
    references: [REF.tls, REF.hsts, REF.cwe(319)],
    likelihood: 3,
    impact: (el) => impactForClassification(el.dataClassification),
  },
  {
    id: 'DF-T-01',
    category: 'T',
    appliesTo: 'dataflow',
    when: (el) => el.crossesTrustBoundary === true && transportSecurity(el.protocol) === 'plaintext',
    title: (el, ctx) => `Man-in-the-middle modifies cleartext traffic (${protoLabel(el)}): ${flowEnds(el, ctx)}`,
    description: (el) =>
      `Without transport integrity, an on-path attacker can alter requests and responses on this ${protoLabel(el)} flow — inject scripts into pages, change payment amounts or redirect downloads — without either side noticing.`,
    mitigations: [
      'Use TLS (authenticated encryption) end to end; terminate TLS as close to the workload as possible.',
      'For messages that pass through intermediaries, sign payloads (e.g. JWS / HMAC) and verify at the receiver.',
    ],
    references: [REF.tls, REF.cwe(319), REF.cwe(345)],
    likelihood: 3,
    impact: (el) => Math.max(2, impactForClassification(el.dataClassification)),
  },
  {
    id: 'DF-I-02',
    category: 'I',
    appliesTo: 'dataflow',
    when: (el) => el.crossesTrustBoundary !== true && transportSecurity(el.protocol) === 'plaintext' && isSensitive(el.dataClassification),
    title: (el, ctx) => `${el.dataClassification} data sent in cleartext on the internal network: ${flowEnds(el, ctx)}`,
    description: (el) =>
      `The flow stays inside a trust boundary but carries ${el.dataClassification} data over ${protoLabel(el)}. Once any host in the segment is compromised, the attacker can sniff this traffic; "internal network = trusted" assumptions rarely hold in cloud and Kubernetes environments.`,
    mitigations: [
      'Encrypt internal traffic too (TLS to the database, mTLS via service mesh).',
      'Segment the network so only the two endpoints can reach each other.',
    ],
    references: [REF.microservices, REF.tls, REF.cwe(319)],
    likelihood: 2,
    impact: (el) => impactForClassification(el.dataClassification),
  },
  {
    id: 'DF-I-03',
    category: 'I',
    appliesTo: 'dataflow',
    when: (el) => el.crossesTrustBoundary === true && transportSecurity(el.protocol) === 'unknown',
    title: (el, ctx) => `Transport encryption not confirmed for a flow crossing a trust boundary: ${flowEnds(el, ctx)}`,
    description: (el) =>
      `The protocol "${protoLabel(el)}" can run with or without encryption (for example PostgreSQL sslmode, Kafka listeners, Redis). If TLS is optional or not enforced, the data can be read and modified in transit.`,
    mitigations: [
      'Enforce TLS on the server side (e.g. `hostssl` only in pg_hba.conf, `require_secure_transport` in MySQL, TLS-only Kafka listeners).',
      'Configure clients to require TLS and verify the certificate (e.g. sslmode=verify-full).',
      'Record the actual protocol in this model (e.g. "PostgreSQL over TLS") once confirmed.',
    ],
    references: [REF.tls, REF.database, REF.cwe(319)],
    likelihood: 2,
    impact: (el) => impactForClassification(el.dataClassification),
  },
  {
    id: 'DF-I-04',
    category: 'I',
    appliesTo: 'dataflow',
    when: (el) => el.crossesTrustBoundary === true && transportSecurity(el.protocol) === 'encrypted' && isSensitive(el.dataClassification),
    title: (el, ctx) => `Weak TLS configuration or disabled certificate validation exposes ${el.dataClassification} data: ${flowEnds(el, ctx)}`,
    description: (el) =>
      `The flow is encrypted, but protection depends on configuration: legacy protocol versions (SSLv3, TLS 1.0/1.1), weak cipher suites, expired certificates, or clients that skip certificate verification (verify=False, InsecureSkipVerify) re-open the door to interception of ${el.dataClassification} data.`,
    mitigations: [
      'Allow only TLS 1.2 and 1.3 with modern AEAD cipher suites; check endpoints with testssl.sh or SSL Labs.',
      'Search the codebase for disabled certificate verification and forbid it with a lint/SAST rule.',
      'Automate certificate renewal and monitor expiry.',
    ],
    references: [REF.tls, REF.cwe(295), REF.cwe(326)],
    likelihood: 1,
    impact: (el) => impactForClassification(el.dataClassification),
  },
  {
    id: 'DF-I-05',
    category: 'I',
    appliesTo: 'dataflow',
    when: (el) => el.dataClassification === 'secret',
    title: (el, ctx) => `Secrets in transit leak through URLs, proxies or intermediaries: ${flowEnds(el, ctx)}`,
    description: () =>
      'This flow carries secret data (credentials, keys, tokens). Even over TLS, secrets placed in URLs or query strings are written to proxy, CDN, server and browser history logs, and TLS-terminating intermediaries see them in clear.',
    mitigations: [
      'Send secrets only in request bodies or Authorization headers, never in URLs.',
      'Prefer short-lived, audience-restricted tokens over long-lived static secrets.',
      'Minimise the number of TLS-terminating hops; encrypt payloads end-to-end when they transit third-party infrastructure.',
    ],
    references: [REF.secrets, REF.cwe(598)],
    likelihood: 2,
    impact: 3,
  },
  {
    id: 'DF-T-02',
    category: 'T',
    appliesTo: 'dataflow',
    when: (el, ctx) => el.crossesTrustBoundary === true && ctx.byId.get(el.toId ?? '')?.type === 'process',
    title: (el, ctx) => `Malicious or replayed input crossing the trust boundary into ${ctx.name(ctx.byId.get(el.toId ?? ''))}: ${flowEnds(el, ctx)}`,
    description: (el, ctx) =>
      `Data arriving from ${ctx.name(ctx.byId.get(el.fromId ?? ''))} is outside your control. Encryption protects it in transit, not its content: the sender can craft any payload (oversized fields, unexpected types, duplicated keys, replayed requests).`,
    mitigations: [
      'Validate every message at the boundary against a strict schema (OpenAPI/JSON Schema) and reject unknown fields.',
      'Use idempotency keys or nonces for state-changing requests to make replays harmless.',
      'Protect cookie-authenticated, state-changing browser requests against CSRF (SameSite cookies plus anti-CSRF tokens or Origin checks).',
    ],
    references: [REF.inputValidation, 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html', REF.cwe(20)],
    likelihood: 2,
    impact: (el) => Math.max(2, impactForClassification(el.dataClassification)),
  },
  {
    id: 'DF-D-01',
    category: 'D',
    appliesTo: 'dataflow',
    when: (el) => el.crossesTrustBoundary === true,
    title: (el, ctx) => `Flow ${flowEnds(el, ctx)} disrupted or flooded`,
    description: (el, ctx) =>
      `Traffic crossing a trust boundary can be flooded by the sending side, or interrupted by the network/provider in between. Consider what happens to ${ctx.name(ctx.byId.get(el.toId ?? ''))} when this flow receives 100x normal volume or stops entirely.`,
    mitigations: [
      'Rate-limit and size-limit at the receiving edge (API gateway, load balancer, queue quotas).',
      'Use timeouts, retries with backoff and queues/dead-letter queues so that outages do not lose data.',
      'Monitor throughput and error rates of this flow and alert on anomalies.',
    ],
    references: [REF.dos, REF.cwe(770)],
    likelihood: 2,
    impact: 2,
  },
  {
    id: 'DF-T-03',
    category: 'T',
    appliesTo: 'dataflow',
    when: (el, ctx) => {
      const dst = ctx.byId.get(el.toId ?? '')
      return !!dst && dst.type === 'datastore' && has(dst, 'logs')
    },
    title: (el, ctx) => `Log injection: forged entries written to ${ctx.name(ctx.byId.get(el.toId ?? ''))}`,
    description: (el, ctx) =>
      `User-controlled values logged by ${ctx.name(ctx.byId.get(el.fromId ?? ''))} can contain newlines or control characters to forge fake entries, break parsers, or inject payloads that execute in log viewers (e.g. HTML/JS in a web console).`,
    mitigations: [
      'Use structured logging (JSON) so user values are always data fields, never raw lines.',
      'Encode or strip CR/LF and control characters from user-supplied values; never log raw request bodies.',
      'Ensure log viewers encode output.',
    ],
    references: [REF.logging, REF.cwe(117)],
    likelihood: 2,
    impact: 2,
  },
]

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

export interface ThreatCandidate {
  ruleId: string
  elementId: string
  category: StrideCategory
  title: string
  description: string
  likelihood: number
  impact: number
  mitigations: string[]
  references: string[]
}

const evalNum = (v: Rule['likelihood'], el: ModelElement, ctx: RuleContext) => {
  const n = typeof v === 'function' ? v(el, ctx) : v
  return Math.min(3, Math.max(1, Math.round(n)))
}

/** Evaluate all rules against every element. Pure and deterministic (element order, then rule order). */
export function generateCandidates(model: ThreatModel, rules: Rule[] = RULES): ThreatCandidate[] {
  const ctx = buildContext(model)
  const out: ThreatCandidate[] = []
  for (const el of model.elements) {
    const allowed = applicableCategories(el)
    for (const rule of rules) {
      if (rule.appliesTo !== el.type) continue
      if (!allowed.includes(rule.category)) continue
      if (rule.when && !rule.when(el, ctx)) continue
      out.push({
        ruleId: rule.id,
        elementId: el.id,
        category: rule.category,
        title: rule.title(el, ctx),
        description: rule.description(el, ctx),
        likelihood: evalNum(rule.likelihood, el, ctx),
        impact: evalNum(rule.impact, el, ctx),
        mitigations: [...rule.mitigations],
        references: [...rule.references],
      })
    }
  }
  return out
}

export function suggestedMitigationText(mitigations: string[]): string {
  return mitigations.map((m) => `- ${m}`).join('\n')
}

export interface MergeStats {
  added: number
  refreshed: number
  unchanged: number
  newlyStale: number
  revived: number
}

export interface MergeResult {
  threats: Threat[]
  stats: MergeStats
}

const key = (ruleId: string | undefined, elementId: string) => `${ruleId ?? ''}\u0000${elementId}`

const sameArr = (a: string[] | undefined, b: string[]) => !!a && a.length === b.length && a.every((x, i) => x === b[i])

/**
 * Merge freshly generated candidates into existing threats.
 *
 * - Manual threats (generated: false) are never touched.
 * - Existing generated threats matching a candidate (same ruleId + elementId) keep every user-owned field
 *   (status, mitigation, owner, ticket, and likelihood/impact once the user changed them); rule-owned text
 *   (title, description, category, suggestions, references) is refreshed, and any stale marker is cleared.
 *   Likelihood/impact still equal to the rule's previous default (ruleLikelihood/ruleImpact) follow the rule.
 * - Existing generated threats without a matching candidate are kept and marked stale (status untouched).
 * - Candidates without an existing threat are appended as new open threats, with the mitigation
 *   pre-filled from the suggestions.
 * Running it twice with the same input yields the same output (idempotent).
 */
export function mergeThreats(existing: Threat[], candidates: ThreatCandidate[], makeId: () => string): MergeResult {
  const stats: MergeStats = { added: 0, refreshed: 0, unchanged: 0, newlyStale: 0, revived: 0 }
  const byKey = new Map<string, ThreatCandidate>()
  for (const c of candidates) if (!byKey.has(key(c.ruleId, c.elementId))) byKey.set(key(c.ruleId, c.elementId), c)

  const matched = new Set<string>()
  const threats: Threat[] = existing.map((t) => {
    if (!t.generated || !t.ruleId) return t
    const k = key(t.ruleId, t.elementId)
    const c = byKey.get(k)
    if (!c) {
      if (t.stale) return t
      stats.newlyStale++
      return { ...t, stale: true }
    }
    matched.add(k)
    // A score still equal to the rule's previous default was never overridden by the user: follow the rule
    // (e.g. a flow reclassified as "secret" raises impact). A user-chosen score is never touched.
    const likelihood = t.ruleLikelihood !== undefined && t.likelihood === t.ruleLikelihood ? c.likelihood : t.likelihood
    const impact = t.ruleImpact !== undefined && t.impact === t.ruleImpact ? c.impact : t.impact
    const changed =
      t.title !== c.title ||
      t.description !== c.description ||
      t.category !== c.category ||
      t.likelihood !== likelihood ||
      t.impact !== impact ||
      t.ruleLikelihood !== c.likelihood ||
      t.ruleImpact !== c.impact ||
      !sameArr(t.suggestedMitigations, c.mitigations) ||
      !sameArr(t.references, c.references)
    if (t.stale) stats.revived++
    else if (changed) stats.refreshed++
    else stats.unchanged++
    if (!changed && !t.stale) return t
    const next: Threat = {
      ...t,
      category: c.category,
      title: c.title,
      description: c.description,
      likelihood,
      impact,
      ruleLikelihood: c.likelihood,
      ruleImpact: c.impact,
      suggestedMitigations: [...c.mitigations],
      references: [...c.references],
    }
    delete next.stale
    return next
  })

  for (const c of candidates) {
    const k = key(c.ruleId, c.elementId)
    if (matched.has(k)) continue
    matched.add(k)
    stats.added++
    threats.push({
      id: makeId(),
      elementId: c.elementId,
      category: c.category,
      title: c.title,
      description: c.description,
      likelihood: c.likelihood,
      impact: c.impact,
      status: 'open',
      mitigation: suggestedMitigationText(c.mitigations),
      generated: true,
      ruleId: c.ruleId,
      ruleLikelihood: c.likelihood,
      ruleImpact: c.impact,
      suggestedMitigations: [...c.mitigations],
      references: [...c.references],
    })
  }
  return { threats, stats }
}

/** Generate + merge in one step. */
export function refreshThreats(model: ThreatModel, makeId: () => string): { model: ThreatModel; stats: MergeStats } {
  const { threats, stats } = mergeThreats(model.threats, generateCandidates(model), makeId)
  return { model: { ...model, threats }, stats }
}

/** User-initiated cleanup of threats flagged stale. */
export function removeStaleThreats(model: ThreatModel): ThreatModel {
  return { ...model, threats: model.threats.filter((t) => !t.stale) }
}
