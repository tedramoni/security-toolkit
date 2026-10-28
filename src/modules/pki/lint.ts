/** Certificate linter: RFC 5280 + CA/Browser Forum TLS Baseline Requirements sanity checks. */
import type { Finding } from '../toolbox/types'
import type { CertInfo } from './cert'
import { isSelfIssued } from './cert'
import type { GeneralNameInfo } from './extensions'
import { extDecoded, findExt, sanNames } from './extensions'
import { dnsIdMatches, normalizeHostname, parseIp } from './hostname'
import { nameField } from './names'
import { OID, PROCESSABLE_EXTENSIONS } from './oids'

const BR_URL = 'https://cabforum.org/working-groups/server/baseline-requirements/requirements/'
const SC081_URL = 'https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/'
const RFC5280 = 'https://www.rfc-editor.org/rfc/rfc5280'

const DAY = 86_400_000

/**
 * Maximum TLS subscriber certificate validity (days) by issuance date, per the CA/B Forum Baseline Requirements
 * §6.3.2: 398 days since 2020-09-01, then ballot SC-081: 200 days from 2026-03-15, 100 days from 2027-03-15,
 * 47 days from 2029-03-15. Returns undefined before 2020-09-01 (older limits are not checked).
 */
export function maxTlsValidityDays(notBefore: Date): number | undefined {
  const t = notBefore.getTime()
  if (t >= Date.UTC(2029, 2, 15)) return 47
  if (t >= Date.UTC(2027, 2, 15)) return 100
  if (t >= Date.UTC(2026, 2, 15)) return 200
  if (t >= Date.UTC(2020, 8, 1)) return 398
  return undefined
}

export const VALIDITY_SCHEDULE: readonly { from: string; days: number }[] = [
  { from: '2020-09-01', days: 398 },
  { from: '2026-03-15', days: 200 },
  { from: '2027-03-15', days: 100 },
  { from: '2029-03-15', days: 47 },
]

/** BR "validity period": notBefore through notAfter inclusive, i.e. notAfter − notBefore + 1 second. */
export function validityDays(info: Pick<CertInfo, 'notBefore' | 'notAfter'>): number {
  return (info.notAfter.getTime() - info.notBefore.getTime() + 1000) / DAY
}

export interface CertRoles {
  isCA: boolean
  bcPresent: boolean
  ekus: string[] | undefined
  dnsSans: string[]
  ipSans: string[]
  /** Looks like a TLS server certificate (serverAuth EKU, or no EKU and DNS/IP SANs). */
  tlsServer: boolean
  selfIssued: boolean
}

export function roles(info: CertInfo): CertRoles {
  const bc = extDecoded(info.extensions, OID.basicConstraints, 'bc')
  const eku = extDecoded(info.extensions, OID.extKeyUsage, 'eku')
  const sans = sanNames(info.extensions)
  const dnsSans = sans.filter((s) => s.type === 'DNS').map((s) => s.value)
  const ipSans = sans.filter((s) => s.type === 'IP').map((s) => s.value)
  const ekus = eku?.usages.map((u) => u.oid)
  const isCA = bc?.ca === true
  const cn = nameField(info.subject, OID.commonName)
  const hostLike = cn.some((c) => !!normalizeHostname(c) && c.includes('.'))
  const tlsServer = !isCA && (ekus ? ekus.includes(OID.serverAuth) : dnsSans.length > 0 || ipSans.length > 0 || hostLike)
  return { isCA, bcPresent: !!bc, ekus, dnsSans, ipSans, tlsServer, selfIssued: isSelfIssued(info) }
}

function hostnameLike(s: string): boolean {
  return !!normalizeHostname(s.replace(/^\*\./, 'x.')) && s.includes('.')
}

function cnCoveredBySan(cn: string, sans: GeneralNameInfo[]): boolean {
  const ip = parseIp(cn)
  if (ip) return sans.some((s) => s.type === 'IP' && parseIp(s.value)?.join('.') === ip.join('.'))
  const n = cn.toLowerCase().replace(/\.$/, '')
  return sans.some((s) => s.type === 'DNS' && s.value.toLowerCase().replace(/\.$/, '') === n)
}

export interface LintOptions {
  now?: Date
  /** Result of verifying the signature with the certificate's own key (undefined = unknown). */
  selfSigned?: boolean
}

export function lintCertificate(info: CertInfo, opts: LintOptions = {}): Finding[] {
  const f: Finding[] = []
  const now = opts.now ?? new Date()
  const r = roles(info)
  const selfSigned = opts.selfSigned ?? r.selfIssued

  // ---- validity window
  if (now < info.notBefore) {
    f.push({ severity: 'medium', title: 'Not yet valid', detail: `Valid from ${info.notBefore.toISOString()} — relying parties will reject it until then (check the issuer's clock).` })
  } else if (now > info.notAfter) {
    const ago = Math.floor((now.getTime() - info.notAfter.getTime()) / DAY)
    f.push({ severity: 'high', title: 'Expired', detail: `Expired on ${info.notAfter.toISOString()} (${ago} day${ago === 1 ? '' : 's'} ago).`, fix: 'Renew the certificate and deploy the new one.' })
  } else {
    const left = (info.notAfter.getTime() - now.getTime()) / DAY
    if (left <= 30) {
      f.push({ severity: 'low', title: 'Expires within 30 days', detail: `Expires on ${info.notAfter.toISOString()} (${Math.floor(left)} days left).`, fix: 'Renew now; automate renewal (ACME) so this never becomes an outage.' })
    }
  }
  if (info.notAfter < info.notBefore) {
    f.push({ severity: 'high', title: 'notAfter is before notBefore', detail: 'The validity window is empty — the certificate can never be valid.' })
  }

  // ---- TLS validity length (CA/B BR)
  if (r.tlsServer && !selfSigned) {
    const max = maxTlsValidityDays(info.notBefore)
    const days = validityDays(info)
    if (max !== undefined && days > max) {
      f.push({
        severity: 'medium',
        title: `Validity ${Math.floor(days)} days exceeds the ${max}-day CA/B Forum limit`,
        detail: `Issued ${info.notBefore.toISOString().slice(0, 10)}: publicly-trusted TLS server certificates issued then may be valid for at most ${max} days (Baseline Requirements §6.3.2${max < 398 ? ', ballot SC-081' : ''}). Browsers reject longer ones. Private/internal CAs are not bound by this rule, but short lifetimes are still good practice.`,
        fix: 'Reissue with a shorter lifetime and automate renewal.',
        ref: max < 398 ? SC081_URL : BR_URL,
      })
    }
    if (info.notBefore.getTime() < Date.UTC(2029, 2, 15)) {
      f.push({
        severity: 'info',
        title: 'TLS lifetimes are shrinking (ballot SC-081)',
        detail: 'Maximum publicly-trusted TLS validity: 398 days → 200 days from 2026-03-15 → 100 days from 2027-03-15 → 47 days from 2029-03-15 (domain-validation reuse drops to 10 days). Plan for fully automated renewal.',
        ref: SC081_URL,
      })
    }
  }

  // ---- signature algorithm
  const sig = info.signatureAlg
  if (sig.weak) {
    const algo = sig.weak === 'md' ? sig.hash ?? 'MD5' : 'SHA-1'
    if (selfSigned && r.isCA) {
      f.push({ severity: 'info', title: `${algo} self-signature on a root`, detail: 'A trust anchor\'s self-signature is not used for path validation, so a weak hash here is not exploitable — but it signals an old root; plan its replacement.' })
    } else {
      f.push({
        severity: sig.weak === 'md' ? 'critical' : 'high',
        title: `Weak signature hash: ${sig.name}`,
        detail: `${algo} is broken for signatures (chosen-prefix collisions are practical); browsers and modern TLS stacks reject such certificates.`,
        fix: 'Reissue with SHA-256 or stronger.',
      })
    }
  }
  if (info.signatureAlgMismatch) {
    f.push({ severity: 'high', title: 'Signature algorithm mismatch', detail: 'The algorithm inside the TBSCertificate differs from the outer signatureAlgorithm (RFC 5280 §4.1.1.2 requires them to be identical).', ref: RFC5280 })
  }

  // ---- key strength
  const pk = info.publicKey
  if ((pk.type === 'RSA' || pk.type === 'RSA-PSS') && pk.bits !== undefined) {
    if (pk.bits < 1024) f.push({ severity: 'critical', title: `RSA key of ${pk.bits} bits`, detail: 'Keys this small can be factored with modest resources.', fix: 'Use RSA ≥ 2048 bits or ECDSA P-256.' })
    else if (pk.bits < 2048) f.push({ severity: 'high', title: `RSA key of ${pk.bits} bits`, detail: 'RSA below 2048 bits is disallowed by the CA/B Forum and NIST (SP 800-131A).', fix: 'Use RSA ≥ 2048 bits (3072 for long-lived CA keys) or ECDSA P-256/P-384.' })
    if (pk.bits % 8 !== 0) f.push({ severity: 'low', title: 'Unusual RSA modulus size', detail: `${pk.bits} bits is not a multiple of 8; the CA/B BR require the modulus size in bits to be evenly divisible by 8.`, ref: BR_URL })
    if (pk.exponent && (pk.exponent === '1' || pk.exponent === '3' || BigInt(pk.exponent) % 2n === 0n)) {
      f.push({ severity: 'medium', title: `Unusual RSA public exponent (${pk.exponent})`, detail: 'The BR require an odd exponent ≥ 3; 65537 is the standard choice.' })
    }
  } else if (pk.type === 'EC') {
    if (pk.curve && !['P-256', 'P-384', 'P-521'].includes(pk.curve)) {
      f.push({ severity: 'medium', title: `EC curve ${pk.curve} is not widely supported`, detail: 'Only NIST P-256, P-384 and P-521 are allowed by the CA/B Forum and supported by all browsers / TLS libraries.', fix: 'Use P-256 or P-384.' })
    }
  } else if (pk.type === 'DSA') {
    f.push({ severity: 'high', title: 'DSA key', detail: 'DSA is deprecated (FIPS 186-5 removed it for signature generation) and unsupported by browsers.', fix: 'Use ECDSA or RSA.' })
  }

  // ---- serial number
  if (info.serialNegative) f.push({ severity: 'medium', title: 'Negative serial number', detail: 'RFC 5280 §4.1.2.2 requires a positive serial number.', ref: RFC5280 })
  if (info.serialBits === 0) f.push({ severity: 'medium', title: 'Serial number is zero', detail: 'RFC 5280 requires a positive integer.' })
  if (info.serialOctets > 20) f.push({ severity: 'medium', title: 'Serial number longer than 20 octets', detail: `It is ${info.serialOctets} octets; RFC 5280 §4.1.2.2 caps it at 20 and some software rejects longer ones.`, ref: RFC5280 })
  // A 64-bit random value has fewer than 57 significant bits with probability 1/256, so below that the serial almost
  // certainly lacks 64 random bits. 57–63 bits is normal for 64-bit random serials (leading zero bits) but is also
  // what CAs that cleared the top bit produced (the 2019 "63-bit serial" incidents) — one certificate cannot tell.
  if (!selfSigned && info.serialBits > 0 && info.serialBits < 57) {
    f.push({
      severity: r.tlsServer ? 'medium' : 'low',
      title: `Serial number has only ${info.serialBits} significant bits`,
      detail: 'The CA/B Forum BR (§7.1) require serials to contain at least 64 bits of CSPRNG output; a serial this short almost certainly does not. Unpredictable serials protect against hash-collision attacks.',
      fix: 'Generate serials from ≥ 64 (ideally 128) random bits.',
      ref: BR_URL,
    })
  } else if (!selfSigned && info.serialBits >= 57 && info.serialBits < 64 && r.tlsServer) {
    f.push({
      severity: 'info',
      title: `Serial number has ${info.serialBits} significant bits`,
      detail: 'Fine if the CA draws 64 random bits (leading zero bits happen), but CAs that force the top bit to 0 only get 63 random bits, which the CA/B Forum BR (§7.1) treat as non-compliant. Check other certificates from the same CA: if none ever has 64 bits, its serials are too short.',
      ref: BR_URL,
    })
  }

  // ---- version
  if (info.version !== 3 && info.extensions.length > 0) f.push({ severity: 'medium', title: `Version ${info.version} certificate with extensions`, detail: 'Extensions require an X.509 v3 certificate.' })
  if (info.version < 3) f.push({ severity: 'low', title: `X.509 v${info.version} certificate`, detail: 'v1/v2 certificates cannot carry Basic Constraints, so verifiers cannot tell whether it is a CA. Use v3.' })

  // ---- extensions: duplicates, unknown critical
  const seen = new Set<string>()
  for (const e of info.extensions) {
    if (seen.has(e.oid)) f.push({ severity: 'high', title: `Duplicate extension ${e.name ?? e.oid}`, detail: 'RFC 5280 §4.2: a certificate MUST NOT include more than one instance of an extension.' })
    seen.add(e.oid)
    if (e.critical && e.oid === OID.ctPoison) {
      f.push({ severity: 'info', title: 'This is a CT precertificate', detail: 'It carries the critical poison extension (RFC 6962) and cannot be used; the real certificate has the same serial.' })
    } else if (e.critical && !PROCESSABLE_EXTENSIONS.has(e.oid)) {
      f.push({ severity: 'high', title: `Unknown critical extension ${e.name ? `${e.name} (${e.oid})` : e.oid}`, detail: 'RFC 5280 requires verifiers to reject a certificate containing a critical extension they do not recognize; most clients will refuse it.', fix: 'Mark the extension non-critical or remove it.' })
    }
    if (e.error) f.push({ severity: 'medium', title: `Malformed extension ${e.name ?? e.oid}`, detail: e.error })
  }

  // ---- basic constraints & key usage
  const bc = extDecoded(info.extensions, OID.basicConstraints, 'bc')
  const ku = extDecoded(info.extensions, OID.keyUsage, 'ku')
  const hasKeyCertSign = ku?.usages.includes('keyCertSign') ?? false
  if (r.isCA) {
    if (ku && !hasKeyCertSign) {
      f.push({ severity: 'high', title: 'CA:TRUE without keyCertSign', detail: 'The certificate claims to be a CA but its Key Usage does not allow signing certificates (RFC 5280 §4.2.1.3) — chains through it will fail.', fix: 'Add keyCertSign (and cRLSign) to Key Usage.' })
    } else if (!ku) {
      f.push({ severity: 'medium', title: 'CA certificate without Key Usage', detail: 'RFC 5280 says CA certificates MUST include Key Usage (with keyCertSign); the CA/B BR require it too.' })
    }
    if (bc && findExt(info.extensions, OID.basicConstraints)?.critical === false) {
      f.push({ severity: 'medium', title: 'Basic Constraints not critical on a CA', detail: 'RFC 5280 §4.2.1.9: conforming CAs MUST mark Basic Constraints critical in CA certificates.', ref: RFC5280 })
    }
    if (r.dnsSans.length > 0 && !selfSigned) {
      f.push({ severity: 'high', title: 'Leaf-looking certificate with CA:TRUE', detail: 'It has CA:TRUE but also carries DNS names in its SAN like a server certificate. A server certificate that is a CA can sign certificates for any domain.', fix: 'Issue end-entity certificates with CA:FALSE.' })
    }
    if (r.ekus?.includes(OID.serverAuth) && !selfSigned) {
      f.push({ severity: 'info', title: 'CA certificate with serverAuth EKU', detail: 'Normal for subordinate CAs constrained to TLS issuance; unusual for a server certificate.' })
    }
  } else {
    if (hasKeyCertSign) f.push({ severity: 'high', title: 'keyCertSign without CA:TRUE', detail: 'Key Usage allows certificate signing but Basic Constraints does not mark it as a CA (RFC 5280 §4.2.1.3: keyCertSign requires cA=TRUE).' })
    if (r.tlsServer && !bc && !selfSigned) f.push({ severity: 'info', title: 'No Basic Constraints', detail: 'Absent Basic Constraints means "not a CA"; that is fine for leaves.' })
  }
  if (ku && ku.usages.length === 0) f.push({ severity: 'medium', title: 'Key Usage present but empty', detail: 'RFC 5280: when present, at least one bit MUST be set.' })

  // ---- AKI / SKI
  if (!selfSigned && !findExt(info.extensions, OID.authorityKeyIdentifier)) {
    f.push({ severity: 'medium', title: 'Missing Authority Key Identifier', detail: 'RFC 5280 §4.2.1.1: required on all certificates except self-signed roots. Without it, path building (choosing between re-keyed issuers with the same name) is unreliable.', ref: RFC5280 })
  }
  if (r.isCA && !findExt(info.extensions, OID.subjectKeyIdentifier)) {
    f.push({ severity: 'medium', title: 'CA certificate without Subject Key Identifier', detail: 'RFC 5280 §4.2.1.2: CA certificates MUST include SKI so children can reference it via AKI.' })
  }

  // ---- SAN / CN for TLS leaves
  const cns = nameField(info.subject, OID.commonName)
  const sans = sanNames(info.extensions)
  if (r.tlsServer) {
    if (sans.length === 0) {
      f.push({ severity: 'high', title: 'TLS certificate without Subject Alternative Name', detail: 'Browsers ignore the subject CN and only match hostnames against SAN DNS/IP entries (Chrome since v58), so this certificate fails hostname verification everywhere.', fix: 'Reissue with every hostname in the SAN extension.' })
    }
    for (const cn of cns) {
      if (sans.length > 0 && hostnameLike(cn) && !cnCoveredBySan(cn, sans)) {
        f.push({ severity: 'medium', title: `CN "${cn}" is not in the SAN`, detail: 'The CA/B BR require the CN, when present, to repeat one of the SAN values.', fix: 'Add the CN to the SAN or drop the CN.', ref: BR_URL })
      }
    }
    if (r.ekus && !r.ekus.includes(OID.serverAuth) && !r.ekus.includes(OID.anyEku)) {
      f.push({ severity: 'medium', title: 'EKU does not include serverAuth', detail: 'It has DNS names but its Extended Key Usage does not allow TLS server authentication; TLS clients will reject it as a server certificate.' })
    } else if (!r.ekus && !selfSigned) {
      f.push({ severity: 'low', title: 'No Extended Key Usage', detail: 'An absent EKU means "any purpose". The CA/B BR require serverAuth in publicly-trusted TLS certificates.' })
    }
  } else if (!r.isCA && sans.length > 0 && r.ekus && !r.ekus.includes(OID.serverAuth) && r.dnsSans.length > 0 && !r.ekus.includes(OID.anyEku)) {
    f.push({ severity: 'medium', title: 'EKU missing serverAuth on a TLS-looking certificate', detail: 'The certificate carries DNS names but its EKU does not allow TLS server authentication.' })
  }
  if (r.ekus?.includes(OID.anyEku) && !r.isCA) {
    f.push({ severity: 'low', title: 'anyExtendedKeyUsage on an end-entity', detail: 'The CA/B BR forbid anyExtendedKeyUsage in subscriber certificates; list the specific purposes.' })
  }

  // ---- wildcards
  for (const s of sans) {
    if (s.type !== 'DNS' || !s.value.includes('*')) continue
    const parts = s.value.split('.')
    if (parts[0] !== '*' || parts.slice(1).some((p) => p.includes('*'))) {
      f.push({ severity: 'medium', title: `Invalid wildcard "${s.value}"`, detail: 'Only a complete left-most "*" label is accepted by browsers (RFC 9525 / CA/B BR); partial or inner wildcards never match.' })
    } else if (parts.length < 3) {
      f.push({ severity: 'high', title: `Wildcard on a top-level domain "${s.value}"`, detail: 'Browsers refuse wildcards directly under a public suffix.' })
    } else {
      f.push({ severity: 'info', title: `Wildcard "${s.value}"`, detail: `Covers exactly one label (a.${parts.slice(1).join('.')}), not ${parts.slice(1).join('.')} itself nor deeper names. A wildcard key is shared by every host it covers — a compromise of one server exposes them all.` })
    }
  }
  for (const s of sans) {
    if (s.type === 'DNS' && s.value !== '' && !s.value.includes('*') && !hostnameLike(s.value) && !/^[a-z0-9-]{1,63}$/i.test(s.value)) {
      f.push({ severity: 'medium', title: `Malformed SAN DNS name "${s.value}"`, detail: 'dNSName entries must be LDH hostnames (IDNs as xn-- A-labels).' })
    }
  }

  // ---- self-signed leaf
  if (selfSigned && !r.isCA) {
    f.push({ severity: r.tlsServer ? 'medium' : 'info', title: 'Self-signed end-entity certificate', detail: 'No client will trust it unless it is pinned or installed manually. Fine for tests and some internal mTLS setups; use a CA (internal or ACME) for anything shared.' })
  }

  if (f.filter((x) => x.severity !== 'info').length === 0) {
    f.push({ severity: 'pass', title: 'No problems found', detail: 'None of the lint rules triggered.' })
  }
  return f
}

/** DNS names from SAN that the hostname check would consider; exported for the UI. */
export function wildcardCovers(pattern: string, host: string): boolean {
  return dnsIdMatches(pattern.toLowerCase(), host.toLowerCase()).match
}
