/**
 * security.txt parser (RFC 9116). Line-based, no regex backtracking on field values.
 * PGP cleartext signatures (RFC 4880 §7) are detected and the signed body is extracted; the signature itself is
 * not verified (that needs the publisher's key).
 */
import type { Finding } from './types'

const RFC9116 = 'https://www.rfc-editor.org/rfc/rfc9116'

export interface SecurityTxt {
  contact: string[]
  expires: string[]
  encryption: string[]
  acknowledgments: string[]
  preferredLanguages: string[]
  canonical: string[]
  policy: string[]
  hiring: string[]
  csaf: string[]
  signed: boolean
  /** Lines that are neither comments, blank, nor "Field: value". */
  invalidLines: number
  unknownFields: string[]
}

const FIELDS: Record<string, keyof SecurityTxt> = {
  contact: 'contact',
  expires: 'expires',
  encryption: 'encryption',
  acknowledgments: 'acknowledgments',
  acknowledgements: 'acknowledgments',
  'preferred-languages': 'preferredLanguages',
  canonical: 'canonical',
  policy: 'policy',
  hiring: 'hiring',
  csaf: 'csaf',
}

/** Extract the signed text of a PGP cleartext-signed message (dash-escaping removed). */
export function stripPgpSignature(text: string): { body: string; signed: boolean } {
  const lines = text.split(/\r?\n/)
  const start = lines.findIndex((l) => l.trim() === '-----BEGIN PGP SIGNED MESSAGE-----')
  if (start === -1) return { body: text, signed: false }
  let i = start + 1
  // Armor headers ("Hash: SHA256") until the first blank line
  while (i < lines.length && lines[i].trim() !== '') i++
  const end = lines.findIndex((l, idx) => idx > i && l.trim() === '-----BEGIN PGP SIGNATURE-----')
  const bodyLines = lines.slice(i + 1, end === -1 ? lines.length : end).map((l) => (l.startsWith('- ') ? l.slice(2) : l))
  return { body: bodyLines.join('\n'), signed: end !== -1 }
}

export function parseSecurityTxt(text: string): SecurityTxt {
  const { body, signed } = stripPgpSignature(text.slice(0, 32768))
  const out: SecurityTxt = {
    contact: [],
    expires: [],
    encryption: [],
    acknowledgments: [],
    preferredLanguages: [],
    canonical: [],
    policy: [],
    hiring: [],
    csaf: [],
    signed,
    invalidLines: 0,
    unknownFields: [],
  }
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (line === '' || line.startsWith('#')) continue
    const i = line.indexOf(':')
    if (i <= 0) {
      out.invalidLines++
      continue
    }
    const name = line.slice(0, i).trim().toLowerCase()
    const value = line.slice(i + 1).trim()
    if (!/^[a-z0-9-]+$/.test(name)) {
      out.invalidLines++
      continue
    }
    const key = FIELDS[name]
    if (!key) {
      if (!out.unknownFields.includes(name) && out.unknownFields.length < 20) out.unknownFields.push(name)
      continue
    }
    const list = out[key]
    if (Array.isArray(list) && list.length < 50) list.push(value)
  }
  return out
}

/**
 * Findings for a parsed file.
 * @param fetchedUrl URL the file was retrieved from (Canonical should list it)
 * @param legacyLocation found at /security.txt instead of /.well-known/security.txt
 */
export function securityTxtFindings(s: SecurityTxt, now: number, fetchedUrl?: string, legacyLocation = false): Finding[] {
  const f: Finding[] = []
  if (s.contact.length === 0) {
    f.push({ severity: 'high', title: 'security.txt has no Contact field', detail: 'Contact is required (RFC 9116 §2.5.3): researchers have no way to report vulnerabilities.', ref: RFC9116 })
  } else {
    for (const c of s.contact) {
      const lc = c.toLowerCase()
      if (!lc.startsWith('mailto:') && !lc.startsWith('https://') && !lc.startsWith('tel:')) {
        f.push({ severity: 'low', title: `Contact "${c.slice(0, 80)}" is not a mailto:, https: or tel: URI`, detail: 'RFC 9116 requires a URI; web contacts must use https.', ref: RFC9116 })
      }
    }
    f.push({ severity: 'pass', title: 'security.txt Contact present', detail: s.contact.slice(0, 5).join(', ') })
  }
  if (s.expires.length === 0) {
    f.push({ severity: 'medium', title: 'security.txt has no Expires field', detail: 'Expires is required (RFC 9116 §2.5.5) so stale contact data is not trusted forever.', ref: RFC9116 })
  } else {
    if (s.expires.length > 1) f.push({ severity: 'low', title: 'Expires appears more than once', detail: 'The field must appear exactly once.', ref: RFC9116 })
    const t = Date.parse(s.expires[0])
    if (Number.isNaN(t)) {
      f.push({ severity: 'medium', title: `Invalid Expires date "${s.expires[0].slice(0, 60)}"`, detail: 'Use an RFC 3339 date-time, e.g. 2026-12-31T23:00:00.000Z.', ref: RFC9116 })
    } else if (t < now) {
      f.push({ severity: 'high', title: `security.txt expired on ${s.expires[0].slice(0, 10)}`, detail: 'Researchers should treat the file as stale; the contact data may be outdated.', fix: 'Review the contacts and set a new Expires date (less than a year ahead).', ref: RFC9116 })
    } else if (t - now > 366 * 86400000) {
      f.push({ severity: 'low', title: 'Expires is more than a year ahead', detail: 'RFC 9116 recommends less than a year to force periodic review.', ref: RFC9116 })
    } else {
      f.push({ severity: 'pass', title: `security.txt valid until ${s.expires[0].slice(0, 10)}`, detail: 'Expires is set and in the future.' })
    }
  }
  if (legacyLocation) f.push({ severity: 'low', title: 'security.txt served from the legacy location', detail: 'Found at /security.txt; the standard location is /.well-known/security.txt (the root path is only a fallback).', ref: RFC9116 })
  if (fetchedUrl && s.canonical.length > 0 && !s.canonical.includes(fetchedUrl)) {
    f.push({ severity: 'low', title: 'Canonical does not list this URL', detail: `The file was fetched from ${fetchedUrl} but Canonical says ${s.canonical.slice(0, 3).join(', ')}.`, ref: RFC9116 })
  }
  if (s.signed) f.push({ severity: 'info', title: 'security.txt is PGP-signed', detail: 'The signature is not verified here; check it with the key referenced by Encryption.' })
  if (s.policy.length === 0) f.push({ severity: 'info', title: 'No Policy link', detail: 'A disclosure policy tells researchers what is in scope and how reports are handled.' })
  if (s.invalidLines > 0) f.push({ severity: 'low', title: `${s.invalidLines} malformed line(s)`, detail: 'Lines must be "Field: value" or comments starting with #.' })
  return f
}
