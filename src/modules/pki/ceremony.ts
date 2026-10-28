/** Key ceremony planning: M-of-N quorum math and a Markdown runbook generator. */
import { mdTable } from '../../lib/markdown'
import { mdText } from '../toolbox/types'

export const CEREMONY_STORAGE_KEY = 'scp:pki-ceremony'

export function binomial(n: number, k: number): number {
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 0 || n < 0 || k > n) return 0
  let r = 1
  const kk = Math.min(k, n - k)
  for (let i = 1; i <= kk; i++) r = (r * (n - kk + i)) / i
  return Math.round(r)
}

export interface QuorumAnalysis {
  m: number
  n: number
  /** Custodians (or their cards) that can be lost while the key stays recoverable. */
  lossTolerance: number
  /** Minimum number of custodians that must collude to use the key without the others. */
  collusionThreshold: number
  /** Number of distinct M-sized groups that can activate the key. */
  quorums: number
  warnings: { severity: 'high' | 'medium' | 'low'; text: string }[]
  recommendation: string
}

export function analyzeQuorum(mIn: number, nIn: number): QuorumAnalysis {
  const n = Math.min(15, Math.max(1, Math.floor(nIn)))
  const m = Math.min(n, Math.max(1, Math.floor(mIn)))
  const warnings: QuorumAnalysis['warnings'] = []
  if (m === 1) warnings.push({ severity: 'high', text: 'M = 1: any single custodian can activate the key alone — there is no dual control / split knowledge.' })
  if (m === n && n > 1) warnings.push({ severity: 'high', text: `M = N: losing ANY one of the ${n} custodians or cards makes the key unrecoverable.` })
  if (n === 1) warnings.push({ severity: 'high', text: 'N = 1: a single point of failure for both loss and misuse.' })
  if (m > 1 && m <= n / 2) {
    warnings.push({ severity: 'medium', text: `M ≤ N/2: two disjoint groups of ${m} custodians can each activate the key independently, so a minority can act without the majority knowing.` })
  }
  if (n - m === 1 && n > 2) warnings.push({ severity: 'low', text: 'Only one custodian of margin: a single absence on ceremony day plus one lost card blocks recovery. Consider N − M ≥ 2.' })
  if (n > 9) warnings.push({ severity: 'low', text: 'Many custodians increase coordination, training and card-tracking burden; most CAs use 5–7.' })
  let recommendation: string
  if (warnings.some((w) => w.severity === 'high')) recommendation = 'Not recommended. A common, balanced choice is 3-of-5 (tolerates 2 losses, needs 3 colluders).'
  else if (m > n / 2 && n - m >= 2) recommendation = `Good balance: a majority (${m}) is needed and ${n - m} custodians can be unavailable. Spread custodians across teams and sites.`
  else recommendation = `Acceptable, but review the trade-offs above. ${m > n / 2 ? '' : 'Prefer M > N/2 so a minority can never act alone. '}Common choices: 2-of-3, 3-of-5, 4-of-7.`
  return { m, n, lossTolerance: n - m, collusionThreshold: m, quorums: binomial(n, m), warnings, recommendation }
}

export const ROLES = [
  'Ceremony Administrator',
  'Key Custodian',
  'Internal Witness',
  'External Auditor',
  'Security Officer',
  'HSM Operator',
  'Video Operator',
  'Scribe',
] as const

export interface Participant {
  id: string
  name: string
  role: string
  organization: string
}

export interface CeremonyDraft {
  caName: string
  title: string
  date: string
  location: string
  hsmModel: string
  keyAlgorithm: string
  m: number
  n: number
  participants: Participant[]
  notes: string
}

export const EMPTY_CEREMONY: CeremonyDraft = {
  caName: '',
  title: '',
  date: '',
  location: '',
  hsmModel: '',
  keyAlgorithm: 'ECDSA P-384 (SHA-384)',
  m: 3,
  n: 5,
  participants: [],
  notes: '',
}

/** Sanitize a persisted draft (localStorage content is untrusted). */
export function sanitizeDraft(x: unknown): CeremonyDraft {
  const o = (typeof x === 'object' && x !== null ? x : {}) as Record<string, unknown>
  const str = (v: unknown, max = 500) => (typeof v === 'string' ? v.slice(0, max) : '')
  const num = (v: unknown, d: number) => (typeof v === 'number' && Number.isFinite(v) ? v : d)
  const parts = Array.isArray(o.participants) ? o.participants.slice(0, 40) : []
  return {
    caName: str(o.caName),
    title: str(o.title),
    date: str(o.date, 40),
    location: str(o.location),
    hsmModel: str(o.hsmModel),
    keyAlgorithm: str(o.keyAlgorithm) || EMPTY_CEREMONY.keyAlgorithm,
    m: num(o.m, 3),
    n: num(o.n, 5),
    notes: str(o.notes, 5000),
    participants: parts.map((p, i) => {
      const q = (typeof p === 'object' && p !== null ? p : {}) as Record<string, unknown>
      return { id: str(q.id, 64) || `p${i}`, name: str(q.name, 200), role: str(q.role, 100) || 'Key Custodian', organization: str(q.organization, 200) }
    }),
  }
}

const t = (s: string, fallback: string) => mdText(s.trim() || fallback)

export function ceremonyMarkdown(d: CeremonyDraft): string {
  const q = analyzeQuorum(d.m, d.n)
  const ca = t(d.caName, '[CA name]')
  const title = t(d.title, `${d.caName.trim() || '[CA name]'} Root Key Generation Ceremony`)
  const custodians = d.participants.filter((p) => p.role === 'Key Custodian')
  const people = d.participants.length
    ? mdTable(
        ['#', 'Name', 'Role', 'Organization', 'ID verified (initials)'],
        d.participants.map((p, i) => [String(i + 1), mdText(p.name || '—'), mdText(p.role), mdText(p.organization || '—'), '']),
      )
    : '_Add participants (at least: Ceremony Administrator, the key custodians, an internal witness and ideally an external auditor)._'
  const cardRows = Array.from({ length: q.n }, (_, i) => [`Card ${i + 1} of ${q.n}`, mdText(custodians[i]?.name ?? ''), '', '', ''])
  const L: string[] = []
  L.push(`# ${title}`, '')
  L.push(mdTable(['Field', 'Value'], [
    ['CA', ca],
    ['Date', t(d.date, '[YYYY-MM-DD]')],
    ['Location', t(d.location, '[secure room / site]')],
    ['HSM', t(d.hsmModel, '[HSM model, firmware version, FIPS 140-3 / CC certificate #]')],
    ['Key algorithm', t(d.keyAlgorithm, '[algorithm]')],
    ['Quorum', `${q.m}-of-${q.n} (tolerates ${q.lossTolerance} lost card${q.lossTolerance === 1 ? '' : 's'}; ${q.collusionThreshold} custodians needed to activate; ${q.quorums} possible quorums)`],
  ]))
  L.push('', '> Every step is read aloud by the Ceremony Administrator, performed, then initialled by the Internal Witness with the time. Any deviation is recorded in the Exception Log (section 11) before continuing.', '')
  L.push('## 1. Preparation checklist (before the day)', '')
  for (const s of [
    'Ceremony script reviewed and approved by the Policy Authority; copies printed for every participant.',
    'CP/CPS sections for key generation (RFC 3647 §6.1, §6.2) referenced and current.',
    'Room booked with controlled access; access log ready; mobile phones and personal electronics collected at the door.',
    'Offline laptop (air-gapped, no wireless hardware / disabled) with verified OS image hash and tooling versions recorded.',
    'HSM shipped in tamper-evident packaging; serial numbers matched against the purchase order and shipping record.',
    `${q.n} smart cards / tokens (+ spares) for the M-of-N split, in sealed bags.`,
    'Tamper-evident bags, safe(s) and transport plan for each custodian’s share prepared.',
    'Video recording equipment tested; clock synchronized with a trusted time source.',
    'Certificate profile (subject DN, validity, extensions) and key parameters agreed in writing.',
  ]) L.push(`- [ ] ${s}`)
  L.push('', '## 2. Participants and roles', '', people, '')
  L.push('## 3. Equipment and tamper-evident bag serials', '')
  L.push(mdTable(['Item', 'Model / description', 'Serial number', 'Tamper bag # (in)', 'Bag intact? (Y/N)', 'Tamper bag # (out)'], [
    ['HSM', t(d.hsmModel, ''), '', '', '', ''],
    ['Offline laptop', '', '', '', '', ''],
    ['Boot media (USB / DVD)', '', '', '', '', ''],
    ['Export media (public cert / CSR)', '', '', '', '', ''],
    ['Smart cards / tokens', `${q.n} + spares`, '', '', '', ''],
  ]))
  L.push('', '## 4. Opening and identity verification', '')
  for (const s of [
    'Start video recording; state date, time, location and purpose.',
    'Each participant presents government-issued photo ID; the Internal Witness verifies and initials section 2.',
    'Confirm that no unauthorized devices are present; record the room access log.',
    'Inspect every tamper-evident bag in front of the camera, read the serial aloud, record it in section 3.',
  ]) L.push(`1. [ ] ${s}`)
  L.push('', '## 5. HSM initialization', '')
  for (const s of [
    'Boot the offline laptop from verified media; record the image hash shown.',
    'Connect and power on the HSM; record firmware version and confirm it matches the approved version.',
    'Factory-reset / initialize the HSM; set the security domain and Security Officer credentials (split if supported).',
    `Configure the operator/crypto-officer quorum as ${q.m}-of-${q.n}.`,
    'Enable audit logging; record the HSM audit log start counter.',
  ]) L.push(`1. [ ] ${s}`)
  L.push('', '## 6. Key generation', '')
  for (const s of [
    `Generate the ${t(d.keyAlgorithm, 'CA')} key pair INSIDE the HSM, marked non-exportable except for the backup procedure below.`,
    'Record the key label/handle and the public key SHA-256 fingerprint as displayed by the HSM.',
    'Do not print or photograph any secret material.',
  ]) L.push(`1. [ ] ${s}`)
  L.push('', `## 7. Backup and M-of-N split (${q.m}-of-${q.n})`, '')
  L.push('1. [ ] Create the key backup / domain key according to the HSM vendor procedure.')
  L.push(`1. [ ] Write the ${q.n} shares to the ${q.n} cards; each custodian sets their own PIN privately.`)
  L.push('1. [ ] Each card goes into an individually numbered tamper-evident bag, sealed in front of the camera.', '')
  L.push(mdTable(['Share', 'Custodian', 'Card serial', 'Tamper bag #', 'Custodian signature'], cardRows))
  L.push('', '## 8. Root certificate self-signing', '')
  for (const s of [
    'Load the approved certificate profile; read the subject DN, validity and extensions aloud.',
    'Self-sign the root certificate with the new key (quorum present).',
    'Export ONLY the public certificate to the export media.',
  ]) L.push(`1. [ ] ${s}`)
  L.push('', '## 9. Verification of fingerprints', '')
  L.push('1. [ ] On a second, independent machine, compute the SHA-256 fingerprint of the exported certificate (e.g. `openssl x509 -in root.pem -noout -fingerprint -sha256`).')
  L.push('1. [ ] Two participants independently read the fingerprint aloud and compare with the HSM display; record below.', '')
  L.push(mdTable(['Item', 'SHA-256 fingerprint', 'Verified by (2 initials)'], [['Root certificate', '', ''], ['Public key (SPKI)', '', '']]))
  L.push('', '## 10. Secure storage and closing', '')
  for (const s of [
    'Power down the HSM; place HSM, laptop and media in numbered tamper-evident bags; record serials in section 3.',
    'Move bags to the designated safes; record safe IDs and who holds which combination/key.',
    'Custodians take their sealed share to their designated (geographically separated) storage.',
    'Export the HSM audit log; attach to the ceremony record.',
    'Stop video recording; state the end time. Store the recording with the ceremony record.',
  ]) L.push(`1. [ ] ${s}`)
  L.push('', '## 11. Exception log', '')
  L.push(mdTable(['Time', 'Step', 'Description of deviation', 'Resolution', 'Approved by'], [['', '', '', '', ''], ['', '', '', '', '']]))
  if (d.notes.trim()) L.push('', '### Notes', '', mdText(d.notes.trim()))
  L.push('', '## 12. Sign-off', '', 'By signing, each participant attests that the ceremony was performed according to this script, with any deviations recorded in section 11.', '')
  L.push(mdTable(['Name', 'Role', 'Signature', 'Date / time'], (d.participants.length ? d.participants : [{ name: '', role: '' }]).map((p) => [mdText(p.name), mdText(p.role), '', ''])))
  L.push('', `_Quorum analysis: ${q.recommendation}_`, '')
  return L.join('\n')
}
