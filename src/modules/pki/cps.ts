/** RFC 3647 §6 "Outline of a Set of Provisions" skeleton for a CP / CPS, exported as Markdown. */
import { mdText } from '../toolbox/types'

export const CPS_STORAGE_KEY = 'scp:pki-cps'

/** Section numbers and titles exactly as in RFC 3647 §6 (sub-subsections included). */
export const RFC3647_OUTLINE: readonly [string, string][] = [
  ['1', 'Introduction'],
  ['1.1', 'Overview'],
  ['1.2', 'Document name and identification'],
  ['1.3', 'PKI participants'],
  ['1.3.1', 'Certification authorities'],
  ['1.3.2', 'Registration authorities'],
  ['1.3.3', 'Subscribers'],
  ['1.3.4', 'Relying parties'],
  ['1.3.5', 'Other participants'],
  ['1.4', 'Certificate usage'],
  ['1.4.1', 'Appropriate certificate uses'],
  ['1.4.2', 'Prohibited certificate uses'],
  ['1.5', 'Policy administration'],
  ['1.5.1', 'Organization administering the document'],
  ['1.5.2', 'Contact person'],
  ['1.5.3', 'Person determining CPS suitability for the policy'],
  ['1.5.4', 'CPS approval procedures'],
  ['1.6', 'Definitions and acronyms'],
  ['2', 'Publication and repository responsibilities'],
  ['2.1', 'Repositories'],
  ['2.2', 'Publication of certification information'],
  ['2.3', 'Time or frequency of publication'],
  ['2.4', 'Access controls on repositories'],
  ['3', 'Identification and authentication'],
  ['3.1', 'Naming'],
  ['3.1.1', 'Types of names'],
  ['3.1.2', 'Need for names to be meaningful'],
  ['3.1.3', 'Anonymity or pseudonymity of subscribers'],
  ['3.1.4', 'Rules for interpreting various name forms'],
  ['3.1.5', 'Uniqueness of names'],
  ['3.1.6', 'Recognition, authentication, and role of trademarks'],
  ['3.2', 'Initial identity validation'],
  ['3.2.1', 'Method to prove possession of private key'],
  ['3.2.2', 'Authentication of organization identity'],
  ['3.2.3', 'Authentication of individual identity'],
  ['3.2.4', 'Non-verified subscriber information'],
  ['3.2.5', 'Validation of authority'],
  ['3.2.6', 'Criteria for interoperation'],
  ['3.3', 'Identification and authentication for re-key requests'],
  ['3.3.1', 'Identification and authentication for routine re-key'],
  ['3.3.2', 'Identification and authentication for re-key after revocation'],
  ['3.4', 'Identification and authentication for revocation request'],
  ['4', 'Certificate life-cycle operational requirements'],
  ['4.1', 'Certificate Application'],
  ['4.1.1', 'Who can submit a certificate application'],
  ['4.1.2', 'Enrollment process and responsibilities'],
  ['4.2', 'Certificate application processing'],
  ['4.2.1', 'Performing identification and authentication functions'],
  ['4.2.2', 'Approval or rejection of certificate applications'],
  ['4.2.3', 'Time to process certificate applications'],
  ['4.3', 'Certificate issuance'],
  ['4.3.1', 'CA actions during certificate issuance'],
  ['4.3.2', 'Notification to subscriber by the CA of issuance of certificate'],
  ['4.4', 'Certificate acceptance'],
  ['4.4.1', 'Conduct constituting certificate acceptance'],
  ['4.4.2', 'Publication of the certificate by the CA'],
  ['4.4.3', 'Notification of certificate issuance by the CA to other entities'],
  ['4.5', 'Key pair and certificate usage'],
  ['4.5.1', 'Subscriber private key and certificate usage'],
  ['4.5.2', 'Relying party public key and certificate usage'],
  ['4.6', 'Certificate renewal'],
  ['4.6.1', 'Circumstance for certificate renewal'],
  ['4.6.2', 'Who may request renewal'],
  ['4.6.3', 'Processing certificate renewal requests'],
  ['4.6.4', 'Notification of new certificate issuance to subscriber'],
  ['4.6.5', 'Conduct constituting acceptance of a renewal certificate'],
  ['4.6.6', 'Publication of the renewal certificate by the CA'],
  ['4.6.7', 'Notification of certificate issuance by the CA to other entities'],
  ['4.7', 'Certificate re-key'],
  ['4.7.1', 'Circumstance for certificate re-key'],
  ['4.7.2', 'Who may request certification of a new public key'],
  ['4.7.3', 'Processing certificate re-keying requests'],
  ['4.7.4', 'Notification of new certificate issuance to subscriber'],
  ['4.7.5', 'Conduct constituting acceptance of a re-keyed certificate'],
  ['4.7.6', 'Publication of the re-keyed certificate by the CA'],
  ['4.7.7', 'Notification of certificate issuance by the CA to other entities'],
  ['4.8', 'Certificate modification'],
  ['4.8.1', 'Circumstance for certificate modification'],
  ['4.8.2', 'Who may request certificate modification'],
  ['4.8.3', 'Processing certificate modification requests'],
  ['4.8.4', 'Notification of new certificate issuance to subscriber'],
  ['4.8.5', 'Conduct constituting acceptance of modified certificate'],
  ['4.8.6', 'Publication of the modified certificate by the CA'],
  ['4.8.7', 'Notification of certificate issuance by the CA to other entities'],
  ['4.9', 'Certificate revocation and suspension'],
  ['4.9.1', 'Circumstances for revocation'],
  ['4.9.2', 'Who can request revocation'],
  ['4.9.3', 'Procedure for revocation request'],
  ['4.9.4', 'Revocation request grace period'],
  ['4.9.5', 'Time within which CA must process the revocation request'],
  ['4.9.6', 'Revocation checking requirement for relying parties'],
  ['4.9.7', 'CRL issuance frequency (if applicable)'],
  ['4.9.8', 'Maximum latency for CRLs (if applicable)'],
  ['4.9.9', 'On-line revocation/status checking availability'],
  ['4.9.10', 'On-line revocation checking requirements'],
  ['4.9.11', 'Other forms of revocation advertisements available'],
  ['4.9.12', 'Special requirements re key compromise'],
  ['4.9.13', 'Circumstances for suspension'],
  ['4.9.14', 'Who can request suspension'],
  ['4.9.15', 'Procedure for suspension request'],
  ['4.9.16', 'Limits on suspension period'],
  ['4.10', 'Certificate status services'],
  ['4.10.1', 'Operational characteristics'],
  ['4.10.2', 'Service availability'],
  ['4.10.3', 'Optional features'],
  ['4.11', 'End of subscription'],
  ['4.12', 'Key escrow and recovery'],
  ['4.12.1', 'Key escrow and recovery policy and practices'],
  ['4.12.2', 'Session key encapsulation and recovery policy and practices'],
  ['5', 'Facility, management, and operational controls'],
  ['5.1', 'Physical controls'],
  ['5.1.1', 'Site location and construction'],
  ['5.1.2', 'Physical access'],
  ['5.1.3', 'Power and air conditioning'],
  ['5.1.4', 'Water exposures'],
  ['5.1.5', 'Fire prevention and protection'],
  ['5.1.6', 'Media storage'],
  ['5.1.7', 'Waste disposal'],
  ['5.1.8', 'Off-site backup'],
  ['5.2', 'Procedural controls'],
  ['5.2.1', 'Trusted roles'],
  ['5.2.2', 'Number of persons required per task'],
  ['5.2.3', 'Identification and authentication for each role'],
  ['5.2.4', 'Roles requiring separation of duties'],
  ['5.3', 'Personnel controls'],
  ['5.3.1', 'Qualifications, experience, and clearance requirements'],
  ['5.3.2', 'Background check procedures'],
  ['5.3.3', 'Training requirements'],
  ['5.3.4', 'Retraining frequency and requirements'],
  ['5.3.5', 'Job rotation frequency and sequence'],
  ['5.3.6', 'Sanctions for unauthorized actions'],
  ['5.3.7', 'Independent contractor requirements'],
  ['5.3.8', 'Documentation supplied to personnel'],
  ['5.4', 'Audit logging procedures'],
  ['5.4.1', 'Types of events recorded'],
  ['5.4.2', 'Frequency of processing log'],
  ['5.4.3', 'Retention period for audit log'],
  ['5.4.4', 'Protection of audit log'],
  ['5.4.5', 'Audit log backup procedures'],
  ['5.4.6', 'Audit collection system (internal vs. external)'],
  ['5.4.7', 'Notification to event-causing subject'],
  ['5.4.8', 'Vulnerability assessments'],
  ['5.5', 'Records archival'],
  ['5.5.1', 'Types of records archived'],
  ['5.5.2', 'Retention period for archive'],
  ['5.5.3', 'Protection of archive'],
  ['5.5.4', 'Archive backup procedures'],
  ['5.5.5', 'Requirements for time-stamping of records'],
  ['5.5.6', 'Archive collection system (internal or external)'],
  ['5.5.7', 'Procedures to obtain and verify archive information'],
  ['5.6', 'Key changeover'],
  ['5.7', 'Compromise and disaster recovery'],
  ['5.7.1', 'Incident and compromise handling procedures'],
  ['5.7.2', 'Computing resources, software, and/or data are corrupted'],
  ['5.7.3', 'Entity private key compromise procedures'],
  ['5.7.4', 'Business continuity capabilities after a disaster'],
  ['5.8', 'CA or RA termination'],
  ['6', 'Technical security controls'],
  ['6.1', 'Key pair generation and installation'],
  ['6.1.1', 'Key pair generation'],
  ['6.1.2', 'Private key delivery to subscriber'],
  ['6.1.3', 'Public key delivery to certificate issuer'],
  ['6.1.4', 'CA public key delivery to relying parties'],
  ['6.1.5', 'Key sizes'],
  ['6.1.6', 'Public key parameters generation and quality checking'],
  ['6.1.7', 'Key usage purposes (as per X.509 v3 key usage field)'],
  ['6.2', 'Private Key Protection and Cryptographic Module Engineering Controls'],
  ['6.2.1', 'Cryptographic module standards and controls'],
  ['6.2.2', 'Private key (n out of m) multi-person control'],
  ['6.2.3', 'Private key escrow'],
  ['6.2.4', 'Private key backup'],
  ['6.2.5', 'Private key archival'],
  ['6.2.6', 'Private key transfer into or from a cryptographic module'],
  ['6.2.7', 'Private key storage on cryptographic module'],
  ['6.2.8', 'Method of activating private key'],
  ['6.2.9', 'Method of deactivating private key'],
  ['6.2.10', 'Method of destroying private key'],
  ['6.2.11', 'Cryptographic Module Rating'],
  ['6.3', 'Other aspects of key pair management'],
  ['6.3.1', 'Public key archival'],
  ['6.3.2', 'Certificate operational periods and key pair usage periods'],
  ['6.4', 'Activation data'],
  ['6.4.1', 'Activation data generation and installation'],
  ['6.4.2', 'Activation data protection'],
  ['6.4.3', 'Other aspects of activation data'],
  ['6.5', 'Computer security controls'],
  ['6.5.1', 'Specific computer security technical requirements'],
  ['6.5.2', 'Computer security rating'],
  ['6.6', 'Life cycle technical controls'],
  ['6.6.1', 'System development controls'],
  ['6.6.2', 'Security management controls'],
  ['6.6.3', 'Life cycle security controls'],
  ['6.7', 'Network security controls'],
  ['6.8', 'Time-stamping'],
  ['7', 'Certificate, CRL, and OCSP profiles'],
  ['7.1', 'Certificate profile'],
  ['7.1.1', 'Version number(s)'],
  ['7.1.2', 'Certificate extensions'],
  ['7.1.3', 'Algorithm object identifiers'],
  ['7.1.4', 'Name forms'],
  ['7.1.5', 'Name constraints'],
  ['7.1.6', 'Certificate policy object identifier'],
  ['7.1.7', 'Usage of Policy Constraints extension'],
  ['7.1.8', 'Policy qualifiers syntax and semantics'],
  ['7.1.9', 'Processing semantics for the critical Certificate Policies extension'],
  ['7.2', 'CRL profile'],
  ['7.2.1', 'Version number(s)'],
  ['7.2.2', 'CRL and CRL entry extensions'],
  ['7.3', 'OCSP profile'],
  ['7.3.1', 'Version number(s)'],
  ['7.3.2', 'OCSP extensions'],
  ['8', 'Compliance audit and other assessments'],
  ['8.1', 'Frequency or circumstances of assessment'],
  ['8.2', 'Identity/qualifications of assessor'],
  ['8.3', "Assessor's relationship to assessed entity"],
  ['8.4', 'Topics covered by assessment'],
  ['8.5', 'Actions taken as a result of deficiency'],
  ['8.6', 'Communication of results'],
  ['9', 'Other business and legal matters'],
  ['9.1', 'Fees'],
  ['9.1.1', 'Certificate issuance or renewal fees'],
  ['9.1.2', 'Certificate access fees'],
  ['9.1.3', 'Revocation or status information access fees'],
  ['9.1.4', 'Fees for other services'],
  ['9.1.5', 'Refund policy'],
  ['9.2', 'Financial responsibility'],
  ['9.2.1', 'Insurance coverage'],
  ['9.2.2', 'Other assets'],
  ['9.2.3', 'Insurance or warranty coverage for end-entities'],
  ['9.3', 'Confidentiality of business information'],
  ['9.3.1', 'Scope of confidential information'],
  ['9.3.2', 'Information not within the scope of confidential information'],
  ['9.3.3', 'Responsibility to protect confidential information'],
  ['9.4', 'Privacy of personal information'],
  ['9.4.1', 'Privacy plan'],
  ['9.4.2', 'Information treated as private'],
  ['9.4.3', 'Information not deemed private'],
  ['9.4.4', 'Responsibility to protect private information'],
  ['9.4.5', 'Notice and consent to use private information'],
  ['9.4.6', 'Disclosure pursuant to judicial or administrative process'],
  ['9.4.7', 'Other information disclosure circumstances'],
  ['9.5', 'Intellectual property rights'],
  ['9.6', 'Representations and warranties'],
  ['9.6.1', 'CA representations and warranties'],
  ['9.6.2', 'RA representations and warranties'],
  ['9.6.3', 'Subscriber representations and warranties'],
  ['9.6.4', 'Relying party representations and warranties'],
  ['9.6.5', 'Representations and warranties of other participants'],
  ['9.7', 'Disclaimers of warranties'],
  ['9.8', 'Limitations of liability'],
  ['9.9', 'Indemnities'],
  ['9.10', 'Term and termination'],
  ['9.10.1', 'Term'],
  ['9.10.2', 'Termination'],
  ['9.10.3', 'Effect of termination and survival'],
  ['9.11', 'Individual notices and communications with participants'],
  ['9.12', 'Amendments'],
  ['9.12.1', 'Procedure for amendment'],
  ['9.12.2', 'Notification mechanism and period'],
  ['9.12.3', 'Circumstances under which OID must be changed'],
  ['9.13', 'Dispute resolution provisions'],
  ['9.14', 'Governing law'],
  ['9.15', 'Compliance with applicable law'],
  ['9.16', 'Miscellaneous provisions'],
  ['9.16.1', 'Entire agreement'],
  ['9.16.2', 'Assignment'],
  ['9.16.3', 'Severability'],
  ['9.16.4', "Enforcement (attorneys' fees and waiver of rights)"],
  ['9.16.5', 'Force Majeure'],
  ['9.17', 'Other provisions'],
]

export interface CpsDraft {
  docType: 'CPS' | 'CP'
  caName: string
  orgName: string
  policyOids: string
  version: string
  effectiveDate: string
  contactName: string
  contactEmail: string
  contactAddress: string
  repositoryUrl: string
  /** Free text per section number (optional). */
  sections: Record<string, string>
}

export const EMPTY_CPS: CpsDraft = {
  docType: 'CPS',
  caName: '',
  orgName: '',
  policyOids: '',
  version: '1.0',
  effectiveDate: '',
  contactName: '',
  contactEmail: '',
  contactAddress: '',
  repositoryUrl: '',
  sections: {},
}

export function sanitizeCps(x: unknown): CpsDraft {
  const o = (typeof x === 'object' && x !== null ? x : {}) as Record<string, unknown>
  const str = (v: unknown, max = 1000) => (typeof v === 'string' ? v.slice(0, max) : '')
  const sections: Record<string, string> = {}
  if (typeof o.sections === 'object' && o.sections !== null) {
    for (const [k, v] of Object.entries(o.sections as Record<string, unknown>)) {
      if (/^\d{1,2}(\.\d{1,2}){0,2}$/.test(k) && typeof v === 'string') sections[k] = v.slice(0, 20000)
    }
  }
  return {
    docType: o.docType === 'CP' ? 'CP' : 'CPS',
    caName: str(o.caName),
    orgName: str(o.orgName),
    policyOids: str(o.policyOids),
    version: str(o.version, 40) || '1.0',
    effectiveDate: str(o.effectiveDate, 40),
    contactName: str(o.contactName),
    contactEmail: str(o.contactEmail),
    contactAddress: str(o.contactAddress),
    repositoryUrl: str(o.repositoryUrl),
    sections,
  }
}

/** Validate dotted OIDs in the comma/space separated policy OID field. */
export function parsePolicyOids(s: string): { oids: string[]; invalid: string[] } {
  const oids: string[] = []
  const invalid: string[] = []
  for (const tok of s.split(/[\s,;]+/)) {
    if (tok === '') continue
    if (/^[0-2](\.(0|[1-9]\d{0,15})){1,30}$/.test(tok)) oids.push(tok)
    else invalid.push(tok)
  }
  return { oids, invalid }
}

const TODO = '_To be completed._'

function prefill(d: CpsDraft): Record<string, string> {
  const ca = mdText(d.caName.trim() || '[CA name]')
  const org = mdText(d.orgName.trim() || '[Organization]')
  const { oids } = parsePolicyOids(d.policyOids)
  const doc = d.docType === 'CPS' ? 'Certification Practice Statement' : 'Certificate Policy'
  const repo = /^https?:\/\//i.test(d.repositoryUrl.trim()) ? mdText(d.repositoryUrl.trim()) : '[repository URL]'
  return {
    '1.1': `This ${doc} describes the practices of ${ca}, operated by ${org}. It is structured according to RFC 3647.`,
    '1.2': [
      `Document: ${ca} ${doc}, version ${mdText(d.version.trim() || '1.0')}${d.effectiveDate ? `, effective ${mdText(d.effectiveDate)}` : ''}.`,
      oids.length ? `Policy OID(s): ${oids.map((o) => `\`${o}\``).join(', ')}.` : 'Policy OID(s): [assign under your organization’s OID arc].',
    ].join('\n\n'),
    '1.3.1': `${ca} issues certificates under this ${doc}.`,
    '1.5.1': org,
    '1.5.2': [d.contactName && mdText(d.contactName), d.contactEmail && mdText(d.contactEmail), d.contactAddress && mdText(d.contactAddress)].filter(Boolean).join('  \n') || '[name, e-mail, postal address]',
    '2.1': `Repository: ${repo}`,
    '7.1.6': oids.length ? oids.map((o) => `- \`${o}\``).join('\n') : TODO,
  }
}

export function cpsMarkdown(d: CpsDraft, includePlaceholders = true): string {
  const pre = prefill(d)
  const doc = d.docType === 'CPS' ? 'Certification Practice Statement' : 'Certificate Policy'
  const L: string[] = [`# ${mdText(d.caName.trim() || '[CA name]')} — ${doc}`, '']
  L.push(`Version ${mdText(d.version.trim() || '1.0')}${d.effectiveDate ? ` — effective ${mdText(d.effectiveDate)}` : ''}`, '')
  L.push('_Outline per RFC 3647 §6 (Internet X.509 PKI Certificate Policy and Certification Practices Framework). Use "No stipulation." for sections that do not apply rather than removing them._', '')
  for (const [num, title] of RFC3647_OUTLINE) {
    const depth = num.split('.').length
    const heading = '#'.repeat(Math.min(depth + 1, 6))
    L.push(`${heading} ${num}${depth === 1 ? '.' : ''} ${depth === 1 ? title.toUpperCase() : title}`, '')
    const user = d.sections[num]?.trim()
    const body = user ? mdText(user) : pre[num]
    if (body) L.push(body, '')
    else if (includePlaceholders && depth > 1) {
      const hasChildren = RFC3647_OUTLINE.some(([n]) => n.startsWith(`${num}.`))
      if (!hasChildren) L.push(TODO, '')
    }
  }
  return L.join('\n')
}
