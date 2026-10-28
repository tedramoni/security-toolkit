/** Key / CSR / certificate generation with WebCrypto + @peculiar/x509, and the equivalent OpenSSL commands. */
import type { Bytes } from './bytes'
import { concat, derOid, derSeq, tlv } from './der'
import { normalizeHostname, parseIPv4, parseIPv6 } from './hostname'
import { toPem } from './pem'
import { x509 } from './x509'

export type KeyType = 'RSA-2048' | 'RSA-3072' | 'RSA-4096' | 'P-256' | 'P-384' | 'Ed25519'
export type HashName = 'SHA-256' | 'SHA-384' | 'SHA-512'

export const KEY_TYPES: readonly { id: KeyType; label: string }[] = [
  { id: 'RSA-2048', label: 'RSA 2048' },
  { id: 'RSA-3072', label: 'RSA 3072' },
  { id: 'RSA-4096', label: 'RSA 4096' },
  { id: 'P-256', label: 'ECDSA P-256' },
  { id: 'P-384', label: 'ECDSA P-384' },
  { id: 'Ed25519', label: 'Ed25519' },
]

export function keyGenParams(kt: KeyType, hash: HashName): RsaHashedKeyGenParams | EcKeyGenParams | Algorithm {
  if (kt.startsWith('RSA')) {
    return { name: 'RSASSA-PKCS1-v1_5', modulusLength: Number(kt.slice(4)), publicExponent: new Uint8Array([1, 0, 1]), hash }
  }
  if (kt === 'Ed25519') return { name: 'Ed25519' }
  return { name: 'ECDSA', namedCurve: kt }
}

export function signingAlgorithm(kt: KeyType, hash: HashName): Algorithm | EcdsaParams {
  if (kt.startsWith('RSA')) return { name: 'RSASSA-PKCS1-v1_5', hash } as Algorithm
  if (kt === 'Ed25519') return { name: 'Ed25519' }
  return { name: 'ECDSA', hash } as EcdsaParams
}

export async function generateKeyPair(kt: KeyType, hash: HashName = 'SHA-256'): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(keyGenParams(kt, hash), true, ['sign', 'verify'])) as CryptoKeyPair
}

/** Feature-detect Ed25519 in WebCrypto (Chrome 137+, Firefox 129+, Safari 17+, Node 18.4+). */
export async function supportsEd25519(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
    return true
  } catch {
    return false
  }
}

// ------------------------------------------------------------------------------------------------ subject

export interface SubjectFields {
  CN: string
  O: string
  OU: string
  L: string
  ST: string
  C: string
  E: string
}

export const EMPTY_SUBJECT: SubjectFields = { CN: '', O: '', OU: '', L: '', ST: '', C: '', E: '' }

/** DER order used for the subject (and for -subj): C, ST, L, O, OU, CN, emailAddress. */
const SUBJECT_ORDER: readonly { key: keyof SubjectFields; oid: string; max: number; label: string }[] = [
  { key: 'C', oid: '2.5.4.6', max: 2, label: 'Country' },
  { key: 'ST', oid: '2.5.4.8', max: 128, label: 'State / Province' },
  { key: 'L', oid: '2.5.4.7', max: 128, label: 'Locality' },
  { key: 'O', oid: '2.5.4.10', max: 64, label: 'Organization' },
  { key: 'OU', oid: '2.5.4.11', max: 64, label: 'Organizational Unit' },
  { key: 'CN', oid: '2.5.4.3', max: 64, label: 'Common Name' },
  { key: 'E', oid: '1.2.840.113549.1.9.1', max: 128, label: 'E-mail' },
]

const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63}){1,10}$/
const PRINTABLE_RE = /^[A-Za-z0-9 '()+,\-./:=?]*$/

/** Validate subject fields (RFC 5280 upper bounds). Returns field → error message. */
export function validateSubject(s: SubjectFields): Partial<Record<keyof SubjectFields, string>> {
  const errs: Partial<Record<keyof SubjectFields, string>> = {}
  for (const f of SUBJECT_ORDER) {
    const v = s[f.key]
    if (v === '') continue
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(v)) errs[f.key] = 'Control characters are not allowed'
    else if (v !== v.trim()) errs[f.key] = 'Remove leading/trailing spaces'
    else if ([...v].length > f.max) errs[f.key] = `At most ${f.max} characters (RFC 5280 upper bound)`
  }
  if (s.C !== '' && !/^[A-Z]{2}$/.test(s.C)) errs.C = 'Use the 2-letter ISO 3166-1 code in upper case (e.g. FR, US)'
  if (s.E !== '' && !EMAIL_RE.test(s.E)) errs.E = 'Not a valid e-mail address'
  if (Object.values(s).every((v) => v === '')) errs.CN = 'Enter at least one subject field (usually CN)'
  return errs
}

/** Encode the subject as a DER Name (PrintableString when possible, UTF8String otherwise, IA5String for e-mail). */
export function encodeSubject(s: SubjectFields): Bytes {
  const rdns: Uint8Array[] = []
  for (const f of SUBJECT_ORDER) {
    const v = s[f.key]
    if (v === '') continue
    const bytes = new TextEncoder().encode(v)
    const tag = f.key === 'E' ? 0x16 : f.key === 'C' || PRINTABLE_RE.test(v) ? 0x13 : 0x0c
    rdns.push(tlv(0x31, derSeq(derOid(f.oid), tlv(tag, bytes))))
  }
  return derSeq(concat(...rdns))
}

// ------------------------------------------------------------------------------------------------ SANs

export interface SanEntry {
  type: 'dns' | 'ip' | 'email'
  value: string
}

/**
 * Parse a free-form SAN list (comma / whitespace / newline separated). Entries may be prefixed with "DNS:",
 * "IP:" or "email:"; otherwise the type is inferred. IDNs are converted to punycode.
 */
export function parseSanList(text: string): { sans: SanEntry[]; errors: string[] } {
  const sans: SanEntry[] = []
  const errors: string[] = []
  const seen = new Set<string>()
  for (const rawTok of text.split(/[\s,;]+/)) {
    const tok = rawTok.trim()
    if (tok === '') continue
    const m = /^(dns|ip|email):(.*)$/i.exec(tok)
    const hint = m?.[1].toLowerCase()
    const value = m ? m[2] : tok
    let entry: SanEntry | undefined
    if (hint === 'ip' || (!hint && (parseIPv4(value) || (value.includes(':') && parseIPv6(value))))) {
      const v4 = parseIPv4(value)
      const v6 = v4 ? undefined : parseIPv6(value)
      if (!v4 && !v6) errors.push(`"${tok}" is not a valid IP address`)
      else entry = { type: 'ip', value: value.replace(/^\[|\]$/g, '') }
    } else if (hint === 'email' || (!hint && value.includes('@'))) {
      if (EMAIL_RE.test(value)) entry = { type: 'email', value }
      else errors.push(`"${tok}" is not a valid e-mail address`)
    } else {
      const wildcard = value.startsWith('*.')
      const host = normalizeHostname(wildcard ? value.slice(2) : value)
      if (!host || host.includes('*') || host.includes('_')) errors.push(`"${tok}" is not a valid DNS name`)
      else if (wildcard && !host.includes('.')) errors.push(`"${tok}": wildcard directly on a TLD is not allowed`)
      else entry = { type: 'dns', value: wildcard ? `*.${host}` : host }
    }
    if (entry) {
      const k = `${entry.type}:${entry.value}`
      if (!seen.has(k)) {
        seen.add(k)
        sans.push(entry)
      }
    }
  }
  return { sans, errors }
}

// ------------------------------------------------------------------------------------------------ CSR / cert

export interface GenerateRequest {
  keyType: KeyType
  hash: HashName
  subject: SubjectFields
  sans: SanEntry[]
}

export interface GeneratedCsr {
  csrPem: string
  privateKeyPem: string
  publicKeyPem: string
  keys: CryptoKeyPair
}

export async function exportPrivateKeyPem(key: CryptoKey): Promise<string> {
  return toPem(new Uint8Array(await crypto.subtle.exportKey('pkcs8', key)), 'PRIVATE KEY')
}

export async function exportPublicKeyPem(key: CryptoKey): Promise<string> {
  return toPem(new Uint8Array(await crypto.subtle.exportKey('spki', key)), 'PUBLIC KEY')
}

function sanExtension(sans: SanEntry[]): x509.SubjectAlternativeNameExtension {
  return new x509.SubjectAlternativeNameExtension(sans.map((s) => ({ type: s.type, value: s.value })))
}

export async function generateCsr(req: GenerateRequest, keys?: CryptoKeyPair): Promise<GeneratedCsr> {
  const kp = keys ?? (await generateKeyPair(req.keyType, req.hash))
  const extensions: x509.Extension[] = []
  if (req.sans.length) extensions.push(sanExtension(req.sans))
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: new x509.Name(encodeSubject(req.subject)),
    keys: kp,
    signingAlgorithm: signingAlgorithm(req.keyType, req.hash),
    extensions,
  })
  return {
    csrPem: csr.toString('pem'),
    privateKeyPem: await exportPrivateKeyPem(kp.privateKey),
    publicKeyPem: await exportPublicKeyPem(kp.publicKey),
    keys: kp,
  }
}

/** 128-bit positive random serial as hex (high bit cleared, never zero-leading → 16 octets). */
export function randomSerialHex(bytes = 16): string {
  const b = crypto.getRandomValues(new Uint8Array(bytes))
  b[0] = (b[0] & 0x7f) | 0x40
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

export async function generateSelfSigned(req: GenerateRequest & { days: number }, keys?: CryptoKeyPair): Promise<{ certPem: string; privateKeyPem: string }> {
  const kp = keys ?? (await generateKeyPair(req.keyType, req.hash))
  const notBefore = new Date(Date.now() - 60_000)
  const notAfter = new Date(notBefore.getTime() + req.days * 86_400_000)
  const ku = req.keyType.startsWith('RSA')
    ? x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment
    : x509.KeyUsageFlags.digitalSignature
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(ku, true),
    new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth]),
    await x509.SubjectKeyIdentifierExtension.create(kp.publicKey),
  ]
  if (req.sans.length) extensions.push(sanExtension(req.sans))
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerialHex(),
    name: new x509.Name(encodeSubject(req.subject)),
    notBefore,
    notAfter,
    keys: kp,
    signingAlgorithm: signingAlgorithm(req.keyType, req.hash),
    extensions,
  })
  return { certPem: cert.toString('pem'), privateKeyPem: await exportPrivateKeyPem(kp.privateKey) }
}

// ------------------------------------------------------------------------------------------------ OpenSSL

/** POSIX shell single-quoting. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

/** Escape a value for `openssl req -subj`: backslash, "/" (RDN separator) and "+" (multi-valued RDN). */
export function escapeSubjValue(v: string): string {
  return v.replace(/[\\/+]/g, (c) => `\\${c}`)
}

const SUBJ_LABEL: Record<keyof SubjectFields, string> = { C: 'C', ST: 'ST', L: 'L', O: 'O', OU: 'OU', CN: 'CN', E: 'emailAddress' }

export function opensslSubj(s: SubjectFields): string {
  return SUBJECT_ORDER.filter((f) => s[f.key] !== '')
    .map((f) => `/${SUBJ_LABEL[f.key]}=${escapeSubjValue(s[f.key])}`)
    .join('')
}

export function opensslSanValue(sans: SanEntry[]): string {
  return sans.map((s) => `${s.type === 'dns' ? 'DNS' : s.type === 'ip' ? 'IP' : 'email'}:${s.value}`).join(',')
}

function newKeyArgs(kt: KeyType): string[] {
  if (kt.startsWith('RSA')) return ['-newkey', `rsa:${kt.slice(4)}`]
  if (kt === 'Ed25519') return ['-newkey', 'ed25519']
  return ['-newkey', 'ec', '-pkeyopt', `ec_paramgen_curve:${kt}`]
}

/** Equivalent `openssl req` command (OpenSSL ≥ 1.1.1 for -addext). */
export function opensslReqCommand(req: GenerateRequest & { selfSigned?: boolean; days?: number; baseName?: string }): string {
  const base = req.baseName || (req.subject.CN ? req.subject.CN.replace(/^\*/, 'wildcard').replace(/[^A-Za-z0-9.-]+/g, '_') : 'request')
  const args: string[] = ['openssl', 'req', req.selfSigned ? '-x509' : '-new', ...newKeyArgs(req.keyType), '-nodes']
  args.push('-keyout', shellQuote(`${base}.key`))
  args.push('-out', shellQuote(`${base}.${req.selfSigned ? 'crt' : 'csr'}`))
  if (req.keyType !== 'Ed25519') args.push(`-${req.hash.replace('-', '').toLowerCase()}`)
  if (req.selfSigned) args.push('-days', String(Math.max(1, Math.floor(req.days ?? 30))))
  const lines = [args.join(' ')]
  lines.push(`-subj ${shellQuote(opensslSubj(req.subject))}`)
  if (req.sans.length) lines.push(`-addext ${shellQuote(`subjectAltName=${opensslSanValue(req.sans)}`)}`)
  if (req.selfSigned) {
    lines.push(`-addext ${shellQuote('basicConstraints=critical,CA:FALSE')}`)
    lines.push(`-addext ${shellQuote(`keyUsage=critical,digitalSignature${req.keyType.startsWith('RSA') ? ',keyEncipherment' : ''}`)}`)
    lines.push(`-addext ${shellQuote('extendedKeyUsage=serverAuth,clientAuth')}`)
  }
  return lines.join(' \\\n  ')
}
