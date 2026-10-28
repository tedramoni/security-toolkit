/**
 * Chain building from an unordered bundle: match issuer name ↔ subject name (+ AKI ↔ SKI when both present),
 * verify every signature with WebCrypto, order leaf → root. Trust is NOT evaluated (there is no root store).
 */
import { bytesEqual } from './bytes'
import type { CertInfo } from './cert'
import { decodeCertificate, isSelfIssued } from './cert'
import { accessUrls, extDecoded } from './extensions'
import { namesEqualLoose } from './names'
import { OID } from './oids'
import { toPem } from './pem'
import type { VerifyResult } from './verify'
import { verifyCertSignature } from './verify'

export interface ChainLink {
  index: number
  info: CertInfo
  /** Signature of this cert verified with the next cert's key (or its own key for a self-signed root). */
  signature?: VerifyResult
  issuerIndex?: number
  problems: string[]
  selfSigned: boolean
}

export interface BuiltChain {
  links: ChainLink[]
  /** True if the last link is a self-signed certificate (a root). */
  complete: boolean
  /** Issuer of the last link is missing from the bundle. */
  missingIssuer?: { issuer: string; caIssuersUrls: string[] }
}

export interface ChainReport {
  chains: BuiltChain[]
  /** Certificates that ended up in no chain (bundle index). */
  unused: number[]
  parseErrors: string[]
}

export const MAX_BUNDLE = 100

type Verifier =(cert: Uint8Array, issuer: Uint8Array) => Promise<VerifyResult>

function keyId(info: CertInfo, which: 'ski' | 'aki'): string | undefined {
  return which === 'ski'
    ? extDecoded(info.extensions, OID.subjectKeyIdentifier, 'keyId')?.keyId
    : extDecoded(info.extensions, OID.authorityKeyIdentifier, 'aki')?.keyId
}

/** Name + key-identifier match (signature not checked). */
export function couldIssue(issuer: CertInfo, child: CertInfo): boolean {
  if (!bytesEqual(issuer.subjectDer, child.issuerDer) && !namesEqualLoose(issuer.subject, child.issuer)) return false
  const aki = keyId(child, 'aki')
  const ski = keyId(issuer, 'ski')
  return !(aki && ski && aki !== ski)
}

export async function buildChains(ders: Uint8Array[], opts: { now?: Date; verify?: Verifier } = {}): Promise<ChainReport> {
  const now = opts.now ?? new Date()
  const verify = opts.verify ?? verifyCertSignature
  const parseErrors: string[] = []
  // Path building tries every name-matching candidate with a WebCrypto verify: O(n²) in the worst case (many
  // certificates with the same subject). Real chains are short, so cap the bundle to keep the tab responsive.
  if (ders.length > MAX_BUNDLE) {
    parseErrors.push(`The bundle has ${ders.length} certificates; only the first ${MAX_BUNDLE} are used for chain building.`)
    ders = ders.slice(0, MAX_BUNDLE)
  }
  const infos: (CertInfo | undefined)[] = ders.map((d, i) => {
    try {
      return decodeCertificate(d)
    } catch (e) {
      parseErrors.push(`Certificate #${i + 1}: ${(e as Error).message}`)
      return undefined
    }
  })
  // Deduplicate identical certificates.
  const idx: number[] = []
  infos.forEach((info, i) => {
    if (info && !idx.some((j) => bytesEqual(infos[j]!.der, info.der))) idx.push(i)
  })

  const sigCache = new Map<string, Promise<VerifyResult>>()
  const verifyPair = (c: number, iss: number) => {
    const k = `${c}>${iss}`
    let p = sigCache.get(k)
    if (!p) {
      p = verify(infos[c]!.der, infos[iss]!.der)
      sigCache.set(k, p)
    }
    return p
  }

  const selfSigned = new Map<number, boolean>()
  for (const i of idx) {
    const info = infos[i]!
    selfSigned.set(i, isSelfIssued(info) ? (await verifyPair(i, i)).ok : false)
  }

  // Leaves: certs that issue nothing else in the bundle. If everything issues something (e.g. a loop), take non-roots.
  const issuesSomething = (i: number) => idx.some((j) => j !== i && !selfSigned.get(j) && couldIssue(infos[i]!, infos[j]!))
  let leaves = idx.filter((i) => !issuesSomething(i))
  // A self-signed root that issues nothing here is an unrelated root (e.g. ISRG Root X2 next to an X1 chain): report
  // it as unused rather than as a one-certificate "chain", unless the bundle holds nothing else.
  const realLeaves = leaves.filter((i) => !selfSigned.get(i))
  if (realLeaves.length > 0) leaves = realLeaves
  if (leaves.length === 0) leaves = idx.filter((i) => !selfSigned.get(i))
  if (leaves.length === 0) leaves = idx.slice(0, 1)
  // Prefer end-entities first.
  leaves.sort((a, b) => Number(extDecoded(infos[a]!.extensions, OID.basicConstraints, 'bc')?.ca ?? false) - Number(extDecoded(infos[b]!.extensions, OID.basicConstraints, 'bc')?.ca ?? false))

  const used = new Set<number>()
  const chains: BuiltChain[] = []
  for (const leaf of leaves) {
    const links: ChainLink[] = []
    const visited = new Set<number>()
    let cur: number | undefined = leaf
    let complete = false
    let missingIssuer: BuiltChain['missingIssuer']
    while (cur !== undefined && links.length < 12) {
      visited.add(cur)
      used.add(cur)
      const info: CertInfo = infos[cur]!
      const link: ChainLink = { index: cur, info, problems: [], selfSigned: !!selfSigned.get(cur) }
      links.push(link)
      if (now > info.notAfter) link.problems.push(`expired on ${info.notAfter.toISOString().slice(0, 10)}`)
      if (now < info.notBefore) link.problems.push(`not valid before ${info.notBefore.toISOString().slice(0, 10)}`)
      if (link.selfSigned) {
        link.signature = await verifyPair(cur, cur)
        complete = true
        break
      }
      // candidate issuers
      const candidates = idx.filter((j) => j !== cur && !visited.has(j) && couldIssue(infos[j]!, info))
      let chosen: number | undefined
      for (const c of candidates) {
        const r = await verifyPair(cur, c)
        if (r.ok) {
          chosen = c
          link.signature = r
          break
        }
      }
      if (chosen === undefined && candidates.length > 0) {
        chosen = candidates[0]
        link.signature = await verifyPair(cur, chosen)
        link.problems.push('signature does NOT verify with the issuer’s public key')
      }
      if (chosen === undefined) {
        if (isSelfIssued(info)) link.problems.push('self-issued but the self-signature does not verify')
        missingIssuer = { issuer: info.issuerString, caIssuersUrls: accessUrls(info.extensions, OID.caIssuers) }
        break
      }
      link.issuerIndex = chosen
      const issuer = infos[chosen]!
      const bc = extDecoded(issuer.extensions, OID.basicConstraints, 'bc')
      const ku = extDecoded(issuer.extensions, OID.keyUsage, 'ku')
      if (!bc?.ca) link.problems.push('its issuer is not a CA (Basic Constraints CA:FALSE or absent)')
      if (ku && !ku.usages.includes('keyCertSign')) link.problems.push('its issuer’s Key Usage lacks keyCertSign')
      if (issuer.notAfter < info.notAfter) link.problems.push('outlives its issuer (notAfter later than the issuer’s)')
      cur = chosen
    }
    // pathLen constraints: number of non-self-issued intermediates below each CA.
    for (let i = 0; i < links.length; i++) {
      const bc = extDecoded(links[i].info.extensions, OID.basicConstraints, 'bc')
      if (bc?.ca && bc.pathLen !== undefined) {
        const below = links.slice(1, i).filter((l) => !isSelfIssued(l.info)).length
        if (below > bc.pathLen) links[i].problems.push(`pathLenConstraint ${bc.pathLen} exceeded (${below} CA certificate(s) below it)`)
      }
    }
    chains.push({ links, complete, missingIssuer })
  }
  const unused = idx.filter((i) => !used.has(i))
  return { chains, unused, parseErrors }
}

export function chainToPem(chain: BuiltChain, includeRoot: boolean): string {
  return chain.links
    .filter((l, i) => includeRoot || !(l.selfSigned && i === chain.links.length - 1) || chain.links.length === 1)
    .map((l) => toPem(l.info.der, 'CERTIFICATE'))
    .join('')
}
