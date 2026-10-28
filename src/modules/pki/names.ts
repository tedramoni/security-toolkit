/** Distinguished Name decoding / formatting from raw DER. */
import type { AsnNode } from './der'
import { contents, decodeOid, decodeString, parseOne } from './der'
import { toHex } from './bytes'
import { NAME_ATTRS } from './oids'

export interface NameAttr {
  oid: string
  /** OpenSSL-style short name (CN, O…) or the dotted OID when unknown. */
  short: string
  value: string
}

/** One RDN = one or more attributes (multi-valued RDNs are rare but legal). */
export type Rdn = NameAttr[]

export function decodeNameNode(b: Uint8Array, name: AsnNode): Rdn[] {
  const out: Rdn[] = []
  for (const set of name.children ?? []) {
    const rdn: Rdn = []
    for (const atv of set.children ?? []) {
      const [t, v] = atv.children ?? []
      if (!t || !v) continue
      const oid = decodeOid(contents(b, t))
      const c = contents(b, v)
      const value = v.tagClass === 'universal' ? (decodeString(v.tagNumber, c) ?? `#${toHex(c)}`) : `#${toHex(c)}`
      rdn.push({ oid, short: NAME_ATTRS[oid]?.short ?? oid, value })
    }
    out.push(rdn)
  }
  return out
}

export function decodeName(der: Uint8Array): Rdn[] {
  return decodeNameNode(der, parseOne(der))
}

/** RFC 4514-ish escaping of an attribute value for display / string compare. */
function escapeRfc4514(v: string): string {
  let s = v.replace(/[\\,+"<>;=]/g, (c) => `\\${c}`)
  if (s.startsWith('#') || s.startsWith(' ')) s = `\\${s}`
  if (s.endsWith(' ')) s = `${s.slice(0, -1)}\\ `
  return s
}

/** 'openssl': DER order ("C=US, O=Bar, CN=foo"), like `openssl x509 -subject`. 'rfc4514': reversed (CN first). */
export function formatName(rdns: Rdn[], order: 'openssl' | 'rfc4514' = 'openssl'): string {
  const list = order === 'rfc4514' ? [...rdns].reverse() : rdns
  return list.map((rdn) => rdn.map((a) => `${a.short}=${escapeRfc4514(a.value)}`).join(' + ')).join(', ')
}

export function nameField(rdns: Rdn[], oid: string): string[] {
  return rdns.flatMap((r) => r.filter((a) => a.oid === oid).map((a) => a.value))
}

/** Loose name equality (case-insensitive, internal whitespace collapsed) per the spirit of RFC 5280 §7.1. */
export function namesEqualLoose(a: Rdn[], b: Rdn[]): boolean {
  if (a.length !== b.length) return false
  const norm = (s: string) => s.trim().replace(/\s+/g, ' ').toLowerCase()
  for (let i = 0; i < a.length; i++) {
    if (a[i].length !== b[i].length) return false
    for (let j = 0; j < a[i].length; j++) {
      if (a[i][j].oid !== b[i][j].oid || norm(a[i][j].value) !== norm(b[i][j].value)) return false
    }
  }
  return true
}
