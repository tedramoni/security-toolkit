/** Tolerant input parsing: PEM (one or many blocks, any surrounding text, CRLF), bare base64 DER, hex, raw DER. */
import type { Bytes } from './bytes'
import { fromBase64, fromHex, toBase64 } from './bytes'

export interface PemBlock {
  /** PEM label, e.g. "CERTIFICATE". For non-PEM input: "" (unknown). */
  label: string
  der: Bytes
  /** Legacy OpenSSL encrypted PEM (Proc-Type: 4,ENCRYPTED). */
  encrypted?: boolean
  source: 'pem' | 'base64' | 'hex' | 'der'
}

export interface ParsedInput {
  blocks: PemBlock[]
  /** Problems with individual blocks (e.g. bad base64). */
  warnings: string[]
}

const BEGIN = '-----BEGIN '
const DASHES = '-----'
const MAX_LABEL = 64

const END = '-----END '
const LABEL_RE = /^[A-Z0-9 #-]{1,64}$/
const MAX_WARNINGS = 20

/** Label of a "-----BEGIN X-----" / "-----END X-----" marker whose label starts at `start`, or undefined. */
function markerLabel(text: string, start: number): string | undefined {
  // Bounded search: never scan more than MAX_LABEL characters for the closing dashes.
  const end = text.slice(start, start + MAX_LABEL + DASHES.length).indexOf(DASHES)
  if (end < 0) return undefined
  const label = text.slice(start, start + end)
  return LABEL_RE.test(label) ? label : undefined
}

/**
 * Find every PEM block in linear time (no backtracking regex). All "-----END X-----" markers are indexed in one
 * pass first, so thousands of unterminated BEGIN lines cannot trigger a quadratic search.
 */
export function parsePem(text: string): ParsedInput {
  const blocks: PemBlock[] = []
  const warningSet = new Set<string>()
  const warn = (w: string) => {
    if (warningSet.size < MAX_WARNINGS) warningSet.add(w)
  }
  // label → ascending positions of "-----END label-----", plus a cursor (BEGIN positions only increase).
  const ends = new Map<string, { at: number[]; cur: number }>()
  for (let i = text.indexOf(END); i >= 0; i = text.indexOf(END, i + 1)) {
    const label = markerLabel(text, i + END.length)
    if (label === undefined) continue
    let e = ends.get(label)
    if (!e) ends.set(label, (e = { at: [], cur: 0 }))
    e.at.push(i)
  }
  let pos = 0
  while (pos < text.length) {
    const b = text.indexOf(BEGIN, pos)
    if (b < 0) break
    const labelStart = b + BEGIN.length
    const label = markerLabel(text, labelStart)
    if (label === undefined) {
      pos = labelStart
      continue
    }
    const bodyStart = labelStart + label.length + DASHES.length
    const endMarker = `-----END ${label}-----`
    const list = ends.get(label)
    while (list && list.cur < list.at.length && list.at[list.cur] < bodyStart) list.cur++
    const e = list && list.cur < list.at.length ? list.at[list.cur] : -1
    if (e < 0) {
      warn(`"BEGIN ${label}" without a matching "END ${label}" line — the block looks truncated.`)
      pos = bodyStart
      continue
    }
    // A BEGIN before our END means this block was truncated (e.g. a half-copied certificate followed by a full
    // one): report it and resume at the inner BEGIN instead of swallowing the next block as base64.
    const inner = text.indexOf(BEGIN, bodyStart)
    if (inner >= 0 && inner < e) {
      warn(`"BEGIN ${label}" without a matching "END ${label}" line — the block looks truncated.`)
      pos = inner
      continue
    }
    const body = text.slice(bodyStart, e)
    pos = e + endMarker.length
    let encrypted = false
    // Drop RFC 1421 headers (Proc-Type / DEK-Info) used by legacy encrypted OpenSSL keys.
    const lines = body.split(/\r?\n|\r/)
    const b64Lines: string[] = []
    for (const line of lines) {
      const t = line.trim()
      if (t === '') continue
      const colon = t.indexOf(':')
      if (colon > 0 && colon < 20 && /^[A-Za-z-]+$/.test(t.slice(0, colon))) {
        if (/^Proc-Type:\s*4,\s*ENCRYPTED/i.test(t)) encrypted = true
        continue
      }
      b64Lines.push(t)
    }
    try {
      const der = fromBase64(b64Lines.join(''))
      if (der.length === 0) throw new Error('empty body')
      blocks.push({ label, der, encrypted: encrypted || undefined, source: 'pem' })
    } catch (err) {
      warn(`Block "${label}" has invalid base64: ${(err as Error).message}`)
    }
  }
  return { blocks, warnings: [...warningSet] }
}

/**
 * Parse whatever the user pasted: PEM blocks, or else a single base64 / hex encoded DER blob.
 * Returns no blocks (and a warning) if nothing usable was found.
 */
export function parseInputText(text: string): ParsedInput {
  const pem = parsePem(text)
  if (pem.blocks.length > 0 || text.includes(BEGIN)) return pem
  const trimmed = text.trim()
  if (trimmed === '') return { blocks: [], warnings: [] }
  const compact = trimmed.replace(/\s+/g, '')
  if (/^[0-9a-fA-F:]+$/.test(compact) && compact.replace(/:/g, '').length % 2 === 0 && /^(30|31|a0)/i.test(compact)) {
    try {
      return { blocks: [{ label: '', der: fromHex(compact), source: 'hex' }], warnings: [] }
    } catch {
      /* fall through to base64 */
    }
  }
  try {
    const der = fromBase64(compact)
    if (der.length > 1 && der[0] === 0x30) return { blocks: [{ label: '', der, source: 'base64' }], warnings: [] }
    return { blocks: [], warnings: ['Input is not PEM, and decodes to base64 that is not a DER SEQUENCE.'] }
  } catch {
    return { blocks: [], warnings: ['Input is neither PEM ("-----BEGIN …-----"), base64 DER nor hex DER.'] }
  }
}

/** Parse an uploaded file: binary DER or text (PEM/base64). */
export function parseInputBytes(bytes: Uint8Array): ParsedInput {
  if (bytes.length === 0) return { blocks: [], warnings: ['The file is empty.'] }
  // DER starts with a SEQUENCE tag; PEM/base64 text never starts with 0x30 followed by a length byte ≥ 0x80.
  if (bytes[0] === 0x30 && bytes.length > 1 && (bytes[1] >= 0x80 || bytes[1] + 2 === bytes.length)) {
    return { blocks: [{ label: '', der: Uint8Array.from(bytes), source: 'der' }], warnings: [] }
  }
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  return parseInputText(text)
}

export function toPem(der: Uint8Array, label: string): string {
  const b64 = toBase64(der)
  const lines: string[] = []
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64))
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`
}
