/*
 * "Magic": propose decoding chains for unknown data. Breadth-first search (depth ≤ 3) over cheap, linear-time
 * format checks; each candidate is actually executed and its output scored for printability, English-likeness,
 * entropy drop and recognisable structure (file magic, JSON). Bounded by a wall-clock budget and an input cap.
 */
import { detectFileType, englishScore, printableRatio, shannonEntropy } from './analysis'
import { bytesEqual, isValidUtf8, utf8Decode } from './bytes'
import { defaultArgs } from './recipe'
import type { ArgValues, Bytes, OpDef, RecipeStep } from './types'

export const MAGIC_MAX_INPUT = 1024 * 1024
export const MAGIC_DEFAULT_BUDGET_MS = 1500

interface Candidate {
  opId: string
  args?: ArgValues
  label: string
  /** Cheap check on the (trimmed) text / raw bytes. Must be linear-time. */
  test(text: string, bytes: Uint8Array): boolean
}

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/
const B64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/
const B32_RE = /^[A-Z2-7]+=*$/
const HEX_RE = /^(?:0x)?[0-9a-fA-F]+$/
const HEX_DELIM_RE = /^[0-9a-fA-F]{2}(?:[ ,:\n-]{1,2}[0-9a-fA-F]{2})+$/
const BIN_RE = /^[01]{8}(?:[ ,\n]?[01]{8})*$/
const DEC_RE = /^\d{1,3}(?:[ ,]{1,2}\d{1,3}){2,}$/
const B58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/

function isPrintableAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (!((c >= 0x20 && c <= 0x7e) || c === 9 || c === 10 || c === 13)) return false
  }
  return true
}

function stripWs(s: string): string {
  return s.replace(/\s+/g, '')
}

const CANDIDATES: readonly Candidate[] = [
  {
    opId: 'from-base64',
    label: 'Base64',
    test: (t) => {
      const s = stripWs(t)
      return s.length >= 8 && s.length % 4 !== 1 && B64_RE.test(s) && /[A-Z]/.test(s) && /[a-z0-9]/.test(s)
    },
  },
  {
    opId: 'from-base64',
    args: { alphabet: 'url' },
    label: 'Base64URL',
    test: (t) => {
      const s = stripWs(t)
      return s.length >= 8 && s.length % 4 !== 1 && /[-_]/.test(s) && B64URL_RE.test(s)
    },
  },
  {
    opId: 'from-base32',
    label: 'Base32',
    test: (t) => {
      const s = stripWs(t)
      return s.length >= 8 && B32_RE.test(s) && (s.includes('=') ? s.length % 8 === 0 : [0, 2, 4, 5, 7].includes(s.length % 8))
    },
  },
  {
    opId: 'from-hex',
    label: 'Hex',
    test: (t) => {
      if (HEX_DELIM_RE.test(t)) return true
      const s = stripWs(t)
      return s.length >= 4 && s.length % 2 === 0 && HEX_RE.test(s)
    },
  },
  { opId: 'url-decode', label: 'URL encoding', test: (t) => /%[0-9A-Fa-f]{2}/.test(t) },
  { opId: 'from-binary', label: 'Binary', test: (t) => t.length >= 8 && BIN_RE.test(t) },
  { opId: 'from-decimal', label: 'Decimal bytes', test: (t) => DEC_RE.test(t) },
  { opId: 'gunzip', label: 'Gzip', test: (_t, b) => b.length > 18 && b[0] === 0x1f && b[1] === 0x8b && b[2] === 0x08 },
  {
    opId: 'zlib-inflate',
    label: 'Zlib',
    test: (_t, b) => b.length > 6 && b[0] === 0x78 && ((b[0] << 8) | b[1]) % 31 === 0,
  },
  { opId: 'jwt-decode', label: 'JWT', test: (t) => /^eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/.test(t) },
  {
    opId: 'from-quoted-printable',
    label: 'Quoted-printable',
    test: (t) => /=[0-9A-F]{2}/.test(t) && (t.match(/=[0-9A-F]{2}/g)?.length ?? 0) >= 2 && !/%[0-9A-F]{2}/.test(t),
  },
  { opId: 'html-entity-decode', label: 'HTML entities', test: (t) => /&(?:#\d{1,7}|#x[0-9a-fA-F]{1,6}|[A-Za-z]{2,10});/.test(t) },
  { opId: 'unicode-unescape', label: 'Unicode escapes', test: (t) => /\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}|\\x[0-9a-fA-F]{2}/.test(t) },
  { opId: 'rot13', label: 'ROT13', test: (t) => /[A-Za-z]{3}/.test(t) && isPrintableAscii(t.slice(0, 4096)) },
  { opId: 'from-punycode', label: 'Punycode', test: (t) => /(^|\.)xn--[a-z0-9-]{2,}/i.test(t) },
  {
    opId: 'from-base58',
    label: 'Base58',
    test: (t) => {
      const s = t.trim()
      return s.length >= 12 && s.length <= 8192 && B58_RE.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s) && /[1-9]/.test(s)
    },
  },
  { opId: 'from-base85', label: 'Ascii85', test: (t) => t.startsWith('<~') && t.endsWith('~>') },
  { opId: 'from-hexdump', label: 'Hexdump', test: (t) => /^[0-9a-fA-F]{8}:? {1,2}[0-9a-fA-F]{2}/.test(t) },
]

export interface MagicResult {
  steps: RecipeStep[]
  labels: string[]
  score: number
  /** Decoded output (first MAGIC_MAX_INPUT bytes). */
  output: Bytes
  preview: string
  /** Why it scored well. */
  reason: string
}

export interface ScoreInfo {
  score: number
  reason: string
}

/** Score how "meaningful" bytes look, 0–1. */
export function scoreOutput(bytes: Uint8Array): ScoreInfo {
  if (bytes.length === 0) return { score: 0, reason: 'empty' }
  const sig = detectFileType(bytes)
  if (sig && !sig.name.startsWith('ASN.1') && !sig.name.startsWith('Windows PE')) return { score: 0.85, reason: sig.name }
  const sample = bytes.subarray(0, 65536)
  const printable = printableRatio(sample)
  if (!isValidUtf8(sample) && printable < 0.9) return { score: 0.05 * printable, reason: 'binary' }
  const text = utf8Decode(sample).trim()
  if ((text.startsWith('{') || text.startsWith('[')) && text.length < 1_000_000) {
    try {
      JSON.parse(text)
      return { score: 0.95, reason: 'valid JSON' }
    } catch {
      /* not JSON */
    }
  }
  const eng = englishScore(sample)
  const words = (text.match(/\b[a-z]{2,}\b/gi) ?? []).length
  let score = printable * (0.45 + 0.55 * eng)
  if (words === 0) score *= 0.6
  const reason = `${Math.round(printable * 100)}% printable, English-likeness ${eng.toFixed(2)}`
  return { score: Math.min(1, score), reason }
}

export interface MagicOptions {
  budgetMs?: number
  maxDepth?: number
  maxResults?: number
  lookup: (id: string) => OpDef | undefined
}

interface Node {
  steps: RecipeStep[]
  labels: string[]
  data: Bytes
  score: number
}

const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now())

/** Find decoding chains for `input`. Resolves within roughly the time budget. */
export async function magic(input: Bytes, opts: MagicOptions): Promise<MagicResult[]> {
  const deadline = now() + (opts.budgetMs ?? MAGIC_DEFAULT_BUDGET_MS)
  const maxDepth = opts.maxDepth ?? 3
  const data = input.length > MAGIC_MAX_INPUT ? input.slice(0, MAGIC_MAX_INPUT) : input
  const base = scoreOutput(data)
  const baseEntropy = shannonEntropy(data.subarray(0, 65536))
  const results: MagicResult[] = []
  let frontier: Node[] = [{ steps: [], labels: [], data, score: base.score }]
  for (let depth = 1; depth <= maxDepth && frontier.length; depth++) {
    const next: Node[] = []
    for (const node of frontier) {
      const text = isValidUtf8(node.data.subarray(0, 65536)) ? utf8Decode(node.data).trim() : ''
      for (const c of CANDIDATES) {
        if (now() > deadline) return finish(results, opts.maxResults)
        const prev = node.steps[node.steps.length - 1]
        if (prev && prev.opId === c.opId && c.opId === 'rot13') continue
        let ok = false
        try {
          ok = c.test(text, node.data)
        } catch {
          ok = false
        }
        if (!ok) continue
        const op = opts.lookup(c.opId)
        if (!op) continue
        const step: RecipeStep = { opId: op.id, args: { ...defaultArgs(op), ...c.args } }
        let out: Bytes
        try {
          out = await op.run(node.data, step.args, {})
        } catch {
          continue
        }
        if (out.length === 0 || bytesEqual(out, node.data)) continue
        // Decompression can blow the data up (up to the 256 MB bomb cap): keep exploring, scoring and returning only
        // the first MAGIC_MAX_INPUT bytes so deeper levels stay fast and results stay small to post back.
        if (out.length > MAGIC_MAX_INPUT) out = out.slice(0, MAGIC_MAX_INPUT)
        const s = scoreOutput(out)
        // ROT13 only counts when it makes text clearly more English-like.
        if (c.opId === 'rot13' && englishScore(out) < englishScore(node.data) + 0.1) continue
        const child: Node = { steps: [...node.steps, step], labels: [...node.labels, c.label], data: out, score: s.score }
        const entropyDrop = baseEntropy - shannonEntropy(out.subarray(0, 65536))
        const score = s.score - 0.03 * (depth - 1) + (entropyDrop > 0.5 && s.score > 0.5 ? 0.03 : 0)
        if (s.score > Math.max(0.3, base.score * 0.9) || s.reason !== 'binary') {
          results.push({
            steps: child.steps,
            labels: child.labels,
            score,
            output: out,
            preview: utf8Decode(out.subarray(0, 300)),
            reason: s.reason,
          })
        }
        next.push(child)
      }
    }
    // Keep the most promising nodes to bound the search.
    next.sort((a, b) => b.score - a.score)
    frontier = next.slice(0, 6)
  }
  return finish(results, opts.maxResults)
}

function finish(results: MagicResult[], max = 6): MagicResult[] {
  results.sort((a, b) => b.score - a.score || a.steps.length - b.steps.length)
  const seen = new Set<string>()
  const out: MagicResult[] = []
  for (const r of results) {
    const key = r.labels.join('>')
    if (seen.has(key)) continue
    seen.add(key)
    out.push(r)
    if (out.length >= max) break
  }
  return out
}
