/*
 * Invisible / deceptive Unicode helpers.
 * - TAG characters U+E0000–U+E007F mirror ASCII (U+E0020–U+E007E ↔ 0x20–0x7E) and are not rendered:
 *   "ASCII smuggling" of hidden prompts.
 * - Bidi controls U+202A–U+202E and isolates U+2066–U+2069: Trojan Source (CVE-2021-42574).
 * - Variation selectors VS1–VS16 (U+FE00–FE0F) and VS17–VS256 (U+E0100–E01EF) can carry one byte each
 *   when appended to a character ("emoji smuggling").
 */

export const TAG_RUN_RE = /[\u{E0000}-\u{E007F}]{1,20000}/gu
export const BIDI_RE = /[\u202A-\u202E\u2066-\u2069]/g
// ZWJ (U+200D) and the combining grapheme joiner (U+034F) are alternations, not class members,
// so the class never "joins" characters (no-misleading-character-class).
export const ZERO_WIDTH_RE = /[\u200B\u200C\u2060-\u2064\uFEFF\u180E\u00AD\u115F\u1160\u3164\uFFA0\u17B4\u17B5\u2800]|\u200D|\u034F/g
export const VS_RUN_RE = /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]{2,20000}/gu

/** Decode a run of TAG characters to the ASCII it smuggles (begin/cancel tags dropped). */
export function decodeTags(run: string): string {
  let out = ''
  for (const ch of run) {
    const cp = ch.codePointAt(0) ?? 0
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000)
  }
  return out
}

/** Encode ASCII text as TAG characters (used for samples and tests). */
export function encodeTags(ascii: string): string {
  let out = ''
  for (const ch of ascii) {
    const c = ch.charCodeAt(0)
    if (c >= 0x20 && c <= 0x7e) out += String.fromCodePoint(0xe0000 + c)
  }
  return out
}

/** Bytes carried by a run of variation selectors (VS1–16 → 0–15, VS17–256 → 16–255). */
export function decodeVariationSelectors(run: string): Uint8Array {
  const bytes: number[] = []
  for (const ch of run) {
    const cp = ch.codePointAt(0) ?? 0
    if (cp >= 0xfe00 && cp <= 0xfe0f) bytes.push(cp - 0xfe00)
    else if (cp >= 0xe0100 && cp <= 0xe01ef) bytes.push(cp - 0xe0100 + 16)
  }
  return new Uint8Array(bytes)
}

export function encodeVariationSelectors(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + (b - 16))
  return out
}

/** Best-effort printable rendering of decoded bytes. */
export function bytesPreview(bytes: Uint8Array, max = 200): string {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  return visibleEscape(text.slice(0, max)) + (text.length > max ? '…' : '')
}

/** Replace control chars by \xNN so previews are safe to show on one line. */
export function visibleEscape(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).replace(/\n/g, '⏎')
}

export function codePointLabel(ch: string): string {
  return 'U+' + (ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')
}

const NAMES: Record<number, string> = {
  0x200b: 'ZERO WIDTH SPACE',
  0x200c: 'ZERO WIDTH NON-JOINER',
  0x200d: 'ZERO WIDTH JOINER',
  0x2060: 'WORD JOINER',
  0xfeff: 'ZERO WIDTH NO-BREAK SPACE / BOM',
  0x00ad: 'SOFT HYPHEN',
  0x180e: 'MONGOLIAN VOWEL SEPARATOR',
  0x202a: 'LEFT-TO-RIGHT EMBEDDING',
  0x202b: 'RIGHT-TO-LEFT EMBEDDING',
  0x202c: 'POP DIRECTIONAL FORMATTING',
  0x202d: 'LEFT-TO-RIGHT OVERRIDE',
  0x202e: 'RIGHT-TO-LEFT OVERRIDE',
  0x2066: 'LEFT-TO-RIGHT ISOLATE',
  0x2067: 'RIGHT-TO-LEFT ISOLATE',
  0x2068: 'FIRST STRONG ISOLATE',
  0x2069: 'POP DIRECTIONAL ISOLATE',
  0x3164: 'HANGUL FILLER',
  0x2800: 'BRAILLE PATTERN BLANK',
}

export function charName(ch: string): string {
  return NAMES[ch.codePointAt(0) ?? 0] ?? codePointLabel(ch)
}

/* ---------- Homoglyphs ---------- */

const LATIN_RE = /\p{Script=Latin}/u
const CONFUSABLE_SCRIPT_RE = /[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}\p{Script=Cherokee}]/u
const WORD_RE = /[\p{L}\p{M}]{3,64}/gu

/** Cyrillic / Greek letters that look like Latin ones. */
const CONFUSABLES: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ԛ: 'q', ԝ: 'w', һ: 'h', ӏ: 'l',
  А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', Х: 'X', У: 'Y', І: 'I', Ј: 'J', Ѕ: 'S',
  ο: 'o', α: 'a', ν: 'v', ρ: 'p', τ: 't', ι: 'i', κ: 'k', Α: 'A', Β: 'B', Ε: 'E', Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K',
  Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P', Τ: 'T', Υ: 'Y', Χ: 'X',
}

export interface MixedWord {
  index: number
  word: string
  /** ASCII skeleton (confusables replaced). */
  skeleton: string
}

export function skeleton(word: string): string {
  let out = ''
  for (const ch of word) out += CONFUSABLES[ch] ?? ch
  return out
}

/** Words mixing Latin with Cyrillic/Greek/Armenian/Cherokee letters. */
export function findMixedScriptWords(line: string): MixedWord[] {
  const out: MixedWord[] = []
  if (!CONFUSABLE_SCRIPT_RE.test(line) || !LATIN_RE.test(line)) return out
  for (const m of line.matchAll(WORD_RE)) {
    const w = m[0]
    let latin = false
    let other = false
    for (const ch of w) {
      if (!latin && LATIN_RE.test(ch)) latin = true
      else if (!other && CONFUSABLE_SCRIPT_RE.test(ch)) other = true
      if (latin && other) break
    }
    if (latin && other) out.push({ index: m.index ?? 0, word: w, skeleton: skeleton(w) })
  }
  return out
}

/* ---------- Visible rendering ---------- */

export type VisiblePart = { text: string } | { invisible: string; title: string }

// eslint-disable-next-line no-control-regex
const INVISIBLE_RE = /[\u{E0000}-\u{E007F}]{1,20000}|[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]{2,20000}|[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u206F\u2800\u3164\uFEFF\uFFA0\uFFF9-\uFFFB]|\u200D|\u034F/gu

/**
 * Split text into plain parts and labels for invisible characters, e.g. ⟦U+200B⟧ or
 * ⟦TAG "hidden text"⟧. Never returns HTML — callers render parts as text nodes.
 */
export function toVisibleParts(text: string): VisiblePart[] {
  const parts: VisiblePart[] = []
  let last = 0
  for (const m of text.matchAll(INVISIBLE_RE)) {
    const i = m.index ?? 0
    if (i > last) parts.push({ text: text.slice(last, i) })
    const s = m[0]
    const cp = s.codePointAt(0) ?? 0
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      const decoded = decodeTags(s)
      parts.push({ invisible: `⟦TAG ×${[...s].length}: "${visibleEscape(decoded)}"⟧`, title: 'Unicode TAG characters (invisible ASCII smuggling)' })
    } else if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) {
      parts.push({ invisible: `⟦VS ×${[...s].length}: "${bytesPreview(decodeVariationSelectors(s), 60)}"⟧`, title: 'Variation selectors carrying hidden bytes' })
    } else {
      parts.push({ invisible: `⟦${codePointLabel(s)}⟧`, title: charName(s) })
    }
    last = i + s.length
  }
  if (last < text.length) parts.push({ text: text.slice(last) })
  return parts
}

export function hasInvisible(text: string): boolean {
  INVISIBLE_RE.lastIndex = 0
  const r = INVISIBLE_RE.test(text)
  INVISIBLE_RE.lastIndex = 0
  return r
}
