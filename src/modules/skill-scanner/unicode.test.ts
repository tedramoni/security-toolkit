import { describe, expect, it } from 'vitest'
import {
  bytesPreview,
  decodeTags,
  decodeVariationSelectors,
  encodeTags,
  encodeVariationSelectors,
  findMixedScriptWords,
  hasInvisible,
  skeleton,
  toVisibleParts,
} from './unicode'

describe('TAG characters', () => {
  it('round-trips ASCII and maps to U+E0000 + code', () => {
    const t = encodeTags('Hi!')
    expect([...t].map((c) => c.codePointAt(0))).toEqual([0xe0048, 0xe0069, 0xe0021])
    expect(decodeTags(t)).toBe('Hi!')
  })
  it('drops the language tag and cancel tag', () => {
    expect(decodeTags(String.fromCodePoint(0xe0001) + encodeTags('x') + String.fromCodePoint(0xe007f))).toBe('x')
  })
})

describe('variation selectors', () => {
  it('round-trips bytes (VS1–16 → 0–15, VS17–256 → 16–255)', () => {
    const bytes = new Uint8Array([0, 15, 16, 255, 104, 105])
    const s = encodeVariationSelectors(bytes)
    expect(s.codePointAt(0)).toBe(0xfe00)
    expect([...s][2].codePointAt(0)).toBe(0xe0100)
    expect([...s][3].codePointAt(0)).toBe(0xe01ef)
    expect(decodeVariationSelectors(s)).toEqual(bytes)
  })
  it('previews decoded bytes safely', () => {
    expect(bytesPreview(new TextEncoder().encode('a\nb\u0001'))).toBe('a⏎b\\x01')
  })
})

describe('homoglyphs', () => {
  it('finds mixed-script words and their skeleton', () => {
    const w = findMixedScriptWords('login at pаypal.com today')
    expect(w).toHaveLength(1)
    expect(w[0].word).toBe('pаypal')
    expect(w[0].skeleton).toBe('paypal')
    expect(skeleton('сор')).toBe('cop')
  })
  it('ignores single-script words', () => {
    expect(findMixedScriptWords('Привет мир hello world αβγ')).toEqual([])
  })
})

describe('toVisibleParts', () => {
  it('labels invisible characters and decodes smuggled runs', () => {
    const parts = toVisibleParts('a\u200Bb' + encodeTags('hid') + '\u202E')
    expect(parts).toEqual([
      { text: 'a' },
      { invisible: '⟦U+200B⟧', title: 'ZERO WIDTH SPACE' },
      { text: 'b' },
      { invisible: '⟦TAG ×3: "hid"⟧', title: expect.stringMatching(/TAG/) },
      { invisible: '⟦U+202E⟧', title: 'RIGHT-TO-LEFT OVERRIDE' },
    ])
  })
  it('leaves normal text untouched', () => {
    expect(toVisibleParts('plain <b>text</b>')).toEqual([{ text: 'plain <b>text</b>' }])
    expect(hasInvisible('plain')).toBe(false)
    expect(hasInvisible('x\uFEFF')).toBe(true)
  })
})
