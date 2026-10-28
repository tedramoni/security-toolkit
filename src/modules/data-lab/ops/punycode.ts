/*
 * Punycode (RFC 3492) — own implementation of the reference algorithm in §6.
 * Domain mode splits on label separators and applies the "xn--" ACE prefix (RFC 5891). It lowercases and
 * NFC-normalises labels but does NOT apply the full UTS #46 / IDNA2008 mapping and validity rules.
 */
import { OpError } from '../engine/types'

const BASE = 36
const TMIN = 1
const TMAX = 26
const SKEW = 38
const DAMP = 700
const INITIAL_BIAS = 72
const INITIAL_N = 128
const MAX_INT = 0x7fffffff

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1
  delta += Math.floor(delta / numPoints)
  let k = 0
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN))
    k += BASE
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW))
}

function digitToChar(d: number): string {
  // 0..25 -> a..z, 26..35 -> 0..9
  return String.fromCharCode(d < 26 ? d + 97 : d + 22)
}

function charToDigit(c: number): number {
  if (c >= 48 && c <= 57) return c - 22
  if (c >= 65 && c <= 90) return c - 65
  if (c >= 97 && c <= 122) return c - 97
  return BASE
}

/** Encode a Unicode string to Punycode (no ACE prefix). Basic code points keep their case. */
export function punycodeEncode(input: string): string {
  const cps = Array.from(input, (c) => c.codePointAt(0) as number)
  let output = ''
  for (const cp of cps) if (cp < 0x80) output += String.fromCharCode(cp)
  const b = output.length
  let h = b
  if (b > 0) output += '-'
  let n = INITIAL_N
  let delta = 0
  let bias = INITIAL_BIAS
  while (h < cps.length) {
    let m = MAX_INT
    for (const cp of cps) if (cp >= n && cp < m) m = cp
    if (m - n > Math.floor((MAX_INT - delta) / (h + 1))) throw new OpError('Punycode overflow')
    delta += (m - n) * (h + 1)
    n = m
    for (const cp of cps) {
      if (cp < n) {
        delta++
        if (delta > MAX_INT) throw new OpError('Punycode overflow')
      }
      if (cp === n) {
        let q = delta
        for (let k = BASE; ; k += BASE) {
          const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias
          if (q < t) break
          output += digitToChar(t + ((q - t) % (BASE - t)))
          q = Math.floor((q - t) / (BASE - t))
        }
        output += digitToChar(q)
        bias = adapt(delta, h + 1, h === b)
        delta = 0
        h++
      }
    }
    delta++
    n++
  }
  return output
}

/** Decode Punycode (no ACE prefix) to a Unicode string. */
export function punycodeDecode(input: string): string {
  const out: number[] = []
  const basicEnd = input.lastIndexOf('-')
  for (let j = 0; j < Math.max(0, basicEnd); j++) {
    const c = input.charCodeAt(j)
    if (c >= 0x80) throw new OpError(`Invalid Punycode: non-basic character at position ${j}`)
    out.push(c)
  }
  let n = INITIAL_N
  let i = 0
  let bias = INITIAL_BIAS
  for (let idx = basicEnd > 0 ? basicEnd + 1 : 0; idx < input.length; ) {
    const oldi = i
    let w = 1
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new OpError('Invalid Punycode: truncated input')
      const digit = charToDigit(input.charCodeAt(idx++))
      if (digit >= BASE) throw new OpError(`Invalid Punycode digit '${input[idx - 1]}'`)
      if (digit > Math.floor((MAX_INT - i) / w)) throw new OpError('Punycode overflow')
      i += digit * w
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias
      if (digit < t) break
      if (w > Math.floor(MAX_INT / (BASE - t))) throw new OpError('Punycode overflow')
      w *= BASE - t
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0)
    if (Math.floor(i / (out.length + 1)) > MAX_INT - n) throw new OpError('Punycode overflow')
    n += Math.floor(i / (out.length + 1))
    i %= out.length + 1
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) throw new OpError('Invalid Punycode: decodes to an invalid code point')
    out.splice(i, 0, n)
    i++
  }
  return String.fromCodePoint(...out)
}

function isAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0x7f) return false
  return true
}

const LABEL_SEPARATORS =/[.。．｡]/

/** Convert a domain name to its ASCII (xn--) form, label by label. */
export function domainToAscii(domain: string): string {
  return domain
    .split(LABEL_SEPARATORS)
    .map((label) => {
      const l = label.normalize('NFC').toLowerCase()
      return isAscii(l) ? l : 'xn--' + punycodeEncode(l)
    })
    .join('.')
}

/** Convert xn-- labels of a domain name back to Unicode. */
export function domainToUnicode(domain: string): string {
  return domain
    .split('.')
    .map((label) => (/^xn--/i.test(label) ? punycodeDecode(label.slice(4).toLowerCase()) : label))
    .join('.')
}
