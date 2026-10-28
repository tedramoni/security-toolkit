import { describe, expect, it } from 'vitest'
import { runOp } from '../testUtil'
import { domainToAscii, domainToUnicode, punycodeDecode, punycodeEncode } from './punycode'

// RFC 3492 §7.1 sample strings
const SAMPLES: [string, string, string][] = [
  ['(A) Arabic (Egyptian)', 'ليهمابتكلموشعربي؟', 'egbpdaj6bu4bxfgehfvwxn'],
  ['(B) Chinese (simplified)', '他们为什么不说中文', 'ihqwcrb4cv8a8dqg056pqjye'],
  ['(J) Spanish', 'PorquénopuedensimplementehablarenEspañol', 'PorqunopuedensimplementehablarenEspaol-fmd56a'],
  ['(L) 3<nen>B<gumi><kinpachi><sensei>', '3年B組金八先生', '3B-ww4c5e180e575a65lsy2b'],
  ['(M) <amuro><namie>-with-SUPER-MONKEYS', '安室奈美恵-with-SUPER-MONKEYS', '-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n'],
  ['(R) <sono><supiido><de>', 'そのスピードで', 'd9juau41awczczp'],
]

describe('Punycode (RFC 3492 §7.1 samples)', () => {
  for (const [name, unicode, puny] of SAMPLES) {
    it(name, () => {
      expect(punycodeEncode(unicode)).toBe(puny)
      expect(punycodeDecode(puny)).toBe(unicode)
    })
  }
  it('common IDN examples', () => {
    expect(punycodeEncode('bücher')).toBe('bcher-kva')
    expect(punycodeEncode('münchen')).toBe('mnchen-3ya')
    expect(punycodeEncode('abc')).toBe('abc-')
    expect(punycodeDecode('abc-')).toBe('abc')
  })
  it('rejects invalid input', () => {
    expect(() => punycodeDecode('ab!c')).toThrow(/Invalid Punycode digit/)
    expect(() => punycodeDecode('99999999999')).toThrow()
  })
})

describe('domain mode', () => {
  it('converts only non-ASCII labels and lowercases', () => {
    expect(domainToAscii('Bücher.Example')).toBe('xn--bcher-kva.example')
    expect(domainToAscii('münchen。de')).toBe('xn--mnchen-3ya.de')
    expect(domainToUnicode('xn--bcher-kva.example')).toBe('bücher.example')
    expect(domainToUnicode('XN--MNCHEN-3YA.de')).toBe('münchen.de')
  })
  it('works through the ops, line by line', async () => {
    expect(await runOp('to-punycode', 'bücher.de\nexample.com')).toBe('xn--bcher-kva.de\nexample.com')
    expect(await runOp('from-punycode', 'xn--bcher-kva.de')).toBe('bücher.de')
    expect(await runOp('to-punycode', 'bücher', { domain: false })).toBe('bcher-kva')
  })
})
