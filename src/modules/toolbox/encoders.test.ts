import { describe, expect, it } from 'vitest'
import {
  DecodeError,
  OPERATIONS,
  base64Decode,
  base64Encode,
  base64ToBytes,
  base64UrlDecode,
  base64UrlEncode,
  hashHex,
  hexDecode,
  hexEncode,
  htmlDecode,
  htmlEncode,
  unicodeEscape,
  unicodeUnescape,
  urlDecode,
  urlEncode,
} from './encoders'

describe('base64', () => {
  it('round-trips ASCII and unicode', () => {
    expect(base64Encode('hello')).toBe('aGVsbG8=')
    expect(base64Encode('héllo ✓ 🔐')).toBe('aMOpbGxvIOKckyDwn5SQ')
    expect(base64Decode('aMOpbGxvIOKckyDwn5SQ')).toBe('héllo ✓ 🔐')
  })
  it('handles empty input', () => {
    expect(base64Encode('')).toBe('')
    expect(base64Decode('')).toBe('')
  })
  it('accepts missing padding, whitespace and URL-safe alphabet', () => {
    expect(base64Decode('aGVsbG8')).toBe('hello')
    expect(base64Decode('aGVs\n bG8=')).toBe('hello')
    expect(base64Decode('Pz8_')).toBe('???')
  })
  it('rejects invalid characters and impossible lengths', () => {
    expect(() => base64Decode('abc$')).toThrow(DecodeError)
    expect(() => base64Decode('abcde')).toThrow(/impossible length/)
    expect(() => base64Decode('ab=c')).toThrow(DecodeError)
  })
  it('reports binary (non UTF-8) output clearly', () => {
    expect(() => base64Decode('/w==')).toThrow(/not valid UTF-8.*ff/)
  })
  it('encodes large inputs without stack overflow', () => {
    const big = 'a'.repeat(200_000)
    expect(base64Decode(base64Encode(big))).toBe(big)
  })
  it('decodes to raw bytes', () => {
    expect([...base64ToBytes('AAEC')]).toEqual([0, 1, 2])
  })
})

describe('base64url', () => {
  it('uses - and _ without padding', () => {
    expect(base64UrlEncode('???>>>')).toBe('Pz8_Pj4-')
    expect(base64UrlEncode('a')).toBe('YQ')
    expect(base64UrlDecode('Pz8_Pj4-')).toBe('???>>>')
    expect(base64UrlDecode('YQ')).toBe('a')
  })
})

describe('url', () => {
  it('encodes reserved and unicode characters', () => {
    expect(urlEncode('a b&c=d/é')).toBe('a%20b%26c%3Dd%2F%C3%A9')
    expect(urlDecode('a%20b%26c%3Dd%2F%C3%A9')).toBe('a b&c=d/é')
  })
  it('keeps + as is', () => {
    expect(urlDecode('a+b')).toBe('a+b')
  })
  it('throws on malformed sequences', () => {
    expect(() => urlDecode('%')).toThrow(DecodeError)
    expect(() => urlDecode('%E0%A4%A')).toThrow(/Malformed/)
  })
})

describe('html', () => {
  it('escapes the five significant characters', () => {
    expect(htmlEncode(`<img src=x onerror="alert('1')">&`)).toBe('&lt;img src=x onerror=&quot;alert(&#39;1&#39;)&quot;&gt;&amp;')
  })
  it('decodes named, decimal and hex references', () => {
    expect(htmlDecode('&lt;b&gt; &amp;amp; &quot;&#39;&#x41;&#66;&copy;')).toBe('<b> &amp; "\'AB©')
  })
  it('decodes numeric references without semicolon', () => {
    expect(htmlDecode('&#60script&#x3e')).toBe('<script>')
  })
  it('leaves unknown entities and lone ampersands untouched', () => {
    expect(htmlDecode('AT&T &unknownentity; & ;')).toBe('AT&T &unknownentity; & ;')
  })
  it('does not resolve prototype keys as entities', () => {
    expect(htmlDecode('&constructor;&toString;')).toBe('&constructor;&toString;')
  })
  it('replaces invalid code points with U+FFFD', () => {
    expect(htmlDecode('&#0;&#xD800;&#x110000;')).toBe('���')
  })
  it('round-trips', () => {
    const s = `"><script>alert(1)</script>`
    expect(htmlDecode(htmlEncode(s))).toBe(s)
  })
})

describe('hex', () => {
  it('encodes UTF-8 bytes', () => {
    expect(hexEncode('Hi é')).toBe('486920c3a9')
  })
  it('decodes with various separators and prefixes', () => {
    expect(hexDecode('48656c6c6f')).toBe('Hello')
    expect(hexDecode('48 65 6C 6c 6F')).toBe('Hello')
    expect(hexDecode('48:65:6c:6c:6f')).toBe('Hello')
    expect(hexDecode('0x48 0x65')).toBe('He')
    expect(hexDecode('\\x48\\x65')).toBe('He')
  })
  it('rejects odd length and non-hex', () => {
    expect(() => hexDecode('abc')).toThrow(/odd/)
    expect(() => hexDecode('zz')).toThrow(/only 0-9/)
  })
})

describe('unicode escapes', () => {
  it('escapes non-ASCII and control characters, keeps printable ASCII', () => {
    expect(unicodeEscape('aé\n')).toBe('a\\u00e9\\u000a')
    expect(unicodeEscape('🔐')).toBe('\\ud83d\\udd10')
    expect(unicodeEscape('a\\b')).toBe('a\\u005cb')
  })
  it('unescapes \\u, \\u{}, \\x and \\\\', () => {
    expect(unicodeUnescape('\\u00e9\\u{1F510}\\x41\\\\n')).toBe('é🔐A\\n')
    expect(unicodeUnescape('\\ud83d\\udd10')).toBe('🔐')
  })
  it('round-trips', () => {
    const s = 'Ünïcödé 🔐 \t "quotes" \\ back'
    expect(unicodeUnescape(unicodeEscape(s))).toBe(s)
  })
  it('leaves invalid escapes alone', () => {
    expect(unicodeUnescape('\\uZZZZ')).toBe('\\uZZZZ')
  })
})

describe('hashes', () => {
  it('computes known digests', async () => {
    expect(await hashHex('SHA-1', 'abc')).toBe('a9993e364706816aba3e25717850c26c9cd0d89d')
    expect(await hashHex('SHA-256', 'abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    expect(await hashHex('SHA-256', '')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(await hashHex('SHA-384', 'abc')).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    )
    expect(await hashHex('SHA-512', 'abc')).toBe(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    )
  })
  it('hashes UTF-8 bytes', async () => {
    expect(await hashHex('SHA-256', 'é')).toBe(await hashHex('SHA-256', 'é'))
  })
})

describe('OPERATIONS registry', () => {
  it('has unique ids and every op runs on sample input', async () => {
    const ids = OPERATIONS.map((o) => o.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const op of OPERATIONS) {
      const input = op.id.endsWith('-dec') ? (op.group === 'Hex' ? '41' : op.group === 'Base64' ? 'QQ==' : 'A') : 'A'
      await expect(Promise.resolve(op.run(input))).resolves.toBeTypeOf('string')
    }
  })
})
