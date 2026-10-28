import { describe, expect, it } from 'vitest'
import { bytesToHex, hex, runOp, runOpBytes, runOpHex } from '../testUtil'
import { ascii85Decode, ascii85Encode, base58Decode, base58Encode, htmlDecode, htmlEncode, LATIN1_ENTITY_NAMES, NAMED_ENTITIES } from './codecs'

// RFC 4648 §10 test vectors
const RFC4648 = ['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar']
const B64 = ['', 'Zg==', 'Zm8=', 'Zm9v', 'Zm9vYg==', 'Zm9vYmE=', 'Zm9vYmFy']
const B32 = ['', 'MY======', 'MZXQ====', 'MZXW6===', 'MZXW6YQ=', 'MZXW6YTB', 'MZXW6YTBOI======']
const B32HEX = ['', 'CO======', 'CPNG====', 'CPNMU===', 'CPNMUOG=', 'CPNMUOJ1', 'CPNMUOJ1E8======']
const B16 = ['', '66', '666f', '666f6f', '666f6f62', '666f6f6261', '666f6f626172']

describe('Base64 (RFC 4648 §10)', () => {
  RFC4648.forEach((plain, i) => {
    it(`encodes "${plain}"`, async () => {
      expect(await runOp('to-base64', plain)).toBe(B64[i])
      expect(await runOp('from-base64', B64[i])).toBe(plain)
    })
  })
  it('URL-safe alphabet without padding', async () => {
    expect(await runOp('to-base64', hex('fbff'), { alphabet: 'url', padding: false })).toBe('-_8')
    expect(await runOpHex('from-base64', '-_8')).toBe('fbff')
    expect(await runOp('to-base64', hex('fbff'))).toBe('+/8=')
  })
  it('rejects invalid characters with a position', async () => {
    await expect(runOp('from-base64', 'Zm9v!')).rejects.toThrow(/position 4/)
    await expect(runOp('from-base64', 'Zm9v-_', { alphabet: 'standard' })).rejects.toThrow(/Invalid Base64 character/)
    await expect(runOp('from-base64', 'Z')).rejects.toThrow(/impossible length/)
  })
  it('ignores whitespace and missing padding', async () => {
    expect(await runOp('from-base64', 'Zm9v\nYmE')).toBe('fooba')
  })
})

describe('Base32 (RFC 4648 §10)', () => {
  RFC4648.forEach((plain, i) => {
    it(`encodes "${plain}"`, async () => {
      expect(await runOp('to-base32', plain)).toBe(B32[i])
      expect(await runOp('from-base32', B32[i])).toBe(plain)
      expect(await runOp('to-base32', plain, { alphabet: 'hex' })).toBe(B32HEX[i])
      expect(await runOp('from-base32', B32HEX[i], { alphabet: 'hex' })).toBe(plain)
    })
  })
  it('is case-insensitive and rejects bad chars', async () => {
    expect(await runOp('from-base32', 'mzxw6ytboi')).toBe('foobar')
    await expect(runOp('from-base32', 'MZXW1')).rejects.toThrow(/Invalid Base32 character '1'/)
  })
})

describe('Base16 (RFC 4648 §10)', () => {
  RFC4648.forEach((plain, i) => {
    it(`encodes "${plain}"`, async () => {
      expect(await runOp('to-hex', plain, { delimiter: 'none' })).toBe(B16[i])
      expect(await runOp('from-hex', B16[i].toUpperCase())).toBe(plain)
    })
  })
  it('handles delimiters and prefixes', async () => {
    expect(await runOp('to-hex', 'AB', { delimiter: '0x' })).toBe('0x41, 0x42')
    expect(await runOp('to-hex', 'AB', { delimiter: '\\x', case: 'upper' })).toBe('\\x41\\x42')
    expect(await runOp('to-hex', 'ABCD', { perLine: 2 })).toBe('41 42\n43 44')
    expect(await runOp('from-hex', '0x41, 0x42 \\x43:44-45')).toBe('ABCDE')
    await expect(runOp('from-hex', '414')).rejects.toThrow(/odd/)
    await expect(runOp('from-hex', '41zz')).rejects.toThrow(/Invalid hex character 'z'/)
  })
})

describe('Base58 (Bitcoin alphabet)', () => {
  it('known vectors', () => {
    const enc = (s: string) => base58Encode(new TextEncoder().encode(s))
    expect(enc('Hello World!')).toBe('2NEpo7TZRRrLZSi2U')
    expect(enc('The quick brown fox jumps over the lazy dog.')).toBe('USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z')
    expect(base58Encode(hex('0000287fb4cd'))).toBe('11233QC4')
    expect(bytesToHex(base58Decode('11233QC4'))).toBe('0000287fb4cd')
    expect(base58Encode(new Uint8Array(0))).toBe('')
  })
  it('rejects ambiguous characters', () => {
    expect(() => base58Decode('0OIl')).toThrow(/Invalid Base58 character '0'/)
  })
  it('refuses huge inputs via maxInputBytes', async () => {
    const { getOp } = await import('./index')
    expect(getOp('to-base58')?.maxInputBytes).toBe(65536)
  })
})

describe('Ascii85', () => {
  it('known vectors (Wikipedia)', () => {
    const enc = (s: string) => ascii85Encode(new TextEncoder().encode(s))
    expect(enc('Man ')).toBe('9jqo^')
    expect(enc('sure.')).toBe('F*2M7/c')
    expect(enc('Man is distinguished')).toBe('9jqo^BlbD-BleB1DJ+*+F(f,q')
    expect(ascii85Encode(new Uint8Array(4))).toBe('z')
    expect(ascii85Encode(new Uint8Array(3))).toBe('!!!!')
    expect(ascii85Encode(new TextEncoder().encode('hi'), true)).toBe('<~BP@~>')
  })
  it('round-trips arbitrary bytes', () => {
    const data = Uint8Array.from({ length: 257 }, (_, i) => (i * 37) & 255)
    expect(bytesToHex(ascii85Decode(ascii85Encode(data, true)))).toBe(bytesToHex(data))
  })
  it('rejects invalid input', () => {
    expect(() => ascii85Decode('9jqo^v')).toThrow(/Invalid Ascii85 character 'v'/)
    expect(() => ascii85Decode('9jqo^B')).toThrow(/single character/)
    expect(() => ascii85Decode('s8W-"')).toThrow(/exceeds 32 bits/)
  })
})

describe('binary / decimal / octal / charcode', () => {
  it('round-trips', async () => {
    expect(await runOp('to-binary', 'Hi')).toBe('01001000 01101001')
    expect(await runOp('from-binary', '01001000 01101001')).toBe('Hi')
    expect(await runOp('from-binary', '0100100001101001')).toBe('Hi')
    expect(await runOp('to-decimal', 'Hi', { delimiter: 'comma' })).toBe('72,105')
    expect(await runOp('from-decimal', '72, 105')).toBe('Hi')
    expect(await runOp('to-octal', 'Hi')).toBe('110 151')
    expect(await runOp('from-octal', '110 151')).toBe('Hi')
    expect(await runOp('to-charcode', 'é😀')).toBe('233 128512')
    expect(await runOp('to-charcode', 'é', { base: '16' })).toBe('e9')
    expect(await runOp('from-charcode', '233 128512')).toBe('é😀')
    expect(await runOp('from-charcode', '0x1F600 e9', { base: '16' })).toBe('😀é')
  })
  it('rejects out-of-range values', async () => {
    await expect(runOp('from-decimal', '256')).rejects.toThrow(/0–255/)
    await expect(runOp('from-binary', '0101')).rejects.toThrow(/multiple of 8/)
    await expect(runOp('from-charcode', '1114112')).rejects.toThrow(/Invalid code point/)
  })
})

describe('URL encoding', () => {
  it('component mode matches encodeURIComponent', async () => {
    const s = "a b&c=d/é?!*'()~ü😀"
    expect(await runOp('url-encode', s)).toBe(encodeURIComponent(s))
    expect(await runOp('url-encode', s, { mode: 'uri' })).toBe(encodeURI(s))
    expect(await runOp('url-encode', 'ab', { mode: 'all' })).toBe('%61%62')
  })
  it('decodes at byte level and keeps malformed sequences', async () => {
    expect(await runOpHex('url-decode', '%ff%41')).toBe('ff41')
    expect(await runOp('url-decode', 'a+b%2')).toBe('a b%2')
    expect(await runOp('url-decode', 'a+b', { plus: false })).toBe('a+b')
    expect(await runOp('url-decode', '%zz%')).toBe('%zz%')
  })
})

describe('HTML entities', () => {
  it('has the full HTML 4 Latin-1 table', () => {
    expect(LATIN1_ENTITY_NAMES).toHaveLength(96)
    expect(NAMED_ENTITIES.get('eacute')).toBe(0xe9)
    expect(NAMED_ENTITIES.get('yuml')).toBe(0xff)
    expect(NAMED_ENTITIES.get('Omega')).toBe(0x3a9)
    expect(NAMED_ENTITIES.get('sigmaf')).toBe(0x3c2)
    expect(NAMED_ENTITIES.has('-')).toBe(false)
  })
  it('encodes', () => {
    expect(htmlEncode(`<a href="x">'&'</a>`, 'minimal')).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;')
    expect(htmlEncode('café €', 'named')).toBe('caf&eacute; &euro;')
    expect(htmlEncode('café', 'decimal')).toBe('caf&#233;')
    expect(htmlEncode('café😀', 'hex')).toBe('caf&#xE9;&#x1F600;')
    expect(htmlEncode('ab', 'decimal', true)).toBe('&#97;&#98;')
  })
  it('decodes named, numeric and invalid references per the HTML spec', () => {
    expect(htmlDecode('&lt;b&gt; &amp;amp; &eacute;&#233;&#xE9;&#x1F600;')).toBe('<b> &amp; ééé😀')
    expect(htmlDecode('&#128;&#0;&#xD800;&#1114112;')).toBe('€���')
    expect(htmlDecode('&unknownentity; &amp')).toBe('&unknownentity; &amp')
  })
})

describe('Unicode escapes', () => {
  it('escapes and unescapes, including surrogate pairs', async () => {
    expect(await runOp('unicode-escape', 'aé😀')).toBe('a\\u00E9\\uD83D\\uDE00')
    expect(await runOp('unicode-escape', 'aé😀', { style: 'ubrace' })).toBe('a\\u{E9}\\u{1F600}')
    expect(await runOp('unicode-escape', 'é', { style: 'uplus' })).toBe('U+00E9')
    expect(await runOp('unicode-escape', 'a', { all: true })).toBe('\\u0061')
    expect(await runOp('unicode-unescape', 'a\\u00E9\\uD83D\\uDE00 \\u{1F600} \\x41 U+00E9')).toBe('aé😀 😀 A é')
  })
})

describe('Quoted-printable (RFC 2045)', () => {
  it('encodes special bytes, trailing whitespace and long lines', async () => {
    expect(await runOp('to-quoted-printable', 'a=b é')).toBe('a=3Db =C3=A9')
    expect(await runOp('to-quoted-printable', 'end \nx')).toBe('end=20\nx')
    const long = 'x'.repeat(100)
    const enc = await runOp('to-quoted-printable', long)
    expect(enc.split('\n').every((l) => l.length <= 76)).toBe(true)
    expect(await runOp('from-quoted-printable', enc)).toBe(long)
  })
  it('decodes soft breaks and keeps CRLF', async () => {
    expect(await runOp('from-quoted-printable', 'caf=C3=A9 =\r\nlatte\r\nnext')).toBe('café latte\r\nnext')
    expect(await runOp('from-quoted-printable', 'trailing   \nx=3d')).toBe('trailing\nx=')
    expect(await runOp('from-quoted-printable', 'bad =ZZ')).toBe('bad =ZZ')
  })
  it('round-trips binary', async () => {
    const data = Uint8Array.from({ length: 300 }, (_, i) => i & 255)
    const enc = await runOpBytes('to-quoted-printable', data)
    expect(bytesToHex(await runOpBytes('from-quoted-printable', enc))).toBe(bytesToHex(data))
  })
})

describe('text encodings', () => {
  it('UTF-16LE/BE and Latin-1', async () => {
    expect(await runOpHex('encode-text', 'Aé😀')).toBe('4100e9003dd800de')
    expect(await runOpHex('encode-text', 'A', { encoding: 'utf-16be', bom: true })).toBe('feff0041')
    expect(await runOp('decode-text', hex('4100e9003dd800de'))).toBe('Aé😀')
    expect(await runOp('decode-text', hex('feff0041'), { encoding: 'utf-16be' })).toBe('A')
    expect(await runOpHex('encode-text', 'é', { encoding: 'iso-8859-1' })).toBe('e9')
    await expect(runOp('encode-text', '€', { encoding: 'iso-8859-1' })).rejects.toThrow(/cannot be represented/)
    expect(await runOpHex('encode-text', '€', { encoding: 'iso-8859-1', replace: true })).toBe('3f')
    expect(await runOp('decode-text', hex('80e9'), { encoding: 'iso-8859-1' })).toBe('\u0080é')
    expect(await runOp('decode-text', hex('80e9'), { encoding: 'windows-1252' })).toBe('€é')
  })
})
