import { describe, expect, it } from 'vitest'
import { bytesToHex, runOp, runOpBytes } from '../testUtil'
import { fromHexdump, generateUuid, guessUnit, hexdump, isoToUnix, parseBigInt, parseUuid, unixToIso } from './formats'
import { cidrInfo, formatIPv6, parseIPv6 } from './ip'
import { csvField, formatJson, jsonToCsv, parseCsv, validateJson } from './json'

describe('JSON', () => {
  it('beautify preserves big numbers, key order and duplicates', () => {
    const src = '{"b":12345678901234567890,"a":[1,{"x":"a,b:{}"}],"b":2,"e":{},"f":[ ]}'
    expect(formatJson(src, '  ')).toBe(
      '{\n  "b": 12345678901234567890,\n  "a": [\n    1,\n    {\n      "x": "a,b:{}"\n    }\n  ],\n  "b": 2,\n  "e": {},\n  "f": []\n}',
    )
    expect(formatJson(formatJson(src, '\t'), '')).toBe(src.replace('[ ]', '[]'))
  })
  it('handles escaped quotes inside strings', () => {
    expect(formatJson('{ "a" : "x\\"y\\\\" }', '')).toBe('{"a":"x\\"y\\\\"}')
  })
  it('reports error positions with a caret', async () => {
    const err = validateJson('{\n  "a": 1,\n  "b": }')
    expect(err?.line).toBe(3)
    await expect(runOp('json-beautify', '{\n  "a": 1,\n  "b": }')).rejects.toThrow(/Line 3, column \d+:[\s\S]*\^/)
    expect(await runOp('json-validate', '[1,2]')).toBe('Valid JSON: array with 2 item(s).')
  })
  it('JSON → CSV with quoting and formula guard', () => {
    const csv = jsonToCsv('[{"name":"a,b","n":1},{"name":"=cmd()","extra":{"k":true}}]', ',', true)
    expect(csv).toBe('name,n,extra\r\n"a,b",1,\r\n\'=cmd(),,"{""k"":true}"')
    expect(jsonToCsv('[[1,"x\\"y"],[2,null]]', ';', false)).toBe('1;"x""y"\r\n2;')
    expect(csvField('-1', ',', true)).toBe("'-1")
    expect(() => jsonToCsv('[1,2]', ',', false)).toThrow(/array of objects/)
  })
  it('CSV → JSON (RFC 4180) and auto delimiter', async () => {
    expect(parseCsv('a,"b ""q""",c\r\n1,"multi\nline",3\n', ',')).toEqual([
      ['a', 'b "q"', 'c'],
      ['1', 'multi\nline', '3'],
    ])
    expect(JSON.parse(await runOp('csv-to-json', 'x;y\n1;2'))).toEqual([{ x: '1', y: '2' }])
    expect(() => parseCsv('"open', ',')).toThrow(/Unterminated/)
    const proto = JSON.parse(await runOp('csv-to-json', '__proto__,b\n1,2'))
    expect(Object.keys(proto[0])).toEqual(['__proto__', 'b'])
    expect(({} as Record<string, unknown>).b).toBeUndefined()
  })
})

describe('JWT, URL and query parsing', () => {
  it('decodes a JWT without verifying', async () => {
    const tok =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    const out = JSON.parse(await runOp('jwt-decode', tok))
    expect(out.header.alg).toBe('HS256')
    expect(out.payload.name).toBe('John Doe')
    expect(out.signature).toEqual({ present: true, bytes: 32, verified: false })
    await expect(runOp('jwt-decode', 'a.b')).rejects.toThrow(/3 dot-separated parts/)
  })
  it('parses URLs, flags credentials and shows IDN hosts', async () => {
    const out = await runOp('parse-url', 'https://user:pw@xn--bcher-kva.example:8443/p/a?q=1&q=2&x=%20y#frag')
    expect(out).toMatch(/Password:\s+pw .*credentials/)
    expect(out).toMatch(/Unicode: bücher\.example/)
    expect(out).toMatch(/Port:\s+8443/)
    expect(out).toContain('  q = 1\n  q = 2\n  x =  y')
    await expect(runOp('parse-url', 'example.com/x')).rejects.toThrow(/absolute URL/)
  })
  it('parses query strings', async () => {
    expect(await runOp('parse-query', 'https://x/?a=1&b=hello+world&c=%26#h')).toBe('a = 1\nb = hello world\nc = &')
  })
})

describe('timestamps', () => {
  it('guesses units by magnitude', () => {
    expect(guessUnit(1700000000)).toBe('s')
    expect(guessUnit(1700000000000)).toBe('ms')
    expect(guessUnit(1700000000000000)).toBe('us')
    expect(guessUnit(1700000000000000000)).toBe('ns')
  })
  it('Unix → ISO', () => {
    expect(unixToIso('0', 'auto')).toBe('0\t1970-01-01T00:00:00.000Z\t(seconds)')
    expect(unixToIso('1700000000123', 'auto')).toContain('2023-11-14T22:13:20.123Z')
    expect(unixToIso('1700000000.5', 's')).toContain('2023-11-14T22:13:20.500Z')
    expect(unixToIso('abc', 'auto')).toContain('not a number')
    expect(unixToIso('99999999999999999999', 's')).toContain('out of range')
  })
  it('ISO → Unix (UTC assumed when no offset)', () => {
    expect(isoToUnix('2023-11-14T22:13:20Z', 's', true)).toBe('1700000000')
    expect(isoToUnix('2023-11-14T22:13:20', 's', true)).toBe('1700000000')
    expect(isoToUnix('2023-11-14 22:13:20', 'ms', true)).toBe('1700000000000')
    expect(isoToUnix('2023-11-15T00:13:20+02:00', 's', true)).toBe('1700000000')
    expect(isoToUnix('nope', 's', true)).toContain('unparseable')
  })
})

describe('hexdump', () => {
  const data = new TextEncoder().encode('Hello, World!\n\u0000ÿ more bytes here')
  it('classic layout', () => {
    const d = hexdump(new TextEncoder().encode('ABCDEFGHIJKLMNOPQ'), 16)
    const lines = d.split('\n')
    // hexdump -C layout: two spaces after the offset, an extra space after 8 bytes, two spaces before the ASCII column
    expect(lines[0]).toBe('00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|')
    expect(lines[1].startsWith('00000010  51 ')).toBe(true)
    expect(lines[1].indexOf('|')).toBe(lines[0].indexOf('|'))
    expect(lines[2]).toBe('00000011')
  })
  it('round-trips through From Hexdump', async () => {
    const dump = await runOpBytes('to-hexdump', data)
    expect(bytesToHex(await runOpBytes('from-hexdump', dump))).toBe(bytesToHex(data))
  })
  it('parses xxd output', () => {
    const xxd = '00000000: 4865 6c6c 6f2c 2057 6f72 6c64 210a       Hello, World!.\n'
    expect(new TextDecoder().decode(fromHexdump(xxd))).toBe('Hello, World!\n')
  })
})

describe('character info, entropy, frequency', () => {
  it('flags bidi controls and invisible chars', async () => {
    const out = await runOp('char-info', 'a‮b​', { onlySuspicious: true })
    expect(out).toMatch(/U\+202E.*BIDI CONTROL/)
    expect(out).toMatch(/U\+200B.*invisible/)
    expect(out).not.toMatch(/U\+0061/)
    expect(await runOp('char-info', 'é')).toContain('UTF-8: c3 a9')
  })
  it('entropy', async () => {
    expect(await runOp('entropy', 'aaaa')).toMatch(/0\.0000 bits\/byte/)
    const all = Uint8Array.from({ length: 256 }, (_, i) => i)
    expect(await runOp('entropy', all)).toMatch(/8\.0000 bits\/byte/)
  })
  it('frequency distribution', async () => {
    const out = await runOp('frequency', 'aab')
    expect(out.split('\n')[0]).toBe('Total bytes: 3   Distinct values: 2/256')
    expect(out).toMatch(/0x61 {2}a {10}2 {3}66\.67%/)
  })
})

describe('IP / CIDR', () => {
  it('IPv4 /24, /31, /32 and host bits', () => {
    const out = cidrInfo('192.168.1.77/24')
    expect(out).toMatch(/Network:\s+192\.168\.1\.0/)
    expect(out).toMatch(/Broadcast:\s+192\.168\.1\.255/)
    expect(out).toMatch(/Netmask:\s+255\.255\.255\.0/)
    expect(out).toMatch(/Host range:\s+192\.168\.1\.1 – 192\.168\.1\.254/)
    expect(out).toMatch(/Usable hosts:\s+254/)
    expect(out).toMatch(/Private \(RFC 1918\)/)
    expect(out).toMatch(/host bits set/)
    expect(cidrInfo('10.0.0.0/31')).toMatch(/Usable hosts:\s+2 \(point-to-point/)
    expect(cidrInfo('8.8.8.8')).toMatch(/Total addresses:\s+1\n[\s\S]*Public/)
    expect(cidrInfo('0.0.0.0/0')).toMatch(/Total addresses:\s+4,294,967,296/)
    expect(() => cidrInfo('1.2.3.4/33')).toThrow(/prefix/)
    expect(() => cidrInfo('1.2.3.004')).toThrow(/not an IPv4/)
  })
  it('IPv6', () => {
    expect(formatIPv6(parseIPv6('2001:0db8:0000:0000:0000:ff00:0042:8329') as bigint)).toBe('2001:db8::ff00:42:8329')
    expect(formatIPv6(parseIPv6('::ffff:192.0.2.1') as bigint)).toBe('::ffff:c000:201')
    expect(formatIPv6(parseIPv6('1:0:0:2:0:0:0:3') as bigint)).toBe('1:0:0:2::3')
    const out = cidrInfo('2001:db8:abcd:12::1/64')
    expect(out).toMatch(/Network:\s+2001:db8:abcd:12::/)
    expect(out).toMatch(/Range:.*2001:db8:abcd:12:ffff:ffff:ffff:ffff/)
    expect(out).toMatch(/18,446,744,073,709,551,616 \(2\^64\)/)
    expect(out).toMatch(/Documentation/)
    expect(cidrInfo('fe80::1')).toMatch(/Link-local/)
  })
})

describe('UUID', () => {
  it('generates valid v4 and v7', () => {
    expect(generateUuid('v4')).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    const v7 = generateUuid('v7', 1700000000123)
    expect(v7).toMatch(/^018bcfe5-687b-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(parseUuid(v7)).toContain('Timestamp: 2023-11-14T22:13:20.123Z')
  })
  it('parses RFC 9562 example UUIDs', () => {
    // RFC 9562 Appendix A test vectors: v1, v6 and v7 all encode 2022-02-22T19:22:22Z (Tuesday, February 22, 2022 2:22:22.00 PM GMT-05:00)
    expect(parseUuid('C232AB00-9414-11EC-B3C8-9F6BDECED846')).toMatch(/Version:\s+1[\s\S]*Timestamp: 2022-02-22T19:22:22\.000Z/)
    expect(parseUuid('1EC9414C-232A-6B00-B3C8-9F6BDECED846')).toMatch(/Version:\s+6[\s\S]*Timestamp: 2022-02-22T19:22:22\.000Z/)
    expect(parseUuid('017F22E2-79B0-7CC3-98C4-DC0C0C07398F')).toMatch(/Version:\s+7[\s\S]*Timestamp: 2022-02-22T19:22:22\.000Z/)
    expect(parseUuid('919108f7-52d1-4320-9bac-f847db4148a8')).toMatch(/Version:\s+4 — random/)
    expect(parseUuid('{00000000-0000-0000-0000-000000000000}')).toContain('Nil UUID')
    expect(parseUuid('urn:uuid:ffffffff-ffff-ffff-ffff-ffffffffffff')).toContain('Max UUID')
    expect(() => parseUuid('not-a-uuid')).toThrow(/not a UUID/)
  })
  it('generate op honours count and v7 ordering', async () => {
    const list = (await runOp('uuid-generate', '', { version: 'v7', count: 50 })).split('\n')
    expect(list).toHaveLength(50)
    expect([...list].sort()).toEqual(list)
  })
})

describe('number base conversion', () => {
  it('BigInt with prefixes and negatives', async () => {
    expect(parseBigInt('0xff', 'auto')).toBe(255n)
    expect(parseBigInt('-0b101', 'auto')).toBe(-5n)
    expect(parseBigInt('zz', 36)).toBe(1295n)
    expect(() => parseBigInt('19', 8)).toThrow(/base-8/)
    expect(await runOp('base-convert', '255 4096\n18446744073709551616', { to: 16, prefix: true })).toBe('0xff 0x1000\n0x10000000000000000')
    expect(await runOp('base-convert', 'ff', { from: 16, to: 2 })).toBe('11111111')
    expect(await runOp('base-convert', '-10', { to: 2 })).toBe('-1010')
  })
})

describe('take / drop bytes', () => {
  it('slices', async () => {
    expect(await runOp('take-bytes', 'abcdef', { offset: 1, length: 2 })).toBe('bc')
    expect(await runOp('take-bytes', 'abcdef', { offset: 4, length: 0 })).toBe('ef')
    expect(await runOp('drop-bytes', 'abcdef', { offset: 1, length: 2 })).toBe('adef')
    expect(await runOp('drop-bytes', 'abcdef', { offset: 10, length: 2 })).toBe('abcdef')
  })
})

describe('review regressions (formats)', () => {
  it('from hexdump expands "*" repeated-line markers of hexdump -C (regression: they were silently dropped)', () => {
    // printf 'A%.0s' {1..48} | hexdump -C  → 3 identical lines collapsed into one + "*"
    const dump = [
      '00000000  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|',
      '*',
      '00000030  42 0a                                             |B.|',
      '00000032',
    ].join('\n')
    const out = new TextDecoder().decode(fromHexdump(dump))
    expect(out).toBe('A'.repeat(48) + 'B\n')
  })
  it('from hexdump rejects a "*" that does not line up with the next offset', () => {
    const dump = '00000000  41 41 41  |AAA|\n*\n00000004  42  |B|'
    expect(() => fromHexdump(dump)).toThrow(/Cannot expand/)
  })
})
