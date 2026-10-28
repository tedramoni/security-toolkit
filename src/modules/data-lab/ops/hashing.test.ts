import { describe, expect, it } from 'vitest'
import { bytesToHex, runOp, runOpBytes } from '../testUtil'
import { adler32, crc32, md5 } from './checksums'

const enc = (s: string) => new TextEncoder().encode(s)

describe('MD5 (RFC 1321 §A.5 test suite)', () => {
  const suite: [string, string][] = [
    ['', 'd41d8cd98f00b204e9800998ecf8427e'],
    ['a', '0cc175b9c0f1b6a831c399e269772661'],
    ['abc', '900150983cd24fb0d6963f7d28e17f72'],
    ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
    ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
    ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'd174ab98d277d9f5a5611c2c9f419d9f'],
    ['1234567890'.repeat(8), '57edf4a22be3c955ac49da2e2107b67a'],
  ]
  for (const [input, digest] of suite) {
    it(`MD5("${input.slice(0, 20)}")`, () => expect(bytesToHex(md5(enc(input)))).toBe(digest))
  }
  it('handles padding boundaries (55/56/64 bytes)', () => {
    expect(bytesToHex(md5(enc('a'.repeat(55))))).toBe('ef1772b6dff9a122358552954ad0df65')
    expect(bytesToHex(md5(enc('a'.repeat(56))))).toBe('3b0c8ac703f828b04c6c197006d17218')
    expect(bytesToHex(md5(enc('a'.repeat(64))))).toBe('014842d480b571495a4a0363793f7367')
  })
  it('via the op, hex and raw', async () => {
    expect(await runOp('md5', 'abc')).toBe('900150983cd24fb0d6963f7d28e17f72')
    expect((await runOpBytes('md5', 'abc', { output: 'raw' })).length).toBe(16)
  })
})

describe('CRC-32 and Adler-32', () => {
  it('check values', () => {
    expect(crc32(enc('123456789')).toString(16)).toBe('cbf43926')
    expect(crc32(new Uint8Array(0))).toBe(0)
    expect(crc32(enc('The quick brown fox jumps over the lazy dog')).toString(16)).toBe('414fa339')
    expect(adler32(enc('Wikipedia')).toString(16)).toBe('11e60398')
    expect(adler32(new Uint8Array(0))).toBe(1)
  })
  it('Adler-32 stays correct past the 5552-byte chunk boundary', () => {
    const big = new Uint8Array(100_000).fill(0xff)
    // reference: straightforward modular implementation
    let a = 1
    let b = 0
    for (const x of big) {
      a = (a + x) % 65521
      b = (b + a) % 65521
    }
    expect(adler32(big)).toBe(((b << 16) | a) >>> 0)
  })
  it('ops output 8 hex digits', async () => {
    expect(await runOp('crc32', '123456789')).toBe('cbf43926')
    expect(await runOp('adler32', 'Wikipedia')).toBe('11e60398')
    expect(await runOp('crc32', 'a')).toBe('e8b7be43')
  })
})

describe('SHA family (FIPS 180 "abc" vectors, via WebCrypto)', () => {
  it('SHA-1/256/384/512', async () => {
    expect(await runOp('sha1', 'abc')).toBe('a9993e364706816aba3e25717850c26c9cd0d89d')
    expect(await runOp('sha256', 'abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    expect(await runOp('sha384', 'abc')).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    )
    expect(await runOp('sha512', 'abc')).toBe(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    )
  })
})

describe('compression', () => {
  const text = 'hello hello hello hello compression '.repeat(20)
  for (const [c, d] of [
    ['gzip', 'gunzip'],
    ['zlib-deflate', 'zlib-inflate'],
    ['raw-deflate', 'raw-inflate'],
  ] as const) {
    it(`${c} → ${d} round-trips`, async () => {
      const packed = await runOpBytes(c, text)
      expect(packed.length).toBeLessThan(text.length)
      expect(await runOp(d, packed)).toBe(text)
    })
  }
  it('gzip has the 1f 8b magic; zlib passes the FCHECK test', async () => {
    const gz = await runOpBytes('gzip', 'x')
    expect([gz[0], gz[1]]).toEqual([0x1f, 0x8b])
    const z = await runOpBytes('zlib-deflate', 'x')
    expect(z[0]).toBe(0x78)
    expect(((z[0] << 8) | z[1]) % 31).toBe(0)
  })
  it('reports corrupt and truncated input', async () => {
    await expect(runOp('gunzip', 'definitely not gzip')).rejects.toThrow(/Corrupt or truncated/)
    const gz = await runOpBytes('gzip', text)
    await expect(runOp('gunzip', gz.slice(0, gz.length - 10))).rejects.toThrow(/Corrupt or truncated/)
    await expect(runOp('zlib-inflate', '')).rejects.toThrow(/empty/)
  })
})
