import { describe, expect, it } from 'vitest'
import { fromBase64, fromHex, toBase64, toBase64Url, toHex } from './bytes'
import { decodeOid, decodeTime, describeValue, encodeOid, parseDer, readHeader, tagName } from './der'
import { parseInputText, parsePem } from './pem'
import { ISRG_ROOT_X1_PEM } from './publicCerts'

describe('bytes', () => {
  it('base64 round trip (RFC 4648 §10 vectors)', () => {
    const vec: [string, string][] = [['', ''], ['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foob', 'Zm9vYg=='], ['fooba', 'Zm9vYmE='], ['foobar', 'Zm9vYmFy']]
    for (const [plain, b64] of vec) {
      expect(toBase64(new TextEncoder().encode(plain))).toBe(b64)
      expect(new TextDecoder().decode(fromBase64(b64))).toBe(plain)
    }
    expect(toBase64Url(new Uint8Array([0xfb, 0xff]))).toBe('-_8')
    expect(toHex(fromBase64('-_8'))).toBe('fbff')
    expect(() => fromBase64('ab$d')).toThrow()
    expect(() => fromBase64('a')).toThrow()
  })
  it('hex', () => {
    expect(toHex(fromHex('DE:AD be ef'))).toBe('deadbeef')
    expect(() => fromHex('abc')).toThrow()
  })
})

describe('OID / time codecs', () => {
  it('encodes and decodes OIDs including large arcs', () => {
    for (const oid of ['1.2.840.113549.1.1.11', '2.5.29.17', '0.9.2342.19200300.100.1.25', '2.999.3', '1.3.6.1.4.1.11129.2.4.2', '2.25.329800735698586629295641978511506172918']) {
      expect(decodeOid(encodeOid(oid))).toBe(oid)
    }
    expect(toHex(encodeOid('1.2.840.113549'))).toBe('2a864886f70d')
    expect(() => decodeOid(new Uint8Array([0x2a, 0x86]))).toThrow('Truncated')
    expect(() => encodeOid('1.40.1')).toThrow()
  })
  it('parses UTCTime and GeneralizedTime', () => {
    const enc = (s: string) => new TextEncoder().encode(s)
    expect(decodeTime(23, enc('491231235959Z')).toISOString()).toBe('2049-12-31T23:59:59.000Z')
    expect(decodeTime(23, enc('500101000000Z')).toISOString()).toBe('1950-01-01T00:00:00.000Z')
    expect(decodeTime(24, enc('20500101000000Z')).toISOString()).toBe('2050-01-01T00:00:00.000Z')
    expect(() => decodeTime(23, enc('garbage'))).toThrow()
  })
})

describe('DER walker', () => {
  const root = parseInputText(ISRG_ROOT_X1_PEM).blocks[0].der

  it('parses a real certificate fully, with encapsulated extension values', () => {
    const r = parseDer(root)
    expect(r.errors).toEqual([])
    expect(r.nodes).toHaveLength(1)
    const cert = r.nodes[0]
    expect(tagName(cert)).toBe('SEQUENCE')
    expect(cert.children).toHaveLength(3)
    expect(cert.headerLength + cert.length).toBe(root.length)
    // signatureValue BIT STRING should not be mis-parsed as nested DER
    expect(cert.children![2].encapsulated).toBeUndefined()
    // Extensions contain encapsulated OCTET STRING contents
    const json = JSON.stringify(r.nodes)
    expect(json).toContain('"encapsulated":true')
    expect(describeValue(root, cert.children![1].children![0])).toBe('1.2.840.113549.1.1.11')
  })

  it('reports truncated input without throwing', () => {
    for (const cut of [1, 2, 4, 10, 100, root.length - 1]) {
      const r = parseDer(root.subarray(0, cut))
      const hasErr = r.errors.length > 0 || JSON.stringify(r.nodes).includes('"error"')
      expect(hasErr).toBe(true)
    }
  })

  it('rejects absurd lengths and garbage', () => {
    expect(() => readHeader(new Uint8Array([0x30, 0x85, 1, 2, 3, 4, 5]), 0)).toThrow('too large')
    expect(() => readHeader(new Uint8Array([0x30, 0x82, 0xff, 0xff, 0x00]), 0)).toThrow('exceeds')
    expect(() => readHeader(new Uint8Array([0x04, 0x80]), 0)).toThrow('Indefinite length on a primitive')
    const rnd = new Uint8Array(4096)
    let x = 12345
    for (let i = 0; i < rnd.length; i++) rnd[i] = x = (x * 1103515245 + 12345) & 0xff
    expect(() => parseDer(rnd)).not.toThrow()
  })

  it('caps nesting depth (no stack overflow on deeply nested input)', () => {
    const depth = 100_000
    // 0x30 0x80 ... 0x00 0x00 repeated: indefinite-length nesting needs no length bookkeeping.
    const buf = new Uint8Array(depth * 4)
    for (let i = 0; i < depth; i++) {
      buf[i * 2] = 0x30
      buf[i * 2 + 1] = 0x80
    }
    const r = parseDer(buf, { maxDepth: 64 })
    expect(JSON.stringify(r).includes('Maximum nesting depth')).toBe(true)
  })

  it('caps the number of nodes', () => {
    const n = 50_000
    const buf = new Uint8Array(n * 2)
    for (let i = 0; i < n; i++) buf[i * 2] = 0x05 // NULL, length 0
    const r = parseDer(buf, { maxNodes: 1000 })
    expect(r.truncated).toBe(true)
    expect(r.nodeCount).toBe(1000)
  })

  it('supports BER indefinite lengths', () => {
    const ber = fromHex('3080 0201 05 0400 0000')
    const r = parseDer(ber)
    expect(r.errors).toEqual([])
    expect(r.nodes[0].indefinite).toBe(true)
    expect(r.nodes[0].children).toHaveLength(2)
    const bad = fromHex('3080 0201 05')
    expect(JSON.stringify(parseDer(bad))).toContain('end-of-contents')
  })

  it('is fast on large adversarial inputs', () => {
    const big = new Uint8Array(2_000_000).fill(0x30)
    let t = performance.now()
    parseDer(big)
    expect(performance.now() - t).toBeLessThan(1500)
    const pemish = '-----BEGIN '.repeat(50_000) + '-----BEGIN CERTIFICATE-----' + 'A'.repeat(200_000)
    t = performance.now()
    const r = parsePem(pemish)
    expect(r.blocks).toHaveLength(0)
    expect(performance.now() - t).toBeLessThan(1500)
  })
})

describe('PEM parsing', () => {
  it('ignores Proc-Type headers and flags encrypted keys', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0011\n\nMAA=\n-----END RSA PRIVATE KEY-----'
    const r = parsePem(pem)
    expect(r.blocks[0].encrypted).toBe(true)
    expect(toHex(r.blocks[0].der)).toBe('3000')
  })
  it('warns on unterminated and invalid blocks', () => {
    expect(parsePem('-----BEGIN CERTIFICATE-----\nMIIB').warnings[0]).toContain('truncated')
    expect(parsePem('-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----').warnings[0]).toContain('invalid base64')
  })
})
