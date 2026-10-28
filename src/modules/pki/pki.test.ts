import { beforeAll, describe, expect, it } from 'vitest'
import { fromBase64, toHex } from './bytes'
import { decodeCertificate } from './cert'
import { buildChains, chainToPem } from './chain'
import { certToJwk, extractPkcs7, jwkThumbprint, jwkToSpki, spkiToJwk } from './convert'
import { crlFreshness, decodeCrl, indexCrl, normalizeSerial } from './crl'
import { decodeCsr, lintCsr } from './csr'
import { concat, derSeq, derOid, tlv, parseOne, child, contents } from './der'
import { sanNames } from './extensions'
import { generateCsr, generateSelfSigned, EMPTY_SUBJECT } from './generate'
import { analyzeKeyBlock, matchMatrix, pkcs1PrivateToPkcs8 } from './keys'
import { buildOcspRequest, opensslOcspCommand } from './ocsp'
import { parseInputText } from './pem'
import { ISRG_ROOT_X1_PEM, ISRG_ROOT_X2_PEM, LE_R12_PEM } from './publicCerts'
import type { SamplePki } from './samples'
import { generateSamplePki } from './samples'
import { verifyCrlSignature, verifyCsrSignature } from './verify'

let pki: SamplePki
beforeAll(async () => {
  pki = await generateSamplePki()
})

const der = (pem: string) => parseInputText(pem).blocks[0].der

describe('chain builder', () => {
  it('orders a shuffled bundle leaf → root and verifies every signature', async () => {
    const bundle = [pki.pem.root, pki.pem.leaf, pki.pem.intermediate].map(der)
    const r = await buildChains(bundle)
    expect(r.chains).toHaveLength(1)
    const c = r.chains[0]
    expect(c.complete).toBe(true)
    expect(c.links.map((l) => l.info.subjectString)).toEqual(['CN=www.example.test', 'C=ZZ, O=Example Test PKI, CN=Example Test Issuing CA 1', 'C=ZZ, O=Example Test PKI, CN=Example Test Root CA'])
    expect(c.links.every((l) => l.signature?.ok)).toBe(true)
    expect(c.links.flatMap((l) => l.problems)).toEqual([])
    expect(parseInputText(chainToPem(c, false)).blocks).toHaveLength(2)
    expect(parseInputText(chainToPem(c, true)).blocks).toHaveLength(3)
  })

  it('reports a missing intermediate with the AIA caIssuers URL', async () => {
    const r = await buildChains([der(pki.pem.root), der(pki.pem.leaf)])
    const c = r.chains.find((x) => x.links[0].info.subjectString === 'CN=www.example.test')!
    expect(c.complete).toBe(false)
    expect(c.missingIssuer?.caIssuersUrls).toEqual(['http://pki.example.test/issuing-ca-1.cer'])
    expect(r.unused.length + r.chains.length).toBeGreaterThanOrEqual(2)
  })

  it('builds the real Let’s Encrypt R12 → ISRG Root X1 chain (shuffled with an unrelated root)', async () => {
    const r = await buildChains([ISRG_ROOT_X2_PEM, ISRG_ROOT_X1_PEM, LE_R12_PEM].map(der), { now: new Date('2026-01-01') })
    const c = r.chains.find((x) => x.links[0].info.subjectString.endsWith('CN=R12'))!
    expect(c.links.map((l) => l.info.subjectString.split('CN=')[1])).toEqual(['R12', 'ISRG Root X1'])
    expect(c.links.every((l) => l.signature?.ok)).toBe(true)
    expect(c.complete).toBe(true)
  })

  it('flags expired links and a signature that does not verify', async () => {
    const r = await buildChains([der(pki.pem.badLeaf), der(pki.pem.intermediate)])
    const bad = r.chains[0].links[0]
    expect(bad.problems.join(' ')).toContain('expired')
    const tampered = der(pki.pem.leaf)
    tampered[tampered.length - 5] ^= 0xff
    const r2 = await buildChains([tampered, der(pki.pem.intermediate)])
    expect(r2.chains[0].links[0].problems.join(' ')).toContain('does NOT verify')
  })
})

describe('key matcher', () => {
  it('matches certificate, CSR, SPKI and PKCS#8 for EC keys', async () => {
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pki.leafKeys.privateKey))
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pki.leafKeys.publicKey))
    const items = await Promise.all([
      analyzeKeyBlock({ label: 'CERTIFICATE', der: der(pki.pem.leaf), source: 'pem' }),
      analyzeKeyBlock({ label: 'CERTIFICATE REQUEST', der: der(pki.pem.csr), source: 'pem' }),
      analyzeKeyBlock({ label: 'PUBLIC KEY', der: spki, source: 'pem' }),
      analyzeKeyBlock({ label: 'PRIVATE KEY', der: pkcs8, source: 'pem' }),
      analyzeKeyBlock({ label: 'CERTIFICATE', der: der(pki.pem.root), source: 'pem' }),
    ])
    expect(items.map((i) => i.error)).toEqual([undefined, undefined, undefined, undefined, undefined])
    const m = matchMatrix(items)
    expect(m[0].slice(0, 4)).toEqual([true, true, true, true])
    expect(m[0][4]).toBe(false)
    expect(items[3].isPrivate).toBe(true)
  })

  it('matches RSA keys including PKCS#1 private keys (converted via ASN.1)', async () => {
    const r = await generateSelfSigned({ keyType: 'RSA-2048', hash: 'SHA-256', subject: { ...EMPTY_SUBJECT, CN: 'rsa.example' }, sans: [{ type: 'dns', value: 'rsa.example' }], days: 7 })
    const pkcs8 = der(r.privateKeyPem)
    // PKCS#8 → PKCS#1: the inner OCTET STRING content
    const pkcs1 = contents(pkcs8, child(parseOne(pkcs8), 2)!)
    expect(toHex(pkcs1PrivateToPkcs8(pkcs1))).toBe(toHex(pkcs8))
    const items = await Promise.all([
      analyzeKeyBlock({ label: 'CERTIFICATE', der: der(r.certPem), source: 'pem' }),
      analyzeKeyBlock({ label: 'RSA PRIVATE KEY', der: pkcs1, source: 'pem' }),
      analyzeKeyBlock({ label: 'PRIVATE KEY', der: pkcs8, source: 'pem' }),
    ])
    expect(items.map((i) => i.error)).toEqual([undefined, undefined, undefined])
    expect(new Set(items.map((i) => i.fingerprint)).size).toBe(1)
    expect(items[1].note).toContain('openssl pkcs8 -topk8')
  })

  it('handles SEC1 EC private keys and explains encrypted keys', async () => {
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pki.rootKeys.privateKey))
    const inner = contents(pkcs8, child(parseOne(pkcs8), 2)!)
    // Add the [0] curve parameters like `openssl ecparam -genkey` does.
    const n = parseOne(inner)
    const parts = n.children!.filter((c) => !(c.tagClass === 'context' && c.tagNumber === 0)).map((c) => inner.slice(c.offset, c.offset + c.headerLength + c.length))
    const sec1 = derSeq(concat(parts[0], parts[1], tlv(0xa0, derOid('1.2.840.10045.3.1.7')), ...parts.slice(2)))
    const item = await analyzeKeyBlock({ label: 'EC PRIVATE KEY', der: sec1, source: 'pem' })
    const cert = await analyzeKeyBlock({ label: 'CERTIFICATE', der: der(pki.pem.root), source: 'pem' })
    expect(item.error).toBeUndefined()
    expect(item.fingerprint).toBe(cert.fingerprint)
    const enc = await analyzeKeyBlock({ label: 'ENCRYPTED PRIVATE KEY', der: new Uint8Array([0x30, 0]), source: 'pem' })
    expect(enc.note).toContain('openssl pkcs8')
  })
})

describe('CRL', () => {
  it('decodes the sample CRL and finds revoked serials', async () => {
    const crl = decodeCrl(der(pki.pem.crl))
    expect(crl.issuerString).toBe('C=ZZ, O=Example Test PKI, CN=Example Test Issuing CA 1')
    expect(crl.version).toBe(2)
    expect(crl.crlNumber).toBe('42')
    expect(crl.entries).toHaveLength(3)
    const idx = indexCrl(crl)
    expect(idx.get(normalizeSerial('10:01'))?.reason).toBe(1)
    expect(idx.get(normalizeSerial('0A1B2C3D4E5F'))?.reason).toBe(4)
    expect(idx.get(normalizeSerial('77'))?.reason).toBeUndefined()
    expect(idx.has(normalizeSerial('1002'))).toBe(false)
    const bad = decodeCertificate(der(pki.pem.badLeaf))
    expect(idx.has(normalizeSerial(bad.serialHex))).toBe(true)
    expect(crlFreshness(crl).state).toBe('fresh')
    expect(crlFreshness(crl, new Date(Date.now() + 30 * 86_400_000)).state).toBe('stale')
    expect((await verifyCrlSignature(crl.der, der(pki.pem.intermediate))).ok).toBe(true)
    expect((await verifyCrlSignature(crl.der, der(pki.pem.root))).ok).toBe(false)
  })

  it('parses a large CRL quickly', () => {
    // Synthesize 100k entries around the real TBS structure.
    const base = der(pki.pem.crl)
    const n = parseOne(base)
    const tbs = child(n, 0)!
    const tb = contents(base, tbs)
    const t = parseOne(Uint8Array.from(tlv(0x30, tb)))
    const kids = t.children!
    const raw = Uint8Array.from(tlv(0x30, tb))
    const slice = (i: number) => raw.slice(kids[i].offset, kids[i].offset + kids[i].headerLength + kids[i].length)
    const entries: Uint8Array[] = []
    const date = tlv(0x17, new TextEncoder().encode('250101000000Z'))
    for (let i = 1; i <= 100_000; i++) entries.push(derSeq(tlv(0x02, new Uint8Array([0x01, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff])), date))
    const newTbs = derSeq(slice(0), slice(1), slice(2), slice(3), slice(4), derSeq(concat(...entries)))
    const fake = derSeq(newTbs, base.slice(child(n, 1)!.offset, child(n, 1)!.offset + child(n, 1)!.headerLength + child(n, 1)!.length), tlv(0x03, new Uint8Array([0, 1])))
    const start = performance.now()
    const crl = decodeCrl(fake)
    expect(crl.entries).toHaveLength(100_000)
    expect(indexCrl(crl).has('1000064')).toBe(true)
    expect(performance.now() - start).toBeLessThan(2000)
  })

  it('normalizes serial formats', () => {
    expect(normalizeSerial('00:0A:1b')).toBe('a1b')
    expect(normalizeSerial('0x00')).toBe('0')
    expect(() => normalizeSerial('xyz')).toThrow()
  })
})

describe('CSR', () => {
  it('decodes, verifies and lints a generated CSR', async () => {
    const g = await generateCsr({ keyType: 'P-256', hash: 'SHA-256', subject: { ...EMPTY_SUBJECT, CN: 'app.example.com', O: 'Ex "Q" Inc', C: 'FR' }, sans: [{ type: 'dns', value: 'app.example.com' }, { type: 'ip', value: '10.1.2.3' }] })
    const d = der(g.csrPem)
    const csr = decodeCsr(d)
    expect(csr.subjectString).toBe('C=FR, O=Ex \\"Q\\" Inc, CN=app.example.com')
    expect(sanNames(csr.extensions)).toEqual([{ type: 'DNS', value: 'app.example.com' }, { type: 'IP', value: '10.1.2.3' }])
    expect(csr.publicKey.summary).toBe('EC P-256')
    expect((await verifyCsrSignature(d)).ok).toBe(true)
    expect(lintCsr(csr, true).map((f) => f.severity)).toEqual(['pass'])
    const t = Uint8Array.from(d)
    t[40] ^= 1
    expect((await verifyCsrSignature(t)).ok).toBe(false)
  })

  it('lints missing SAN, CN not in SAN and challengePassword', () => {
    const csr = decodeCsr(der(pki.pem.csr))
    expect(lintCsr(csr, true).map((f) => f.title)).toContain('CN "shop.example.test" is not in the SAN')
    const noSan = { ...csr, extensions: [], challengePassword: 'secret' }
    const t = lintCsr(noSan, true).map((f) => f.title)
    expect(t).toContain('No Subject Alternative Name requested')
    expect(t).toContain('challengePassword attribute present')
  })

  it('generates an Ed25519 CSR when supported', async () => {
    const g = await generateCsr({ keyType: 'Ed25519', hash: 'SHA-256', subject: { ...EMPTY_SUBJECT, CN: 'ed.example' }, sans: [] })
    const csr = decodeCsr(der(g.csrPem))
    expect(csr.publicKey.type).toBe('Ed25519')
    expect(csr.signatureAlg.name).toBe('Ed25519')
    expect((await verifyCsrSignature(der(g.csrPem))).ok).toBe(true)
  })
})

describe('converter', () => {
  const P7B = 'MIICSgYJKoZIhvcNAQcCoIICOzCCAjcCAQExADALBgkqhkiG9w0BBwGgggIfMIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZIzj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdWtL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1/q4AaOeMSQ+2b1tbFfLnMQA='

  it('extracts certificates from a real DER .p7b (openssl crl2pkcs7)', () => {
    const r = extractPkcs7(fromBase64(P7B))
    expect(r.certs).toHaveLength(1)
    expect(toHex(r.certs[0])).toBe(toHex(der(ISRG_ROOT_X2_PEM)))
  })

  it('extracts certificates from a BER (indefinite length) PKCS#7', () => {
    const c1 = der(pki.pem.leaf)
    const c2 = der(pki.pem.intermediate)
    const ind = (tag: number, ...parts: Uint8Array[]) => concat(new Uint8Array([tag, 0x80]), ...parts, new Uint8Array([0, 0]))
    const sd = ind(0x30, new Uint8Array([2, 1, 1]), new Uint8Array([0x31, 0]), derSeq(derOid('1.2.840.113549.1.7.1')), ind(0xa0, c1, c2), new Uint8Array([0x31, 0]))
    const ci = ind(0x30, derOid('1.2.840.113549.1.7.2'), ind(0xa0, sd))
    const r = extractPkcs7(ci)
    expect(r.certs.map((x) => toHex(x))).toEqual([toHex(c1), toHex(c2)])
    expect(() => extractPkcs7(derSeq(derOid('1.2.840.113549.1.7.1')))).toThrow('not signedData')
  })

  it('RFC 7638 §3.1 JWK thumbprint test vector', async () => {
    const jwk = {
      kty: 'RSA' as const,
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
    }
    expect(await jwkThumbprint(jwk)).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')
    // and SPKI ↔ JWK round trip
    const spki = await jwkToSpki(jwk)
    expect(await spkiToJwk(spki)).toEqual(jwk)
  })

  it('certificate → JWK with x5c and x5t#S256; EC round trip; private JWK refused', async () => {
    const j = await certToJwk([der(ISRG_ROOT_X2_PEM)])
    expect(j.kty).toBe('EC')
    expect(j.crv).toBe('P-384')
    expect((j.x5c as string[])[0]).toBe(ISRG_ROOT_X2_PEM.split('\n').slice(1, -2).join(''))
    // x5t#S256 = base64url(SHA-256(DER)) — ISRG Root X2 fingerprint 69:72:9B…
    expect(toHex(fromBase64(j['x5t#S256'] as string))).toBe('69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470')
    const spki = await jwkToSpki({ kty: j.kty, crv: j.crv, x: j.x, y: j.y })
    expect(toHex(spki)).toBe(toHex(decodeCertificate(der(ISRG_ROOT_X2_PEM)).spkiDer))
    await expect(jwkToSpki({ kty: 'EC', crv: 'P-256', x: 'a', y: 'b', d: 'c' })).rejects.toThrow('PRIVATE')
  })
})

describe('OCSP', () => {
  it('builds an RFC 6960 request with SHA-1 CertID', async () => {
    const leaf = decodeCertificate(der(pki.pem.leaf))
    const issuer = decodeCertificate(der(pki.pem.intermediate))
    const r = await buildOcspRequest(leaf, issuer, 'http://ocsp.example.test')
    const n = parseOne(r.der)
    const certId = child(child(child(child(n, 0), 0), 0), 0)!
    expect(certId.children).toHaveLength(4)
    expect(toHex(contents(r.der, child(certId, 3)!))).toBe(leaf.serialHex)
    expect(r.issuerNameHash).toHaveLength(40)
    expect(r.getUrl?.startsWith('http://ocsp.example.test/M')).toBe(true)
    expect(r.getUrl).not.toMatch(/[+=]/)
    expect(opensslOcspCommand('http://ocsp.example.test')).toContain("-url 'http://ocsp.example.test'")
    expect(opensslOcspCommand('javascript:alert(1)')).not.toContain('javascript')
  })

  it('matches the openssl-generated request for Let’s Encrypt R12 / ISRG Root X1', async () => {
    // openssl ocsp -issuer isrgrootx1.pem -cert r12.pem -no_nonce -reqout req.der
    const r = await buildOcspRequest(decodeCertificate(der(LE_R12_PEM)), decodeCertificate(der(ISRG_ROOT_X1_PEM)))
    expect(toHex(r.der)).toBe(OPENSSL_R12_REQ)
  })
})

// Filled from `openssl ocsp -issuer isrgrootx1.pem -cert r12.pem -no_nonce -reqout req.der` (OpenSSL 3.5).
const OPENSSL_R12_REQ = '30523050304e304c304a300906052b0e03021a05000414281aea4e6a11200e3949b766237385489c2e8792041479b459e67bb6e5e40173800888c81a58f6e99b6e021100c212324b70a9b49171dc40f7e285263c'
