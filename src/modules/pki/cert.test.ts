import { beforeAll, describe, expect, it } from 'vitest'
import { decodeCertificate, fingerprints, serialDisplay } from './cert'
import { accessUrls, crlUrls, extDecoded, sanNames } from './extensions'
import { lintCertificate, maxTlsValidityDays, validityDays } from './lint'
import { OID } from './oids'
import { parseInputBytes, parseInputText, toPem } from './pem'
import { ISRG_ROOT_X1_PEM, ISRG_ROOT_X1_SHA256, ISRG_ROOT_X2_PEM, ISRG_ROOT_X2_SHA256, LE_R12_PEM, LE_R12_SHA256 } from './publicCerts'
import type { SamplePki } from './samples'
import { generateSamplePki } from './samples'
import { x509 } from './x509'
import { toBase64 } from './bytes'

let pki: SamplePki
beforeAll(async () => {
  pki = await generateSamplePki()
})

const titles = (fs: { title: string }[]) => fs.map((f) => f.title)

describe('real-world public certificates', () => {
  it('parses a bundle with surrounding text and CRLF line endings', async () => {
    const text = `Here is my bundle:\r\n${LE_R12_PEM.replace(/\n/g, '\r\n')}\r\nsome junk\r\n${ISRG_ROOT_X1_PEM}\n\n${ISRG_ROOT_X2_PEM}trailing`
    const parsed = parseInputText(text)
    expect(parsed.warnings).toEqual([])
    expect(parsed.blocks).toHaveLength(3)
    const infos = parsed.blocks.map((b) => decodeCertificate(b.der))
    const fps = await Promise.all(infos.map((i) => fingerprints(i)))
    expect(fps.map((f) => f.sha256)).toEqual([LE_R12_SHA256, ISRG_ROOT_X1_SHA256, ISRG_ROOT_X2_SHA256])
  })

  it('decodes ISRG Root X1 fields', () => {
    const der = parseInputText(ISRG_ROOT_X1_PEM).blocks[0].der
    const c = decodeCertificate(der)
    expect(c.subjectString).toBe('C=US, O=Internet Security Research Group, CN=ISRG Root X1')
    expect(c.issuerString).toBe(c.subjectString)
    expect(serialDisplay(c)).toBe('82:10:CF:B0:D2:40:E3:59:44:63:E0:BB:63:82:8B:00')
    expect(c.serialHex.startsWith('00')).toBe(true)
    expect(c.publicKey.type).toBe('RSA')
    expect(c.publicKey.bits).toBe(4096)
    expect(c.publicKey.exponent).toBe('65537')
    expect(c.signatureAlg.name).toBe('sha256WithRSAEncryption')
    expect(c.notBefore.toISOString()).toBe('2015-06-04T11:04:38.000Z')
    expect(c.notAfter.toISOString()).toBe('2035-06-04T11:04:38.000Z')
    expect(extDecoded(c.extensions, OID.basicConstraints, 'bc')).toEqual({ kind: 'bc', ca: true, pathLen: undefined })
    expect(extDecoded(c.extensions, OID.keyUsage, 'ku')?.usages).toEqual(['keyCertSign', 'cRLSign'])
    expect(extDecoded(c.extensions, OID.subjectKeyIdentifier, 'keyId')?.keyId).toBe('79:b4:59:e6:7b:b6:e5:e4:01:73:80:08:88:c8:1a:58:f6:e9:9b:6e')
    const lint = lintCertificate(c, { now: new Date('2026-01-01'), selfSigned: true })
    expect(lint.map((f) => f.severity)).toEqual(['pass'])
  })

  it('decodes ISRG Root X2 (EC P-384) and Let’s Encrypt R12 extensions', () => {
    const x2 = decodeCertificate(parseInputText(ISRG_ROOT_X2_PEM).blocks[0].der)
    expect(x2.publicKey.summary).toBe('EC P-384')
    expect(x2.signatureAlg.name).toBe('ecdsa-with-SHA384')
    const r12 = decodeCertificate(parseInputText(LE_R12_PEM).blocks[0].der)
    expect(r12.subjectString).toBe("C=US, O=Let's Encrypt, CN=R12")
    expect(extDecoded(r12.extensions, OID.basicConstraints, 'bc')).toMatchObject({ ca: true, pathLen: 0 })
    expect(accessUrls(r12.extensions, OID.caIssuers)).toEqual(['http://x1.i.lencr.org/'])
    expect(crlUrls(r12.extensions)).toEqual(['http://x1.c.lencr.org/'])
    expect(extDecoded(r12.extensions, OID.certificatePolicies, 'policies')?.policies[0]).toMatchObject({ oid: '2.23.140.1.2.1', name: 'CA/B Forum Domain Validated (DV) TLS' })
    expect(extDecoded(r12.extensions, OID.extKeyUsage, 'eku')?.usages.map((u) => u.oid)).toEqual([OID.clientAuth, OID.serverAuth])
    expect(extDecoded(r12.extensions, OID.authorityKeyIdentifier, 'aki')?.keyId).toBe('79:b4:59:e6:7b:b6:e5:e4:01:73:80:08:88:c8:1a:58:f6:e9:9b:6e')
  })

  it('accepts base64 DER, hex DER and binary DER uploads', () => {
    const der = parseInputText(ISRG_ROOT_X2_PEM).blocks[0].der
    expect(parseInputText(toBase64(der)).blocks[0].der).toEqual(der)
    expect(parseInputText(Array.from(der, (b) => b.toString(16).padStart(2, '0')).join('')).blocks[0].der).toEqual(der)
    expect(parseInputBytes(der).blocks[0].source).toBe('der')
    expect(parseInputBytes(new TextEncoder().encode(ISRG_ROOT_X2_PEM)).blocks[0].der).toEqual(der)
    expect(parseInputText('not a cert').blocks).toHaveLength(0)
  })

  it('round-trips PEM encoding', () => {
    const der = parseInputText(ISRG_ROOT_X2_PEM).blocks[0].der
    expect(toPem(der, 'CERTIFICATE')).toBe(ISRG_ROOT_X2_PEM)
  })
})

describe('lint rules on generated certificates', () => {
  it('generated good leaf has only informational findings', () => {
    const c = decodeCertificate(new Uint8Array(pki.leaf.rawData))
    const f = lintCertificate(c, { selfSigned: false })
    expect(f.filter((x) => !['info', 'pass'].includes(x.severity))).toEqual([])
    expect(titles(f)).toContain('Wildcard "*.api.example.test"')
    expect(sanNames(c.extensions).map((s) => `${s.type}:${s.value}`)).toEqual(['DNS:www.example.test', 'DNS:example.test', 'DNS:*.api.example.test', 'IP:192.0.2.10'])
    expect(accessUrls(c.extensions, OID.ocsp)).toEqual(['http://ocsp.example.test'])
  })

  it('bad leaf triggers the expected rules', () => {
    const c = decodeCertificate(new Uint8Array(pki.badLeaf.rawData))
    const t = titles(lintCertificate(c, { selfSigned: false }))
    expect(t).toContain('Expired')
    expect(t).toContain('Serial number has only 13 significant bits')
    expect(t).toContain('Missing Authority Key Identifier')
    expect(t).toContain('CA:TRUE without keyCertSign')
    expect(t).toContain('Leaf-looking certificate with CA:TRUE')
    expect(t).toContain('Invalid wildcard "f*.example.test"')
    expect(t).toContain('Basic Constraints not critical on a CA')
  })

  it('flags a TLS leaf: no SAN, CN not in SAN, serverAuth missing, long validity, self-signed', async () => {
    const keys = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const mk = async (exts: x509.Extension[], days = 90, nb = new Date()) =>
      decodeCertificate(
        new Uint8Array(
          (
            await x509.X509CertificateGenerator.create({
              serialNumber: '7f112233445566778899',
              subject: 'CN=app.example.com',
              issuer: 'CN=Some CA',
              notBefore: nb,
              notAfter: new Date(nb.getTime() + days * 86_400_000),
              publicKey: keys.publicKey,
              signingKey: keys.privateKey,
              signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
              extensions: exts,
            })
          ).rawData,
        ),
      )
    const aki = await x509.AuthorityKeyIdentifierExtension.create(keys.publicKey)
    const noSan = await mk([aki, new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth])])
    expect(titles(lintCertificate(noSan, { selfSigned: false }))).toContain('TLS certificate without Subject Alternative Name')

    const cnNotInSan = await mk([aki, new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'other.example.com' }])])
    const t2 = titles(lintCertificate(cnNotInSan, { selfSigned: false }))
    expect(t2).toContain('CN "app.example.com" is not in the SAN')
    expect(t2).toContain('No Extended Key Usage')

    const clientOnly = await mk([aki, new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth]), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'app.example.com' }])])
    expect(titles(lintCertificate(clientOnly, { selfSigned: false }))).toContain('EKU missing serverAuth on a TLS-looking certificate')

    const long = await mk([aki, new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'app.example.com' }])], 250, new Date('2026-06-01'))
    expect(titles(lintCertificate(long, { selfSigned: false, now: new Date('2026-07-01') }))).toContain('Validity 250 days exceeds the 200-day CA/B Forum limit')

    const ss = await mk([new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'app.example.com' }])])
    expect(titles(lintCertificate(ss, { selfSigned: true }))).toContain('Self-signed end-entity certificate')

    const crit = await mk([aki, new x509.Extension('1.2.3.4.5', true, new Uint8Array([5, 0]))])
    expect(titles(lintCertificate(crit, { selfSigned: false }))).toContain('Unknown critical extension 1.2.3.4.5')
  })

  it('flags small RSA keys and non-standard curves', async () => {
    const rsa = (await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: 'CN=weak', keys: rsa, signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5' } })
    const c = decodeCertificate(new Uint8Array(cert.rawData))
    expect(c.publicKey.bits).toBe(1024)
    expect(titles(lintCertificate(c))).toContain('RSA key of 1024 bits')
    const k1 = { ...c, publicKey: { ...c.publicKey, type: 'EC', curve: 'secp256k1', bits: 256 } }
    expect(titles(lintCertificate(k1))).toContain('EC curve secp256k1 is not widely supported')
    const sha1 = { ...c, signatureAlg: { oid: '1.2.840.113549.1.1.5', name: 'sha1WithRSAEncryption', hash: 'SHA-1', weak: 'sha1' as const } }
    expect(titles(lintCertificate(sha1, { selfSigned: false }))).toContain('Weak signature hash: sha1WithRSAEncryption')
  })

  it('validity schedule follows CA/B BR + SC-081', () => {
    expect(maxTlsValidityDays(new Date('2020-08-31T23:59:59Z'))).toBeUndefined()
    expect(maxTlsValidityDays(new Date('2020-09-01T00:00:00Z'))).toBe(398)
    expect(maxTlsValidityDays(new Date('2026-03-14T23:59:59Z'))).toBe(398)
    expect(maxTlsValidityDays(new Date('2026-03-15T00:00:00Z'))).toBe(200)
    expect(maxTlsValidityDays(new Date('2027-03-15T00:00:00Z'))).toBe(100)
    expect(maxTlsValidityDays(new Date('2029-03-15T00:00:00Z'))).toBe(47)
    expect(validityDays({ notBefore: new Date(0), notAfter: new Date(86_400_000 - 1000) })).toBe(1)
  })
})
