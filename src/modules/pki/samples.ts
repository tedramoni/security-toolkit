/**
 * Runtime-generated sample PKI (root → intermediate → leaf, plus a "bad" leaf and a CRL). Keys are created fresh
 * in WebCrypto each time and never leave the page — nothing here is a real system's key.
 */
import { randomSerialHex } from './generate'
import { toPem } from './pem'
import { x509 } from './x509'

export interface SamplePki {
  root: x509.X509Certificate
  intermediate: x509.X509Certificate
  leaf: x509.X509Certificate
  badLeaf: x509.X509Certificate
  crl: x509.X509Crl
  csr: x509.Pkcs10CertificateRequest
  leafKeys: CryptoKeyPair
  intermediateKeys: CryptoKeyPair
  rootKeys: CryptoKeyPair
  pem: { root: string; intermediate: string; leaf: string; badLeaf: string; crl: string; csr: string }
}

const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const
const SIG = { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams
const DAY = 86_400_000

async function ecKeys(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair
}

export async function generateSamplePki(now = new Date()): Promise<SamplePki> {
  const [rootKeys, intermediateKeys, leafKeys, badKeys] = await Promise.all([ecKeys(), ecKeys(), ecKeys(), ecKeys()])
  const t = now.getTime()

  const root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerialHex(),
    name: 'C=ZZ, O=Example Test PKI, CN=Example Test Root CA',
    notBefore: new Date(t - 30 * DAY),
    notAfter: new Date(t + 3650 * DAY),
    keys: rootKeys,
    signingAlgorithm: SIG,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(rootKeys.publicKey),
    ],
  })

  const intermediate = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialHex(),
    subject: 'C=ZZ, O=Example Test PKI, CN=Example Test Issuing CA 1',
    issuer: root.subject,
    notBefore: new Date(t - 20 * DAY),
    notAfter: new Date(t + 1825 * DAY),
    publicKey: intermediateKeys.publicKey,
    signingKey: rootKeys.privateKey,
    signingAlgorithm: SIG,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth]),
      await x509.SubjectKeyIdentifierExtension.create(intermediateKeys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(rootKeys.publicKey),
      new x509.AuthorityInfoAccessExtension({ caIssuers: 'http://pki.example.test/root.cer' }),
      new x509.CRLDistributionPointsExtension(['http://pki.example.test/root.crl']),
    ],
  })

  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialHex(),
    subject: 'CN=www.example.test',
    issuer: intermediate.subject,
    notBefore: new Date(t - 2 * DAY),
    notAfter: new Date(t + 88 * DAY),
    publicKey: leafKeys.publicKey,
    signingKey: intermediateKeys.privateKey,
    signingAlgorithm: SIG,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension([
        { type: 'dns', value: 'www.example.test' },
        { type: 'dns', value: 'example.test' },
        { type: 'dns', value: '*.api.example.test' },
        { type: 'ip', value: '192.0.2.10' },
      ]),
      await x509.SubjectKeyIdentifierExtension.create(leafKeys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(intermediateKeys.publicKey),
      new x509.AuthorityInfoAccessExtension({ ocsp: 'http://ocsp.example.test', caIssuers: 'http://pki.example.test/issuing-ca-1.cer' }),
      new x509.CRLDistributionPointsExtension(['http://pki.example.test/issuing-ca-1.crl']),
      new x509.CertificatePolicyExtension(['2.23.140.1.2.1']),
    ],
  })

  // Deliberately bad: expired, 2-byte serial, 800-day validity, CA:TRUE without keyCertSign, CN not in SAN, no AKI.
  const badLeaf = await x509.X509CertificateGenerator.create({
    serialNumber: '1001',
    subject: 'CN=legacy.example.test, O=Example Test PKI',
    issuer: intermediate.subject,
    notBefore: new Date(Date.UTC(2023, 0, 1)),
    notAfter: new Date(Date.UTC(2023, 0, 1) + 800 * DAY),
    publicKey: badKeys.publicKey,
    signingKey: intermediateKeys.privateKey,
    signingAlgorithm: SIG,
    extensions: [
      new x509.BasicConstraintsExtension(true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth]),
      new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'old.example.test' }, { type: 'dns', value: 'f*.example.test' }]),
    ],
  })

  const crl = await x509.X509CrlGenerator.create({
    issuer: intermediate.subject,
    thisUpdate: new Date(t - DAY),
    nextUpdate: new Date(t + 6 * DAY),
    signingKey: intermediateKeys.privateKey,
    signingAlgorithm: SIG,
    extensions: [await x509.AuthorityKeyIdentifierExtension.create(intermediateKeys.publicKey), new x509.Extension('2.5.29.20', false, new Uint8Array([0x02, 0x01, 0x2a]))],
    entries: [
      { serialNumber: '1001', revocationDate: new Date(t - 3 * DAY), reason: x509.X509CrlReason.keyCompromise },
      { serialNumber: '0a1b2c3d4e5f', revocationDate: new Date(t - 10 * DAY), reason: x509.X509CrlReason.superseded },
      { serialNumber: '77', revocationDate: new Date(t - 40 * DAY) },
    ],
  })

  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: 'CN=shop.example.test, O=Example Test PKI, C=ZZ',
    keys: leafKeys,
    signingAlgorithm: SIG,
    // Deliberately omits the CN from the SAN so the CSR linter has something to report.
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'www.shop.example.test' }])],
  })

  return {
    root,
    intermediate,
    leaf,
    badLeaf,
    crl,
    csr,
    leafKeys,
    intermediateKeys,
    rootKeys,
    pem: {
      root: root.toString('pem'),
      intermediate: intermediate.toString('pem'),
      leaf: leaf.toString('pem'),
      badLeaf: badLeaf.toString('pem'),
      // OpenSSL's label is "X509 CRL" (the library would emit "CRL").
      crl: toPem(new Uint8Array(crl.rawData), 'X509 CRL'),
      csr: csr.toString('pem'),
    },
  }
}

let cached: Promise<SamplePki> | undefined

/** One shared sample PKI per page load so every tab's sample data is consistent (chain, CRL, OCSP, key match). */
export function getSamplePki(): Promise<SamplePki> {
  if (!cached) {
    cached = generateSamplePki()
    cached.catch(() => {
      cached = undefined
    })
  }
  return cached
}
