/** Regression tests for defects found in the independent review of the PKI module. */
import { beforeAll, describe, expect, it } from 'vitest'
import { buildChains, MAX_BUNDLE } from './chain'
import { decodeCertificate, fingerprints } from './cert'
import { decodeCrl } from './crl'
import { decodeCsr } from './csr'
import { decodeTime, parseDer } from './der'
import { EMPTY_SUBJECT, opensslReqCommand } from './generate'
import { lintCertificate } from './lint'
import { parseInputText, parsePem } from './pem'
import { ISRG_ROOT_X1_PEM, ISRG_ROOT_X2_PEM, LE_R12_PEM, LE_R12_SHA256 } from './publicCerts'
import type { SamplePki } from './samples'
import { generateSamplePki } from './samples'
import { x509 } from './x509'

let pki: SamplePki
beforeAll(async () => {
  pki = await generateSamplePki()
})

const der = (pem: string) => parseInputText(pem).blocks[0].der
const withTrailing = (d: Uint8Array) => new Uint8Array([...d, 0x05, 0x00, 0x0a])

describe('PEM scanner is linear on adversarial input', () => {
  it('thousands of unterminated BEGIN lines (same label) do not cause a quadratic END search', () => {
    const text = '-----BEGIN X-----\n'.repeat(60_000)
    const t = performance.now()
    const r = parsePem(text)
    // Work is capped by maxNodes (~0.9 s flat from 125 KB to 1 MB); generous bound for loaded CI runners.
    expect(performance.now() - t).toBeLessThan(5000)
    expect(r.blocks).toHaveLength(0)
    // Warnings are de-duplicated and capped (the UI renders one callout per warning).
    expect(r.warnings.length).toBeLessThanOrEqual(20)
  })

  it('unique labels and BEGIN markers without closing dashes stay fast', () => {
    let s = ''
    for (let i = 0; i < 40_000; i++) s += `-----BEGIN A${i}-----\n`
    s += '-----BEGIN ' + 'A'.repeat(500_000)
    const t = performance.now()
    parsePem(s)
    // Work is capped by maxNodes (~0.9 s flat from 125 KB to 1 MB); generous bound for loaded CI runners.
    expect(performance.now() - t).toBeLessThan(5000)
  })

  it('a truncated block does not swallow the following complete block', () => {
    const half = ISRG_ROOT_X1_PEM.slice(0, 300)
    const r = parsePem(`${half}\n${ISRG_ROOT_X1_PEM}${LE_R12_PEM}`)
    expect(r.blocks).toHaveLength(2)
    expect(r.blocks[0].der).toEqual(der(ISRG_ROOT_X1_PEM))
    expect(r.warnings.join(' ')).toContain('truncated')
    expect(parsePem(`${ISRG_ROOT_X1_PEM}${LE_R12_PEM}`).blocks).toHaveLength(2)
  })
})

describe('DER walker encapsulation budget', () => {
  it('nested OCTET STRINGs with a bad trailing byte at every level do not re-walk the subtree per level', () => {
    // L_k = OCTET STRING( L_{k+1} || NULL || 0xff ): every encapsulation attempt fails at its last byte.
    let inner: number[] = [0x04, 0x00]
    for (let k = 0; k < 60; k++) {
      const c = [...inner, 0x05, 0x00, 0xff]
      const len = c.length
      const hdr = len < 128 ? [len] : len < 256 ? [0x81, len] : len < 65536 ? [0x82, len >> 8, len & 255] : [0x83, len >> 16, (len >> 8) & 255, len & 255]
      inner = [0x04, ...hdr, ...c]
    }
    const unit = new Uint8Array(inner)
    const b = new Uint8Array(Math.ceil(1_000_000 / unit.length) * unit.length)
    for (let o = 0; o < b.length; o += unit.length) b.set(unit, o)
    const t = performance.now()
    const r = parseDer(b, { maxNodes: 20_000 })
    // Work is capped by maxNodes (~0.9 s flat from 125 KB to 1 MB); generous bound for loaded CI runners.
    expect(performance.now() - t).toBeLessThan(5000)
    expect(r.nodes.length).toBeGreaterThan(0)
  })

  it('still expands encapsulated extension values of a real certificate', () => {
    const r = parseDer(der(LE_R12_PEM))
    let encapsulated = 0
    const walk = (ns: typeof r.nodes) => {
      for (const n of ns) {
        if (n.encapsulated) encapsulated++
        if (n.children) walk(n.children)
      }
    }
    walk(r.nodes)
    expect(encapsulated).toBeGreaterThan(3)
  })
})

describe('trailing bytes after a DER object are ignored', () => {
  it('certificate fingerprint and DER are unaffected', async () => {
    const info = decodeCertificate(withTrailing(der(LE_R12_PEM)))
    expect((await fingerprints(info)).sha256).toBe(LE_R12_SHA256)
    expect(info.der.length).toBe(der(LE_R12_PEM).length)
  })

  it('CSR and CRL keep exactly their own bytes', () => {
    const csr = der(pki.pem.csr)
    expect(decodeCsr(withTrailing(csr)).der).toEqual(csr)
    const crl = der(pki.pem.crl)
    const decoded = decodeCrl(withTrailing(crl))
    expect(decoded.der).toEqual(crl)
    expect(decoded.entries).toHaveLength(3)
  })

  it('rejects a BER indefinite-length CRL with a clear message', () => {
    expect(() => decodeCrl(new Uint8Array([0x30, 0x80, 0x30, 0x00, 0x00, 0x00]))).toThrow(/Indefinite/)
  })
})

describe('time decoding', () => {
  it('GeneralizedTime years below 100 are not mapped to the 1900s', () => {
    const enc = (s: string) => new TextEncoder().encode(s)
    expect(decodeTime(24, enc('00500101000000Z')).getUTCFullYear()).toBe(50)
    expect(decodeTime(24, enc('99991231235959Z')).toISOString()).toBe('9999-12-31T23:59:59.000Z')
    expect(decodeTime(23, enc('491231235959Z')).toISOString()).toBe('2049-12-31T23:59:59.000Z')
  })

  it('rejects out-of-range fields instead of rolling them over', () => {
    const enc = (s: string) => new TextEncoder().encode(s)
    expect(() => decodeTime(24, enc('20231301000000Z'))).toThrow()
    expect(() => decodeTime(24, enc('20230230000000Z'))).toThrow()
    expect(() => decodeTime(23, enc('230101240000Z'))).toThrow()
    expect(decodeTime(24, enc('20240229120000Z')).toISOString()).toBe('2024-02-29T12:00:00.000Z')
  })
})

describe('serial entropy lint', () => {
  it('does not claim a 57–63 bit serial cannot hold 64 random bits; still flags short serials', async () => {
    const keys = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
    const aki = await x509.AuthorityKeyIdentifierExtension.create(keys.publicKey)
    const mk = async (serialNumber: string) =>
      decodeCertificate(
        new Uint8Array(
          (
            await x509.X509CertificateGenerator.create({
              serialNumber,
              subject: 'CN=app.example.com',
              issuer: 'CN=Some CA',
              notBefore: new Date(),
              notAfter: new Date(Date.now() + 90 * 86_400_000),
              publicKey: keys.publicKey,
              signingKey: keys.privateKey,
              signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
              extensions: [aki, new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'app.example.com' }])],
            })
          ).rawData,
        ),
      )
    const sixty = lintCertificate(await mk('0fedcba987654321'), { selfSigned: false })
    const s60 = sixty.find((f) => f.title.startsWith('Serial number has'))
    expect(s60?.severity).toBe('info')
    const short = lintCertificate(await mk('00ffeeddccbbaa'), { selfSigned: false })
    expect(short.find((f) => f.title.startsWith('Serial number has only'))?.severity).toBe('medium')
    const full = lintCertificate(await mk('7f112233445566778899aabb'), { selfSigned: false })
    expect(full.some((f) => f.title.startsWith('Serial number has'))).toBe(false)
  })
})

describe('chain builder', () => {
  it('reports an unrelated root as unused instead of a one-certificate chain', async () => {
    const r = await buildChains([ISRG_ROOT_X2_PEM, ISRG_ROOT_X1_PEM, LE_R12_PEM].map(der), { now: new Date('2026-01-01') })
    expect(r.chains).toHaveLength(1)
    expect(r.chains[0].links.map((l) => l.info.subjectString.split('CN=')[1])).toEqual(['R12', 'ISRG Root X1'])
    expect(r.unused).toHaveLength(1)
  })

  it('a bundle of only a root is still shown as a chain', async () => {
    const r = await buildChains([der(ISRG_ROOT_X1_PEM)])
    expect(r.chains).toHaveLength(1)
    expect(r.chains[0].complete).toBe(true)
  })

  it('caps very large bundles (worst case is O(n²) signature checks)', async () => {
    const leaf = der(pki.pem.leaf)
    let calls = 0
    const r = await buildChains(Array.from({ length: MAX_BUNDLE + 50 }, () => leaf), {
      verify: async () => {
        calls++
        return { ok: false }
      },
    })
    expect(r.parseErrors.join(' ')).toContain(`only the first ${MAX_BUNDLE}`)
    expect(calls).toBeLessThan(10)
  })
})

describe('openssl req command', () => {
  it('names wildcard key files "wildcard…" instead of "_…"', () => {
    const cmd = opensslReqCommand({ keyType: 'P-256', hash: 'SHA-256', subject: { ...EMPTY_SUBJECT, CN: '*.example.com' }, sans: [] })
    expect(cmd).toContain("-keyout 'wildcard.example.com.key'")
  })
})
