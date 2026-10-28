import { describe, expect, it } from 'vitest'
import { parseSecurityTxt, securityTxtFindings, stripPgpSignature } from './securitytxt'

const NOW = Date.parse('2026-10-28T12:00:00Z')

const SIGNED = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

# Our security policy
Contact: mailto:security@example.com
Contact: https://example.com/security/report
Expires: 2027-06-30T22:00:00.000Z
Encryption: https://example.com/pgp-key.txt
Preferred-Languages: en, fr
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security/policy
Acknowledgements: https://example.com/hall-of-fame
# end of file
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE...
-----END PGP SIGNATURE-----
`

describe('security.txt', () => {
  it('parses a signed RFC 9116 file', () => {
    const s = parseSecurityTxt(SIGNED)
    expect(s.signed).toBe(true)
    expect(s.contact).toEqual(['mailto:security@example.com', 'https://example.com/security/report'])
    expect(s.expires).toEqual(['2027-06-30T22:00:00.000Z'])
    expect(s.encryption).toEqual(['https://example.com/pgp-key.txt'])
    expect(s.acknowledgments).toEqual(['https://example.com/hall-of-fame'])
    expect(s.preferredLanguages).toEqual(['en, fr'])
    expect(s.invalidLines).toBe(0)
    const f = securityTxtFindings(s, NOW, 'https://example.com/.well-known/security.txt')
    expect(f.filter((x) => x.severity !== 'pass' && x.severity !== 'info')).toEqual([])
  })

  it('removes dash-escaping in signed bodies', () => {
    expect(stripPgpSignature('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n- -----x\nContact: a\n-----BEGIN PGP SIGNATURE-----\nxx').body).toBe('-----x\nContact: a')
  })

  it('flags expired, missing and malformed fields', () => {
    const expired = securityTxtFindings(parseSecurityTxt('Contact: mailto:a@b.c\nExpires: 2025-01-01T00:00:00Z'), NOW)
    expect(expired.find((f) => f.severity === 'high')?.title).toBe('security.txt expired on 2025-01-01')
    const empty = securityTxtFindings(parseSecurityTxt('# nothing\nhello world\n'), NOW).map((f) => `${f.severity}:${f.title}`)
    expect(empty).toContain('high:security.txt has no Contact field')
    expect(empty).toContain('medium:security.txt has no Expires field')
    expect(empty).toContain('low:1 malformed line(s)')
    const far = securityTxtFindings(parseSecurityTxt('Contact: http://x.example\nExpires: 2030-01-01T00:00:00Z'), NOW).map((f) => f.title)
    expect(far).toContain('Expires is more than a year ahead')
    expect(far.some((t) => t.includes('is not a mailto:, https: or tel: URI'))).toBe(true)
    const legacy = securityTxtFindings(parseSecurityTxt('Contact: mailto:a@b.c\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://other.example/.well-known/security.txt'), NOW, 'https://example.com/security.txt', true).map((f) => f.title)
    expect(legacy).toContain('security.txt served from the legacy location')
    expect(legacy).toContain('Canonical does not list this URL')
    expect(securityTxtFindings(parseSecurityTxt('Contact: a\nExpires: soon'), NOW).some((f) => f.title.startsWith('Invalid Expires'))).toBe(true)
  })

  it('is linear on hostile input', () => {
    const t0 = performance.now()
    parseSecurityTxt(':'.repeat(100000) + '\n' + 'a'.repeat(100000) + ':' + ' '.repeat(100000))
    parseSecurityTxt('-----BEGIN PGP SIGNED MESSAGE-----\n' + 'Hash: x\n'.repeat(20000))
    expect(performance.now() - t0).toBeLessThan(500)
  })
})
