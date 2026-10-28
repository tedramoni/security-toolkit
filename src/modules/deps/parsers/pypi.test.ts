import { describe, expect, it } from 'vitest'
import { normalizePyName, parsePipfileLock, parseRequirements } from './pypi.ts'

const REQS = `# production deps
-r base.txt
--index-url https://pypi.org/simple
-e git+https://github.com/org/pkg.git#egg=pkg
Django==3.2.0  # LTS
requests[security,socks]==2.19.1
Flask_SQLAlchemy == 2.5.1
pywin32==306 ; sys_platform == "win32"
cryptography==41.0.0 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
urllib3>=1.26
numpy
pandas==2.*
zope.interface===5.4.0
mypkg @ https://example.com/mypkg-1.0.tar.gz
./local/package
`

describe('parseRequirements', () => {
  const r = parseRequirements(REQS)

  it('extracts exact pins with PEP 503 normalized names', () => {
    expect(r.deps).toEqual([
      { name: 'django', version: '3.2.0', ecosystem: 'PyPI' },
      { name: 'requests', version: '2.19.1', ecosystem: 'PyPI' },
      { name: 'flask-sqlalchemy', version: '2.5.1', ecosystem: 'PyPI' },
      { name: 'pywin32', version: '306', ecosystem: 'PyPI' },
      { name: 'cryptography', version: '41.0.0', ecosystem: 'PyPI' },
      { name: 'zope-interface', version: '5.4.0', ecosystem: 'PyPI' },
    ])
  })

  it('reports unpinned and unsupported lines', () => {
    const reasons = Object.fromEntries(r.skipped.map((s) => [s.entry, s.reason]))
    expect(reasons['urllib3>=1.26']).toBe('skipped: not pinned')
    expect(reasons.numpy).toBe('skipped: not pinned')
    expect(reasons['pandas==2.*']).toMatch(/wildcard/)
    expect(reasons['mypkg @ https://example.com/mypkg-1.0.tar.gz']).toMatch(/URL/)
    expect(reasons['./local/package']).toMatch(/local path/)
  })

  it('ignores options, includes and comments', () => {
    expect(r.skipped.find((s) => s.entry.startsWith('-'))).toBeUndefined()
    expect(r.skipped.find((s) => s.entry.includes('#'))).toBeUndefined()
  })

  it('handles empty input', () => {
    expect(parseRequirements('')).toEqual({ deps: [], skipped: [] })
    expect(parseRequirements('# only a comment\n\n')).toEqual({ deps: [], skipped: [] })
  })
})

describe('normalizePyName', () => {
  it('follows PEP 503', () => {
    expect(normalizePyName('Friendly-Bard')).toBe('friendly-bard')
    expect(normalizePyName('FRIENDLY-BARD')).toBe('friendly-bard')
    expect(normalizePyName('friendly.bard')).toBe('friendly-bard')
    expect(normalizePyName('friendly_bard')).toBe('friendly-bard')
    expect(normalizePyName('friendly--bard')).toBe('friendly-bard')
    expect(normalizePyName('FrIeNdLy-._.-bArD')).toBe('friendly-bard')
  })
})

describe('parsePipfileLock', () => {
  const text = JSON.stringify({
    _meta: { hash: { sha256: 'x' }, 'pipfile-spec': 6 },
    default: { requests: { version: '==2.31.0', hashes: [] }, mylocal: { path: '.', editable: true } },
    develop: { Pytest: { version: '==7.4.0' } },
  })
  it('reads default and develop sections', () => {
    const r = parsePipfileLock(text)
    expect(r.deps).toEqual([
      { name: 'requests', version: '2.31.0', ecosystem: 'PyPI', dev: false },
      { name: 'pytest', version: '7.4.0', ecosystem: 'PyPI', dev: true },
    ])
    expect(r.skipped).toHaveLength(1)
  })
  it('rejects invalid JSON', () => {
    expect(() => parsePipfileLock('nope')).toThrow(/valid JSON/)
  })
})
