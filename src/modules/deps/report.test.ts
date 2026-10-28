import { describe, expect, it } from 'vitest'
import type { OsvVuln } from './osv.ts'
import { aliasesToEnrich, buildFindings, countBySeverity, csvField, filterFindings, mdText, toCsv, toMarkdown } from './report.ts'
import { compareLoose, deriveSeverity, fixedVersions, maxSeverity } from './severity.ts'
import type { Dependency } from './types.ts'
import { depKey } from './types.ts'

// Trimmed real record (GHSA-35jh-r3h4-6jhm, lodash command injection) as returned by GET /v1/vulns/{id}
const LODASH: OsvVuln = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { severity: 'HIGH', cwe_ids: ['CWE-77', 'CWE-94'] },
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    { package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] },
    { package: { name: 'lodash-es', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] },
  ],
}

const lodash: Dependency = { name: 'lodash', version: '4.17.15', ecosystem: 'npm', dev: false }

describe('deriveSeverity', () => {
  it('prefers the advisory label and still reports the CVSS score', () => {
    expect(deriveSeverity(LODASH)).toEqual({
      level: 'high',
      score: 7.2,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
      source: 'advisory',
    })
  })
  it('maps MODERATE to medium', () => {
    expect(deriveSeverity({ id: 'x', database_specific: { severity: 'MODERATE' } }).level).toBe('medium')
  })
  it('falls back to the CVSS v3 vector (top-level or per affected package)', () => {
    expect(deriveSeverity({ id: 'x', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] })).toMatchObject({
      level: 'critical',
      score: 9.8,
      source: 'cvss3',
    })
    expect(
      deriveSeverity({ id: 'x', affected: [{ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' }] }] }),
    ).toMatchObject({ level: 'medium', score: 5.3 })
  })
  it('is unknown with only CVSS v4 or nothing', () => {
    expect(deriveSeverity({ id: 'x', severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }] }).level).toBe('unknown')
    expect(deriveSeverity({ id: 'x' })).toEqual({ level: 'unknown', source: 'none' })
    expect(deriveSeverity({ id: 'x', database_specific: { severity: 'weird' } }).level).toBe('unknown')
  })
  it('maxSeverity picks the worst', () => {
    expect(maxSeverity([{ level: 'low', source: 'none' }, { level: 'high', score: 7.5, source: 'cvss3' }, { level: 'high', score: 8.1, source: 'cvss3' }]).score).toBe(8.1)
    expect(maxSeverity([]).level).toBe('unknown')
  })
})

describe('compareLoose', () => {
  it.each([
    ['1.2.10', '1.2.9', 1],
    ['1.0', '1.0.0', 0],
    ['1.0', '1.0.1', -1],
    ['1.0.0', '1.0', 0],
    ['1.0.0-rc1', '1.0.0', -1],
    ['2.0.0.RELEASE', '2.0.0', -1],
    ['v1.2.3', '1.2.3', 0],
    ['1.0.0a1', '1.0.0', -1],
    ['10.0', '9.9', 1],
  ])('%s vs %s', (a, b, sign) => {
    expect(Math.sign(compareLoose(a, b))).toBe(sign)
  })
})

describe('fixedVersions', () => {
  it('returns the fix for the matching package only', () => {
    expect(fixedVersions(LODASH, lodash)).toEqual(['4.17.21'])
    expect(fixedVersions(LODASH, { ...lodash, name: 'underscore' })).toEqual([])
  })
  it('picks the fix of the branch containing the installed version', () => {
    const v: OsvVuln = {
      id: 'x',
      affected: [
        {
          package: { name: 'django', ecosystem: 'PyPI' },
          ranges: [
            { type: 'ECOSYSTEM', events: [{ introduced: '3.2' }, { fixed: '3.2.19' }, { introduced: '4.0' }, { fixed: '4.1.9' }, { introduced: '4.2' }, { fixed: '4.2.1' }] },
          ],
        },
      ],
    }
    expect(fixedVersions(v, { name: 'Django', version: '4.1.2', ecosystem: 'PyPI' })).toEqual(['4.1.9'])
    // version outside every interval (e.g. odd version string) -> all fixes, sorted
    expect(fixedVersions(v, { name: 'django', version: '5.0', ecosystem: 'PyPI' })).toEqual(['3.2.19', '4.1.9', '4.2.1'])
  })
  it('ignores GIT ranges and matches ecosystem prefixes', () => {
    const v: OsvVuln = {
      id: 'x',
      affected: [
        { package: { name: 'a', ecosystem: 'npm' }, ranges: [{ type: 'GIT', events: [{ introduced: '0' }, { fixed: 'abcdef' }] }] },
        { package: { name: 'a', ecosystem: 'Maven' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '9' }] }] },
      ],
    }
    expect(fixedVersions(v, { name: 'a', version: '1', ecosystem: 'npm' })).toEqual([])
  })
  it('returns empty when only last_affected is known', () => {
    const v: OsvVuln = { id: 'x', affected: [{ package: { name: 'a', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '2.0.0' }] }] }] }
    expect(fixedVersions(v, { name: 'a', version: '1.0.0', ecosystem: 'npm' })).toEqual([])
  })
})

describe('buildFindings', () => {
  const jinja: Dependency = { name: 'jinja2', version: '2.4.1', ecosystem: 'PyPI', dev: true }
  const GHSA: OsvVuln = {
    id: 'GHSA-462w-v97r-4m45',
    summary: 'Jinja2 sandbox escape',
    aliases: ['CVE-2019-10906', 'PYSEC-2019-217'],
    database_specific: { severity: 'HIGH' },
    affected: [{ package: { name: 'Jinja2', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.10.1' }] }] }],
  }
  const PYSEC: OsvVuln = {
    id: 'PYSEC-2019-217',
    details: 'In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.',
    aliases: ['CVE-2019-10906', 'GHSA-462w-v97r-4m45'],
    affected: [{ package: { name: 'jinja2', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.10.1' }] }] }],
  }
  const OTHER: OsvVuln = { id: 'PYSEC-2014-8', aliases: ['CVE-2014-1402'], details: 'Insecure temp files\nmore', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' }] }
  const vulns = new Map<string, OsvVuln>([
    [LODASH.id, LODASH],
    [GHSA.id, GHSA],
    [PYSEC.id, PYSEC],
    [OTHER.id, OTHER],
    ['GHSA-gone', { id: 'GHSA-gone', withdrawn: '2023-01-01T00:00:00Z' }],
  ])
  const idsByDep = new Map([
    [depKey(lodash), [LODASH.id]],
    [depKey(jinja), [PYSEC.id, GHSA.id, OTHER.id, 'GHSA-gone', 'MISSING-1']],
  ])
  const findings = buildFindings([lodash, jinja], idsByDep, vulns)

  it('merges aliased records, prefers GHSA ids, drops withdrawn records', () => {
    const merged = findings.find((f) => f.ids.includes('GHSA-462w-v97r-4m45'))!
    expect(merged.ids.sort()).toEqual(['GHSA-462w-v97r-4m45', 'PYSEC-2019-217'])
    expect(merged.primaryId).toBe('GHSA-462w-v97r-4m45')
    expect(merged.aliases).toEqual(['CVE-2019-10906'])
    expect(merged.severity.level).toBe('high')
    expect(merged.fixed).toEqual(['2.10.1'])
    expect(findings.some((f) => f.ids.includes('GHSA-gone'))).toBe(false)
  })

  it('uses the first details line when there is no summary and flags missing details', () => {
    expect(findings.find((f) => f.primaryId === 'PYSEC-2014-8')!.summary).toBe('Insecure temp files')
    const missing = findings.find((f) => f.primaryId === 'MISSING-1')!
    expect(missing.detailsMissing).toBe(true)
    expect(missing.severity.level).toBe('unknown')
  })

  it('sorts by severity then score', () => {
    expect(findings.map((f) => f.primaryId)).toEqual(['PYSEC-2014-8', 'GHSA-35jh-r3h4-6jhm', 'GHSA-462w-v97r-4m45', 'MISSING-1'])
    expect(countBySeverity(findings)).toMatchObject({ high: 3, unknown: 1, critical: 0 })
  })

  it('filters by severity, dev and text', () => {
    // unknown-severity findings are never hidden by the threshold (they may be critical)
    expect(filterFindings(findings, { minLevel: 'high', hideDev: false, text: '' })).toHaveLength(4)
    expect(filterFindings(findings, { minLevel: 'critical', hideDev: false, text: '' }).map((f) => f.severity.level)).toEqual(['unknown'])
    expect(filterFindings(findings, { minLevel: 'all', hideDev: true, text: '' }).map((f) => f.dep.name)).toEqual(['lodash'])
    expect(filterFindings(findings, { minLevel: 'all', hideDev: false, text: 'cve-2019' })).toHaveLength(1)
  })

  it('exports Markdown with links and escaped cells', () => {
    const md = toMarkdown(findings, { scannedPackages: 2, sources: ['package-lock.json'], date: '2026-10-28', failedPackages: 1 })
    expect(md).toContain('| high (7.2) | lodash | 4.17.15 | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | CVE-2021-23337 | Command Injection in lodash | 4.17.21 |')
    expect(md).toContain('jinja2 (dev)')
    expect(md).toContain('could not be checked')
    expect(md).toContain('no fix available')
  })

  it('reports an empty result', () => {
    expect(toMarkdown([], { scannedPackages: 3, sources: [], date: 'd', failedPackages: 0 })).toContain('No known vulnerabilities found.')
  })

  it('exports CSV', () => {
    const csv = toCsv(findings)
    const lines = csv.trimEnd().split('\r\n')
    expect(lines[0]).toBe('Severity,CVSS,Package,Version,Ecosystem,Dev,ID,Aliases,Summary,Fixed in,Link')
    expect(lines).toHaveLength(findings.length + 1)
    expect(csv).toContain('high,7.2,lodash,4.17.15,npm,no,GHSA-35jh-r3h4-6jhm,CVE-2021-23337,Command Injection in lodash,4.17.21,https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm')
  })
})

describe('severity enrichment from aliases', () => {
  const GO: OsvVuln = {
    id: 'GO-2024-3333',
    aliases: ['CVE-2024-45338', 'GHSA-w32m-9786-jp63'],
    affected: [{ package: { name: 'golang.org/x/net', ecosystem: 'Go' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.33.0' }] }] }],
  }
  const net: Dependency = { name: 'golang.org/x/net', version: 'v0.17.0', ecosystem: 'Go' }

  it('lists GHSA aliases of unscored records that are not yet downloaded', () => {
    expect(aliasesToEnrich(new Map([[GO.id, GO]]))).toEqual(['GHSA-w32m-9786-jp63'])
    const scored: OsvVuln = { ...GO, id: 'X', database_specific: { severity: 'LOW' } }
    expect(aliasesToEnrich(new Map([[scored.id, scored]]))).toEqual([])
  })

  it('uses the alias severity but keeps the finding identity', () => {
    const ghsa: OsvVuln = { id: 'GHSA-w32m-9786-jp63', database_specific: { severity: 'MODERATE' } }
    const vulns = new Map([
      [GO.id, GO],
      [ghsa.id, ghsa],
    ])
    expect(aliasesToEnrich(vulns)).toEqual([])
    const [f] = buildFindings([net], new Map([[depKey(net), [GO.id]]]), vulns)
    expect(f.primaryId).toBe('GO-2024-3333')
    expect(f.severity.level).toBe('medium')
    expect(f.fixed).toEqual(['0.33.0'])
  })
})

describe('escaping', () => {
  it('csvField quotes and neutralises formulas', () => {
    expect(csvField('plain')).toBe('plain')
    expect(csvField('a,b')).toBe('"a,b"')
    expect(csvField('say "hi"')).toBe('"say ""hi"""')
    expect(csvField('line1\nline2')).toBe('"line1\nline2"')
    expect(csvField('=HYPERLINK("http://evil")')).toBe(`"'=HYPERLINK(""http://evil"")"`)
    expect(csvField('+1')).toBe("'+1")
    expect(csvField('@SUM(A1)')).toBe("'@SUM(A1)")
    expect(csvField('-2')).toBe("'-2")
  })
  it('markdown neutralises HTML and pipes in untrusted text', () => {
    expect(mdText('<img src=x onerror=alert(1)>')).toBe('&lt;img src=x onerror=alert(1)&gt;')
    const md = toMarkdown(
      [
        {
          dep: { name: 'x', version: '1', ecosystem: 'npm' },
          ids: ['BAD](javascript:alert(1))'],
          primaryId: 'BAD](javascript:alert(1))',
          aliases: [],
          summary: 'a | b <script>',
          severity: { level: 'low', source: 'none' },
          fixed: [],
        },
      ],
      { scannedPackages: 1, sources: [], date: 'd', failedPackages: 0 },
    )
    expect(md).toContain('a \\| b &lt;script&gt;')
    expect(md).not.toMatch(/\[[^\]]*\]\(javascript/)
    expect(md).not.toContain('(https://osv.dev/vulnerability/BAD')
  })
  it('markdown neutralises links/images in summaries and fixed versions', () => {
    expect(mdText('[click](https://evil.example)')).toBe('&#91;click&#93;(https://evil.example)')
    const md = toMarkdown(
      [
        {
          dep: { name: 'x', version: '1', ecosystem: 'npm' },
          ids: ['GHSA-aaaa-bbbb-cccc'],
          primaryId: 'GHSA-aaaa-bbbb-cccc',
          aliases: [],
          summary: '![t](https://tracker.example/p.png) see [here](https://evil.example)',
          severity: { level: 'low', source: 'none' },
          fixed: ['<b>2.0</b>', '[x](https://evil.example)'],
        },
      ],
      { scannedPackages: 1, sources: [], date: 'd', failedPackages: 0 },
    )
    expect(md).not.toMatch(/\]\(https:\/\/(evil|tracker)/)
    expect(md).not.toContain('<b>')
    expect(md).toContain('[GHSA-aaaa-bbbb-cccc](https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc)')
  })
})
