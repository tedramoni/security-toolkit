import { describe, expect, it } from 'vitest'
import type { CiOptions } from './generators.ts'
import {
  CODEQL_LANGUAGES,
  DEFAULT_OPTIONS,
  DEPENDABOT_ECOSYSTEMS,
  bundle,
  codeqlWorkflow,
  dependabotConfig,
  dependencyReviewWorkflow,
  generateAll,
  gitleaksWorkflow,
  normalizeOptions,
  safeBranch,
  safeContext,
  safeDirectory,
  scorecardWorkflow,
  semgrepWorkflow,
  trivyWorkflow,
} from './generators.ts'
import { ACTIONS } from './versions.ts'

const ALL_ON: CiOptions = normalizeOptions({
  ...DEFAULT_OPTIONS,
  codeql: { ...DEFAULT_OPTIONS.codeql, languages: [...CODEQL_LANGUAGES] },
  dependabot: { ...DEFAULT_OPTIONS.dependabot, ecosystems: [...DEPENDABOT_ECOSYSTEMS] },
  semgrep: { enabled: true, config: 'p/owasp-top-ten' },
  trivy: { ...DEFAULT_OPTIONS.trivy, enabled: true, image: true },
  scorecard: { enabled: true, publishResults: true },
})

/**
 * Structural YAML checks for the block-style subset we generate: no tabs, no trailing spaces,
 * 2-space indentation, children only under "key:" or "- " lines, and balanced ${{ }}.
 * (The generated output was additionally verified with the `yaml` npm parser during development;
 * it is not a project dependency.)
 */
function yamlProblems(text: string): string[] {
  const problems: string[] = []
  const lines = text.split('\n')
  let prevIndent = 0
  let prevOpens = true // a line ending with ':' (or a list item) may be followed by deeper indentation
  lines.forEach((line, i) => {
    const n = i + 1
    if (line.includes('\t')) problems.push(`${n}: tab`)
    if (/ +$/.test(line)) problems.push(`${n}: trailing space`)
    if (line.trim() === '' || line.trimStart().startsWith('#')) return
    const indent = line.length - line.trimStart().length
    if (indent % 2 !== 0) problems.push(`${n}: odd indentation`)
    if (indent > prevIndent && !prevOpens) problems.push(`${n}: unexpected indentation`)
    if (indent > prevIndent + 4) problems.push(`${n}: indentation jump`)
    const body = line.trim().replace(/\s+#.*$/, '')
    const opens = (body.match(/\$\{\{/g) ?? []).length
    const closes = (body.match(/\}\}/g) ?? []).length
    if (opens !== closes) problems.push(`${n}: unbalanced expression`)
    prevIndent = indent + (body.startsWith('- ') ? 2 : 0)
    prevOpens = body.endsWith(':') || body.startsWith('- ')
    if (body.startsWith('- ') && !body.endsWith(':')) prevOpens = /^- [\w-]+: /.test(body)
  })
  return problems
}

/** Top-level keys of a generated document. */
function topKeys(text: string): string[] {
  return text
    .split('\n')
    .filter((l) => /^[a-z][\w-]*:/.test(l))
    .map((l) => l.split(':')[0])
}

describe('generated files are structurally valid YAML', () => {
  const files = generateAll(ALL_ON)
  it('generates every selected file', () => {
    expect(files.map((f) => f.path)).toEqual([
      '.github/workflows/codeql.yml',
      '.github/dependabot.yml',
      '.github/workflows/dependency-review.yml',
      '.github/workflows/gitleaks.yml',
      '.github/workflows/semgrep.yml',
      '.github/workflows/trivy.yml',
      '.github/workflows/scorecard.yml',
    ])
  })
  it.each(files.map((f) => [f.path, f.content]))('%s', (_path, content) => {
    expect(yamlProblems(content)).toEqual([])
    expect(content.endsWith('\n')).toBe(true)
  })
  it('the checker catches broken YAML', () => {
    expect(yamlProblems('a:\n\tb: 1\n')).toContain('2: tab')
    expect(yamlProblems('a: 1\n   b: 2\n')).toContain('2: odd indentation')
    expect(yamlProblems('a: 1\n  b: 2\n')).toContain('2: unexpected indentation')
    expect(yamlProblems('x: ${{ github.sha }\n')).toContain('1: unbalanced expression')
  })
})

describe('workflows use least privilege', () => {
  const workflows = generateAll(ALL_ON).filter((f) => f.path.startsWith('.github/workflows/'))
  it.each(workflows.map((f) => [f.path, f.content]))('%s has read-only top-level permissions', (_p, content) => {
    expect(topKeys(content)).toEqual(['name', 'on', 'permissions', 'jobs'])
    expect(content).toMatch(/\npermissions:\n {2}contents: read\n\njobs:/)
    expect(content).not.toMatch(/write-all|read-all/)
    // write scopes only appear in job-level blocks (4+ spaces of indentation)
    for (const line of content.split('\n')) if (/: write/.test(line)) expect(line).toMatch(/^ {6}\S/)
    // checkout never leaves the token on disk
    const checkouts = content.match(/uses: actions\/checkout@/g)?.length ?? 0
    expect(content.match(/persist-credentials: false/g)?.length ?? 0).toBe(checkouts)
  })
  it('pins every action to the verified ref, never to a branch or fabricated SHA', () => {
    for (const f of workflows) {
      for (const m of f.content.matchAll(/uses: (\S+)@(\S+)/g)) {
        const ref = Object.values(ACTIONS).find((a) => a.uses === m[1])
        expect(ref, m[1]).toBeDefined()
        expect(m[2]).toBe(ref!.ref)
        expect(m[2]).not.toMatch(/^[0-9a-f]{40}$|^main$|^master$/)
      }
    }
  })
})

describe('CodeQL', () => {
  it('builds a matrix with correct build modes and suite', () => {
    const o = normalizeOptions({ ...DEFAULT_OPTIONS, codeql: { enabled: true, languages: ['python', 'go', 'java-kotlin'], querySuite: 'security-extended' } })
    const c = codeqlWorkflow(o).content
    expect(c).toContain('          - language: python\n            build-mode: none')
    expect(c).toContain('          - language: go\n            build-mode: autobuild')
    expect(c).toContain('          - language: java-kotlin\n            build-mode: none')
    expect(c).toContain('queries: security-extended')
    expect(c).toContain('      security-events: write')
    expect(c).toContain("    - cron: '27 3 * * 1'")
    expect(c).toContain('runs-on: ubuntu-latest')
    expect(c).toContain(`uses: github/codeql-action/init@${ACTIONS.codeqlInit.ref}`)
  })
  it('uses macOS for Swift and omits queries for the default suite', () => {
    const o = normalizeOptions({ ...DEFAULT_OPTIONS, codeql: { enabled: true, languages: ['swift', 'ruby'], querySuite: 'default' } })
    const c = codeqlWorkflow(o).content
    expect(c).toContain('runs-on: ${{ matrix.runner }}')
    expect(c).toContain('runner: macos-latest')
    expect(c).not.toContain('queries:')
  })
  it('falls back to default languages when none selected', () => {
    const o = normalizeOptions({ ...DEFAULT_OPTIONS, codeql: { enabled: true, languages: [], querySuite: 'default' } })
    expect(codeqlWorkflow(o).content).toContain('language: javascript-typescript')
  })
})

describe('Dependabot', () => {
  it('emits one update entry per ecosystem with grouping and cooldown', () => {
    const c = dependabotConfig(ALL_ON).content
    expect(c.startsWith('# Dependabot')).toBe(true)
    expect(topKeys(c)).toEqual(['version', 'updates'])
    expect(c.match(/package-ecosystem:/g)).toHaveLength(DEPENDABOT_ECOSYSTEMS.length)
    expect(c).toContain("  - package-ecosystem: 'github-actions'\n    directory: '/'")
    expect(c).toContain('      npm-minor-and-patch:\n        update-types:\n          - \'minor\'\n          - \'patch\'')
    expect(c).toContain('      default-days: 7')
    // group identifiers must start and end with a letter
    for (const m of c.matchAll(/^ {6}([\w-]+):$/gm)) expect(m[1]).toMatch(/^[a-z].*[a-z]$/)
  })
  it('can disable grouping and cooldown, and validates the directory', () => {
    const o = normalizeOptions({ ...DEFAULT_OPTIONS, dependabot: { ...DEFAULT_OPTIONS.dependabot, ecosystems: ['pip'], groupMinorPatch: false, cooldownDays: 0, directory: "/app'\nevil: x" } })
    const f = dependabotConfig(o)
    expect(f.content).not.toContain('groups:')
    expect(f.content).not.toContain('cooldown:')
    expect(f.content).toContain("directory: '/'")
    expect(f.notes.join(' ')).toMatch(/github-actions/)
  })
})

describe('other workflows', () => {
  it('dependency review: fail-on-severity and PR comment permission', () => {
    const on = dependencyReviewWorkflow(normalizeOptions({ ...DEFAULT_OPTIONS, dependencyReview: { enabled: true, failOnSeverity: 'critical', commentInPr: true } })).content
    expect(on).toContain('fail-on-severity: critical')
    expect(on).toContain('pull-requests: write')
    expect(on).toContain('comment-summary-in-pr: on-failure')
    const off = dependencyReviewWorkflow(normalizeOptions({ ...DEFAULT_OPTIONS, dependencyReview: { enabled: true, failOnSeverity: 'low', commentInPr: false } })).content
    expect(off).not.toContain('pull-requests')
    expect(off).not.toContain('comment-summary')
  })
  it('gitleaks: full history and optional license', () => {
    const org = gitleaksWorkflow(ALL_ON).content
    expect(org).toContain('fetch-depth: 0')
    expect(org).toContain('GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}')
    expect(org).toMatch(/on:\n {2}push:\n {2}pull_request:/)
    const personal = gitleaksWorkflow(normalizeOptions({ ...DEFAULT_OPTIONS, gitleaks: { enabled: true, organization: false } })).content
    expect(personal).not.toContain('GITLEAKS_LICENSE')
  })
  it('semgrep: container, SARIF upload, metrics handling', () => {
    const c = semgrepWorkflow(ALL_ON).content
    expect(c).toContain('image: semgrep/semgrep')
    expect(c).toContain('run: semgrep scan --config p/owasp-top-ten --sarif --output semgrep.sarif --metrics=off')
    expect(c).toContain('sarif_file: semgrep.sarif')
    const auto = semgrepWorkflow(normalizeOptions({ ...DEFAULT_OPTIONS, semgrep: { enabled: true, config: 'auto' } }))
    expect(auto.content).not.toContain('--metrics=off')
    expect(auto.notes.join(' ')).toMatch(/metrics/)
  })
  it('trivy: fs + image jobs with SARIF and severity filter', () => {
    const f = trivyWorkflow(ALL_ON)
    expect(f.content).toContain('  trivy-fs:')
    expect(f.content).toContain('  trivy-image:')
    expect(f.content).toContain('scan-type: fs')
    expect(f.content).toContain('image-ref: local/app:${{ github.sha }}')
    expect(f.content).toContain('run: docker build -t local/app:${{ github.sha }} .')
    expect(f.content).toContain('limit-severities-for-sarif: true')
    expect(f.content).toContain('severity: CRITICAL,HIGH')
    expect(f.content).toContain("exit-code: '0'")
    expect(f.notes[0]).toMatch(/SHA/)
    const onlyImage = trivyWorkflow(normalizeOptions({ ...DEFAULT_OPTIONS, trivy: { ...DEFAULT_OPTIONS.trivy, enabled: true, filesystem: false, image: true, imageContext: '; rm -rf /', failBuild: true } }))
    expect(onlyImage.content).not.toContain('trivy-fs:')
    expect(onlyImage.content).toContain('docker build -t local/app:${{ github.sha }} .\n')
    expect(onlyImage.content).toContain("exit-code: '1'")
  })
  it('scorecard: id-token only when publishing', () => {
    expect(scorecardWorkflow(ALL_ON).content).toContain('id-token: write')
    expect(scorecardWorkflow(ALL_ON).content).toContain('publish_results: true')
    expect(scorecardWorkflow(ALL_ON).content).not.toContain('run:')
    const priv = scorecardWorkflow(normalizeOptions({ ...DEFAULT_OPTIONS, scorecard: { enabled: true, publishResults: false } })).content
    expect(priv).not.toContain('id-token')
    expect(priv).toContain('publish_results: false')
  })
})

describe('options handling', () => {
  it('pin-to-SHA adds guidance but never a SHA', () => {
    const pinned = codeqlWorkflow({ ...ALL_ON, pinSha: true }).content
    expect(pinned).toContain('pinact run')
    expect(pinned).not.toMatch(/@[0-9a-f]{40}/)
    expect(codeqlWorkflow({ ...ALL_ON, pinSha: false }).content).not.toContain('pinact')
  })
  it('normalizeOptions repairs junk and keeps valid values', () => {
    expect(normalizeOptions(null)).toEqual(DEFAULT_OPTIONS)
    expect(normalizeOptions('x')).toEqual(DEFAULT_OPTIONS)
    const o = normalizeOptions({ codeql: { languages: ['python', 'cobol'], querySuite: 'bogus' }, dependabot: { cooldownDays: 999 } })
    expect(o.codeql.languages).toEqual(['python'])
    expect(o.codeql.querySuite).toBe(DEFAULT_OPTIONS.codeql.querySuite)
    expect(o.dependabot.cooldownDays).toBe(DEFAULT_OPTIONS.dependabot.cooldownDays)
  })
  it('sanitises user-provided strings', () => {
    expect(safeBranch('release/1.x')).toBe('release/1.x')
    expect(safeBranch("main']\non: x")).toBe('main')
    expect(safeBranch('')).toBe('main')
    expect(safeDirectory('/services/api')).toBe('/services/api')
    expect(safeDirectory('services')).toBe('/')
    expect(safeDirectory('/../etc')).toBe('/')
    expect(safeContext('docker/app')).toBe('docker/app')
    expect(safeContext('--build-arg x')).toBe('.')
  })
  it('custom branch appears quoted in triggers', () => {
    expect(codeqlWorkflow({ ...ALL_ON, branch: 'develop' }).content).toContain("branches: ['develop']")
  })
  it('generateAll returns nothing when all disabled; bundle adds path headers', () => {
    const none = normalizeOptions({
      codeql: { enabled: false },
      dependabot: { enabled: false },
      dependencyReview: { enabled: false },
      gitleaks: { enabled: false },
      semgrep: { enabled: false },
      trivy: { enabled: false },
      scorecard: { enabled: false },
    })
    expect(generateAll(none)).toEqual([])
    expect(bundle(generateAll(ALL_ON))).toContain('# ===== .github/dependabot.yml =====\n')
  })
})
