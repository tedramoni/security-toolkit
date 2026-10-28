import type { ActionRef } from './versions.ts'
import { ACTIONS, VERIFIED_ON } from './versions.ts'

export const CODEQL_LANGUAGES = [
  'actions',
  'c-cpp',
  'csharp',
  'go',
  'java-kotlin',
  'javascript-typescript',
  'python',
  'ruby',
  'rust',
  'swift',
] as const
export type CodeqlLanguage = (typeof CODEQL_LANGUAGES)[number]

/**
 * Build mode per language (https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/codeql-code-scanning-for-compiled-languages):
 * "none" analyses without building (interpreted languages, and C/C++, C#, Java, Rust);
 * Go and Swift only support autobuild/manual.
 */
export const CODEQL_BUILD_MODE: Record<CodeqlLanguage, 'none' | 'autobuild'> = {
  actions: 'none',
  'c-cpp': 'none',
  csharp: 'none',
  go: 'autobuild',
  'java-kotlin': 'none',
  'javascript-typescript': 'none',
  python: 'none',
  ruby: 'none',
  rust: 'none',
  swift: 'autobuild',
}

export const DEPENDABOT_ECOSYSTEMS = [
  'npm',
  'pip',
  'uv',
  'maven',
  'gradle',
  'gomod',
  'bundler',
  'nuget',
  'composer',
  'cargo',
  'docker',
  'github-actions',
] as const
export type DependabotEcosystem = (typeof DEPENDABOT_ECOSYSTEMS)[number]

export type QuerySuite = 'default' | 'security-extended' | 'security-and-quality'
export type ReviewSeverity = 'low' | 'moderate' | 'high' | 'critical'
export type SemgrepConfig = 'p/default' | 'p/owasp-top-ten' | 'p/ci' | 'auto'
export type TrivySeverity = 'CRITICAL' | 'CRITICAL,HIGH' | 'CRITICAL,HIGH,MEDIUM'

export interface CiOptions {
  branch: string
  pinSha: boolean
  codeql: { enabled: boolean; languages: CodeqlLanguage[]; querySuite: QuerySuite }
  dependabot: {
    enabled: boolean
    ecosystems: DependabotEcosystem[]
    directory: string
    interval: 'daily' | 'weekly' | 'monthly'
    groupMinorPatch: boolean
    /** Days to wait before proposing a freshly published version (0 = no cooldown setting). */
    cooldownDays: number
  }
  dependencyReview: { enabled: boolean; failOnSeverity: ReviewSeverity; commentInPr: boolean }
  gitleaks: { enabled: boolean; organization: boolean }
  semgrep: { enabled: boolean; config: SemgrepConfig }
  trivy: { enabled: boolean; filesystem: boolean; image: boolean; imageContext: string; severity: TrivySeverity; failBuild: boolean }
  scorecard: { enabled: boolean; publishResults: boolean }
}

export const DEFAULT_OPTIONS: CiOptions = {
  branch: 'main',
  pinSha: true,
  codeql: { enabled: true, languages: ['javascript-typescript', 'actions'], querySuite: 'security-extended' },
  dependabot: {
    enabled: true,
    ecosystems: ['npm', 'github-actions'],
    directory: '/',
    interval: 'weekly',
    groupMinorPatch: true,
    cooldownDays: 7,
  },
  dependencyReview: { enabled: true, failOnSeverity: 'high', commentInPr: true },
  gitleaks: { enabled: true, organization: true },
  semgrep: { enabled: false, config: 'p/owasp-top-ten' },
  trivy: { enabled: false, filesystem: true, image: false, imageContext: '.', severity: 'CRITICAL,HIGH', failBuild: false },
  scorecard: { enabled: false, publishResults: true },
}

export interface GeneratedFile {
  id: string
  title: string
  path: string
  content: string
  notes: string[]
}

// ---------------------------------------------------------------- input sanitising

const BRANCH_RE = /^[A-Za-z0-9._/-]{1,100}$/
const DIR_RE = /^\/[A-Za-z0-9._/-]{0,200}$/
const CONTEXT_RE = /^[A-Za-z0-9._/-]{1,200}$/

export function safeBranch(b: string): string {
  const t = b.trim()
  return BRANCH_RE.test(t) && !t.includes('..') ? t : 'main'
}
export function safeDirectory(d: string): string {
  const t = d.trim()
  return DIR_RE.test(t) && !t.includes('..') ? t : '/'
}
export function safeContext(c: string): string {
  const t = c.trim()
  return CONTEXT_RE.test(t) && !t.includes('..') && !t.startsWith('-') ? t : '.'
}

function pickArray<T extends string>(value: unknown, allowed: readonly T[], fallback: T[]): T[] {
  if (!Array.isArray(value)) return fallback
  return allowed.filter((a) => value.includes(a))
}
function pickOne<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.includes(value as T) ? (value as T) : fallback
}
function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback
}
function obj(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

/** Merge persisted (possibly stale or tampered) settings with the defaults. */
export function normalizeOptions(raw: unknown): CiOptions {
  const r = obj(raw)
  const d = DEFAULT_OPTIONS
  const cq = obj(r.codeql)
  const db = obj(r.dependabot)
  const dr = obj(r.dependencyReview)
  const gl = obj(r.gitleaks)
  const sg = obj(r.semgrep)
  const tv = obj(r.trivy)
  const sc = obj(r.scorecard)
  const cooldown = Number(db.cooldownDays)
  return {
    branch: typeof r.branch === 'string' ? r.branch : d.branch,
    pinSha: bool(r.pinSha, d.pinSha),
    codeql: {
      enabled: bool(cq.enabled, d.codeql.enabled),
      languages: pickArray(cq.languages, CODEQL_LANGUAGES, d.codeql.languages),
      querySuite: pickOne(cq.querySuite, ['default', 'security-extended', 'security-and-quality'] as const, d.codeql.querySuite),
    },
    dependabot: {
      enabled: bool(db.enabled, d.dependabot.enabled),
      ecosystems: pickArray(db.ecosystems, DEPENDABOT_ECOSYSTEMS, d.dependabot.ecosystems),
      directory: typeof db.directory === 'string' ? db.directory : d.dependabot.directory,
      interval: pickOne(db.interval, ['daily', 'weekly', 'monthly'] as const, d.dependabot.interval),
      groupMinorPatch: bool(db.groupMinorPatch, d.dependabot.groupMinorPatch),
      cooldownDays: Number.isInteger(cooldown) && cooldown >= 0 && cooldown <= 90 ? cooldown : d.dependabot.cooldownDays,
    },
    dependencyReview: {
      enabled: bool(dr.enabled, d.dependencyReview.enabled),
      failOnSeverity: pickOne(dr.failOnSeverity, ['low', 'moderate', 'high', 'critical'] as const, d.dependencyReview.failOnSeverity),
      commentInPr: bool(dr.commentInPr, d.dependencyReview.commentInPr),
    },
    gitleaks: { enabled: bool(gl.enabled, d.gitleaks.enabled), organization: bool(gl.organization, d.gitleaks.organization) },
    semgrep: {
      enabled: bool(sg.enabled, d.semgrep.enabled),
      config: pickOne(sg.config, ['p/default', 'p/owasp-top-ten', 'p/ci', 'auto'] as const, d.semgrep.config),
    },
    trivy: {
      enabled: bool(tv.enabled, d.trivy.enabled),
      filesystem: bool(tv.filesystem, d.trivy.filesystem),
      image: bool(tv.image, d.trivy.image),
      imageContext: typeof tv.imageContext === 'string' ? tv.imageContext : d.trivy.imageContext,
      severity: pickOne(tv.severity, ['CRITICAL', 'CRITICAL,HIGH', 'CRITICAL,HIGH,MEDIUM'] as const, d.trivy.severity),
      failBuild: bool(tv.failBuild, d.trivy.failBuild),
    },
    scorecard: { enabled: bool(sc.enabled, d.scorecard.enabled), publishResults: bool(sc.publishResults, d.scorecard.publishResults) },
  }
}

// ---------------------------------------------------------------- helpers

function uses(a: ActionRef): string {
  return `${a.uses}@${a.ref}`
}

function header(title: string, o: CiOptions): string[] {
  const lines = [
    `# ${title}`,
    '# Generated by Security Champion Toolkit — review before committing.',
    `# Action versions verified ${VERIFIED_ON}; Dependabot (github-actions) keeps them up to date.`,
  ]
  if (o.pinSha) {
    lines.push('# Pin every action to a full commit SHA before merging, e.g. `pinact run` or https://app.stepsecurity.io/secureworkflow')
  }
  return lines
}

function checkoutStep(extra: string[] = []): string[] {
  return [
    '      - name: Checkout',
    `        uses: ${uses(ACTIONS.checkout)}`,
    '        with:',
    ...extra.map((l) => `          ${l}`),
    '          persist-credentials: false',
  ]
}

function uploadSarifStep(file: string, category: string): string[] {
  return [
    '      - name: Upload SARIF to code scanning',
    '        if: always()',
    `        uses: ${uses(ACTIONS.uploadSarif)}`,
    '        with:',
    `          sarif_file: ${file}`,
    `          category: ${category}`,
  ]
}

const SARIF_NOTE =
  'Code scanning (SARIF upload) is free for public repositories; private repositories need GitHub Code Security / Advanced Security.'

function join(lines: string[]): string {
  return lines.join('\n') + '\n'
}

// ---------------------------------------------------------------- generators

export function codeqlWorkflow(o: CiOptions): GeneratedFile {
  const branch = safeBranch(o.branch)
  const langs = o.codeql.languages.length ? o.codeql.languages : DEFAULT_OPTIONS.codeql.languages
  const hasSwift = langs.includes('swift')
  const matrix = langs.flatMap((l) => {
    const entry = [`          - language: ${l}`, `            build-mode: ${CODEQL_BUILD_MODE[l]}`]
    if (hasSwift) entry.push(`            runner: ${l === 'swift' ? 'macos-latest' : 'ubuntu-latest'}`)
    return entry
  })
  const initWith = ['          languages: ${{ matrix.language }}', '          build-mode: ${{ matrix.build-mode }}']
  if (o.codeql.querySuite !== 'default') initWith.push(`          queries: ${o.codeql.querySuite}`)

  const content = join([
    ...header('CodeQL static analysis (SAST)', o),
    'name: CodeQL',
    '',
    'on:',
    '  push:',
    `    branches: ['${branch}']`,
    '  pull_request:',
    `    branches: ['${branch}']`,
    '  schedule:',
    "    - cron: '27 3 * * 1' # weekly, Monday 03:27 UTC",
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    '  analyze:',
    '    name: Analyze (${{ matrix.language }})',
    `    runs-on: ${hasSwift ? '${{ matrix.runner }}' : 'ubuntu-latest'}`,
    '    timeout-minutes: 120',
    '    permissions:',
    '      security-events: write # upload results to code scanning',
    '      packages: read # fetch CodeQL packs',
    '      actions: read # read workflow run info (private repositories)',
    '      contents: read',
    '    strategy:',
    '      fail-fast: false',
    '      matrix:',
    '        include:',
    ...matrix,
    '    steps:',
    ...checkoutStep(),
    '      - name: Initialize CodeQL',
    `        uses: ${uses(ACTIONS.codeqlInit)}`,
    '        with:',
    ...initWith,
    '      - name: Perform CodeQL analysis',
    `        uses: ${uses(ACTIONS.codeqlAnalyze)}`,
    '        with:',
    '          category: /language:${{ matrix.language }}',
  ])
  const notes = [SARIF_NOTE, 'If "default setup" for CodeQL is enabled in the repository settings, disable it — advanced setup (this file) and default setup cannot run together.']
  if (langs.some((l) => CODEQL_BUILD_MODE[l] === 'autobuild')) {
    notes.push('Go/Swift use build-mode "autobuild". If autobuild fails, switch to "manual" and add your build commands between init and analyze.')
  }
  if (langs.includes('java-kotlin')) notes.push('Java uses build-mode "none" (no build needed). Kotlin code needs build-mode "autobuild" or "manual".')
  if (hasSwift) notes.push('Swift analysis runs on macOS runners, which consume minutes at a higher rate on private repositories.')
  return { id: 'codeql', title: 'CodeQL', path: '.github/workflows/codeql.yml', content, notes }
}

export function dependabotConfig(o: CiOptions): GeneratedFile {
  const d = o.dependabot
  const dir = safeDirectory(d.directory)
  const ecosystems = d.ecosystems.length ? d.ecosystems : DEFAULT_OPTIONS.dependabot.ecosystems
  const lines = ['# Dependabot version updates', '# Generated by Security Champion Toolkit — review before committing.', 'version: 2', 'updates:']
  for (const eco of ecosystems) {
    lines.push(
      `  - package-ecosystem: '${eco}'`,
      `    directory: '${eco === 'github-actions' ? '/' : dir}'`,
      '    schedule:',
      `      interval: '${d.interval}'`,
      '    open-pull-requests-limit: 10',
    )
    if (d.cooldownDays > 0) {
      lines.push('    cooldown:', `      default-days: ${d.cooldownDays} # wait before adopting brand-new releases (supply-chain hygiene)`)
    }
    if (d.groupMinorPatch) {
      lines.push('    groups:', `      ${eco}-minor-and-patch:`, '        update-types:', "          - 'minor'", "          - 'patch'")
    }
  }
  const notes = [
    'Also enable "Dependabot alerts" and "Dependabot security updates" in Settings → Code security; this file only configures version updates.',
    'Security updates are not delayed by cooldown and are always proposed as soon as a fix exists.',
  ]
  if (!ecosystems.includes('github-actions')) notes.push('Consider adding the github-actions ecosystem so pinned action versions/SHAs are kept current.')
  if (dir !== '/') notes.push(`Package manifests are expected in ${dir}. Use one entry per directory (or "directories:") for monorepos.`)
  return { id: 'dependabot', title: 'Dependabot', path: '.github/dependabot.yml', content: join(lines), notes }
}

export function dependencyReviewWorkflow(o: CiOptions): GeneratedFile {
  const r = o.dependencyReview
  const branch = safeBranch(o.branch)
  const content = join([
    ...header('Dependency review: block PRs that add vulnerable dependencies', o),
    'name: Dependency review',
    '',
    'on:',
    '  pull_request:',
    `    branches: ['${branch}']`,
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    '  dependency-review:',
    '    runs-on: ubuntu-latest',
    ...(r.commentInPr ? ['    permissions:', '      contents: read', '      pull-requests: write # post the summary comment'] : []),
    '    steps:',
    ...checkoutStep(),
    '      - name: Dependency review',
    `        uses: ${uses(ACTIONS.dependencyReview)}`,
    '        with:',
    `          fail-on-severity: ${r.failOnSeverity}`,
    ...(r.commentInPr ? ['          comment-summary-in-pr: on-failure'] : []),
  ])
  return {
    id: 'dependency-review',
    title: 'Dependency review',
    path: '.github/workflows/dependency-review.yml',
    content,
    notes: [
      'Works on public repositories; private repositories need GitHub Advanced Security / Code Security.',
      'Make "dependency-review" a required status check in branch protection / rulesets so it actually blocks merges.',
    ],
  }
}

export function gitleaksWorkflow(o: CiOptions): GeneratedFile {
  const content = join([
    ...header('Secret scanning with gitleaks', o),
    'name: Secret scanning',
    '',
    'on:',
    '  push:',
    '  pull_request:',
    '  workflow_dispatch:',
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    '  gitleaks:',
    '    runs-on: ubuntu-latest',
    '    permissions:',
    '      contents: read',
    '      pull-requests: write # comment on the offending lines of a PR',
    '    steps:',
    ...checkoutStep(['fetch-depth: 0 # full history: leaked secrets stay in old commits']),
    '      - name: Gitleaks',
    `        uses: ${uses(ACTIONS.gitleaks)}`,
    '        env:',
    '          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}',
    ...(o.gitleaks.organization ? ['          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }} # free key from gitleaks.io, required for organization repos'] : []),
  ])
  const notes = [
    'A finding means the secret is already exposed: revoke/rotate it first, then clean history if needed. Deleting the line is not enough.',
    'Add a .gitleaks.toml (with [allowlist]) to silence verified false positives instead of disabling the job.',
    "Also enable GitHub's native secret scanning and push protection (free for public repos) in Settings → Code security.",
  ]
  if (o.gitleaks.organization) notes.unshift('Repositories owned by an organization need a free GITLEAKS_LICENSE secret (request at https://gitleaks.io).')
  return { id: 'gitleaks', title: 'Gitleaks', path: '.github/workflows/gitleaks.yml', content, notes }
}

export function semgrepWorkflow(o: CiOptions): GeneratedFile {
  const branch = safeBranch(o.branch)
  const cfg = o.semgrep.config
  // --config auto needs registry metrics enabled; for named rulesets we turn metrics off.
  const cmd = `semgrep scan --config ${cfg} --sarif --output semgrep.sarif${cfg === 'auto' ? '' : ' --metrics=off'}`
  const content = join([
    ...header('Semgrep Community Edition (SAST)', o),
    'name: Semgrep',
    '',
    'on:',
    '  pull_request:',
    '  push:',
    `    branches: ['${branch}']`,
    '  schedule:',
    "    - cron: '41 4 * * 2' # weekly, Tuesday 04:41 UTC",
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    '  semgrep:',
    '    runs-on: ubuntu-latest',
    "    if: github.actor != 'dependabot[bot]'",
    '    permissions:',
    '      contents: read',
    '      security-events: write # upload SARIF',
    '    container:',
    '      image: semgrep/semgrep # pin by digest (semgrep/semgrep@sha256:…) for reproducible builds',
    '    steps:',
    ...checkoutStep(),
    '      - name: Semgrep scan',
    `        run: ${cmd}`,
    ...uploadSarifStep('semgrep.sarif', 'semgrep'),
  ])
  const notes = [
    SARIF_NOTE,
    'semgrep scan exits 0 even with findings; add --error to fail the job on findings once the baseline is clean.',
  ]
  if (cfg === 'auto') notes.push('--config auto selects rules from the Semgrep Registry based on your project and requires sending anonymous metrics to semgrep.dev.')
  return { id: 'semgrep', title: 'Semgrep', path: '.github/workflows/semgrep.yml', content, notes }
}

export function trivyWorkflow(o: CiOptions): GeneratedFile {
  const t = o.trivy
  const branch = safeBranch(o.branch)
  const ctx = safeContext(t.imageContext)
  const doFs = t.filesystem || !t.image
  const trivyWith = (extra: string[], output: string) => [
    `        uses: ${uses(ACTIONS.trivy)}`,
    '        with:',
    ...extra.map((l) => `          ${l}`),
    `          severity: ${t.severity}`,
    '          ignore-unfixed: true',
    '          format: sarif',
    `          output: ${output}`,
    '          limit-severities-for-sarif: true',
    `          exit-code: '${t.failBuild ? 1 : 0}'`,
  ]
  const jobPerms = ['    permissions:', '      contents: read', '      security-events: write # upload SARIF']
  const jobs: string[] = []
  if (doFs) {
    jobs.push(
      '  trivy-fs:',
      '    name: Trivy filesystem scan',
      '    runs-on: ubuntu-latest',
      ...jobPerms,
      '    steps:',
      ...checkoutStep(),
      '      - name: Trivy (dependencies, secrets, IaC misconfigurations)',
      ...trivyWith(['scan-type: fs', 'scan-ref: .', 'scanners: vuln,secret,misconfig'], 'trivy-fs.sarif'),
      ...uploadSarifStep('trivy-fs.sarif', 'trivy-fs'),
    )
  }
  if (t.image) {
    if (jobs.length) jobs.push('')
    jobs.push(
      '  trivy-image:',
      '    name: Trivy container image scan',
      '    runs-on: ubuntu-latest',
      ...jobPerms,
      '    steps:',
      ...checkoutStep(),
      '      - name: Build image',
      `        run: docker build -t local/app:\${{ github.sha }} ${ctx}`,
      '      - name: Trivy (image OS packages and libraries)',
      ...trivyWith(['image-ref: local/app:${{ github.sha }}'], 'trivy-image.sarif'),
      ...uploadSarifStep('trivy-image.sarif', 'trivy-image'),
    )
  }
  const content = join([
    ...header('Trivy vulnerability scanning', o),
    'name: Trivy',
    '',
    'on:',
    '  pull_request:',
    '  push:',
    `    branches: ['${branch}']`,
    '  schedule:',
    "    - cron: '13 5 * * 3' # weekly, Wednesday 05:13 UTC",
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    ...jobs,
  ])
  return {
    id: 'trivy',
    title: 'Trivy',
    path: '.github/workflows/trivy.yml',
    content,
    notes: [
      ACTIONS.trivy.note,
      SARIF_NOTE,
      'ignore-unfixed hides vulnerabilities without an available fix to keep results actionable; remove it for a full inventory.',
    ],
  }
}

export function scorecardWorkflow(o: CiOptions): GeneratedFile {
  const branch = safeBranch(o.branch)
  const publish = o.scorecard.publishResults
  const content = join([
    ...header('OpenSSF Scorecard supply-chain security checks', o),
    'name: Scorecard',
    '',
    'on:',
    '  branch_protection_rule:',
    '  schedule:',
    "    - cron: '30 1 * * 6' # weekly, Saturday 01:30 UTC",
    '  push:',
    `    branches: ['${branch}']`,
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    '  analysis:',
    '    name: Scorecard analysis',
    '    runs-on: ubuntu-latest',
    '    permissions:',
    '      contents: read',
    '      actions: read',
    '      security-events: write # upload SARIF',
    ...(publish ? ['      id-token: write # OIDC token to publish results to api.scorecard.dev'] : []),
    '    steps:',
    ...checkoutStep(),
    '      - name: Run Scorecard',
    `        uses: ${uses(ACTIONS.scorecard)}`,
    '        with:',
    '          results_file: results.sarif',
    '          results_format: sarif',
    `          publish_results: ${publish}`,
    '      - name: Upload artifact',
    '        if: always()',
    `        uses: ${uses(ACTIONS.uploadArtifact)}`,
    '        with:',
    '          name: scorecard-sarif',
    '          path: results.sarif',
    '          retention-days: 5',
    ...uploadSarifStep('results.sarif', 'scorecard'),
  ])
  const notes = [SARIF_NOTE]
  if (publish) {
    notes.push(
      'publish_results is for public repositories (enables the Scorecard badge and API). The publishing job may not contain "run" steps and must only use approved actions — keep this job as generated.',
    )
  }
  notes.push('Private repositories: add issues: read, pull-requests: read and checks: read to the job permissions, and set publish_results: false.')
  return { id: 'scorecard', title: 'OpenSSF Scorecard', path: '.github/workflows/scorecard.yml', content, notes }
}

export function generateAll(o: CiOptions): GeneratedFile[] {
  const files: GeneratedFile[] = []
  if (o.codeql.enabled) files.push(codeqlWorkflow(o))
  if (o.dependabot.enabled) files.push(dependabotConfig(o))
  if (o.dependencyReview.enabled) files.push(dependencyReviewWorkflow(o))
  if (o.gitleaks.enabled) files.push(gitleaksWorkflow(o))
  if (o.semgrep.enabled) files.push(semgrepWorkflow(o))
  if (o.trivy.enabled) files.push(trivyWorkflow(o))
  if (o.scorecard.enabled) files.push(scorecardWorkflow(o))
  return files
}

/** All files concatenated, each preceded by a path header — handy for a single copy/download. */
export function bundle(files: GeneratedFile[]): string {
  return files.map((f) => `# ===== ${f.path} =====\n${f.content}`).join('\n')
}
