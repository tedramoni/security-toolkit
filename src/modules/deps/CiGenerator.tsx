import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { CopyButton } from '../../lib/CopyButton.tsx'
import { downloadText } from '../../lib/download.ts'
import { STORAGE_KEYS, useLocalStorage } from '../../lib/storage.ts'
import type { CiOptions, CodeqlLanguage, DependabotEcosystem } from './ci/generators.ts'
import {
  CODEQL_LANGUAGES,
  DEFAULT_OPTIONS,
  DEPENDABOT_ECOSYSTEMS,
  bundle,
  generateAll,
  normalizeOptions,
  safeBranch,
  safeContext,
  safeDirectory,
} from './ci/generators.ts'
import { ACTIONS, VERIFIED_ON } from './ci/versions.ts'

function toggle<T>(list: T[], item: T, on: boolean): T[] {
  return on ? (list.includes(item) ? list : [...list, item]) : list.filter((x) => x !== item)
}

function Section({ title, enabled, onToggle, children }: { title: string; enabled: boolean; onToggle: (v: boolean) => void; children?: ReactNode }) {
  return (
    <fieldset>
      <legend>
        <label className="inline">
          <input type="checkbox" checked={enabled} onChange={(e) => onToggle(e.target.checked)} />
          {title}
        </label>
      </legend>
      {enabled && children && <div className="stack">{children}</div>}
    </fieldset>
  )
}

export function CiGenerator() {
  const [stored, setStored] = useLocalStorage<unknown>(STORAGE_KEYS.ciGenerator, DEFAULT_OPTIONS)
  const o = useMemo(() => normalizeOptions(stored), [stored])
  const set = (patch: (prev: CiOptions) => CiOptions) => setStored(patch(o))
  const files = useMemo(() => generateAll(o), [o])
  const branchInvalid = safeBranch(o.branch) !== o.branch.trim()
  const dirInvalid = safeDirectory(o.dependabot.directory) !== o.dependabot.directory.trim()
  const contextInvalid = safeContext(o.trivy.imageContext) !== o.trivy.imageContext.trim()

  return (
    <div className="deps-layout">
      <div className="card stack deps-options">
        <h2>Options</h2>
        <label>
          Default branch
          <input type="text" value={o.branch} onChange={(e) => set((p) => ({ ...p, branch: e.target.value }))} aria-invalid={branchInvalid} />
          {branchInvalid && <span className="small sev-high">Invalid branch name — “main” is used.</span>}
        </label>
        <label className="inline">
          <input type="checkbox" checked={o.pinSha} onChange={(e) => set((p) => ({ ...p, pinSha: e.target.checked }))} />
          Pin actions to commit SHA (recommended)
        </label>

        <Section title="CodeQL (SAST)" enabled={o.codeql.enabled} onToggle={(v) => set((p) => ({ ...p, codeql: { ...p.codeql, enabled: v } }))}>
          <div className="deps-checkgrid" role="group" aria-label="CodeQL languages">
            {CODEQL_LANGUAGES.map((l) => (
              <label key={l} className="inline small">
                <input
                  type="checkbox"
                  checked={o.codeql.languages.includes(l)}
                  onChange={(e) => set((p) => ({ ...p, codeql: { ...p.codeql, languages: toggle<CodeqlLanguage>(p.codeql.languages, l, e.target.checked) } }))}
                />
                {l}
              </label>
            ))}
          </div>
          {o.codeql.languages.length === 0 && (
            <span className="small sev-high">No language selected — the defaults ({DEFAULT_OPTIONS.codeql.languages.join(', ')}) are used.</span>
          )}
          <label>
            Query suite
            <select
              value={o.codeql.querySuite}
              onChange={(e) => set((p) => ({ ...p, codeql: { ...p.codeql, querySuite: e.target.value as CiOptions['codeql']['querySuite'] } }))}
            >
              <option value="default">default (fewest false positives)</option>
              <option value="security-extended">security-extended (recommended)</option>
              <option value="security-and-quality">security-and-quality (noisiest)</option>
            </select>
          </label>
        </Section>

        <Section title="Dependabot" enabled={o.dependabot.enabled} onToggle={(v) => set((p) => ({ ...p, dependabot: { ...p.dependabot, enabled: v } }))}>
          <div className="deps-checkgrid" role="group" aria-label="Dependabot ecosystems">
            {DEPENDABOT_ECOSYSTEMS.map((eco) => (
              <label key={eco} className="inline small">
                <input
                  type="checkbox"
                  checked={o.dependabot.ecosystems.includes(eco)}
                  onChange={(e) =>
                    set((p) => ({ ...p, dependabot: { ...p.dependabot, ecosystems: toggle<DependabotEcosystem>(p.dependabot.ecosystems, eco, e.target.checked) } }))
                  }
                />
                {eco}
              </label>
            ))}
          </div>
          {o.dependabot.ecosystems.length === 0 && (
            <span className="small sev-high">No ecosystem selected — the defaults ({DEFAULT_OPTIONS.dependabot.ecosystems.join(', ')}) are used.</span>
          )}
          <label>
            Manifest directory
            <input
              type="text"
              value={o.dependabot.directory}
              onChange={(e) => set((p) => ({ ...p, dependabot: { ...p.dependabot, directory: e.target.value } }))}
              aria-invalid={dirInvalid}
            />
            {dirInvalid && <span className="small sev-high">Must start with “/” and use only letters, digits, . _ - / — “/” is used.</span>}
          </label>
          <label>
            Schedule
            <select
              value={o.dependabot.interval}
              onChange={(e) => set((p) => ({ ...p, dependabot: { ...p.dependabot, interval: e.target.value as CiOptions['dependabot']['interval'] } }))}
            >
              <option value="daily">daily</option>
              <option value="weekly">weekly</option>
              <option value="monthly">monthly</option>
            </select>
          </label>
          <label className="inline">
            <input
              type="checkbox"
              checked={o.dependabot.groupMinorPatch}
              onChange={(e) => set((p) => ({ ...p, dependabot: { ...p.dependabot, groupMinorPatch: e.target.checked } }))}
            />
            Group minor + patch updates into one PR
          </label>
          <label>
            Cooldown (days before adopting a new release, 0 = off)
            <input
              type="number"
              min={0}
              max={90}
              value={o.dependabot.cooldownDays}
              onChange={(e) => set((p) => ({ ...p, dependabot: { ...p.dependabot, cooldownDays: Math.max(0, Math.min(90, Math.trunc(Number(e.target.value) || 0))) } }))}
            />
          </label>
        </Section>

        <Section
          title="Dependency review (PRs)"
          enabled={o.dependencyReview.enabled}
          onToggle={(v) => set((p) => ({ ...p, dependencyReview: { ...p.dependencyReview, enabled: v } }))}
        >
          <label>
            Fail on severity
            <select
              value={o.dependencyReview.failOnSeverity}
              onChange={(e) =>
                set((p) => ({ ...p, dependencyReview: { ...p.dependencyReview, failOnSeverity: e.target.value as CiOptions['dependencyReview']['failOnSeverity'] } }))
              }
            >
              <option value="low">low</option>
              <option value="moderate">moderate</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label className="inline">
            <input
              type="checkbox"
              checked={o.dependencyReview.commentInPr}
              onChange={(e) => set((p) => ({ ...p, dependencyReview: { ...p.dependencyReview, commentInPr: e.target.checked } }))}
            />
            Comment summary on the PR when it fails
          </label>
        </Section>

        <Section title="Secret scanning (gitleaks)" enabled={o.gitleaks.enabled} onToggle={(v) => set((p) => ({ ...p, gitleaks: { ...p.gitleaks, enabled: v } }))}>
          <label className="inline">
            <input
              type="checkbox"
              checked={o.gitleaks.organization}
              onChange={(e) => set((p) => ({ ...p, gitleaks: { ...p.gitleaks, organization: e.target.checked } }))}
            />
            Repository belongs to an organization (needs GITLEAKS_LICENSE)
          </label>
        </Section>

        <Section title="Semgrep CE (SAST)" enabled={o.semgrep.enabled} onToggle={(v) => set((p) => ({ ...p, semgrep: { ...p.semgrep, enabled: v } }))}>
          <label>
            Rules
            <select
              value={o.semgrep.config}
              onChange={(e) => set((p) => ({ ...p, semgrep: { ...p.semgrep, config: e.target.value as CiOptions['semgrep']['config'] } }))}
            >
              <option value="p/owasp-top-ten">p/owasp-top-ten</option>
              <option value="p/default">p/default</option>
              <option value="p/ci">p/ci</option>
              <option value="auto">auto (sends metrics to semgrep.dev)</option>
            </select>
          </label>
        </Section>

        <Section title="Trivy" enabled={o.trivy.enabled} onToggle={(v) => set((p) => ({ ...p, trivy: { ...p.trivy, enabled: v } }))}>
          <label className="inline">
            <input type="checkbox" checked={o.trivy.filesystem} onChange={(e) => set((p) => ({ ...p, trivy: { ...p.trivy, filesystem: e.target.checked } }))} />
            Filesystem scan (dependencies, secrets, IaC)
          </label>
          <label className="inline">
            <input type="checkbox" checked={o.trivy.image} onChange={(e) => set((p) => ({ ...p, trivy: { ...p.trivy, image: e.target.checked } }))} />
            Build & scan container image
          </label>
          {o.trivy.image && (
            <label>
              Docker build context
              <input
                type="text"
                value={o.trivy.imageContext}
                onChange={(e) => set((p) => ({ ...p, trivy: { ...p.trivy, imageContext: e.target.value } }))}
                aria-invalid={contextInvalid}
              />
              {contextInvalid && <span className="small sev-high">Use a relative path (letters, digits, . _ - /) — “.” is used.</span>}
            </label>
          )}
          <label>
            Severities
            <select
              value={o.trivy.severity}
              onChange={(e) => set((p) => ({ ...p, trivy: { ...p.trivy, severity: e.target.value as CiOptions['trivy']['severity'] } }))}
            >
              <option value="CRITICAL">CRITICAL</option>
              <option value="CRITICAL,HIGH">CRITICAL,HIGH</option>
              <option value="CRITICAL,HIGH,MEDIUM">CRITICAL,HIGH,MEDIUM</option>
            </select>
          </label>
          <label className="inline">
            <input type="checkbox" checked={o.trivy.failBuild} onChange={(e) => set((p) => ({ ...p, trivy: { ...p.trivy, failBuild: e.target.checked } }))} />
            Fail the job on findings
          </label>
        </Section>

        <Section title="OpenSSF Scorecard" enabled={o.scorecard.enabled} onToggle={(v) => set((p) => ({ ...p, scorecard: { ...p.scorecard, enabled: v } }))}>
          <label className="inline">
            <input
              type="checkbox"
              checked={o.scorecard.publishResults}
              onChange={(e) => set((p) => ({ ...p, scorecard: { ...p.scorecard, publishResults: e.target.checked } }))}
            />
            Publish results (public repos: badge + API)
          </label>
        </Section>

        <button type="button" className="btn btn-sm" onClick={() => setStored(DEFAULT_OPTIONS)}>
          Reset to defaults
        </button>
      </div>

      <div className="stack">
        {o.pinSha && (
          <div className="callout warn">
            <strong>Pin to commit SHA:</strong> tags like <code>@v4</code> are mutable — a compromised maintainer account can repoint them (this
            happened to <code>aquasecurity/trivy-action</code> in March 2026). This page cannot resolve SHAs offline and will not invent them.
            After committing, run{' '}
            <a href="https://github.com/suzuki-shunsuke/pinact" target="_blank" rel="noopener noreferrer">
              pinact
            </a>{' '}
            (<code>pinact run</code>) or{' '}
            <a href="https://app.stepsecurity.io/secureworkflow" target="_blank" rel="noopener noreferrer">
              StepSecurity Secure Workflow
            </a>{' '}
            to rewrite <code>uses:</code> lines to <code>owner/repo@&lt;40-char SHA&gt; # vX.Y.Z</code>; Dependabot (github-actions) then keeps the SHAs
            updated. You can also enforce SHA pinning in Settings → Actions → General.
          </div>
        )}
        {files.length === 0 ? (
          <p className="muted">Select at least one tool.</p>
        ) : (
          <div className="row">
            <span className="small muted">
              {files.length} file(s). Action versions verified {VERIFIED_ON}.
            </span>
            <span className="spacer" />
            <CopyButton text={bundle(files)} label="Copy all" />
          </div>
        )}
        {files.map((f) => (
          <section key={f.id} className="card stack" aria-label={f.path}>
            <div className="row">
              <span className="deps-filepath">{f.path}</span>
              <span className="spacer" />
              <CopyButton text={f.content} />
              <button type="button" className="btn" onClick={() => downloadText(f.path.split('/').pop() ?? 'workflow.yml', f.content, 'text/yaml')}>
                Download
              </button>
            </div>
            {f.notes.length > 0 && (
              <ul className="deps-notes small muted">
                {f.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            )}
            <pre className="codeblock deps-code">
              <code>{f.content}</code>
            </pre>
          </section>
        ))}
        <details className="small muted">
          <summary>Action version sources</summary>
          <ul>
            {Object.values(ACTIONS).map((a) => (
              <li key={a.uses}>
                <code>
                  {a.uses}@{a.ref}
                </code>{' '}
                — {a.source}
              </li>
            ))}
          </ul>
        </details>
      </div>
    </div>
  )
}
