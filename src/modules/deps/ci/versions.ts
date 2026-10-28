/**
 * Action versions used by the generator. Verified against each repository's releases/tags on
 * 2026-10-28. Re-check periodically — Dependabot (github-actions ecosystem) keeps them current
 * once the workflows are committed.
 */
export interface ActionRef {
  uses: string
  ref: string
  source: string
  note?: string
}

export const ACTIONS = {
  checkout: {
    uses: 'actions/checkout',
    ref: 'v7',
    source: 'https://github.com/actions/checkout/releases (latest v7.0.1)',
  },
  codeqlInit: {
    uses: 'github/codeql-action/init',
    ref: 'v4',
    source: 'https://github.com/github/codeql-action/releases (latest v4.39.x)',
  },
  codeqlAnalyze: {
    uses: 'github/codeql-action/analyze',
    ref: 'v4',
    source: 'https://github.com/github/codeql-action/releases (latest v4.39.x)',
  },
  uploadSarif: {
    uses: 'github/codeql-action/upload-sarif',
    ref: 'v4',
    source: 'https://github.com/github/codeql-action/releases (latest v4.39.x)',
  },
  dependencyReview: {
    uses: 'actions/dependency-review-action',
    ref: 'v5',
    source: 'https://github.com/actions/dependency-review-action/releases (latest v5.0.0)',
  },
  gitleaks: {
    uses: 'gitleaks/gitleaks-action',
    ref: 'v3',
    source: 'https://github.com/gitleaks/gitleaks-action (README: v3, Node 24 runtime)',
  },
  trivy: {
    uses: 'aquasecurity/trivy-action',
    ref: 'v0.36.0',
    source: 'https://github.com/aquasecurity/trivy-action/releases (latest v0.36.0; no major-version tag exists)',
    note:
      'In March 2026 attackers force-pushed malicious code to most trivy-action version tags (CVE-2026-33634, ' +
      'https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23). Pin this action to a full commit SHA.',
  },
  scorecard: {
    uses: 'ossf/scorecard-action',
    ref: 'v2.5.0',
    source: 'https://github.com/ossf/scorecard-action/releases (latest v2.5.0; no floating v2 tag)',
  },
  uploadArtifact: {
    uses: 'actions/upload-artifact',
    ref: 'v7',
    source: 'https://github.com/actions/upload-artifact/releases (latest v7.0.2)',
  },
} as const satisfies Record<string, ActionRef>

export const VERIFIED_ON = '2026-10-28'
