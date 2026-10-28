/** Findings reuse the Dev Toolbox model so severity badges, sorting and Markdown export are identical across the app. */
export type { Finding, Severity } from '../toolbox/types'
export { SEVERITY_ORDER, countBySeverity, findingsToMarkdown, mdText, severityRank, sortFindings, worstSeverity } from '../toolbox/types'

export type CheckId = 'dns' | 'email' | 'ct' | 'rdap' | 'ip' | 'wayback' | 'web'

export type CheckStatus = 'idle' | 'running' | 'done' | 'error' | 'needs-proxy' | 'skipped'
