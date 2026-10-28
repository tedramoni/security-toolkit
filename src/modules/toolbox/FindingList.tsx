import { CopyButton } from '../../lib/CopyButton'
import type { Finding, Severity } from './types'
import { SEVERITY_ORDER, countBySeverity, findingsToMarkdown, sortFindings } from './types'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity.toUpperCase()}</span>
}

export function SeveritySummary({ findings }: { findings: readonly { severity: Severity }[] }) {
  const counts = countBySeverity(findings)
  return (
    <div className="row small" aria-label="Findings by severity">
      {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
        <span key={s} className={`badge sev-${s}`}>
          {counts[s]} {s}
        </span>
      ))}
    </div>
  )
}

interface Props {
  findings: readonly Finding[]
  /** Used as the heading of the Markdown export. */
  reportTitle: string
  emptyText?: string
  /** Do not list "pass" findings (they still count in the summary). Default: show them. */
  hidePass?: boolean
}

export function FindingList({ findings, reportTitle, emptyText = 'No findings.', hidePass = false }: Props) {
  const shown = sortFindings(hidePass ? findings.filter((f) => f.severity !== 'pass') : findings)
  return (
    <div className="stack">
      <div className="row">
        <SeveritySummary findings={findings} />
        <span className="spacer" />
        {findings.length > 0 && <CopyButton text={findingsToMarkdown(reportTitle, findings)} label="Copy as Markdown" />}
      </div>
      {shown.length === 0 ? (
        <p className="muted">{emptyText}</p>
      ) : (
        <ul className="toolbox-findings">
          {shown.map((f, i) => (
            <li key={`${f.title}-${i}`} className={`toolbox-finding sev-${f.severity}`}>
              <div className="toolbox-finding-title">
                <SeverityBadge severity={f.severity} />
                <span>{f.title}</span>
              </div>
              <p>{f.detail}</p>
              {f.fix && (
                <p className="toolbox-fix">
                  <strong>Fix:</strong> {f.fix}
                </p>
              )}
              {f.ref && (
                <p className="small">
                  <a href={f.ref} target="_blank" rel="noopener noreferrer">
                    Reference
                  </a>
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
