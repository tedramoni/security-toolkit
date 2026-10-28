import type { ReactNode } from 'react'
import { useId, useState } from 'react'
import { FindingList, SeverityBadge } from '../toolbox/FindingList'
import { safeHref } from './net'
import type { TileStatus } from './tiles'
import { TILE_STATUS_LABEL } from './tiles'
import type { Finding } from './types'
import { sortFindings } from './types'

/** External link from untrusted data: http(s) only, never opener/referrer. */
export function ExtLink({ href, children }: { href: string | undefined; children?: ReactNode }) {
  const safe = safeHref(href)
  if (!safe) return <span className="recon-break">{children ?? href}</span>
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer" className="recon-break">
      {children ?? safe}
    </a>
  )
}

function jsonReplacer(_k: string, v: unknown) {
  if (v instanceof Map) return Object.fromEntries(v)
  if (v instanceof Set) return [...v]
  return v
}

const RAW_MAX = 200_000

/** Only mounted while its toggle is open: crt.sh data can be megabytes and the dashboard re-renders on every update. */
function RawJson({ data }: { data: unknown }) {
  let text: string
  try {
    text = JSON.stringify(data, jsonReplacer, 2) ?? ''
  } catch {
    text = String(data)
  }
  return <pre className="codeblock recon-pre">{text.length > RAW_MAX ? `${text.slice(0, RAW_MAX)}\n… (truncated, ${text.length} characters)` : text}</pre>
}

/** Disclosure button (aria-expanded) + capped, scrollable panel whose content is rendered only when open. */
export function Toggle({ label, children }: { label: ReactNode; children: () => ReactNode }) {
  const [open, setOpen] = useState(false)
  const id = useId()
  return (
    <>
      <button type="button" className="btn btn-sm recon-toggle-btn" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)}>
        <span aria-hidden="true">{open ? '▾' : '▸'}</span> {label}
      </button>
      <div id={id} className="recon-more" hidden={!open}>
        {open && children()}
      </div>
    </>
  )
}

export function KV({ rows }: { rows: Record<string, ReactNode> }) {
  const shown = Object.entries(rows).filter(([, v]) => v !== undefined && v !== null && v !== '')
  if (shown.length === 0) return null
  return (
    <dl className="recon-kv">
      {shown.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  )
}

/** One-line issues (most severe first), at most `max`; pass/info stay behind the Findings toggle. */
function TopFindings({ findings, max = 2 }: { findings: readonly Finding[]; max?: number }) {
  const issues = sortFindings(findings.filter((f) => f.severity !== 'pass' && f.severity !== 'info'))
  if (issues.length === 0) return null
  return (
    <ul className="recon-top">
      {issues.slice(0, max).map((f, i) => (
        <li key={`${f.title}-${i}`}>
          <SeverityBadge severity={f.severity} /> <span>{f.title}</span>
        </li>
      ))}
      {issues.length > max && <li className="muted small">+{issues.length - max} more under Findings</li>}
    </ul>
  )
}

export interface TileMore {
  label: ReactNode
  render: () => ReactNode
}

export interface TileProps {
  id: string
  icon: string
  title: string
  status: TileStatus
  source: string
  /** Error / note shown instead of (or above) the facts. */
  message?: ReactNode
  facts?: Record<string, ReactNode>
  findings?: readonly Finding[]
  /** Expandable detail sections (rendered lazily, each in a capped scroll area). */
  more?: TileMore[]
  raw?: unknown
  wide?: boolean
  onRerun?: () => void
  children?: ReactNode
}

/** Compact dashboard tile: header (icon, title, status, source), key facts, top issues, then toggles. */
export function Tile({ id, icon, title, status, source, message, facts, findings = [], more = [], raw, wide, onRerun, children }: TileProps) {
  const st = TILE_STATUS_LABEL[status]
  const hid = `recon-tile-${id}`
  const loading = status === 'loading'
  return (
    <section className={`recon-tile${wide ? ' recon-span-2' : ''}`} aria-labelledby={hid} aria-busy={loading}>
      <header className="recon-tile-head">
        <span className="recon-tile-icon" aria-hidden="true">
          {icon}
        </span>
        <h3 id={hid} className="recon-tile-title">
          {title}
        </h3>
        <span className={`badge ${st.cls}`}>{st.text}</span>
        {onRerun && !loading && status !== 'skipped' && (
          <button type="button" className="btn btn-sm recon-rerun" onClick={onRerun} aria-label={`Re-run ${title}`} title="Re-run this check">
            ↻
          </button>
        )}
      </header>
      <p className="recon-tile-src small muted" title={`Source: ${source}`}>
        {source}
      </p>
      {loading ? (
        <div className="recon-skeleton" role="status" aria-label={`${title}: loading`}>
          <span />
          <span />
          <span />
        </div>
      ) : (
        <>
          {message && (
            <div className={`recon-msg small${status === 'error' ? ' recon-msg-error' : ''}`} role={status === 'error' ? 'alert' : undefined}>
              {message}
            </div>
          )}
          {facts && <KV rows={facts} />}
          {children}
          <TopFindings findings={findings} />
          {(findings.length > 0 || more.length > 0 || raw !== undefined) && (
            <div className="recon-toggles">
              {findings.length > 0 && <Toggle label={`Findings (${findings.length})`}>{() => <FindingList findings={findings} reportTitle={title} />}</Toggle>}
              {more.map((m, i) => (
                <Toggle key={i} label={m.label}>
                  {m.render}
                </Toggle>
              ))}
              {raw !== undefined && <Toggle label="Raw JSON">{() => <RawJson data={raw} />}</Toggle>}
            </div>
          )}
        </>
      )}
    </section>
  )
}
