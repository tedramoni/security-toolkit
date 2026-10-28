import type { ReactNode } from 'react'
import type { Sev } from './types'
import { toVisibleParts } from './unicode'

/** Render untrusted text as React text nodes with invisible characters made visible. Never uses HTML injection. */
export function VisibleText({ text }: { text: string }) {
  const parts = toVisibleParts(text)
  return (
    <>
      {parts.map((p, i) =>
        'text' in p ? (
          <span key={i}>{p.text}</span>
        ) : (
          <span key={i} className="skill-scanner-invisible" title={p.title}>
            {p.invisible}
          </span>
        ),
      )}
    </>
  )
}

export const MAX_LINE_RENDER = 2000

/** One line, with an optional highlighted (or redacted) span and truncation of very long lines. */
export function LineText({ text, start, end, redact, full }: { text: string; start?: number; end?: number; redact?: boolean; full?: boolean }): ReactNode {
  const limit = full ? Infinity : MAX_LINE_RENDER
  if (start === undefined || end === undefined || end <= start) {
    return <Truncated text={text} limit={limit} />
  }
  // Keep the highlighted span visible even in long lines.
  const from = text.length > limit && start > 200 ? start - 200 : 0
  const before = text.slice(from, start)
  const match = text.slice(start, end)
  const after = text.slice(end)
  return (
    <>
      {from > 0 && <span className="muted">…</span>}
      <VisibleText text={before} />
      <mark className="skill-scanner-mark">{redact ? `${match.slice(0, 4)}•••• (redacted)` : <VisibleText text={match.length > 600 ? match.slice(0, 600) + '…' : match} />}</mark>
      <Truncated text={after} limit={Math.max(200, limit - (end - from))} />
    </>
  )
}

function Truncated({ text, limit }: { text: string; limit: number }) {
  if (text.length <= limit) return <VisibleText text={text} />
  return (
    <>
      <VisibleText text={text.slice(0, limit)} />
      <span className="muted"> … (+{(text.length - limit).toLocaleString('en-US')} chars)</span>
    </>
  )
}

export function SevBadge({ severity }: { severity: Sev }) {
  return <span className={`badge sev-${severity}`}>{severity.toUpperCase()}</span>
}
