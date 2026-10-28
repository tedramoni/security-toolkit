import { useEffect, useMemo, useRef, useState } from 'react'
import { splitLines } from './classify'
import type { FileReport } from './engine'
import type { Finding } from './types'
import { sevRank } from './types'
import { LineText, SevBadge } from './VisibleText'

const PAGE = 1500

interface Props {
  file: FileReport
  findings: readonly Finding[]
  focusLine?: number
  onClose: () => void
}

export function FileViewer({ file, findings, focusLine, onClose }: Props) {
  const lines = useMemo(() => (file.content === undefined ? [] : splitLines(file.content)), [file.content])
  const [baseLimit, setLimit] = useState(PAGE)
  // Always render far enough to include the focused line.
  const limit = Math.max(baseLimit, (focusLine ?? 0) + 200)
  const [full, setFull] = useState(false)
  const focusRef = useRef<HTMLDivElement | null>(null)
  const headingRef = useRef<HTMLHeadingElement | null>(null)
  const byLine = useMemo(() => {
    const m = new Map<number, Finding[]>()
    for (const f of findings) if (f.line > 0) m.set(f.line, [...(m.get(f.line) ?? []), f])
    for (const list of m.values()) list.sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
    return m
  }, [findings])

  useEffect(() => {
    if (focusLine && focusRef.current) focusRef.current.scrollIntoView({ block: 'center' })
    else headingRef.current?.focus()
  }, [focusLine, file.path])

  return (
    <section className="card skill-scanner-viewer" aria-label={`File viewer: ${file.path}`}>
      <div className="row">
        <h3 ref={headingRef} tabIndex={-1} style={{ margin: 0 }} className="mono">
          {file.path}
        </h3>
        <span className="muted small">
          {file.kind} · {file.lineCount.toLocaleString('en-US')} lines · {findings.length} finding{findings.length === 1 ? '' : 's'}
          {file.truncated ? ' · truncated for scanning' : ''}
        </span>
        <span className="spacer" />
        <label className="inline small">
          <input type="checkbox" checked={full} onChange={(e) => setFull(e.target.checked)} /> Show long lines in full
        </label>
        <button type="button" className="btn btn-sm" onClick={onClose}>
          Close viewer
        </button>
      </div>
      {file.content === undefined ? (
        <p className="muted">Binary file — not displayed.</p>
      ) : (
        <div className="skill-scanner-code" role="region" aria-label="File content" tabIndex={0}>
          {lines.slice(0, limit).map((text, i) => {
            const n = i + 1
            const fs = byLine.get(n)
            const top = fs?.[0]
            return (
              <div
                key={n}
                ref={n === focusLine ? focusRef : undefined}
                className={`skill-scanner-line${fs ? ` skill-scanner-flagged sev-${top!.severity}` : ''}${n === focusLine ? ' skill-scanner-focus' : ''}`}
              >
                <span className="skill-scanner-ln" aria-hidden="true">
                  {n}
                </span>
                <span className="skill-scanner-text">
                  {top ? <LineText text={text} start={top.column - 1} end={top.endColumn - 1} redact={top.redactMatch} full={full} /> : <LineText text={text} full={full} />}
                  {fs && (
                    <span className="skill-scanner-line-notes">
                      {fs.map((f) => (
                        <span key={f.fingerprint} className="skill-scanner-line-note">
                          <SevBadge severity={f.severity} /> {f.ruleId} {f.title}
                        </span>
                      ))}
                    </span>
                  )}
                </span>
              </div>
            )
          })}
          {lines.length > limit && (
            <button type="button" className="btn btn-sm" onClick={() => setLimit(limit + PAGE)}>
              Show {Math.min(PAGE, lines.length - limit).toLocaleString('en-US')} more lines ({(lines.length - limit).toLocaleString('en-US')} remaining)
            </button>
          )}
        </div>
      )}
    </section>
  )
}
