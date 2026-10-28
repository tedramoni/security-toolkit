import { useId, useMemo, useRef, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { downloadJSON, downloadText, readFileText, slugify } from '../../lib/download'
import { splitLines } from './classify'
import type { FileReport, ScanResult } from './engine'
import { FileViewer } from './FileViewer'
import { BASELINE_FILENAME, applySuppressions, parseBaseline, toBaseline, toJsonReport, toMarkdown, toSarif } from './report'
import { RULES_BY_ID } from './rules'
import { SCORE_FORMULA, scoreFindings } from './score'
import type { Category, Finding, Sev, Suppression } from './types'
import { CATEGORIES, SEVERITIES, sevRank } from './types'
import { LineText, SevBadge } from './VisibleText'

const PAGE = 100

interface Props {
  result: ScanResult
  source: string
  suppressions: readonly Suppression[]
  onSuppress: (s: Suppression) => void
  onUnsuppress: (fingerprint: string) => void
  onImportBaseline: (list: Suppression[]) => void
}

export function Results({ result, source, suppressions, onSuppress, onUnsuppress, onImportBaseline }: Props) {
  const { active, suppressed } = useMemo(() => applySuppressions(result.findings, suppressions), [result.findings, suppressions])
  const score = useMemo(() => scoreFindings(active), [active])
  const [sevFilter, setSevFilter] = useState<Set<Sev>>(() => new Set(SEVERITIES))
  const [catFilter, setCatFilter] = useState<Category | ''>('')
  const [fileFilter, setFileFilter] = useState<string>('')
  const [text, setText] = useState('')
  const [hideFp, setHideFp] = useState(false)
  const [groupBy, setGroupBy] = useState<'file' | 'category'>('file')
  const [limit, setLimit] = useState(PAGE)
  const [viewer, setViewer] = useState<{ path: string; line?: number }>()
  const [prefix, setPrefix] = useState('')
  const [baselineMsg, setBaselineMsg] = useState<{ ok: boolean; text: string }>()
  const viewerRef = useRef<HTMLDivElement | null>(null)
  const ids = { search: useId(), cat: useId(), prefix: useId(), baseline: useId() }

  const filesByPath = useMemo(() => new Map(result.files.map((f) => [f.path, f])), [result.files])
  // Split lines once per scan, only for files that have findings (used for snippets).
  const linesByPath = useMemo(() => {
    const m = new Map<string, string[]>()
    for (const f of result.findings) if (!m.has(f.path)) m.set(f.path, splitLines(filesByPath.get(f.path)?.content ?? ''))
    return m
  }, [result.findings, filesByPath])
  const linesOf = (path: string): string[] => linesByPath.get(path) ?? []

  const filtered = useMemo(() => {
    const q = text.trim().toLowerCase()
    return active
      .filter((f) => sevFilter.has(f.severity))
      .filter((f) => !catFilter || f.category === catFilter)
      .filter((f) => !fileFilter || f.path === fileFilter)
      .filter((f) => !hideFp || !f.possibleFalsePositive)
      .filter((f) => !q || `${f.ruleId} ${f.title} ${f.message} ${f.path}`.toLowerCase().includes(q))
      .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.path.localeCompare(b.path) || a.line - b.line)
  }, [active, sevFilter, catFilter, fileFilter, hideFp, text])

  const groups = useMemo(() => {
    const m = new Map<string, Finding[]>()
    for (const f of filtered.slice(0, limit)) {
      const k = groupBy === 'file' ? f.path : f.category
      m.set(k, [...(m.get(k) ?? []), f])
    }
    return [...m.entries()]
  }, [filtered, groupBy, limit])

  const counts = useMemo(() => {
    const c: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of active) c[f.severity]++
    return c
  }, [active])

  const reportInput = () => ({ source, files: result.files, findings: active, suppressed, score })
  // Built once per result, not on every keystroke in the filters.
  const markdown = useMemo(() => toMarkdown({ source, files: result.files, findings: active, suppressed, score }), [source, result.files, active, suppressed, score])
  const base = slugify(source).slice(0, 60) || 'scan'
  const openViewer = (path: string, line?: number) => {
    setViewer({ path, line })
    requestAnimationFrame(() => viewerRef.current?.scrollIntoView({ block: 'start' }))
  }
  const viewerFile = viewer ? filesByPath.get(viewer.path) : undefined
  const fpCount = active.filter((f) => f.possibleFalsePositive).length

  return (
    <div className="stack">
      <section className="card skill-scanner-summary" aria-label="Scan summary">
        <div className="skill-scanner-summary-grid">
          <div className={`skill-scanner-verdict skill-scanner-verdict-${score.verdict.toLowerCase()}`} role="status">
            <div className="skill-scanner-verdict-label">{score.verdict}</div>
            <div className="small">Risk score {score.score}/100</div>
            <div className="progress" aria-hidden="true">
              <span style={{ width: `${score.score}%` }} />
            </div>
            <div className="small muted">{score.reasons.join('; ')}</div>
          </div>
          <div className="stack">
            <div className="small muted">
              Source: <span className="mono">{source}</span>
            </div>
            <div className="row small">
              <strong>{result.files.length}</strong> file{result.files.length === 1 ? '' : 's'} scanned ·<strong>{active.length}</strong> finding{active.length === 1 ? '' : 's'}
              {fpCount > 0 && <> ({fpCount} possible false positive{fpCount === 1 ? '' : 's'})</>} ·<strong>{suppressed.length}</strong> suppressed
            </div>
            <div className="row" aria-label="Findings by severity">
              {SEVERITIES.map((s) => (
                <span key={s} className={`badge sev-${s}`}>
                  {counts[s]} {s}
                </span>
              ))}
            </div>
            {score.byCategory.length > 0 && (
              <table className="table skill-scanner-cats">
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>Findings</th>
                    <th>Points</th>
                  </tr>
                </thead>
                <tbody>
                  {score.byCategory.map((c) => (
                    <tr key={c.category}>
                      <td>
                        <button type="button" className="skill-scanner-linkbtn" onClick={() => setCatFilter(c.category)}>
                          {CATEGORIES[c.category].label}
                        </button>
                      </td>
                      <td>{c.count}</td>
                      <td>{c.points.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
        <details className="small">
          <summary>How the score is computed</summary>
          <ul>
            {SCORE_FORMULA.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
          <p className="muted">Static pattern analysis cannot prove a skill is safe: a PASS means no known-bad patterns were found, not that the skill was verified.</p>
        </details>
        <div className="row skill-scanner-exports">
          <button type="button" className="btn btn-sm" onClick={() => downloadJSON(`${base}.sarif`, toSarif(active, { pathPrefix: prefix, informationUri: location.origin + location.pathname }))}>
            Export SARIF
          </button>
          <label htmlFor={ids.prefix} className="inline small">
            SARIF path prefix
          </label>
          <input id={ids.prefix} type="text" className="skill-scanner-prefix" placeholder="e.g. skills/my-skill" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
          <button type="button" className="btn btn-sm" onClick={() => downloadJSON(`${base}.skill-scan.json`, toJsonReport(reportInput()))}>
            Export JSON
          </button>
          <button type="button" className="btn btn-sm" onClick={() => downloadText(`${base}.skill-scan.md`, markdown, 'text/markdown')}>
            Export Markdown
          </button>
          <CopyButton text={markdown} label="Copy Markdown" />
        </div>
      </section>

      <section className="card stack" aria-label="Filters">
        <div className="row">
          <span className="small muted">Severity:</span>
          {SEVERITIES.map((s) => (
            <label key={s} className="inline small">
              <input
                type="checkbox"
                checked={sevFilter.has(s)}
                onChange={(e) => {
                  const next = new Set(sevFilter)
                  if (e.target.checked) next.add(s)
                  else next.delete(s)
                  setSevFilter(next)
                }}
              />
              {s}
            </label>
          ))}
          <label className="inline small">
            <input type="checkbox" checked={hideFp} onChange={(e) => setHideFp(e.target.checked)} /> Hide possible false positives
          </label>
        </div>
        <div className="row">
          <label htmlFor={ids.cat} className="sr-only">
            Category
          </label>
          <select id={ids.cat} value={catFilter} onChange={(e) => setCatFilter(e.target.value as Category | '')} className="skill-scanner-select">
            <option value="">All categories</option>
            {(Object.keys(CATEGORIES) as Category[]).map((c) => (
              <option key={c} value={c}>
                {CATEGORIES[c].label}
              </option>
            ))}
          </select>
          <label htmlFor={ids.search} className="sr-only">
            Search findings
          </label>
          <input id={ids.search} type="search" placeholder="Filter by text, rule id or path…" value={text} onChange={(e) => setText(e.target.value)} className="skill-scanner-search" />
          <div className="row" role="group" aria-label="Group findings by">
            <button type="button" className="btn btn-sm" aria-pressed={groupBy === 'file'} onClick={() => setGroupBy('file')}>
              By file
            </button>
            <button type="button" className="btn btn-sm" aria-pressed={groupBy === 'category'} onClick={() => setGroupBy('category')}>
              By category
            </button>
          </div>
          {(catFilter || fileFilter || text || hideFp || sevFilter.size !== SEVERITIES.length) && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setCatFilter('')
                setFileFilter('')
                setText('')
                setHideFp(false)
                setSevFilter(new Set(SEVERITIES))
              }}
            >
              Reset filters
            </button>
          )}
        </div>
      </section>

      {viewerFile && (
        <div ref={viewerRef}>
          <FileViewer key={viewerFile.path} file={viewerFile} findings={active.filter((f) => f.path === viewerFile.path)} focusLine={viewer?.line} onClose={() => setViewer(undefined)} />
        </div>
      )}

      <div className="skill-scanner-layout">
        <FileTree files={result.files} findings={active} selected={fileFilter} onSelect={(p) => setFileFilter(p === fileFilter ? '' : p)} onOpen={(p) => openViewer(p)} />
        <section className="stack" aria-label="Findings">
          <div className="small muted" aria-live="polite">
            Showing {Math.min(limit, filtered.length)} of {filtered.length} finding{filtered.length === 1 ? '' : 's'}
            {fileFilter && (
              <>
                {' '}
                in <span className="mono">{fileFilter}</span>
              </>
            )}
          </div>
          {filtered.length === 0 && <p className="muted">{active.length === 0 ? 'No findings.' : 'No findings match the filters.'}</p>}
          {groups.map(([key, list]) => (
            <div key={key} className="stack">
              <h3 className="skill-scanner-group">
                {groupBy === 'file' ? <span className="mono">{key}</span> : CATEGORIES[key as Category].label} <span className="muted small">({list.length})</span>
              </h3>
              {list.map((f) => (
                <FindingItem key={f.fingerprint + f.path} finding={f} lines={linesOf(f.path)} onOpen={() => openViewer(f.path, f.line || undefined)} onSuppress={onSuppress} />
              ))}
            </div>
          ))}
          {filtered.length > limit && (
            <button type="button" className="btn" onClick={() => setLimit((l) => l + PAGE)}>
              Show {Math.min(PAGE, filtered.length - limit)} more
            </button>
          )}
        </section>
      </div>

      <section className="card stack" aria-label="Suppressions and baseline">
        <h3 style={{ margin: 0 }}>Suppressions & baseline</h3>
        <p className="small muted">
          Suppressed findings are excluded from the score and exports. They are keyed by a fingerprint of rule + file + line text, so they survive line moves. Only fingerprints, paths, line numbers and reasons are stored in this browser — never file content.
        </p>
        <div className="row">
          <button type="button" className="btn btn-sm" disabled={suppressions.length === 0} onClick={() => downloadJSON(BASELINE_FILENAME, toBaseline(suppressions))}>
            Export {BASELINE_FILENAME}
          </button>
          <label htmlFor={ids.baseline} className="inline small">
            Import baseline:
          </label>
          <input
            id={ids.baseline}
            type="file"
            accept=".json,application/json"
            onChange={async (e) => {
              const file = e.target.files?.[0]
              e.target.value = ''
              if (!file) return
              try {
                if (file.size > 2 * 1024 * 1024) throw new Error('File too large.')
                const list = parseBaseline(JSON.parse(await readFileText(file)))
                onImportBaseline(list)
                setBaselineMsg({ ok: true, text: `Imported ${list.length} suppression${list.length === 1 ? '' : 's'}.` })
              } catch (err) {
                setBaselineMsg({ ok: false, text: `Could not import: ${(err as Error).message}` })
              }
            }}
          />
        </div>
        {baselineMsg && (
          <div className={`callout small${baselineMsg.ok ? '' : ' error'}`} role={baselineMsg.ok ? 'status' : 'alert'}>
            {baselineMsg.text}
          </div>
        )}
        {suppressed.length > 0 ? (
          <table className="table small">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Location</th>
                <th>Reason</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {suppressed.map(({ finding: f, reason }) => (
                <tr key={f.fingerprint + f.path}>
                  <td>
                    <SevBadge severity={f.severity} /> {f.ruleId} {f.title}
                  </td>
                  <td className="mono">
                    {f.path}
                    {f.line > 0 ? `:${f.line}` : ''}
                  </td>
                  <td>{reason || <span className="muted">—</span>}</td>
                  <td>
                    <button type="button" className="btn btn-sm" onClick={() => onUnsuppress(f.fingerprint)}>
                      Unsuppress
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="small muted">No suppressed findings in this scan.</p>
        )}
      </section>
    </div>
  )
}

function FileTree({ files, findings, selected, onSelect, onOpen }: { files: readonly FileReport[]; findings: readonly Finding[]; selected: string; onSelect: (p: string) => void; onOpen: (p: string) => void }) {
  const counts = useMemo(() => {
    const m = new Map<string, { n: number; worst?: Sev }>()
    for (const f of findings) {
      const c = m.get(f.path) ?? { n: 0 }
      c.n++
      if (!c.worst || sevRank(f.severity) < sevRank(c.worst)) c.worst = f.severity
      m.set(f.path, c)
    }
    return m
  }, [findings])
  const extra = [...counts.keys()].filter((p) => !files.some((f) => f.path === p))
  const all = [...files.map((f) => f.path), ...extra].sort((a, b) => a.localeCompare(b))
  return (
    <nav className="card skill-scanner-tree" aria-label="Scanned files">
      <h3 className="small" style={{ marginTop: 0 }}>
        Files ({all.length})
      </h3>
      <ul>
        {all.slice(0, 1000).flatMap((p, idx) => {
          const c = counts.get(p)
          const parts = p.split('/')
          const depth = parts.length - 1
          const name = parts[depth]
          const file = files.find((f) => f.path === p)
          // Directory headers for folders not shared with the previous path.
          const prev = idx > 0 ? all[idx - 1].split('/').slice(0, -1) : []
          let common = 0
          while (common < depth && prev[common] === parts[common]) common++
          const dirs = parts.slice(common, depth).map((d, j) => (
            <li key={`${p}#dir${j}`} className="skill-scanner-tree-dir muted" style={{ paddingLeft: `${Math.min(common + j, 8) * 0.6}rem` }}>
              {d}/
            </li>
          ))
          return [
            ...dirs,
            <li key={p} style={{ paddingLeft: `${Math.min(depth, 8) * 0.6}rem` }} className={selected === p ? 'skill-scanner-tree-selected' : undefined}>
              <button type="button" className="skill-scanner-linkbtn mono" title={`Filter findings to ${p}`} aria-pressed={selected === p} onClick={() => onSelect(p)}>
                {name}
              </button>
              {c && <span className={`badge sev-${c.worst}`}>{c.n}</span>}
              {file?.content !== undefined && (
                <button type="button" className="skill-scanner-linkbtn small" aria-label={`View ${p}`} onClick={() => onOpen(p)}>
                  view
                </button>
              )}
            </li>,
          ]
        })}
      </ul>
      {all.length > 1000 && <p className="small muted">…and {all.length - 1000} more</p>}
    </nav>
  )
}

function FindingItem({ finding: f, lines, onOpen, onSuppress }: { finding: Finding; lines: string[]; onOpen: () => void; onSuppress: (s: Suppression) => void }) {
  const [suppressing, setSuppressing] = useState(false)
  const [reason, setReason] = useState('')
  const reasonId = useId()
  const rule = RULES_BY_ID.get(f.ruleId)
  const from = Math.max(1, f.line - 2)
  const to = Math.min(lines.length, f.line + 2)
  return (
    <article className={`skill-scanner-finding sev-${f.severity}`}>
      <div className="row">
        <SevBadge severity={f.severity} />
        {f.possibleFalsePositive && (
          <span className="badge sev-info" title={f.possibleFalsePositive}>
            possible false positive
          </span>
        )}
        <strong>{f.title}</strong>
        <span className="muted small mono">{f.ruleId}</span>
        <span className="spacer" />
        <button type="button" className="skill-scanner-linkbtn mono small" onClick={onOpen}>
          {f.path}
          {f.line > 0 ? `:${f.line}` : ''}
        </button>
      </div>
      <p className="skill-scanner-message">{f.message}</p>
      {f.possibleFalsePositive && <p className="small muted">Downgraded from {f.baseSeverity}: {f.possibleFalsePositive}</p>}
      {f.line > 0 && lines.length > 0 && (
        <div className="skill-scanner-snippet" aria-label={`Code around line ${f.line}`}>
          {Array.from({ length: to - from + 1 }, (_, i) => from + i).map((n) => (
            <div key={n} className={`skill-scanner-line${n === f.line ? ' skill-scanner-flagged' : ''}`}>
              <span className="skill-scanner-ln" aria-hidden="true">
                {n}
              </span>
              <span className="skill-scanner-text">
                {n === f.line ? <LineText text={lines[n - 1] ?? ''} start={f.column - 1} end={f.endColumn - 1} redact={f.redactMatch} /> : <LineText text={lines[n - 1] ?? ''} />}
              </span>
            </div>
          ))}
        </div>
      )}
      <details className="small">
        <summary>Details & remediation</summary>
        <p>{rule?.description}</p>
        <p>
          <strong>Fix:</strong> {rule?.remediation}
        </p>
        <p className="muted">
          Category: {CATEGORIES[f.category].label}
          {f.ctx ? ` · context: ${f.ctx}` : ''} ·{' '}
          <a href={CATEGORIES[f.category].ref} target="_blank" rel="noopener noreferrer">
            reference
          </a>
        </p>
      </details>
      {suppressing ? (
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault()
            onSuppress({ fingerprint: f.fingerprint, ruleId: f.ruleId, path: f.path, line: f.line, reason: reason.trim().slice(0, 1000), createdAt: new Date().toISOString() })
          }}
        >
          <label htmlFor={reasonId} className="sr-only">
            Reason for suppressing
          </label>
          <input id={reasonId} type="text" placeholder="Reason (e.g. reviewed: documentation example)" value={reason} onChange={(e) => setReason(e.target.value)} autoFocus className="skill-scanner-reason" />
          <button type="submit" className="btn btn-sm">
            Suppress
          </button>
          <button type="button" className="btn btn-sm" onClick={() => setSuppressing(false)}>
            Cancel
          </button>
        </form>
      ) : (
        <div className="row">
          <button type="button" className="btn btn-sm" onClick={() => setSuppressing(true)}>
            Suppress…
          </button>
        </div>
      )}
    </article>
  )
}
