import { useEffect, useMemo, useRef, useState } from 'react'
import type { DragEvent } from 'react'
import { CopyButton } from '../../lib/CopyButton.tsx'
import { downloadText, readFileText } from '../../lib/download.ts'
import { fetchVulns, isAbortError, queryBatch } from './osv.ts'
import { FORMAT_LABELS, detectFormat, parseLockfile } from './parsers/detect.ts'
import type { Finding, FindingFilter } from './report.ts'
import { aliasesToEnrich, buildFindings, countBySeverity, filterFindings, osvUrl, severityLabel, toCsv, toMarkdown } from './report.ts'
import type { SeverityLevel } from './severity.ts'
import { SEVERITY_LEVELS } from './severity.ts'
import type { Dependency, LockfileFormat, SkippedEntry } from './types.ts'
import { dedupeDeps } from './types.ts'

interface Source {
  id: number
  name: string
  format: LockfileFormat | null
  deps: Dependency[]
  skipped: SkippedEntry[]
  error?: string
}

type Phase = 'idle' | 'query' | 'details' | 'enrich' | 'done' | 'cancelled' | 'error'

interface ScanResult {
  findings: Finding[]
  scanned: number
  failed: { dep: Dependency; error: string }[]
  detailErrors: { id: string; error: string }[]
  date: string
  sources: string[]
}

const MAX_FILE_BYTES = 25 * 1024 * 1024
const FORMATS = Object.keys(FORMAT_LABELS) as LockfileFormat[]

const PHASE_LABEL: Partial<Record<Phase, string>> = {
  query: 'Querying packages',
  details: 'Downloading vulnerability details',
  enrich: 'Fetching severities from aliased GitHub advisories',
}

const SEV_CLASS: Record<SeverityLevel, string> = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
  none: 'sev-ok',
  unknown: 'sev-info',
}

function parseSource(id: number, name: string, text: string, forced?: LockfileFormat): Source {
  const format = forced ?? detectFormat(name, text)
  if (!format) {
    return { id, name, format: null, deps: [], skipped: [], error: 'Unrecognised format. Choose the format explicitly or upload a supported lockfile.' }
  }
  try {
    const r = parseLockfile(format, text)
    return { id, name, format, deps: r.deps, skipped: r.skipped }
  } catch (e) {
    return { id, name, format, deps: [], skipped: [], error: (e as Error).message }
  }
}

export function DepsChecker() {
  const [sources, setSources] = useState<Source[]>([])
  const [paste, setPaste] = useState('')
  const [pasteFormat, setPasteFormat] = useState<LockfileFormat | 'auto'>('auto')
  const [dragOver, setDragOver] = useState(false)
  const [phase, setPhase] = useState<Phase>('idle')
  const [progress, setProgress] = useState({ done: 0, total: 0 })
  const [error, setError] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [filter, setFilter] = useState<FindingFilter>({ minLevel: 'all', hideDev: false, text: '' })
  const abortRef = useRef<AbortController | null>(null)
  const nextId = useRef(1)

  // leaving the page cancels an in-flight scan instead of letting it keep hitting OSV.dev
  useEffect(() => () => abortRef.current?.abort(), [])

  const allDeps = useMemo(() => dedupeDeps(sources.flatMap((s) => s.deps)), [sources])
  const running = phase === 'query' || phase === 'details' || phase === 'enrich'

  async function addFiles(files: FileList | File[]) {
    const added: Source[] = []
    for (const file of Array.from(files)) {
      const id = nextId.current++
      if (file.size > MAX_FILE_BYTES) {
        added.push({ id, name: file.name, format: null, deps: [], skipped: [], error: 'File larger than 25 MB — not a lockfile?' })
        continue
      }
      try {
        added.push(parseSource(id, file.name, await readFileText(file)))
      } catch (e) {
        added.push({ id, name: file.name, format: null, deps: [], skipped: [], error: `Could not read file: ${(e as Error).message ?? String(e)}` })
      }
    }
    setSources((s) => [...s, ...added])
  }

  function addPaste() {
    if (!paste.trim()) return
    const forced = pasteFormat === 'auto' ? undefined : pasteFormat
    setSources((s) => [...s, parseSource(nextId.current++, 'pasted text', paste, forced)])
    setPaste('')
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragOver(false)
    if (e.dataTransfer.files.length) void addFiles(e.dataTransfer.files)
  }

  async function scan() {
    const deps = allDeps
    if (deps.length === 0 || running) return
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setError('')
    setResult(null)
    setPhase('query')
    setProgress({ done: 0, total: deps.length })
    try {
      const batch = await queryBatch(deps, {
        signal: ctrl.signal,
        onProgress: (done, total) => setProgress({ done, total }),
      })
      if (batch.failed.length === deps.length) throw new Error(batch.failed[0]?.error ?? 'OSV.dev query failed')
      const ids = [...new Set([...batch.idsByDep.values()].flat())]
      setPhase('details')
      setProgress({ done: 0, total: ids.length })
      const details = await fetchVulns(ids, {
        signal: ctrl.signal,
        concurrency: 6,
        onProgress: (done, total) => setProgress({ done, total }),
      })
      // Unscored records (e.g. Go vuln DB): fetch their GitHub advisory aliases for a severity
      const extra = aliasesToEnrich(details.vulns)
      if (extra.length > 0) {
        setPhase('enrich')
        setProgress({ done: 0, total: extra.length })
        const more = await fetchVulns(extra, {
          signal: ctrl.signal,
          concurrency: 6,
          onProgress: (done, total) => setProgress({ done, total }),
        })
        for (const [id, v] of more.vulns) details.vulns.set(id, v)
      }
      setResult({
        findings: buildFindings(deps, batch.idsByDep, details.vulns),
        scanned: deps.length - batch.failed.length,
        failed: batch.failed,
        detailErrors: details.errors,
        date: new Date().toISOString().slice(0, 10),
        sources: sources.filter((s) => s.deps.length).map((s) => `${s.name} (${s.format ? FORMAT_LABELS[s.format] : '?'})`),
      })
      setPhase('done')
    } catch (e) {
      if (isAbortError(e)) {
        setPhase('cancelled')
      } else {
        setError((e as Error).message)
        setPhase('error')
      }
    } finally {
      abortRef.current = null
    }
  }

  const visible = useMemo(() => (result ? filterFindings(result.findings, filter) : []), [result, filter])
  const counts = useMemo(() => countBySeverity(result?.findings ?? []), [result])
  const affectedPackages = useMemo(() => new Set(result?.findings.map((f) => `${f.dep.ecosystem}:${f.dep.name}@${f.dep.version}`)).size, [result])

  const markdown = result
    ? toMarkdown(visible, { scannedPackages: result.scanned, sources: result.sources, date: result.date, failedPackages: result.failed.length })
    : ''

  return (
    <div className="stack">
      <div className="callout">
        <strong>Privacy:</strong> files are parsed locally in your browser. Only package <em>names, versions and ecosystems</em> are sent
        to <a href="https://osv.dev" target="_blank" rel="noopener noreferrer">OSV.dev</a> (Google-run open source vulnerability database)
        when you click “Check”. File contents, paths and project names never leave your machine.
      </div>

      <section className="card stack" aria-labelledby="deps-input-h">
        <h2 id="deps-input-h">1. Add lockfiles</h2>
        <div
          className={`deps-dropzone${dragOver ? ' deps-dragover' : ''}`}
          onDragOver={(e) => {
            e.preventDefault()
            setDragOver(true)
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
        >
          <p>Drop files here, or</p>
          <label className="btn deps-filelabel">
            Choose files…
            <input
              type="file"
              multiple
              onChange={(e) => {
                if (e.target.files?.length) void addFiles(e.target.files)
                e.target.value = ''
              }}
            />
          </label>
          <p className="muted small" style={{ marginTop: '.75rem', marginBottom: 0 }}>
            Supported: package-lock.json / npm-shrinkwrap.json, yarn.lock, requirements.txt, Pipfile.lock, poetry.lock, pom.xml, go.mod,
            go.sum, Gemfile.lock, composer.lock, Cargo.lock
          </p>
        </div>

        <label>
          …or paste lockfile content
          <textarea value={paste} onChange={(e) => setPaste(e.target.value)} spellCheck={false} placeholder="requests==2.19.0&#10;django==3.2.0" />
        </label>
        <div className="row">
          <label className="inline">
            Format
            <select value={pasteFormat} onChange={(e) => setPasteFormat(e.target.value as LockfileFormat | 'auto')} style={{ width: 'auto' }}>
              <option value="auto">Auto-detect</option>
              {FORMATS.map((f) => (
                <option key={f} value={f}>
                  {FORMAT_LABELS[f]}
                </option>
              ))}
            </select>
          </label>
          <button type="button" className="btn" onClick={addPaste} disabled={!paste.trim()}>
            Add pasted content
          </button>
        </div>

        {sources.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Format</th>
                <th>Packages</th>
                <th>Skipped</th>
                <th>
                  <span className="deps-sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td>{s.format ? FORMAT_LABELS[s.format] : '—'}</td>
                  <td>{s.error ? <span className="sev-critical">{s.error}</span> : s.deps.length}</td>
                  <td>
                    {s.skipped.length === 0 ? (
                      '0'
                    ) : (
                      <details>
                        <summary>{s.skipped.length}</summary>
                        <ul className="small muted">
                          {s.skipped.slice(0, 200).map((k, i) => (
                            <li key={i}>
                              <code>{k.entry}</code> — {k.reason}
                            </li>
                          ))}
                          {s.skipped.length > 200 && <li>… and {s.skipped.length - 200} more</li>}
                        </ul>
                      </details>
                    )}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      onClick={() => setSources((list) => list.filter((x) => x.id !== s.id))}
                      disabled={running}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card stack" aria-labelledby="deps-scan-h">
        <h2 id="deps-scan-h">2. Check against OSV.dev</h2>
        <div className="row">
          <button type="button" className="btn btn-primary" onClick={() => void scan()} disabled={running || allDeps.length === 0}>
            Check {allDeps.length} unique package{allDeps.length === 1 ? '' : 's'}
          </button>
          {running && (
            <button type="button" className="btn btn-danger" onClick={() => abortRef.current?.abort()}>
              Cancel
            </button>
          )}
          {sources.length > 0 && !running && (
            <button
              type="button"
              className="btn"
              onClick={() => {
                setSources([])
                setResult(null)
                setPhase('idle')
              }}
            >
              Clear all
            </button>
          )}
        </div>
        {running && (
          <div className="stack" aria-live="polite">
            <span className="small muted">
              {PHASE_LABEL[phase]}: {progress.done} / {progress.total}
            </span>
            <div
              className="progress"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={progress.total}
              aria-valuenow={progress.done}
              aria-label="Scan progress"
            >
              <span style={{ width: `${progress.total ? (100 * progress.done) / progress.total : 0}%` }} />
            </div>
          </div>
        )}
        {phase === 'cancelled' && <div className="callout warn">Scan cancelled.</div>}
        {phase === 'error' && <div className="callout error">Scan failed: {error}</div>}
      </section>

      {result && (
        <section className="card stack" aria-labelledby="deps-results-h">
          <h2 id="deps-results-h">3. Results</h2>
          {result.failed.length > 0 && (
            <div className="callout warn">
              {result.failed.length} package(s) could not be checked ({result.failed[0].error}). Results are partial — try again later.
            </div>
          )}
          {result.detailErrors.length > 0 && (
            <div className="callout warn">
              Details for {result.detailErrors.length} advisory id(s) could not be downloaded; they are listed with severity “unknown”.
            </div>
          )}
          {result.findings.length === 0 ? (
            <div className="callout">
              <span className="sev-ok">No known vulnerabilities</span> in {result.scanned} checked packages. This only covers publicly
              disclosed issues in OSV.dev for the exact versions listed — not first-party code or unpinned/skipped dependencies.
            </div>
          ) : (
            <>
              <p>
                <strong>{result.findings.length}</strong> vulnerabilities in <strong>{affectedPackages}</strong> of {result.scanned} packages.
              </p>
              <div className="deps-counts" aria-label="Counts by severity">
                {SEVERITY_LEVELS.filter((l) => counts[l] > 0).map((l) => (
                  <span key={l} className={`badge ${SEV_CLASS[l]}`}>
                    {l}: {counts[l]}
                  </span>
                ))}
              </div>
              <div className="row">
                <label className="inline">
                  Minimum severity
                  <select
                    value={filter.minLevel}
                    onChange={(e) => setFilter({ ...filter, minLevel: e.target.value as FindingFilter['minLevel'] })}
                    style={{ width: 'auto' }}
                  >
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High+</option>
                    <option value="medium">Medium+</option>
                    <option value="low">Low+</option>
                  </select>
                  {filter.minLevel !== 'all' && <span className="small muted">(“unknown” is always shown)</span>}
                </label>
                <label className="inline">
                  <input type="checkbox" checked={filter.hideDev} onChange={(e) => setFilter({ ...filter, hideDev: e.target.checked })} />
                  Hide dev/test dependencies
                </label>
                <label className="inline" style={{ flex: '1 1 14rem' }}>
                  Search
                  <input type="search" value={filter.text} onChange={(e) => setFilter({ ...filter, text: e.target.value })} />
                </label>
              </div>
              <div className="row">
                <span className="small muted">
                  Showing {visible.length} of {result.findings.length}. Exports include the filtered rows.
                </span>
                <span className="spacer" />
                <CopyButton text={markdown} label="Copy Markdown" />
                <button type="button" className="btn" onClick={() => downloadText(`dependency-report-${result.date}.md`, markdown, 'text/markdown')}>
                  Download .md
                </button>
                <button type="button" className="btn" onClick={() => downloadText(`dependency-report-${result.date}.csv`, toCsv(visible), 'text/csv')}>
                  Download .csv
                </button>
              </div>
              <div className="deps-tablewrap">
                <table className="table deps-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Package</th>
                      <th>Version</th>
                      <th>Advisory</th>
                      <th>Aliases</th>
                      <th>Summary</th>
                      <th>Fixed in</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((f) => (
                      <tr key={`${f.dep.ecosystem}:${f.dep.name}@${f.dep.version}:${f.primaryId}`}>
                        <td className="deps-nowrap">
                          <span className={`badge ${SEV_CLASS[f.severity.level]}`} title={f.severity.vector ?? f.severity.source}>
                            {severityLabel(f.severity)}
                          </span>
                        </td>
                        <td>
                          <code>{f.dep.name}</code> {f.dep.dev && <span className="badge sev-info">dev</span>}
                          <div className="small muted">{f.dep.ecosystem}</div>
                        </td>
                        <td className="deps-nowrap">
                          <code>{f.dep.version}</code>
                        </td>
                        <td className="deps-ids">
                          {f.ids.map((id) => (
                            <a key={id} href={osvUrl(id)} target="_blank" rel="noopener noreferrer">
                              {id}
                            </a>
                          ))}
                        </td>
                        <td className="small">{f.aliases.join(', ')}</td>
                        <td className="deps-summary">{f.summary || <span className="muted">(no summary)</span>}</td>
                        <td>{f.fixed.length ? <code>{f.fixed.join(', ')}</code> : <span className="sev-high">no fix</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>
      )}
    </div>
  )
}
