import { useEffect, useId, useRef, useState } from 'react'
import type { ArchiveIssue } from './engine'
import { DEFAULT_FETCH_LIMITS, fetchGitHub, GitHubError, parseGitHubUrl } from './github'
import { fromBrowserFiles, ingest, UPLOAD_LIMITS } from './ingest'
import { SAMPLES } from './samples'
import type { FileKind, ScanFile } from './types'
import { FILE_KINDS } from './types'

export interface ScanInput {
  source: string
  files: ScanFile[]
  issues: ArchiveIssue[]
  warnings: string[]
}

type Mode = 'paste' | 'upload' | 'github' | 'samples'
const MODES: { id: Mode; label: string }[] = [
  { id: 'paste', label: 'Paste' },
  { id: 'upload', label: 'Upload files / folder / .zip' },
  { id: 'github', label: 'GitHub URL' },
  { id: 'samples', label: 'Samples' },
]

const MAX_PASTE = 2 * 1024 * 1024

export function InputPanel({ onInput, busy }: { onInput: (i: ScanInput) => void; busy: boolean }) {
  const [mode, setMode] = useState<Mode>('paste')
  return (
    <section className="card stack" aria-label="Input">
      <div className="row" role="group" aria-label="Input method">
        {MODES.map((m) => (
          <button key={m.id} type="button" className={`btn btn-sm${mode === m.id ? ' btn-primary' : ''}`} aria-pressed={mode === m.id} onClick={() => setMode(m.id)}>
            {m.label}
          </button>
        ))}
      </div>
      {mode === 'paste' && <PasteInput onInput={onInput} />}
      {mode === 'upload' && <UploadInput onInput={onInput} busy={busy} />}
      {mode === 'github' && <GitHubInput onInput={onInput} />}
      {mode === 'samples' && <SamplesInput onInput={onInput} />}
    </section>
  )
}

function PasteInput({ onInput }: { onInput: (i: ScanInput) => void }) {
  const [name, setName] = useState('SKILL.md')
  const [kind, setKind] = useState<FileKind | ''>('')
  const [text, setText] = useState('')
  const ids = { name: useId(), kind: useId(), text: useId() }
  // Latest callback in a ref: the parent passes a new function on every render, and having it in the
  // effect's dependencies re-triggered the scan after every scan (endless 400 ms rescan loop).
  const onInputRef = useRef(onInput)
  useEffect(() => {
    onInputRef.current = onInput
  })

  // Debounced auto-scan.
  useEffect(() => {
    if (text.trim() === '') return
    const t = setTimeout(() => {
      const content = text.length > MAX_PASTE ? text.slice(0, MAX_PASTE) : text
      const path = name.trim() || 'pasted.txt'
      onInputRef.current({
        source: `pasted ${path}`,
        files: [{ path, content, size: content.length, kind: kind || undefined, truncated: text.length > MAX_PASTE }],
        issues: [],
        warnings: text.length > MAX_PASTE ? [`Input truncated to ${MAX_PASTE / 1024 / 1024} MB.`] : [],
      })
    }, 400)
    return () => clearTimeout(t)
  }, [text, name, kind])

  return (
    <div className="stack">
      <div className="row">
        <label htmlFor={ids.name} className="skill-scanner-field">
          File name (decides the file type)
          <input id={ids.name} type="text" value={name} onChange={(e) => setName(e.target.value)} spellCheck={false} />
        </label>
        <label htmlFor={ids.kind} className="skill-scanner-field">
          Type
          <select id={ids.kind} value={kind} onChange={(e) => setKind(e.target.value as FileKind | '')}>
            <option value="">Auto-detect from name</option>
            {FILE_KINDS.map((k) => (
              <option key={k.id} value={k.id}>
                {k.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label htmlFor={ids.text}>Content (SKILL.md, AGENTS.md, CLAUDE.md, .mcp.json, settings.json, a script…)</label>
      <textarea id={ids.text} rows={14} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} placeholder={'---\nname: my-skill\ndescription: …\n---\n'} />
      <div className="row small muted">
        Scans automatically as you type. Nothing leaves your browser.
        <span className="spacer" />
        <button type="button" className="btn btn-sm" onClick={() => setText('')} disabled={text === ''}>
          Clear
        </button>
      </div>
    </div>
  )
}

function UploadInput({ onInput, busy }: { onInput: (i: ScanInput) => void; busy: boolean }) {
  const [error, setError] = useState<string>()
  const [drag, setDrag] = useState(false)
  const [reading, setReading] = useState(false)
  const filesId = useId()
  const dirId = useId()

  const handle = async (list: File[], label: string) => {
    if (list.length === 0) return
    setError(undefined)
    setReading(true)
    try {
      const r = await ingest(fromBrowserFiles(list))
      if (r.files.length === 0 && r.issues.length === 0) {
        setError(`No scannable text files found. ${r.warnings.join(' ')}`)
        return
      }
      onInput({ source: label, files: r.files, issues: r.issues, warnings: r.warnings })
    } catch (e) {
      setError(`Could not read the files: ${(e as Error).message}`)
    } finally {
      setReading(false)
    }
  }

  const describe = (list: File[]) => {
    const first = (list[0] as File & { webkitRelativePath?: string }).webkitRelativePath?.split('/')[0]
    return list.length === 1 ? list[0].name : first ? `folder ${first} (${list.length} files)` : `${list.length} files`
  }

  return (
    <div className="stack">
      <div
        className={`skill-scanner-drop${drag ? ' skill-scanner-drop-active' : ''}`}
        onDragOver={(e) => {
          e.preventDefault()
          setDrag(true)
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDrag(false)
          const list = [...e.dataTransfer.files]
          void handle(list, describe(list))
        }}
      >
        <p>Drop files or a .zip here, or choose:</p>
        <div className="row">
          <label htmlFor={filesId} className="inline small">
            Files / .zip:
          </label>
          <input
            id={filesId}
            type="file"
            multiple
            disabled={busy || reading}
            onChange={(e) => {
              const list = [...(e.target.files ?? [])]
              e.target.value = ''
              void handle(list, describe(list))
            }}
          />
        </div>
        <div className="row">
          <label htmlFor={dirId} className="inline small">
            Whole folder:
          </label>
          <input
            id={dirId}
            type="file"
            // Non-standard but supported by Chrome, Edge, Firefox and Safari.
            {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
            disabled={busy || reading}
            onChange={(e) => {
              const list = [...(e.target.files ?? [])]
              e.target.value = ''
              void handle(list, describe(list))
            }}
          />
        </div>
      </div>
      <p className="small muted">
        Limits: {UPLOAD_LIMITS.maxFiles} files, {UPLOAD_LIMITS.maxTotalBytes / 1024 / 1024} MB total, text files over {UPLOAD_LIMITS.maxTextBytes / 1024 / 1024} MB truncated. ZIPs: stored/deflate only; path-traversal and
        symlink entries are rejected and reported; zip-bomb limits (5 MB per entry, 50 MB total, 100:1 ratio). node_modules and .git are ignored.
      </p>
      {reading && <p role="status">Reading files…</p>}
      {error && (
        <div className="callout error" role="alert">
          {error}
        </div>
      )}
    </div>
  )
}

function GitHubInput({ onInput }: { onInput: (i: ScanInput) => void }) {
  const [url, setUrl] = useState('')
  const [token, setToken] = useState('')
  const [status, setStatus] = useState<string>()
  const [error, setError] = useState<string>()
  const [running, setRunning] = useState(false)
  const abort = useRef<AbortController | undefined>(undefined)
  const ids = { url: useId(), token: useId() }

  useEffect(() => () => abort.current?.abort(), [])

  const run = async () => {
    const p = parseGitHubUrl(url)
    if (!p.ok) {
      setError(p.error)
      return
    }
    setError(undefined)
    setRunning(true)
    abort.current?.abort()
    const ctrl = new AbortController()
    abort.current = ctrl
    try {
      const r = await fetchGitHub(p.target, { token, signal: ctrl.signal, onProgress: setStatus })
      if (r.files.length === 0) {
        setError(`No scannable files found. ${r.warnings.join(' ')}`)
        return
      }
      onInput({
        source: `github.com/${r.label}`,
        files: r.files,
        issues: r.symlinks.map((s) => ({ archive: s, entry: s, kind: 'symlink' as const, detail: 'Symbolic link in the repository (not followed).' })),
        warnings: r.warnings,
      })
      setStatus(`Fetched ${r.files.length} files from ${r.label}.`)
    } catch (e) {
      if ((e as Error).name === 'AbortError') setStatus('Cancelled.')
      else setError(e instanceof GitHubError ? e.message : `Unexpected error: ${(e as Error).message}`)
    } finally {
      setRunning(false)
    }
  }

  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault()
        void run()
      }}
    >
      <label htmlFor={ids.url}>Public GitHub URL — repository, folder (/tree/…) or file (/blob/…/SKILL.md scans the whole skill folder)</label>
      <input id={ids.url} type="text" inputMode="url" placeholder="https://github.com/owner/repo/tree/main/skills/my-skill" value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
      <details>
        <summary className="small">Optional token (private repos, higher rate limit)</summary>
        <div className="stack">
          <label htmlFor={ids.token}>GitHub token — kept in memory only, never stored; sent only to api.github.com</label>
          <input id={ids.token} type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} placeholder="github_pat_… (read-only Contents permission is enough)" />
        </div>
      </details>
      <div className="row">
        <button type="submit" className="btn btn-primary" disabled={running || url.trim() === ''}>
          {running ? 'Fetching…' : 'Fetch & scan'}
        </button>
        {running && (
          <button type="button" className="btn" onClick={() => abort.current?.abort()}>
            Cancel
          </button>
        )}
        <span className="small muted" role="status">
          {status}
        </span>
      </div>
      <p className="small muted">
        Files are downloaded straight from api.github.com / raw.githubusercontent.com by your browser. Without a token GitHub allows 60 API requests per hour per IP (listing uses 1–3; file downloads from
        raw.githubusercontent.com don’t count). Caps: {DEFAULT_FETCH_LIMITS.maxFiles} text files, {DEFAULT_FETCH_LIMITS.maxFileBytes / 1024} KB per file, {DEFAULT_FETCH_LIMITS.maxTotalBytes / 1024 / 1024} MB total.
        Binaries are not downloaded (executables are flagged by name).
      </p>
      {error && (
        <div className="callout error" role="alert">
          {error}
        </div>
      )}
    </form>
  )
}

function SamplesInput({ onInput }: { onInput: (i: ScanInput) => void }) {
  return (
    <div className="grid">
      {SAMPLES.map((s) => (
        <div key={s.id} className="card stack">
          <strong>{s.label}</strong>
          <p className="small muted">{s.description}</p>
          <p className="small mono">{s.files.length} files</p>
          <button type="button" className="btn btn-sm" onClick={() => onInput({ source: `sample: ${s.label}`, files: s.files, issues: [], warnings: [] })}>
            Scan this sample
          </button>
        </div>
      ))}
    </div>
  )
}
