import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { MODULES } from './modules.ts'
import { STORAGE_KEYS, exportAll, importAll, readJSON } from '../lib/storage.ts'
import { downloadJSON } from '../lib/download.ts'

export function Home() {
  const fileRef = useRef<HTMLInputElement>(null)
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  // bumped after an import so the counters below re-read localStorage
  const [, setRevision] = useState(0)

  const threatModels = readJSON<unknown[]>(STORAGE_KEYS.threatModels, []).length
  const reviews = readJSON<unknown[]>(STORAGE_KEYS.reviews, []).length

  async function onImport(file: File) {
    try {
      const n = importAll(JSON.parse(await file.text()))
      setMessage({ kind: 'ok', text: `Restored ${n} data set${n === 1 ? '' : 's'}.` })
      setRevision((x) => x + 1)
    } catch (e) {
      setMessage({ kind: 'error', text: `Import failed: ${(e as Error).message}` })
    }
  }

  return (
    <>
      <header className="page-header">
        <h1>Security Champion Toolkit</h1>
        <p>Everyday tools to bring security into your team's design, code review and delivery, with no backend.</p>
      </header>

      <div className="grid">
        {MODULES.map((m) => (
          <Link key={m.path} to={m.path} className="card" style={{ textDecoration: 'none', color: 'inherit' }}>
            <h2>
              <span aria-hidden>{m.icon}</span> {m.title}
            </h2>
            <p className="muted small">{m.description}</p>
          </Link>
        ))}
      </div>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>Your data</h2>
        <p className="muted small">
          Everything is stored in this browser's localStorage. Pasted tokens, headers and code are processed locally;
          only the dependency checker sends package names and versions to the public OSV.dev API.
        </p>
        <p>
          <strong>{threatModels}</strong> threat model{threatModels === 1 ? '' : 's'} · <strong>{reviews}</strong> saved
          review{reviews === 1 ? '' : 's'}
        </p>
        <div className="row">
          <button className="btn" onClick={() => downloadJSON('security-champion-backup.json', exportAll())}>
            Export backup
          </button>
          <button className="btn" onClick={() => fileRef.current?.click()}>
            Import backup
          </button>
          <input
            ref={fileRef}
            type="file"
            accept="application/json,.json"
            hidden
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) void onImport(f)
              e.target.value = ''
            }}
          />
        </div>
        {message && (
          <p className={`callout ${message.kind === 'error' ? 'error' : ''}`} style={{ marginTop: '.75rem' }} role="status">
            {message.text}
          </p>
        )}
      </section>
    </>
  )
}
