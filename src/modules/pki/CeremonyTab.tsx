import { useId, useMemo } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { downloadText, slugify } from '../../lib/download'
import { newId, useLocalStorage } from '../../lib/storage'
import type { CeremonyDraft, Participant } from './ceremony'
import { analyzeQuorum, CEREMONY_STORAGE_KEY, ceremonyMarkdown, EMPTY_CEREMONY, ROLES, sanitizeDraft } from './ceremony'

const NUMS = Array.from({ length: 15 }, (_, i) => i + 1)

export function CeremonyTab() {
  const [raw, setRaw] = useLocalStorage<unknown>(CEREMONY_STORAGE_KEY, EMPTY_CEREMONY)
  const d = useMemo(() => sanitizeDraft(raw), [raw])
  const set = (patch: Partial<CeremonyDraft>) => setRaw({ ...d, ...patch })
  const q = analyzeQuorum(d.m, d.n)
  const md = useMemo(() => ceremonyMarkdown(d), [d])
  const ids = useId()

  const setParticipant = (id: string, patch: Partial<Participant>) => set({ participants: d.participants.map((p) => (p.id === id ? { ...p, ...patch } : p)) })

  const fillCustodians = () => {
    const existing = d.participants.filter((p) => p.role === 'Key Custodian').length
    const add: Participant[] = Array.from({ length: Math.max(0, q.n - existing) }, (_, i) => ({ id: newId(), name: `Custodian ${existing + i + 1}`, role: 'Key Custodian', organization: '' }))
    const base: Participant[] = d.participants.length
      ? d.participants
      : [
          { id: newId(), name: '', role: 'Ceremony Administrator', organization: '' },
          { id: newId(), name: '', role: 'Internal Witness', organization: '' },
          { id: newId(), name: '', role: 'Video Operator', organization: '' },
        ]
    set({ participants: [...base, ...add] })
  }

  return (
    <div className="stack">
      <p className="small muted">The draft is saved in this browser’s localStorage (key scp:pki-ceremony) — no secrets belong here.</p>
      <section className="card stack" aria-label="M-of-N calculator">
        <h2 className="pki-h">M-of-N quorum</h2>
        <div className="row">
          <label htmlFor={`${ids}-m`} className="inline">
            M (needed)
          </label>
          <select id={`${ids}-m`} value={q.m} onChange={(e) => set({ m: Number(e.target.value) })}>
            {NUMS.filter((x) => x <= q.n).map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <span>of</span>
          <label htmlFor={`${ids}-n`} className="inline">
            N (custodians)
          </label>
          <select id={`${ids}-n`} value={q.n} onChange={(e) => set({ n: Number(e.target.value), m: Math.min(q.m, Number(e.target.value)) })}>
            {NUMS.map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </div>
        <div className="pki-stats">
          <div className="pki-stat">
            <div className="pki-stat-num">{q.lossTolerance}</div>
            <div className="small muted">custodians/cards can be lost (N − M)</div>
          </div>
          <div className="pki-stat">
            <div className="pki-stat-num">{q.collusionThreshold}</div>
            <div className="small muted">must collude to misuse the key (M)</div>
          </div>
          <div className="pki-stat">
            <div className="pki-stat-num">{q.quorums.toLocaleString()}</div>
            <div className="small muted">distinct quorums C(N, M)</div>
          </div>
        </div>
        {q.warnings.map((w) => (
          <div key={w.text} className={`callout small ${w.severity === 'high' ? 'error' : 'warn'}`}>
            {w.text}
          </div>
        ))}
        <p>
          <strong>Recommendation:</strong> {q.recommendation}
        </p>
      </section>

      <section className="card stack" aria-label="Ceremony details">
        <h2 className="pki-h">Runbook details</h2>
        <div className="pki-form-grid">
          {(
            [
              ['caName', 'CA name', 'Example Corp Root CA G1'],
              ['title', 'Ceremony title', 'Root key generation ceremony'],
              ['date', 'Date', 'YYYY-MM-DD'],
              ['location', 'Location', 'Secure room B, Paris DC'],
              ['hsmModel', 'HSM model / firmware', 'Vendor model, FW x.y, FIPS 140-3 L3'],
              ['keyAlgorithm', 'Key algorithm', 'ECDSA P-384 (SHA-384)'],
            ] as const
          ).map(([k, label, ph]) => (
            <div key={k} className="stack pki-tight">
              <label htmlFor={`${ids}-${k}`}>{label}</label>
              <input id={`${ids}-${k}`} type={k === 'date' ? 'date' : 'text'} value={d[k]} placeholder={ph} maxLength={500} onChange={(e) => set({ [k]: e.target.value })} />
            </div>
          ))}
        </div>
        <h3 className="pki-h">Participants</h3>
        {d.participants.length > 0 && (
          <div className="pki-table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Role</th>
                  <th scope="col">Organization</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {d.participants.map((p, i) => (
                  <tr key={p.id}>
                    <td>
                      <input type="text" aria-label={`Participant ${i + 1} name`} value={p.name} maxLength={200} onChange={(e) => setParticipant(p.id, { name: e.target.value })} />
                    </td>
                    <td>
                      <select aria-label={`Participant ${i + 1} role`} value={p.role} onChange={(e) => setParticipant(p.id, { role: e.target.value })}>
                        {(ROLES as readonly string[]).includes(p.role) ? null : <option>{p.role}</option>}
                        {ROLES.map((r) => (
                          <option key={r}>{r}</option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <input type="text" aria-label={`Participant ${i + 1} organization`} value={p.organization} maxLength={200} onChange={(e) => setParticipant(p.id, { organization: e.target.value })} />
                    </td>
                    <td>
                      <button type="button" className="btn btn-sm btn-danger" aria-label={`Remove participant ${i + 1}`} onClick={() => set({ participants: d.participants.filter((x) => x.id !== p.id) })}>
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="row">
          <button type="button" className="btn btn-sm" onClick={() => set({ participants: [...d.participants, { id: newId(), name: '', role: 'Key Custodian', organization: '' }] })} disabled={d.participants.length >= 40}>
            Add participant
          </button>
          <button type="button" className="btn btn-sm" onClick={fillCustodians}>
            Add standard roles + {q.n} custodians
          </button>
        </div>
        <label htmlFor={`${ids}-notes`}>Notes</label>
        <textarea id={`${ids}-notes`} rows={3} value={d.notes} maxLength={5000} onChange={(e) => set({ notes: e.target.value })} />
        <div className="row">
          <button
            type="button"
            className="btn btn-sm btn-danger"
            onClick={() => {
              if (window.confirm('Reset the ceremony draft?')) setRaw(EMPTY_CEREMONY)
            }}
          >
            Reset draft
          </button>
        </div>
      </section>

      <section className="card stack" aria-label="Runbook preview">
        <div className="row">
          <h2 className="pki-h">Runbook (Markdown)</h2>
          <span className="spacer" />
          <CopyButton text={md} />
          <button type="button" className="btn btn-primary" onClick={() => downloadText(`${slugify(d.caName || 'key-ceremony')}-ceremony.md`, md, 'text/markdown')}>
            Download .md
          </button>
        </div>
        <pre className="codeblock pki-md">{md}</pre>
      </section>
    </div>
  )
}
