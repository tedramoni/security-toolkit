import { useId, useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { downloadText, slugify } from '../../lib/download'
import { useLocalStorage } from '../../lib/storage'
import type { CpsDraft } from './cps'
import { CPS_STORAGE_KEY, cpsMarkdown, EMPTY_CPS, parsePolicyOids, RFC3647_OUTLINE, sanitizeCps } from './cps'
import { SafeLink } from './ui'

const FIELDS: readonly (readonly [keyof CpsDraft, string, string])[] = [
  ['caName', 'CA name', 'Example Corp Issuing CA 1'],
  ['orgName', 'Operating organization', 'Example Corp'],
  ['policyOids', 'Policy OID(s)', '1.3.6.1.4.1.<your PEN>.1.1'],
  ['version', 'Document version', '1.0'],
  ['effectiveDate', 'Effective date', 'YYYY-MM-DD'],
  ['contactName', 'Contact name / team', 'PKI Policy Authority'],
  ['contactEmail', 'Contact e-mail', 'pki@example.com'],
  ['contactAddress', 'Postal address', ''],
  ['repositoryUrl', 'Repository URL', 'https://pki.example.com/repository'],
]

export function CpsTab() {
  const [raw, setRaw] = useLocalStorage<unknown>(CPS_STORAGE_KEY, EMPTY_CPS)
  const d = useMemo(() => sanitizeCps(raw), [raw])
  const set = (patch: Partial<CpsDraft>) => setRaw({ ...d, ...patch })
  const [section, setSection] = useState('1.1')
  const [placeholders, setPlaceholders] = useState(true)
  const md = useMemo(() => cpsMarkdown(d, placeholders), [d, placeholders])
  const oids = parsePolicyOids(d.policyOids)
  const ids = useId()

  return (
    <div className="stack">
      <p className="small">
        Skeleton for a Certificate Policy or Certification Practice Statement following the outline in{' '}
        <SafeLink href="https://www.rfc-editor.org/rfc/rfc3647#section-6">RFC 3647 §6</SafeLink> (the structure the CA/B
        Forum and root programs expect). The draft is saved in this browser’s localStorage (key scp:pki-cps).
      </p>
      <section className="card stack" aria-label="Document fields">
        <div className="row">
          <label className="inline">
            <input type="radio" name={`${ids}-type`} checked={d.docType === 'CPS'} onChange={() => set({ docType: 'CPS' })} /> CPS
          </label>
          <label className="inline">
            <input type="radio" name={`${ids}-type`} checked={d.docType === 'CP'} onChange={() => set({ docType: 'CP' })} /> CP
          </label>
        </div>
        <div className="pki-form-grid">
          {FIELDS.map(([k, label, ph]) => (
            <div key={k} className="stack pki-tight">
              <label htmlFor={`${ids}-${k}`}>{label}</label>
              <input id={`${ids}-${k}`} type="text" value={d[k] as string} placeholder={ph} maxLength={1000} onChange={(e) => set({ [k]: e.target.value } as Partial<CpsDraft>)} />
              {k === 'policyOids' && oids.invalid.length > 0 && <span className="pki-err small">Invalid OID(s): {oids.invalid.join(', ')}</span>}
              {k === 'repositoryUrl' && d.repositoryUrl && !/^https?:\/\//i.test(d.repositoryUrl) && <span className="pki-err small">Must start with http:// or https://</span>}
            </div>
          ))}
        </div>
        <h3 className="pki-h">Section text (optional)</h3>
        <div className="row">
          <label htmlFor={`${ids}-sec`} className="inline">
            Section
          </label>
          <select id={`${ids}-sec`} value={section} onChange={(e) => setSection(e.target.value)}>
            {RFC3647_OUTLINE.map(([n, t]) => (
              <option key={n} value={n}>
                {n} {t}
                {d.sections[n] ? ' ✎' : ''}
              </option>
            ))}
          </select>
        </div>
        <label htmlFor={`${ids}-text`} className="sr-only">
          Text for section {section}
        </label>
        <textarea
          id={`${ids}-text`}
          rows={5}
          value={d.sections[section] ?? ''}
          placeholder="Write the provision, or “No stipulation.”"
          onChange={(e) => {
            const sections = { ...d.sections }
            if (e.target.value) sections[section] = e.target.value
            else delete sections[section]
            set({ sections })
          }}
        />
        <div className="row">
          <label className="inline">
            <input type="checkbox" checked={placeholders} onChange={(e) => setPlaceholders(e.target.checked)} /> Add “To be completed” placeholders
          </label>
          <span className="spacer" />
          <button
            type="button"
            className="btn btn-sm btn-danger"
            onClick={() => {
              if (window.confirm('Reset the CP/CPS draft?')) setRaw(EMPTY_CPS)
            }}
          >
            Reset draft
          </button>
        </div>
      </section>
      <section className="card stack" aria-label="Markdown preview">
        <div className="row">
          <h2 className="pki-h">{d.docType} outline (Markdown)</h2>
          <span className="spacer" />
          <CopyButton text={md} />
          <button type="button" className="btn btn-primary" onClick={() => downloadText(`${slugify(d.caName || 'ca')}-${d.docType.toLowerCase()}.md`, md, 'text/markdown')}>
            Download .md
          </button>
        </div>
        <pre className="codeblock pki-md">{md}</pre>
      </section>
    </div>
  )
}
