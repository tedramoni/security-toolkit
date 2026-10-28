import type { ComponentType, KeyboardEvent, ReactNode } from 'react'
import { useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CeremonyTab } from './CeremonyTab'
import { CertTab } from './CertTab'
import { ChainTab } from './ChainTab'
import { ConvertTab } from './ConvertTab'
import { CpsTab } from './CpsTab'
import { CrlTab } from './CrlTab'
import { CsrTab } from './CsrTab'
import { GenerateTab } from './GenerateTab'
import { KeyMatchTab } from './KeyMatchTab'
import { OcspTab } from './OcspTab'
import './pki.css'

interface TabDef {
  id: string
  label: string
  Component: ComponentType
}

const TABS: readonly TabDef[] = [
  { id: 'cert', label: 'Certificate', Component: CertTab },
  { id: 'chain', label: 'Chain', Component: ChainTab },
  { id: 'csr', label: 'CSR decoder', Component: CsrTab },
  { id: 'generate', label: 'CSR & key generator', Component: GenerateTab },
  { id: 'keymatch', label: 'Key matcher', Component: KeyMatchTab },
  { id: 'convert', label: 'Converter', Component: ConvertTab },
  { id: 'crl', label: 'CRL', Component: CrlTab },
  { id: 'ocsp', label: 'OCSP', Component: OcspTab },
  { id: 'ceremony', label: 'Key ceremony', Component: CeremonyTab },
  { id: 'cps', label: 'CP/CPS outline', Component: CpsTab },
]

export default function PkiTools() {
  const [params, setParams] = useSearchParams()
  const requested = params.get('tab')
  const active = TABS.find((t) => t.id === requested) ?? TABS[0]
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([])

  const select = (id: string, focus = false) => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.set('tab', id)
        return next
      },
      { replace: true },
    )
    if (focus) tabRefs.current[TABS.findIndex((t) => t.id === id)]?.focus()
  }

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = TABS.indexOf(active)
    let next: number | undefined
    if (e.key === 'ArrowRight') next = (i + 1) % TABS.length
    else if (e.key === 'ArrowLeft') next = (i - 1 + TABS.length) % TABS.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = TABS.length - 1
    if (next === undefined) return
    e.preventDefault()
    select(TABS[next].id, true)
  }

  return (
    <>
      <header className="page-header">
        <h1>PKI Tools</h1>
        <p>
          Decode and lint X.509 certificates, CSRs and CRLs, build and verify chains, generate CSRs, match keys, convert
          formats and plan key ceremonies. Everything runs in your browser with
          WebCrypto — certificates and keys are never uploaded, and only your ceremony / CPS drafts are stored (locally).
        </p>
      </header>

      <div className="tabs pki-tabs" role="tablist" aria-label="PKI tools" onKeyDown={onKeyDown}>
        {TABS.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              tabRefs.current[i] = el
            }}
            type="button"
            role="tab"
            className="tab"
            id={`pki-tab-${t.id}`}
            aria-selected={t === active}
            aria-controls={`pki-panel-${t.id}`}
            tabIndex={t === active ? 0 : -1}
            onClick={() => select(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Panels mount on first visit, then stay mounted (hidden) so input survives tab switches. */}
      {TABS.map(({ id, Component }) => (
        <Panel key={id} id={id} active={id === active.id}>
          <Component />
        </Panel>
      ))}
    </>
  )
}

function Panel({ id, active, children }: { id: string; active: boolean; children: ReactNode }) {
  const [visited, setVisited] = useState(active)
  if (active && !visited) setVisited(true)
  return (
    <div className="pki-panel" role="tabpanel" id={`pki-panel-${id}`} aria-labelledby={`pki-tab-${id}`} hidden={!active}>
      {visited || active ? children : null}
    </div>
  )
}
