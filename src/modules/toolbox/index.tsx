import type { ComponentType, KeyboardEvent } from 'react'
import { useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CspTab } from './CspTab'
import { EncodeTab } from './EncodeTab'
import { HeadersTab } from './HeadersTab'
import { JwtTab } from './JwtTab'
import { SecretsTab } from './SecretsTab'
import './toolbox.css'

interface TabDef {
  id: string
  label: string
  Component: ComponentType
}

const TABS: readonly TabDef[] = [
  { id: 'jwt', label: 'JWT', Component: JwtTab },
  { id: 'csp', label: 'CSP', Component: CspTab },
  { id: 'headers', label: 'Headers', Component: HeadersTab },
  { id: 'encode', label: 'Encode / Hash', Component: EncodeTab },
  { id: 'secrets', label: 'Secrets', Component: SecretsTab },
]

export default function Toolbox() {
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
        <h1>Dev Toolbox</h1>
        <p>
          Everyday helpers for security reviews: decode and lint JWTs, evaluate and build Content-Security-Policies, grade
          HTTP security headers and cookies, encode/decode/hash data and scan text for leaked secrets. Everything runs
          locally in your browser — nothing is sent or stored.
        </p>
      </header>

      <div className="tabs" role="tablist" aria-label="Toolbox tools" onKeyDown={onKeyDown}>
        {TABS.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              tabRefs.current[i] = el
            }}
            type="button"
            role="tab"
            className="tab"
            id={`toolbox-tab-${t.id}`}
            aria-selected={t === active}
            aria-controls={`toolbox-panel-${t.id}`}
            tabIndex={t === active ? 0 : -1}
            onClick={() => select(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* All panels stay mounted (hidden) so input survives tab switches. */}
      {TABS.map(({ id, Component }) => (
        <div key={id} className="toolbox-panel" role="tabpanel" id={`toolbox-panel-${id}`} aria-labelledby={`toolbox-tab-${id}`} hidden={id !== active.id}>
          <Component />
        </div>
      ))}
    </>
  )
}
