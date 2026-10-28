import { useState } from 'react'
import type { KeyboardEvent } from 'react'
import { CiGenerator } from './CiGenerator.tsx'
import { DepsChecker } from './DepsChecker.tsx'
import './deps.css'

const TABS = [
  { id: 'osv', label: 'Vulnerable dependencies' },
  { id: 'ci', label: 'GitHub Actions security workflows' },
] as const
type TabId = (typeof TABS)[number]['id']

export default function DepsModule() {
  const [tab, setTab] = useState<TabId>('osv')

  // WAI-ARIA tabs pattern: arrow keys move between tabs
  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
    const i = TABS.findIndex((t) => t.id === tab)
    const next = TABS[(i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length]
    setTab(next.id)
    document.getElementById(`deps-tab-${next.id}`)?.focus()
  }

  return (
    <>
      <header className="page-header">
        <h1>Dependencies &amp; CI</h1>
        <p>
          Check lockfiles for known vulnerabilities with OSV.dev, and generate least-privilege GitHub Actions workflows for SAST,
          dependency review, secret scanning and supply-chain hygiene.
        </p>
      </header>
      <div className="tabs" role="tablist" aria-label="Dependencies and CI tools">
        {TABS.map((t) => (
          <button
            key={t.id}
            id={`deps-tab-${t.id}`}
            type="button"
            role="tab"
            className="tab"
            aria-selected={tab === t.id}
            aria-controls={`deps-panel-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => setTab(t.id)}
            onKeyDown={onKeyDown}
          >
            {t.label}
          </button>
        ))}
      </div>
      {/* both panels stay mounted so scan results survive switching tabs */}
      <div id="deps-panel-osv" role="tabpanel" aria-labelledby="deps-tab-osv" hidden={tab !== 'osv'}>
        <DepsChecker />
      </div>
      <div id="deps-panel-ci" role="tabpanel" aria-labelledby="deps-tab-ci" hidden={tab !== 'ci'}>
        <CiGenerator />
      </div>
    </>
  )
}
