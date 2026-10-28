import type { KeyboardEvent } from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { AboutTab } from './AboutTab'
import type { ScanResult } from './engine'
import { scanFiles } from './engine'
import type { ScanInput } from './InputPanel'
import { InputPanel } from './InputPanel'
import { mergeSuppressions } from './report'
import { Results } from './Results'
import { RulesTab } from './RulesTab'
import { useScannerState } from './state'
import './skill-scanner.css'

const TABS = [
  { id: 'scan', label: 'Scan' },
  { id: 'rules', label: 'Rules' },
  { id: 'about', label: 'About & CI' },
] as const

export default function SkillScanner() {
  const [params, setParams] = useSearchParams()
  const active = TABS.find((t) => t.id === params.get('tab')) ?? TABS[0]
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([])
  const [state, update] = useScannerState()
  const [input, setInput] = useState<ScanInput>()
  const [result, setResult] = useState<ScanResult>()
  const [progress, setProgress] = useState<{ done: number; total: number }>()
  const [error, setError] = useState<string>()
  const disabled = useMemo(() => new Set(state.disabledRules), [state.disabledRules])

  const startScan = (next: ScanInput) => {
    setInput(next)
    setProgress({ done: 0, total: next.files.length })
    setError(undefined)
  }

  // (Re)scan whenever the input or the enabled rules change. Stale runs are discarded.
  useEffect(() => {
    if (!input) return
    let cancelled = false
    scanFiles(input.files, { disabledRules: disabled, archiveIssues: input.issues }, (done, total) => {
      if (!cancelled) setProgress({ done, total })
    })
      .then((r) => {
        if (!cancelled) {
          setResult(r)
          setProgress(undefined)
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setError(`Scan failed: ${(e as Error).message}`)
          setProgress(undefined)
        }
      })
    return () => {
      cancelled = true
    }
  }, [input, disabled])

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
        <h1>AI Skill Scanner</h1>
        <p>
          Static security scan for AI agent extensions: Agent Skills (SKILL.md + bundled scripts), agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules…), MCP server configs and Claude Code
          settings/hooks. Finds prompt injection, hidden Unicode, exfiltration, credential theft, dangerous commands, unpinned dependencies and over-broad permissions — entirely in your browser.
        </p>
        <p className="small">
          Rule categories inspired by{' '}
          <a href="https://github.com/NVIDIA/SkillSpector" target="_blank" rel="noopener noreferrer">
            NVIDIA SkillSpector
          </a>{' '}
          (Apache-2.0).
        </p>
      </header>

      <div className="tabs" role="tablist" aria-label="AI Skill Scanner" onKeyDown={onKeyDown}>
        {TABS.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              tabRefs.current[i] = el
            }}
            type="button"
            role="tab"
            className="tab"
            id={`skill-scanner-tab-${t.id}`}
            aria-selected={t === active}
            aria-controls={`skill-scanner-panel-${t.id}`}
            tabIndex={t === active ? 0 : -1}
            onClick={() => select(t.id)}
          >
            {t.label}
            {t.id === 'rules' && disabled.size > 0 ? ` (${disabled.size} off)` : ''}
          </button>
        ))}
      </div>

      {/* All panels stay mounted (hidden) so input and results survive tab switches. */}
      <div role="tabpanel" id="skill-scanner-panel-scan" aria-labelledby="skill-scanner-tab-scan" hidden={active.id !== 'scan'}>
        <div className="stack">
        <InputPanel onInput={startScan} busy={progress !== undefined} />
        {input && input.warnings.length > 0 && (
          <div className="callout warn small" role="status">
            {input.warnings.map((w) => (
              <div key={w}>{w}</div>
            ))}
          </div>
        )}
        {progress && (
          <div role="status" className="stack small">
            Scanning {progress.done}/{progress.total} files…
            <div className="progress">
              <span style={{ width: `${progress.total ? (100 * progress.done) / progress.total : 0}%` }} />
            </div>
          </div>
        )}
        {error && (
          <div className="callout error" role="alert">
            {error}
          </div>
        )}
        {result && input && (
          <Results
            // New source → fresh filters/viewer (a stale file filter would hide every finding).
            key={input.source}
            result={result}
            source={input.source}
            suppressions={state.suppressions}
            onSuppress={(s) => update((st) => ({ ...st, suppressions: mergeSuppressions(st.suppressions, [s]) }))}
            onUnsuppress={(fp) => update((st) => ({ ...st, suppressions: st.suppressions.filter((s) => s.fingerprint !== fp) }))}
            onImportBaseline={(list) => update((st) => ({ ...st, suppressions: mergeSuppressions(st.suppressions, list) }))}
          />
        )}
        {!input && <p className="muted">Paste a file, upload a skill folder or .zip, enter a GitHub URL, or try one of the samples.</p>}
        </div>
      </div>

      <div role="tabpanel" id="skill-scanner-panel-rules" aria-labelledby="skill-scanner-tab-rules" hidden={active.id !== 'rules'}>
        <RulesTab disabled={disabled} onChange={(next) => update((st) => ({ ...st, disabledRules: next }))} />
      </div>

      <div role="tabpanel" id="skill-scanner-panel-about" aria-labelledby="skill-scanner-tab-about" hidden={active.id !== 'about'}>
        <AboutTab />
      </div>
    </>
  )
}
