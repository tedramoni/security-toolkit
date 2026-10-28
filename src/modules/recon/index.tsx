import type { KeyboardEvent } from 'react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CopyButton } from '../../lib/CopyButton'
import { downloadJSON, downloadText, slugify } from '../../lib/download'
import { useLocalStorage } from '../../lib/storage'
import { FindingList, SeverityBadge, SeveritySummary } from '../toolbox/FindingList'
import '../toolbox/toolbox.css'
import { ReconTiles } from './cards'
import { ProxyTab } from './ProxyTab'
import type { CheckSnapshot } from './report'
import { CHECK_LABELS, reportJson, reportMarkdown, summaryFindings } from './report'
import type { HistoryEntry, ReconSettings } from './settings'
import { DEFAULT_SETTINGS, HISTORY_KEY, SETTINGS_KEY, pushHistory, sanitizeHistory, sanitizeSettings } from './settings'
import { normalizeTarget } from './target'
import { Toggle } from './ui'
import { CHECK_ORDER, useRecon } from './useRecon'
import './recon.css'

const TABS = [
  { id: 'scan', label: 'Scan' },
  { id: 'proxy', label: 'Proxy & settings' },
] as const

type TabId = (typeof TABS)[number]['id']

export default function WebsiteRecon() {
  const [params, setParams] = useSearchParams()
  const requestedTab = params.get('tab')
  const tab: TabId = TABS.some((t) => t.id === requestedTab) ? (requestedTab as TabId) : 'scan'
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([])

  const [rawSettings, setRawSettings] = useLocalStorage<ReconSettings>(SETTINGS_KEY, DEFAULT_SETTINGS)
  const settings = useMemo(() => sanitizeSettings(rawSettings), [rawSettings])
  const [rawHistory, setHistory] = useLocalStorage<HistoryEntry[]>(HISTORY_KEY, [])
  const history = useMemo(() => sanitizeHistory(rawHistory), [rawHistory])

  // A shared link (?target=) pre-fills the form but never starts a scan by itself: the visitor first sees which
  // third parties will receive the domain, then clicks "Run scan".
  const [input, setInput] = useState(() => params.get('target') ?? '')
  const parsed = useMemo(() => (input.trim() === '' ? undefined : normalizeTarget(input)), [input])
  const [submitError, setSubmitError] = useState<string | undefined>()
  const recon = useRecon()
  const { setProxy } = recon

  useEffect(() => {
    setProxy(settings.proxyUrl || undefined)
  }, [settings.proxyUrl, setProxy])

  const selectTab = (id: TabId, focus = false) => {
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

  const onTabKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = TABS.findIndex((t) => t.id === tab)
    let next: number | undefined
    if (e.key === 'ArrowRight') next = (i + 1) % TABS.length
    else if (e.key === 'ArrowLeft') next = (i - 1 + TABS.length) % TABS.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = TABS.length - 1
    if (next === undefined) return
    e.preventDefault()
    selectTab(TABS[next].id, true)
  }

  const run = (value: string) => {
    const r = normalizeTarget(value)
    if (!r.ok) {
      setSubmitError(r.error)
      return
    }
    setSubmitError(undefined)
    setInput(r.target.host)
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.set('target', r.target.host)
        next.delete('tab')
        return next
      },
      { replace: true },
    )
    if (settings.saveHistory) setHistory(pushHistory(history, r.target.host))
    recon.start(r.target, settings.proxyUrl || undefined)
  }

  const snapshots: CheckSnapshot[] = CHECK_ORDER.map((id) => ({
    id,
    status: recon.checks[id].status,
    findings: recon.checks[id].findings,
    error: recon.checks[id].error,
    data: recon.checks[id].data,
    ms: recon.checks[id].ms,
  }))
  const summary = summaryFindings(snapshots)
  const allFindings = snapshots.flatMap((c) => c.findings)
  const issueCount = summary.filter((f) => f.severity !== 'info').length
  const finished = CHECK_ORDER.filter((id) => !['idle', 'running'].includes(recon.checks[id].status)).length
  const target = recon.target
  const generatedAt = recon.startedAt
  const md = target && generatedAt ? reportMarkdown(target.host, snapshots, generatedAt) : ''

  return (
    <>
      <header className="page-header">
        <h1>Website Recon</h1>
        <p>
          Passive reconnaissance of a domain from public sources: DNS records and DNSSEC, email authentication (SPF, DMARC, DKIM, MTA-STS), certificate
          transparency and subdomain discovery with takeover hints, registration data (RDAP), IP ownership and web archive history — straight from your browser,
          no backend.
        </p>
      </header>

      <div className="recon-intro">
        <div className="callout small" role="note" aria-label="Privacy">
          <strong>Privacy — who receives the domain you enter:</strong> Google Public DNS (dns.google) and Cloudflare DNS (cloudflare-dns.com, fallback),
          crt.sh, rdap.org and the registry or regional Internet registry it redirects to, and the Internet Archive (archive.org)
          {settings.proxyUrl ? (
            <>
              , plus <strong>your proxy</strong> (<span className="recon-break">{settings.proxyUrl}</span>), which contacts the site itself and hstspreload.org
            </>
          ) : (
            '. Nobody else: no proxy is configured, so the target site itself is never contacted'
          )}
          . Results stay in this page and are not stored; only the list of recent targets is kept in this browser
          {settings.saveHistory ? ' (clearable)' : ' — history is off'}.
        </div>
        <div className="callout warn small" role="note" aria-label="Ethics">
          <strong>Passive, public data only.</strong> These lookups query public resolvers, registries and logs, not the target's servers (except optional
          proxied page fetches, equivalent to a normal visit). Results are leads, not proof: verify manually, and only run active tests against systems you are
          authorised to assess.
        </div>
      </div>

      <div className="tabs" role="tablist" aria-label="Website Recon" onKeyDown={onTabKey}>
        {TABS.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              tabRefs.current[i] = el
            }}
            type="button"
            role="tab"
            className="tab"
            id={`recon-tab-${t.id}`}
            aria-selected={t.id === tab}
            aria-controls={`recon-panel-${t.id}`}
            tabIndex={t.id === tab ? 0 : -1}
            onClick={() => selectTab(t.id)}
          >
            {t.label}
            {t.id === 'proxy' && settings.proxyUrl ? ' ✓' : ''}
          </button>
        ))}
      </div>

      <div role="tabpanel" id="recon-panel-scan" aria-labelledby="recon-tab-scan" hidden={tab !== 'scan'} className="stack recon-panel">
        <form
          className="card stack recon-form"
          onSubmit={(e) => {
            e.preventDefault()
            run(input)
          }}
        >
          <div className="recon-form-row">
            <label>
              Domain, URL or IP address
              <input
                type="text"
                inputMode="url"
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                value={input}
                onChange={(e) => {
                  setInput(e.target.value)
                  setSubmitError(undefined)
                }}
                placeholder="example.com"
                aria-invalid={submitError !== undefined || (parsed !== undefined && !parsed.ok)}
                aria-describedby="recon-target-help"
              />
            </label>
            <button type="submit" className="btn btn-primary" disabled={!parsed?.ok}>
              {recon.running ? 'Restart scan' : 'Run scan'}
            </button>
            {recon.running && (
              <button type="button" className="btn" onClick={recon.cancel}>
                Cancel
              </button>
            )}
          </div>
          <div id="recon-target-help" className="small muted">
            {parsed?.ok ? (
              <>
                Target: <code>{parsed.target.host}</code>
                {parsed.target.display ? <> ({parsed.target.display})</> : null}
                {parsed.target.kind === 'ip' ? ' — IP address: reverse DNS and network ownership only.' : null}
                {parsed.target.kind === 'domain' && parsed.target.registrable !== parsed.target.host ? (
                  <>
                    {' '}
                    — registered domain (guess): <code>{parsed.target.registrable}</code>
                  </>
                ) : null}
              </>
            ) : parsed && !parsed.ok ? (
              parsed.error
            ) : (
              'Scheme, path and port are ignored; internationalised names are converted to punycode.'
            )}
          </div>
          {submitError && (
            <div className="callout error" role="alert">
              {submitError}
            </div>
          )}
          {history.length > 0 && (
            <div className="row">
              <span className="small muted">Recent:</span>
              {history.slice(0, 6).map((h) => (
                <button key={h.target} type="button" className="btn btn-sm" onClick={() => run(h.target)} title={`Scanned ${h.at.slice(0, 10)}`}>
                  {h.target}
                </button>
              ))}
              <button type="button" className="btn btn-sm btn-danger" onClick={() => setHistory([])}>
                Clear history
              </button>
            </div>
          )}
        </form>

        {target && (
          <>
            <section className="card recon-strip" aria-labelledby="recon-summary-h">
              <div className="recon-strip-main">
                <h2 id="recon-summary-h" className="recon-strip-title">
                  <span className="recon-break">{target.host}</span>
                </h2>
                <span className="small muted">
                  {recon.running ? `Scanning… ${finished}/${CHECK_ORDER.length} checks` : `${finished}/${CHECK_ORDER.length} checks finished`}
                  {generatedAt ? ` · ${generatedAt.toLocaleTimeString()}` : ''}
                </span>
                <SeveritySummary findings={allFindings} />
                {issueCount === 0 && !recon.running && <span className="badge sev-ok">No issues</span>}
              </div>
              <div
                className="progress recon-strip-progress"
                role="progressbar"
                aria-label="Scan progress"
                aria-valuemin={0}
                aria-valuemax={CHECK_ORDER.length}
                aria-valuenow={finished}
              >
                <span style={{ width: `${(finished / CHECK_ORDER.length) * 100}%` }} />
              </div>
              <div className="row recon-strip-actions">
                <button type="button" className="btn btn-sm" onClick={() => downloadText(`recon-${slugify(target.host)}.md`, md, 'text/markdown')}>
                  Markdown report
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => downloadJSON(`recon-${slugify(target.host)}.json`, reportJson(target.host, snapshots, generatedAt ?? new Date(0)))}
                >
                  JSON
                </button>
                <CopyButton text={md} label="Copy report" />
                <CopyButton text={window.location.href} label="Copy share link" />
              </div>
            </section>
            <div className="recon-grid-wrap">
              <div className="recon-grid">
                <section className="recon-tile recon-span-2 recon-tile-summary" aria-labelledby="recon-top-h">
                  <header className="recon-tile-head">
                    <span className="recon-tile-icon" aria-hidden="true">
                      📋
                    </span>
                    <h3 id="recon-top-h" className="recon-tile-title">
                      Top findings ({summary.length})
                    </h3>
                  </header>
                  {summary.length === 0 ? (
                    <p className="small muted">{recon.running ? 'Waiting for results…' : 'No issues found.'}</p>
                  ) : (
                    <ul className="recon-top recon-scroll">
                      {summary.map((f, i) => (
                        <li key={`${f.check}-${f.title}-${i}`}>
                          <SeverityBadge severity={f.severity} /> <span className="muted">{CHECK_LABELS[f.check]}:</span> {f.title}
                        </li>
                      ))}
                    </ul>
                  )}
                  {summary.length > 0 && (
                    <div className="recon-toggles">
                      <Toggle label="Details & fixes">
                        {() => (
                          <FindingList
                            findings={summary.map((f) => ({ ...f, title: `${CHECK_LABELS[f.check]}: ${f.title}` }))}
                            reportTitle={`Website recon — ${target.host}`}
                          />
                        )}
                      </Toggle>
                    </div>
                  )}
                </section>
                <ReconTiles checks={recon.checks} onRerun={recon.rerun} hasProxy={settings.proxyUrl !== ''} onConfigureProxy={() => selectTab('proxy')} />
              </div>
            </div>
          </>
        )}
      </div>

      <div role="tabpanel" id="recon-panel-proxy" aria-labelledby="recon-tab-proxy" hidden={tab !== 'proxy'} className="recon-panel">
        <ProxyTab settings={settings} onChange={(s) => setRawSettings(s)} historyCount={history.length} onClearHistory={() => setHistory([])} />
      </div>
    </>
  )
}
