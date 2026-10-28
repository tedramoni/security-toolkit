import { useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { downloadText } from '../../lib/download'
import workerSource from './proxy-worker.js.txt?raw'
import { validateProxyUrl } from './proxy'
import type { ReconSettings } from './settings'

interface Props {
  settings: ReconSettings
  onChange: (s: ReconSettings) => void
  historyCount: number
  onClearHistory: () => void
}

export function ProxyTab({ settings, onChange, historyCount, onClearHistory }: Props) {
  const [draft, setDraft] = useState(settings.proxyUrl)
  const trimmed = draft.trim()
  const check = trimmed === '' ? undefined : validateProxyUrl(trimmed)
  const dirty = trimmed !== settings.proxyUrl
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://tedramoni.github.io'

  return (
    <div className="stack">
      <section className="card stack" aria-labelledby="recon-proxy-h">
        <h2 id="recon-proxy-h">Your CORS proxy (optional)</h2>
        <p className="small">
          Browsers block reading responses from other sites, so checks that need the target website itself (security headers, redirects, robots.txt, sitemap,
          security.txt, MTA-STS policy, HSTS preload status) only run through a proxy <strong>you</strong> control.
        </p>
        <div className="callout warn small">
          <strong>Privacy trade-off:</strong> with a proxy set, the target URLs are sent to your proxy, which fetches them from the target site — the site sees requests
          coming from your proxy's IP (Cloudflare's network for the template). Requests are made only when you run a scan. Use only a proxy you deployed yourself; a
          third-party proxy would see every target you analyse.
        </div>
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault()
            if (trimmed === '') onChange({ ...settings, proxyUrl: '' })
            else if (check?.ok) onChange({ ...settings, proxyUrl: check.url })
          }}
        >
          <label>
            Your CORS proxy URL
            <input
              type="text"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder="https://recon-proxy.<you>.workers.dev/"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              aria-invalid={check !== undefined && !check.ok}
              aria-describedby="recon-proxy-help"
            />
          </label>
          <p id="recon-proxy-help" className="small muted">
            https:// only. Leave empty to disable. Stored in this browser only (localStorage key <code>scp:recon-settings</code>).
          </p>
          {check && !check.ok && (
            <p className="small sev-high" role="alert">
              {check.error}
            </p>
          )}
          <div className="row">
            <button type="submit" className="btn btn-primary" disabled={!dirty || (check !== undefined && !check.ok)}>
              Save
            </button>
            {settings.proxyUrl && (
              <button
                type="button"
                className="btn btn-danger"
                onClick={() => {
                  setDraft('')
                  onChange({ ...settings, proxyUrl: '' })
                }}
              >
                Remove proxy
              </button>
            )}
            <span className="small muted">{settings.proxyUrl ? `Active: ${settings.proxyUrl}` : 'No proxy configured.'}</span>
          </div>
        </form>
      </section>

      <section className="card stack" aria-labelledby="recon-worker-h">
        <h2 id="recon-worker-h">Deploy the proxy (Cloudflare Worker)</h2>
        <ol className="small recon-steps">
          <li>
            Create a Worker: <code>npm create cloudflare@latest recon-proxy</code> (Hello World, JavaScript) — or paste the code in the Cloudflare dashboard editor.
          </li>
          <li>
            Replace the Worker code with the template below (<code>src/index.js</code>).
          </li>
          <li>
            Add the variable <code>ALLOWED_ORIGIN</code> = <code>{origin}</code> (Settings → Variables, or <code>[vars]</code> in wrangler.toml). Only pages on this origin
            can use the proxy from a browser.
          </li>
          <li>
            Deploy (<code>npx wrangler deploy</code>) and paste the <code>https://…workers.dev</code> URL above.
          </li>
        </ol>
        <p className="small">
          The template is GET-only, never forwards your cookies or headers, follows at most 5 redirects re-checking each hop, refuses private / loopback / link-local /
          cloud-metadata addresses and internal names (SSRF protection), times out after 10 s, caps bodies at 1 MiB and redacts cookie values. Limitation: a public
          name that resolves to a private address (DNS rebinding) cannot be detected inside a Worker — Cloudflare's network does not reach your LAN, but do not run this
          code on a server inside a private network.
        </p>
        <div className="row">
          <CopyButton text={workerSource} label="Copy worker code" />
          <button type="button" className="btn" onClick={() => downloadText('recon-proxy-worker.js', workerSource, 'text/javascript')}>
            Download worker.js
          </button>
        </div>
        <details className="recon-raw">
          <summary>View the template ({workerSource.split('\n').length} lines)</summary>
          <pre className="codeblock recon-pre">{workerSource}</pre>
        </details>
      </section>

      <section className="card stack" aria-labelledby="recon-history-h">
        <h2 id="recon-history-h">Recent targets</h2>
        <label className="inline">
          <input type="checkbox" checked={settings.saveHistory} onChange={(e) => onChange({ ...settings, saveHistory: e.target.checked })} />
          Remember the last 10 targets in this browser
        </label>
        <div className="row">
          <button type="button" className="btn btn-danger" onClick={onClearHistory} disabled={historyCount === 0}>
            Clear history ({historyCount})
          </button>
        </div>
      </section>
    </div>
  )
}
