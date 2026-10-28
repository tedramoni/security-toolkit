import { describe, expect, it } from 'vitest'
import { reportJson, reportMarkdown, summaryFindings } from './report'
import type { CheckSnapshot } from './report'
import { pushHistory, sanitizeHistory, sanitizeSettings } from './settings'

const checks: CheckSnapshot[] = [
  { id: 'dns', status: 'done', findings: [{ severity: 'low', title: 'DNSSEC not enabled', detail: 'x' }, { severity: 'pass', title: 'CAA ok', detail: 'y' }] },
  { id: 'email', status: 'done', findings: [{ severity: 'high', title: 'No DMARC record', detail: 'Spoof <script>alert(1)</script> | `code`', fix: 'Add one' }] },
  { id: 'web', status: 'needs-proxy', findings: [] },
  { id: 'ct', status: 'error', findings: [], error: 'crt.sh <b>down</b>' },
]

describe('report', () => {
  it('sorts summary findings by severity and drops passes', () => {
    expect(summaryFindings(checks).map((f) => `${f.check}:${f.severity}`)).toEqual(['email:high', 'dns:low'])
    expect(summaryFindings(checks, true)).toHaveLength(3)
  })

  it('escapes untrusted text in Markdown', () => {
    const md = reportMarkdown('example.com', checks, new Date('2026-10-28T00:00:00Z'))
    expect(md).toContain('# Website recon report — example.com')
    expect(md).not.toContain('<script>')
    expect(md).toContain('&lt;script&gt;')
    expect(md).toContain('\\|') // table pipe escaped
    expect(md).toContain('crt.sh &lt;b&gt;down&lt;/b&gt;')
    expect(md).toContain('- **DNS records**: CAA ok')
  })

  it('serialises JSON', () => {
    const j = reportJson('example.com', checks, new Date('2026-10-28T00:00:00Z')) as { checks: { id: string; label: string }[] }
    expect(j.checks.map((c) => c.label)).toEqual(['DNS records', 'Email security', 'Website (via proxy)', 'Certificate transparency'])
  })
})

describe('settings & history', () => {
  it('sanitises stored settings', () => {
    expect(sanitizeSettings({ proxyUrl: 'http://insecure.example/', saveHistory: 'yes' })).toEqual({ proxyUrl: '', saveHistory: true })
    expect(sanitizeSettings({ proxyUrl: 'https://p.example.workers.dev', saveHistory: false })).toEqual({ proxyUrl: 'https://p.example.workers.dev/', saveHistory: false })
    expect(sanitizeSettings(null)).toEqual({ proxyUrl: '', saveHistory: true })
  })

  it('sanitises and caps history', () => {
    expect(sanitizeHistory([{ target: 'EXAMPLE.com', at: 'x' }, { target: 'localhost', at: 'x' }, { nope: 1 }, { target: 'example.com', at: 'y' }])).toEqual([{ target: 'example.com', at: 'x' }])
    let h = sanitizeHistory('garbage')
    for (let i = 0; i < 15; i++) h = pushHistory(h, `d${i}.com`, new Date(0))
    h = pushHistory(h, 'd10.com', new Date(0))
    expect(h).toHaveLength(10)
    expect(h[0].target).toBe('d10.com')
    expect(h.filter((e) => e.target === 'd10.com')).toHaveLength(1)
  })
})
