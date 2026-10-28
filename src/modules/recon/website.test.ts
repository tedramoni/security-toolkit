import { describe, expect, it } from 'vitest'
import { envelopeToRawHeaders, parseEnvelope, proxiedUrl, validateProxyUrl } from './proxy'
import { fakeFetch } from './test-helpers'
import { fetchWayback, parseAvailable, waybackDate } from './wayback'
import { countSitemap, detectTech, isText, metaGenerator, parseRobots, runWebCheck } from './website'

const PROXY = 'https://recon-proxy.example.workers.dev/'

function env(status: number, headers: [string, string][], body = '', extra: Record<string, unknown> = {}) {
  return { url: 'x', finalUrl: 'https://example.com/', status, redirects: [], headers, body, truncated: false, ...extra }
}

describe('proxy URL', () => {
  it('accepts https only', () => {
    expect(validateProxyUrl(PROXY)).toEqual({ ok: true, url: PROXY })
    expect(validateProxyUrl('http://proxy.example.com/').ok).toBe(false)
    expect(validateProxyUrl('https://u:p@proxy.example.com/').ok).toBe(false)
    expect(validateProxyUrl('https://p.example.com/?url=x').ok).toBe(false)
    expect(validateProxyUrl('javascript:alert(1)').ok).toBe(false)
    expect(proxiedUrl(PROXY, 'https://example.com/a?b=c')).toBe(`${PROXY}?url=https%3A%2F%2Fexample.com%2Fa%3Fb%3Dc`)
  })

  it('validates envelopes', () => {
    expect(() => parseEnvelope({ error: 'Origin not allowed' })).toThrow(/Proxy refused: Origin not allowed/)
    expect(() => parseEnvelope({ hello: 1 })).toThrow(/expected format/)
    const e = parseEnvelope(env(200, [['Server', 'nginx'], ['bad' as string, 5 as unknown as string]]))
    expect(e.headers).toEqual([['server', 'nginx']])
    expect(envelopeToRawHeaders(e)).toBe('HTTP/1.1 200\nserver: nginx')
  })
})

describe('robots / sitemap / tech', () => {
  it('parses robots.txt', () => {
    const r = parseRobots('User-agent: *\nDisallow: /admin/ # secret\nDisallow: /admin/\nDisallow:\nAllow: /public\nSitemap: https://example.com/sitemap.xml\nDisallow: /cart')
    expect(r.disallow).toEqual(['/admin/', '/cart'])
    expect(r.interesting).toEqual(['/admin/'])
    expect(r.sitemaps).toEqual(['https://example.com/sitemap.xml'])
    expect(r.allow).toEqual(['/public'])
  })

  it('counts sitemap URLs', () => {
    expect(countSitemap('<urlset><url><loc>a</loc></url><url><LOC>b</LOC></url></urlset>')).toEqual({ urls: 2, isIndex: false })
    expect(countSitemap('<sitemapindex><sitemap><loc>x</loc></sitemap></sitemapindex>').isIndex).toBe(true)
  })

  it('detects technology hints', () => {
    expect(metaGenerator('<html><meta charset="utf-8"><meta name="generator" content="WordPress 6.6"></html>')).toBe('WordPress 6.6')
    expect(metaGenerator("<meta content='Hugo 0.120' name=generator>")).toBe('Hugo 0.120')
    const hints = detectTech(parseEnvelope(env(200, [['server', 'cloudflare'], ['cf-ray', 'abc']], '<script id="__NEXT_DATA__"></script>')))
    expect(hints.map((h) => h.name)).toEqual(['cloudflare', 'Cloudflare', 'Next.js'])
  })

  it('is linear on hostile HTML', () => {
    const t0 = performance.now()
    metaGenerator('<meta name=generator content="'.repeat(20000))
    metaGenerator('<meta' + ' name=generator'.repeat(50000))
    parseRobots('Disallow: /a\n'.repeat(50000))
    countSitemap('<loc>'.repeat(100000))
    expect(performance.now() - t0).toBeLessThan(800)
  })
})

describe('runWebCheck', () => {
  it('runs every proxied check and feeds the header analyzer', async () => {
    const calls: string[] = []
    const routes: Record<string, unknown> = {
      'https://example.com/': env(200, [['strict-transport-security', 'max-age=63072000; includeSubDomains; preload'], ['content-security-policy', "default-src 'self'"], ['x-content-type-options', 'nosniff'], ['set-cookie', 'sid=<redacted>; Path=/']], '<meta name="generator" content="Hugo">'),
      'http://example.com/': env(200, [], '', { redirects: [{ url: 'http://example.com/', status: 301, location: 'https://example.com/' }], finalUrl: 'https://example.com/' }),
      'https://example.com/robots.txt': env(200, [['content-type', 'text/plain']], 'User-agent: *\nDisallow: /backup/\nSitemap: https://example.com/sm.xml'),
      'https://example.com/sm.xml': env(200, [['content-type', 'application/xml']], '<urlset><loc>a</loc><loc>b</loc></urlset>'),
      'https://example.com/.well-known/security.txt': env(200, [['content-type', 'text/plain; charset=utf-8']], 'Contact: mailto:sec@example.com\nExpires: 2099-01-01T00:00:00Z'),
      'https://hstspreload.org/api/v2/status?domain=example.com': env(200, [], '{"name":"example.com","status":"preloaded"}'),
    }
    const fetch = fakeFetch((url) => {
      const target = new URL(url).searchParams.get('url')!
      const r = routes[target]
      return r ? { body: r } : { body: env(404, [], 'nope') }
    }, calls)
    const { data, findings } = await runWebCheck('example.com', PROXY, { fetch })
    expect(calls.every((c) => c.startsWith(PROXY))).toBe(true)
    expect(data.headers?.grade).toBeTruthy()
    expect(data.httpsUpgrade).toBe(true)
    expect(data.robots?.interesting).toEqual(['/backup/'])
    expect(data.sitemap).toMatchObject({ url: 'https://example.com/sm.xml', urls: 2 })
    expect(data.securityTxt?.parsed.contact).toEqual(['mailto:sec@example.com'])
    expect(data.preload?.status).toBe('preloaded')
    expect(data.tech.map((t) => t.name)).toContain('Hugo')
    const titles = findings.map((f) => f.title)
    expect(titles).toContain('HTTP redirects to HTTPS')
    expect(titles).toContain('On the HSTS preload list')
    expect(titles.some((t) => t.startsWith('Headers: '))).toBe(true)
    expect(titles.some((t) => t.startsWith('Cookie sid'))).toBe(true)
  })

  it('fails clearly when the proxy is unreachable', async () => {
    const fetch = fakeFetch(() => ({ fail: true, body: '' }))
    await expect(runWebCheck('example.com', PROXY, { fetch })).rejects.toThrow(/Could not reach your CORS proxy/)
  })

  it('reports missing security.txt and plaintext HTTP', async () => {
    const fetch = fakeFetch((url) => {
      const t = new URL(url).searchParams.get('url')!
      if (t === 'http://example.com/') return { body: env(200, [], 'plain', { finalUrl: 'http://example.com/' }) }
      if (t === 'https://example.com/') return { body: env(200, []) }
      return { body: env(404, [], '') }
    })
    const titles = (await runWebCheck('example.com', PROXY, { fetch })).findings.map((f) => f.title)
    expect(titles).toContain('HTTP is not redirected to HTTPS')
    expect(titles).toContain('No security.txt')
  })

  it('ignores HTML soft-404 pages served as robots.txt / security.txt (regression)', async () => {
    const soft404 = env(200, [['content-type', 'text/html; charset=utf-8']], '<!doctype html><html><body>Not found</body></html>')
    const fetch = fakeFetch((url) => {
      const t = new URL(url).searchParams.get('url')!
      if (t === 'https://example.com/') return { body: env(200, []) }
      return { body: soft404 }
    })
    const { data, findings } = await runWebCheck('example.com', PROXY, { fetch })
    const titles = findings.map((f) => f.title)
    expect(data.securityTxt).toBeUndefined()
    expect(data.robots).toBeUndefined()
    expect(titles).toContain('No security.txt')
    expect(titles.some((t) => /no Contact field/.test(t))).toBe(false)
    expect(isText(env(200, [], '<html>'))).toBe(false)
    expect(isText(env(200, [], 'Contact: mailto:a@b.c'))).toBe(true)
    expect(isText(env(200, [['content-type', 'Text/Plain; charset=utf-8']], 'x'))).toBe(true)
  })
})

describe('wayback', () => {
  it('parses availability answers (real format)', () => {
    const snap = parseAvailable({ url: 'github.com', archived_snapshots: { closest: { status: '200', available: true, url: 'http://web.archive.org/web/20261028070827/https://github.com/', timestamp: '20261028070827' } } })
    expect(snap).toEqual({ url: 'https://web.archive.org/web/20261028070827/https://github.com/', timestamp: '20261028070827', date: '2026-10-28T07:08:27Z', status: '200' })
    expect(parseAvailable({ archived_snapshots: {} })).toBeUndefined()
    expect(parseAvailable({ archived_snapshots: { closest: { available: true, url: 'javascript:alert(1)', timestamp: '20200101000000' } } })).toBeUndefined()
    expect(waybackDate('2020')).toBeUndefined()
  })

  it('fetches latest then first capture, tolerating one failure', async () => {
    const calls: string[] = []
    const fetch = fakeFetch((url) => (url.includes('timestamp=') ? { fail: true, body: '' } : { body: { archived_snapshots: { closest: { available: true, url: 'http://web.archive.org/web/2026/https://x.com/', timestamp: '20261001000000' } } } }), calls)
    const r = await fetchWayback('x.com', { fetch, backoffMs: 0, gapMs: 0 })
    expect(r.latest?.date).toBe('2026-10-01T00:00:00Z')
    expect(r.first).toBeUndefined()
    expect(r.errors[0]).toMatch(/First capture/)
    expect(calls).toHaveLength(3) // 1 latest + 2 attempts for first
    const dead = fakeFetch(() => ({ fail: true, body: '' }))
    await expect(fetchWayback('x.com', { fetch: dead, backoffMs: 0, gapMs: 0 })).rejects.toThrow(/rate-limits/)
  })
})
