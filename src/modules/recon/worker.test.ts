import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import workerSource from './proxy-worker.js.txt?raw'

/**
 * Behavioural test of the shipped Worker template: the text file is loaded as an ES module (data: URL) and its
 * fetch handler is called with a mocked global fetch — no network.
 */
interface WorkerModule {
  default: { fetch: (req: Request, env: Record<string, string>) => Promise<Response> }
}

let worker: WorkerModule['default']
const ORIGIN = 'https://tedramoni.github.io'
const env = { ALLOWED_ORIGIN: ORIGIN }

beforeAll(async () => {
  const mod = (await import(/* @vite-ignore */ `data:text/javascript;charset=utf-8,${encodeURIComponent(workerSource)}`)) as WorkerModule
  worker = mod.default
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function req(target: string | null, init: { origin?: string | null; method?: string } = {}) {
  const u = new URL('https://proxy.example.workers.dev/')
  if (target !== null) u.searchParams.set('url', target)
  const headers = new Headers()
  if (init.origin !== null) headers.set('Origin', init.origin ?? ORIGIN)
  headers.set('Cookie', 'session=should-not-be-forwarded')
  return new Request(u, { method: init.method ?? 'GET', headers })
}

async function body(res: Response) {
  return (await res.json()) as Record<string, unknown>
}

describe('proxy worker template', () => {
  it('rejects other origins, non-GET and missing url', async () => {
    const upstream = vi.fn()
    vi.stubGlobal('fetch', upstream)
    expect((await worker.fetch(req('https://example.com/', { origin: 'https://evil.example' }), env)).status).toBe(403)
    expect((await worker.fetch(req('https://example.com/', { origin: null }), env)).status).toBe(403)
    expect((await worker.fetch(req('https://example.com/', { method: 'POST' }), env)).status).toBe(405)
    expect((await worker.fetch(req(null), env)).status).toBe(400)
    expect((await worker.fetch(req('https://example.com/'), {})).status).toBe(500)
    expect(upstream).not.toHaveBeenCalled()
  })

  it('blocks SSRF targets before fetching', async () => {
    const upstream = vi.fn()
    vi.stubGlobal('fetch', upstream)
    for (const t of ['http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://[::ffff:0:a9fe:a9fe]/', 'http://0x7f.1/', 'http://[::ffff:127.0.0.1]/', 'file:///etc/passwd', 'http://localhost/', 'https://example.com:6379/']) {
      const res = await worker.fetch(req(t), env)
      expect(res.status, t).toBe(400)
      expect(String((await body(res)).error)).toMatch(/blocked|only http|port|invalid/)
    }
    expect(upstream).not.toHaveBeenCalled()
  })

  it('fetches without forwarding cookies, re-checks redirects and redacts Set-Cookie', async () => {
    const seen: { url: string; headers: Headers }[] = []
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      seen.push({ url, headers: new Headers(init.headers) })
      if (url === 'http://example.com/') return new Response(null, { status: 301, headers: { location: 'https://example.com/' } })
      const h = new Headers({ 'content-type': 'text/html', 'strict-transport-security': 'max-age=63072000' })
      h.append('set-cookie', 'sid=SECRET123; Path=/; Secure; HttpOnly')
      return new Response('<html>hi</html>', { status: 200, headers: h })
    })
    const res = await worker.fetch(req('http://example.com/'), env)
    expect(res.status).toBe(200)
    expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(res.headers.get('set-cookie')).toBeNull()
    const j = await body(res)
    expect(j.finalUrl).toBe('https://example.com/')
    expect(j.redirects).toEqual([{ url: 'http://example.com/', status: 301, location: 'https://example.com/' }])
    const headers = j.headers as [string, string][]
    expect(headers).toContainEqual(['set-cookie', 'sid=<redacted>; Path=/; Secure; HttpOnly'])
    expect(JSON.stringify(j)).not.toContain('SECRET123')
    for (const s of seen) expect(s.headers.get('cookie')).toBeNull()
  })

  it('refuses a redirect to a private address', async () => {
    vi.stubGlobal('fetch', async () => new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' } }))
    const res = await worker.fetch(req('https://example.com/'), env)
    expect(res.status).toBe(400)
    expect(String((await body(res)).error)).toMatch(/metadata/)
  })

  it('caps the body size', async () => {
    vi.stubGlobal('fetch', async () => new Response('x'.repeat(1024 * 1024 + 500), { status: 200 }))
    const j = await body(await worker.fetch(req('https://example.com/'), env))
    expect(j.truncated).toBe(true)
    expect((j.body as string).length).toBe(1024 * 1024)
  })
})
