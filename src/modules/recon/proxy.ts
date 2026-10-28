/**
 * Optional user-hosted CORS proxy (see proxy-worker.js.txt). The browser cannot read responses from the target site
 * (no CORS), so checks that need the site itself go through the user's own Worker, which returns a JSON envelope:
 *   GET <proxy>?url=<target>  →  { url, finalUrl, status, redirects[], headers[[name, value]], body, truncated }
 * A plain GET without custom headers: no CORS preflight.
 */
import type { FetchLike } from './net'
import { SourceError, fetchText } from './net'

export type ProxyUrlCheck = { ok: true; url: string } | { ok: false; error: string }

export function validateProxyUrl(input: string): ProxyUrlCheck {
  const s = input.trim()
  if (s === '') return { ok: false, error: 'Empty' }
  let u: URL
  try {
    u = new URL(s)
  } catch {
    return { ok: false, error: 'Not a valid URL.' }
  }
  if (u.protocol !== 'https:') return { ok: false, error: 'The proxy URL must use https://.' }
  if (u.username || u.password) return { ok: false, error: 'Do not put credentials in the proxy URL.' }
  if (u.hash) return { ok: false, error: 'Remove the #fragment.' }
  if (u.searchParams.has('url')) return { ok: false, error: 'Give the proxy base URL only (the app adds ?url=…).' }
  return { ok: true, url: u.href }
}

export function proxiedUrl(proxyBase: string, target: string): string {
  const u = new URL(proxyBase)
  u.searchParams.set('url', target)
  return u.href
}

export interface ProxyRedirect {
  url: string
  status: number
  location?: string
}

export interface ProxyEnvelope {
  url: string
  finalUrl: string
  status: number
  redirects: ProxyRedirect[]
  headers: [string, string][]
  body: string
  truncated: boolean
}

export function parseEnvelope(json: unknown): ProxyEnvelope {
  const j = json as Record<string, unknown> | null
  if (!j || typeof j !== 'object') throw new Error('Proxy returned an unexpected response')
  if (typeof j.error === 'string') throw new Error(`Proxy refused: ${j.error.slice(0, 300)}`)
  if (typeof j.status !== 'number' || !Array.isArray(j.headers)) throw new Error('Proxy response is not in the expected format (deploy the template from the Proxy tab)')
  const headers: [string, string][] = []
  for (const h of j.headers as unknown[]) {
    if (Array.isArray(h) && typeof h[0] === 'string' && typeof h[1] === 'string') headers.push([h[0].toLowerCase(), h[1]])
  }
  const redirects: ProxyRedirect[] = []
  for (const r of Array.isArray(j.redirects) ? (j.redirects as Record<string, unknown>[]) : []) {
    if (r && typeof r.url === 'string' && typeof r.status === 'number') redirects.push({ url: r.url, status: r.status, location: typeof r.location === 'string' ? r.location : undefined })
  }
  return {
    url: typeof j.url === 'string' ? j.url : '',
    finalUrl: typeof j.finalUrl === 'string' ? j.finalUrl : '',
    status: j.status,
    redirects,
    headers,
    body: typeof j.body === 'string' ? j.body : '',
    truncated: j.truncated === true,
  }
}

export interface ProxyOptions {
  fetch?: FetchLike
  signal?: AbortSignal
  timeoutMs?: number
}

export async function fetchViaProxy(proxyBase: string, target: string, opts: ProxyOptions = {}): Promise<ProxyEnvelope> {
  const res = await fetchText(proxiedUrl(proxyBase, target), { source: 'your CORS proxy', fetch: opts.fetch, signal: opts.signal, timeoutMs: opts.timeoutMs ?? 20000, retries: 0 })
  let json: unknown
  try {
    json = JSON.parse(res.text)
  } catch {
    throw new SourceError('your CORS proxy', 'parse', `Proxy returned HTTP ${res.status} with a non-JSON body — is it the template from the Proxy tab?`)
  }
  return parseEnvelope(json)
}

/** Raw header block for the Dev Toolbox header analyzer. */
export function envelopeToRawHeaders(env: ProxyEnvelope): string {
  return [`HTTP/1.1 ${env.status}`, ...env.headers.map(([k, v]) => `${k}: ${v.replace(/[\r\n]+/g, ' ')}`)].join('\n')
}

export function headerValues(env: ProxyEnvelope, name: string): string[] {
  return env.headers.filter(([k]) => k === name).map(([, v]) => v)
}
