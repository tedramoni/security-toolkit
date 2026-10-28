/** Test-only helpers: in-memory DNS and fetch fakes (no network in unit tests). */
import type { DnsResult, Resolve } from './doh'
import { RR, rrName } from './doh'
import type { FetchLike } from './net'

export interface FakeZone {
  [nameAndType: string]: string[] | { status?: number; data?: string[]; cnames?: string[]; ad?: boolean; error?: string }
}

/** Resolver over a map like { 'example.com|TXT': ['v=spf1 -all'], 'gone.example.com|A': { status: 3 } }. */
export function fakeResolver(zone: FakeZone, calls: string[] = []): Resolve {
  return async (name: string, type: string): Promise<DnsResult> => {
    const key = `${name.toLowerCase()}|${type}`
    calls.push(key)
    const z = zone[key]
    const spec = Array.isArray(z) ? { data: z } : (z ?? { status: 3 })
    if ('error' in spec && spec.error) throw new Error(spec.error)
    const t = RR[type]
    const records = (spec.data ?? []).map((data) => ({ name, type: t, typeName: rrName(t), ttl: 300, data }))
    // A name that is absent from the fake zone but whose parent has data is NODATA, not NXDOMAIN.
    const status = spec.status ?? 0
    return { name, type, status, statusText: status === 3 ? 'NXDOMAIN' : status === 0 ? 'NOERROR' : `RCODE ${status}`, ad: spec.ad ?? false, records, cnames: spec.cnames ?? [], answers: records, resolver: 'google' }
  }
}

export interface FakeRoute {
  status?: number
  body: string | unknown
  url?: string
  headers?: Record<string, string>
  /** Throw a network error instead of answering. */
  fail?: boolean
}

/** fetch fake: routes matched by exact URL or by a predicate. Records every requested URL. */
export function fakeFetch(routes: (url: string, init?: RequestInit) => FakeRoute | undefined, calls: string[] = []): FetchLike {
  return async (url: string, init?: RequestInit) => {
    calls.push(url)
    if (init?.signal?.aborted) throw new DOMException('aborted', 'AbortError')
    const r = routes(url, init)
    if (!r) return new Response('not found', { status: 404 })
    if (r.fail) throw new TypeError('Failed to fetch')
    const body = typeof r.body === 'string' ? r.body : JSON.stringify(r.body)
    const res = new Response(body, { status: r.status ?? 200, headers: r.headers })
    if (r.url) Object.defineProperty(res, 'url', { value: r.url })
    return res
  }
}
