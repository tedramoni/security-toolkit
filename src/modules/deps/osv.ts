/**
 * Minimal OSV.dev API client. Docs: https://google.github.io/osv.dev/api/
 *  - POST /v1/querybatch  -> per query only {id, modified} of matching vulns, plus a per-query
 *    next_page_token when that query has more results (https://google.github.io/osv.dev/post-v1-querybatch/)
 *  - GET  /v1/vulns/{id}  -> full OSV record
 * api.osv.dev answers CORS requests from any origin, so this runs directly in the browser.
 */
import type { Dependency } from './types.ts'
import { depKey } from './types.ts'

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export interface OsvEvent {
  introduced?: string
  fixed?: string
  last_affected?: string
  limit?: string
}

export interface OsvSeverity {
  type: string
  score: string
}

export interface OsvAffected {
  package?: { name?: string; ecosystem?: string; purl?: string }
  ranges?: { type?: string; events?: OsvEvent[] }[]
  versions?: string[]
  severity?: OsvSeverity[]
}

export interface OsvVuln {
  id: string
  summary?: string
  details?: string
  aliases?: string[]
  modified?: string
  published?: string
  withdrawn?: string
  severity?: OsvSeverity[]
  affected?: OsvAffected[]
  database_specific?: { severity?: unknown; [k: string]: unknown }
  references?: { type?: string; url?: string }[]
}

export const OSV_API = 'https://api.osv.dev'
/** Documented page sizes are ~1000 results per query; we keep request bodies to 1000 queries as well. */
export const MAX_BATCH = 1000

export class OsvHttpError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'OsvHttpError'
    this.status = status
  }
}

export interface ClientOptions {
  fetch?: FetchLike
  baseUrl?: string
  signal?: AbortSignal
  /** Retries for 429 / 5xx / network errors (default 3). */
  retries?: number
  /** Base back-off in ms (default 500, doubled each attempt). Tests set 0. */
  backoffMs?: number
}

function abortError(): Error {
  return new DOMException('The operation was aborted.', 'AbortError')
}

export function isAbortError(e: unknown): boolean {
  // DOMException is not always `instanceof Error` (e.g. across realms), so check the name only
  return typeof e === 'object' && e !== null && (e as { name?: unknown }).name === 'AbortError'
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(abortError())
  if (ms <= 0) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = () => {
      clearTimeout(t)
      reject(abortError())
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

/** fetch JSON with retry on rate limiting (429), server errors (5xx) and network failures. */
async function requestJSON<T>(url: string, init: RequestInit, opts: ClientOptions): Promise<T> {
  const doFetch: FetchLike = opts.fetch ?? ((u, i) => fetch(u, i))
  const retries = opts.retries ?? 3
  const backoff = opts.backoffMs ?? 500
  let lastError: unknown
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (opts.signal?.aborted) throw abortError()
    let res: Response
    try {
      res = await doFetch(url, { ...init, signal: opts.signal })
    } catch (e) {
      if (isAbortError(e) || opts.signal?.aborted) throw abortError()
      lastError = new Error(`Network error contacting OSV.dev: ${(e as Error).message ?? String(e)}`)
      if (attempt < retries) await sleep(backoff * 2 ** attempt, opts.signal)
      continue
    }
    if (res.ok) return (await res.json()) as T
    const retryable = res.status === 429 || res.status >= 500
    lastError = new OsvHttpError(
      res.status,
      res.status === 429 ? 'OSV.dev rate limit reached (HTTP 429)' : `OSV.dev returned HTTP ${res.status}`,
    )
    if (!retryable || attempt === retries) break
    const retryAfter = Number(res.headers.get('retry-after'))
    const wait = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter, 30) * 1000 : backoff * 2 ** attempt
    await sleep(wait, opts.signal)
  }
  throw lastError
}

interface BatchQuery {
  package: { name: string; ecosystem: string }
  version: string
  page_token?: string
}

interface BatchResponse {
  results?: { vulns?: { id: string }[]; next_page_token?: string }[]
}

export function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = []
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size))
  return out
}

export interface BatchResult {
  /** depKey -> vulnerability ids */
  idsByDep: Map<string, string[]>
  /** Packages that could not be checked (a batch failed after retries). */
  failed: { dep: Dependency; error: string }[]
}

/**
 * Query OSV for every dependency (deduplicate before calling). Chunks of <= MAX_BATCH queries;
 * follows per-query next_page_token. A failing chunk is reported in `failed` and does not stop
 * the other chunks (partial results). Abort rejects with an AbortError.
 */
export async function queryBatch(
  deps: Dependency[],
  opts: ClientOptions & { onProgress?: (done: number, total: number) => void } = {},
): Promise<BatchResult> {
  const base = opts.baseUrl ?? OSV_API
  const idsByDep = new Map<string, string[]>()
  const failed: BatchResult['failed'] = []
  let done = 0

  for (const group of chunk(deps, MAX_BATCH)) {
    // queries still to send for this chunk, with optional page tokens
    let pending: { dep: Dependency; token?: string }[] = group.map((dep) => ({ dep }))
    let pages = 0
    try {
      while (pending.length > 0) {
        if (++pages > 50) throw new Error('Too many result pages from OSV.dev')
        const queries: BatchQuery[] = pending.map(({ dep, token }) => ({
          package: { name: dep.name, ecosystem: dep.ecosystem },
          version: dep.version,
          ...(token ? { page_token: token } : {}),
        }))
        const body = await requestJSON<BatchResponse>(
          `${base}/v1/querybatch`,
          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries }) },
          opts,
        )
        const results = body.results ?? []
        if (results.length !== pending.length) {
          throw new Error(`OSV.dev returned ${results.length} results for ${pending.length} queries`)
        }
        const next: typeof pending = []
        results.forEach((r, i) => {
          const { dep } = pending[i]
          const key = depKey(dep)
          const ids = idsByDep.get(key) ?? []
          for (const v of r.vulns ?? []) if (v && typeof v.id === 'string' && !ids.includes(v.id)) ids.push(v.id)
          idsByDep.set(key, ids)
          if (r.next_page_token) next.push({ dep, token: r.next_page_token })
        })
        pending = next
      }
    } catch (e) {
      if (isAbortError(e)) throw e
      const msg = (e as Error).message ?? String(e)
      // packages never answered, plus packages whose later result pages are missing (results incomplete)
      const incomplete = new Set(pending.map((p) => depKey(p.dep)))
      for (const dep of group) {
        const key = depKey(dep)
        if (!idsByDep.has(key) || incomplete.has(key)) failed.push({ dep, error: incomplete.has(key) && idsByDep.has(key) ? `${msg} (results incomplete)` : msg })
      }
    }
    done += group.length
    opts.onProgress?.(done, deps.length)
  }
  return { idsByDep, failed }
}

export function getVuln(id: string, opts: ClientOptions = {}): Promise<OsvVuln> {
  const base = opts.baseUrl ?? OSV_API
  return requestJSON<OsvVuln>(`${base}/v1/vulns/${encodeURIComponent(id)}`, { method: 'GET' }, opts)
}

export interface VulnDetailsResult {
  vulns: Map<string, OsvVuln>
  errors: { id: string; error: string }[]
}

/** Fetch full records for unique ids with a bounded number of requests in flight. */
export async function fetchVulns(
  ids: string[],
  opts: ClientOptions & { concurrency?: number; onProgress?: (done: number, total: number) => void } = {},
): Promise<VulnDetailsResult> {
  const unique = [...new Set(ids)]
  const vulns = new Map<string, OsvVuln>()
  const errors: VulnDetailsResult['errors'] = []
  const concurrency = Math.max(1, opts.concurrency ?? 6)
  let next = 0
  let done = 0

  const worker = async () => {
    while (next < unique.length) {
      const id = unique[next++]
      try {
        vulns.set(id, await getVuln(id, opts))
      } catch (e) {
        if (isAbortError(e)) throw e
        errors.push({ id, error: (e as Error).message ?? String(e) })
      }
      done++
      opts.onProgress?.(done, unique.length)
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, unique.length) }, worker))
  return { vulns, errors }
}
