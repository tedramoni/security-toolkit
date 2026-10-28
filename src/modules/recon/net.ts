/**
 * Small HTTP helpers shared by every recon data source: injected fetch (tests never hit the network), per-request
 * timeout combined with the caller's AbortSignal, retry with back-off on network errors / 429 / 5xx, and a bounded
 * concurrency pool.
 *
 * Only CORS-enabled public endpoints are called directly. A browser reports a CORS rejection (and a 429 sent without
 * CORS headers) as a generic network error, so those are retried once and then surfaced with a clear message.
 */

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export type SourceErrorKind = 'timeout' | 'network' | 'http' | 'parse' | 'aborted'

export class SourceError extends Error {
  readonly source: string
  readonly kind: SourceErrorKind
  readonly status?: number
  constructor(source: string, kind: SourceErrorKind, message: string, status?: number) {
    super(message)
    this.name = 'SourceError'
    this.source = source
    this.kind = kind
    this.status = status
  }
}

export function abortError(): Error {
  return new DOMException('The operation was aborted.', 'AbortError')
}

export function isAbortError(e: unknown): boolean {
  if (e instanceof SourceError) return e.kind === 'aborted'
  return typeof e === 'object' && e !== null && (e as { name?: unknown }).name === 'AbortError'
}

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  return String(e)
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
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

export interface RequestOptions {
  /** Human name of the data source, used in error messages ("crt.sh", "Google DNS"…). */
  source: string
  fetch?: FetchLike
  signal?: AbortSignal
  /** Per-attempt timeout (default 15 s). */
  timeoutMs?: number
  /** Extra attempts after a network error / 429 / 5xx (default 1). */
  retries?: number
  /** Base back-off in ms, doubled each attempt (default 800). Tests pass 0. */
  backoffMs?: number
  /** Request headers. Keep them CORS-safelisted (Accept…) so no preflight is needed. */
  headers?: Record<string, string>
}

export interface TextResponse {
  status: number
  ok: boolean
  /** Final URL after redirects (empty string when the fetch implementation does not report it). */
  url: string
  text: string
  contentType: string
}

/** Default fetch bound to the global (calling an unbound window.fetch throws "Illegal invocation"). */
export const defaultFetch: FetchLike = (u, i) => fetch(u, i)

/**
 * GET a URL and return the body as text. Resolves for any HTTP status that is not retryable (callers decide what a
 * 404 means). Throws SourceError on timeout / network failure / exhausted retries, and on abort.
 */
export async function fetchText(url: string, opts: RequestOptions): Promise<TextResponse> {
  const doFetch = opts.fetch ?? defaultFetch
  const retries = opts.retries ?? 1
  const backoff = opts.backoffMs ?? 800
  const timeoutMs = opts.timeoutMs ?? 15000
  let last: SourceError | undefined
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (opts.signal?.aborted) throw new SourceError(opts.source, 'aborted', 'Aborted')
    const ctrl = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      ctrl.abort()
    }, timeoutMs)
    const onAbort = () => ctrl.abort()
    opts.signal?.addEventListener('abort', onAbort, { once: true })
    try {
      const res = await doFetch(url, { method: 'GET', headers: opts.headers, signal: ctrl.signal, credentials: 'omit', referrerPolicy: 'no-referrer' })
      const text = await res.text()
      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        last = new SourceError(opts.source, 'http', `${opts.source} returned HTTP ${res.status}`, res.status)
      } else {
        return { status: res.status, ok: res.ok, url: res.url ?? '', text, contentType: res.headers?.get('content-type') ?? '' }
      }
    } catch (e) {
      if (opts.signal?.aborted) throw new SourceError(opts.source, 'aborted', 'Aborted')
      if (timedOut) {
        last = new SourceError(opts.source, 'timeout', `${opts.source} did not answer within ${Math.round(timeoutMs / 1000)} s`)
      } else {
        last = new SourceError(
          opts.source,
          'network',
          `Could not reach ${opts.source} (network error, rate limiting or CORS rejection): ${errorMessage(e)}`,
        )
      }
    } finally {
      clearTimeout(timer)
      opts.signal?.removeEventListener('abort', onAbort)
    }
    if (attempt < retries) {
      try {
        await sleep(backoff * 2 ** attempt, opts.signal)
      } catch {
        throw new SourceError(opts.source, 'aborted', 'Aborted')
      }
    }
  }
  throw last ?? new SourceError(opts.source, 'network', `Could not reach ${opts.source}`)
}

/** GET + JSON.parse. Non-2xx statuses throw SourceError('http'). */
export async function fetchJson<T = unknown>(url: string, opts: RequestOptions): Promise<{ data: T; url: string; status: number }> {
  const res = await fetchText(url, opts)
  if (!res.ok) throw new SourceError(opts.source, 'http', `${opts.source} returned HTTP ${res.status}`, res.status)
  try {
    return { data: JSON.parse(res.text) as T, url: res.url, status: res.status }
  } catch {
    throw new SourceError(opts.source, 'parse', `${opts.source} returned a response that is not valid JSON`)
  }
}

/**
 * Run `fn` over `items` with at most `limit` in flight. Results keep the input order. Stops scheduling new work once
 * the signal is aborted (in-flight calls are expected to observe the signal themselves).
 */
export async function mapPool<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
  signal?: AbortSignal,
): Promise<R[]> {
  const out = new Array<R>(items.length)
  let next = 0
  const worker = async () => {
    while (next < items.length) {
      if (signal?.aborted) throw abortError()
      const i = next++
      out[i] = await fn(items[i], i)
    }
  }
  const n = Math.max(1, Math.min(limit, items.length))
  await Promise.all(Array.from({ length: n }, worker))
  return out
}

/** Only http(s) URLs from external data may become links. Returns the normalised href or undefined. */
export function safeHref(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 2048) return undefined
  try {
    const u = new URL(value.trim())
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : undefined
  } catch {
    return undefined
  }
}
