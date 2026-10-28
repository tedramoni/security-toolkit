/**
 * Internet Archive Wayback Machine availability API (https://archive.org/wayback/available, CORS-enabled).
 *  - latest capture:  ?url=<domain>
 *  - first capture:   ?url=<domain>&timestamp=19960101  (closest to the archive's start)
 * The CDX API (capture counts) does not send CORS headers, so the total count is not available from the browser;
 * the UI links to the calendar view instead. archive.org rate-limits with 429 responses that carry no CORS header
 * (seen as a network error), hence sequential requests with back-off.
 */
import type { FetchLike } from './net'
import { SourceError, fetchText, sleep } from './net'

export interface Snapshot {
  url: string
  timestamp: string
  date: string
  status?: string
}

/** "20240131120000" → ISO date-time. */
export function waybackDate(ts: string): string | undefined {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?$/.exec(ts)
  if (!m) return undefined
  return `${m[1]}-${m[2]}-${m[3]}T${m[4] ?? '00'}:${m[5] ?? '00'}:${m[6] ?? '00'}Z`
}

export function parseAvailable(json: unknown): Snapshot | undefined {
  const closest = (json as { archived_snapshots?: { closest?: Record<string, unknown> } } | null)?.archived_snapshots?.closest
  if (!closest || closest.available === false || typeof closest.url !== 'string' || typeof closest.timestamp !== 'string') return undefined
  const date = waybackDate(closest.timestamp)
  if (!date) return undefined
  // The API returns http:// links; the archive is served over https.
  const url = closest.url.replace(/^http:\/\/web\.archive\.org\//, 'https://web.archive.org/')
  if (!url.startsWith('https://web.archive.org/')) return undefined
  return { url, timestamp: closest.timestamp, date, status: typeof closest.status === 'string' ? closest.status : undefined }
}

export interface WaybackResult {
  first?: Snapshot
  latest?: Snapshot
  calendarUrl: string
  errors: string[]
}

export interface WaybackOptions {
  fetch?: FetchLike
  signal?: AbortSignal
  timeoutMs?: number
  backoffMs?: number
  /** Pause between the two requests (default 1200 ms). */
  gapMs?: number
}

export async function fetchWayback(host: string, opts: WaybackOptions = {}): Promise<WaybackResult> {
  const get = async (ts?: string) => {
    const url = `https://archive.org/wayback/available?url=${encodeURIComponent(host)}${ts ? `&timestamp=${ts}` : ''}`
    const res = await fetchText(url, { source: 'archive.org', fetch: opts.fetch, signal: opts.signal, timeoutMs: opts.timeoutMs ?? 20000, retries: 1, backoffMs: opts.backoffMs ?? 3000 })
    if (!res.ok) throw new SourceError('archive.org', 'http', `archive.org returned HTTP ${res.status}`, res.status)
    try {
      return parseAvailable(JSON.parse(res.text))
    } catch {
      throw new SourceError('archive.org', 'parse', 'archive.org returned invalid JSON')
    }
  }
  const errors: string[] = []
  let latest: Snapshot | undefined
  let first: Snapshot | undefined
  try {
    latest = await get()
  } catch (e) {
    if (e instanceof SourceError && e.kind === 'aborted') throw e
    errors.push(`Latest capture: ${e instanceof Error ? e.message : String(e)}`)
  }
  await sleep(opts.gapMs ?? 1200, opts.signal)
  try {
    first = await get('19960101')
  } catch (e) {
    if (e instanceof SourceError && e.kind === 'aborted') throw e
    errors.push(`First capture: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (errors.length === 2) {
    throw new SourceError('archive.org', 'network', 'archive.org did not answer. It rate-limits with HTTP 429 responses that carry no CORS header, which the browser reports as a network/CORS error — wait a minute and re-run')
  }
  return { first, latest, calendarUrl: `https://web.archive.org/web/*/${encodeURIComponent(host)}`, errors }
}
