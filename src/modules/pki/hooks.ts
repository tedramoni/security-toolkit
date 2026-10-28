/** Small hooks / DOM helpers shared by the PKI tabs. */
import { useEffect, useState } from 'react'

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

/**
 * Run an async computation for an input, ignoring stale results. `fn` must be stable (module-level function).
 * `loading` is derived: true while the latest input has no result yet.
 */
export function useAsync<I, O>(input: I, fn: (i: I) => Promise<O>): { data?: O; error?: string; loading: boolean } {
  const [state, setState] = useState<{ data?: O; error?: string; for?: I; done: boolean }>({ done: false })
  useEffect(() => {
    let alive = true
    fn(input).then(
      (data) => {
        if (alive) setState({ data, for: input, done: true })
      },
      (e: unknown) => {
        if (alive) setState({ error: e instanceof Error ? e.message : String(e), for: input, done: true })
      },
    )
    return () => {
      alive = false
    }
  }, [input, fn])
  const current = state.done && Object.is(state.for, input)
  // Keep showing the previous result while the next one computes (avoids flicker).
  return { data: state.data, error: current ? state.error : undefined, loading: !current }
}

/** Current time, refreshed every minute (for "days left" badges). */
export function useNow(intervalMs = 60_000): Date {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), intervalMs)
    return () => clearInterval(t)
  }, [intervalMs])
  return now
}

export function downloadBytes(filename: string, bytes: Uint8Array, mime = 'application/octet-stream'): void {
  const blob = new Blob([Uint8Array.from(bytes)], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
