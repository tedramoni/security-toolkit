/** Resolve hosts discovered in CT logs (A, then AAAA when needed) and assess dangling CNAMEs. */
import type { Resolve } from './doh'
import { mapPool } from './net'
import type { TakeoverAssessment } from './takeover'
import { assessTakeover } from './takeover'
import type { Finding } from './types'

export const RESOLVE_CONCURRENCY = 6
export const RESOLVE_CAP = 200

export interface ResolvedHost {
  host: string
  status: string
  rcode: number
  cnames: string[]
  addresses: string[]
  error?: string
  takeover: TakeoverAssessment
}

export async function resolveHosts(
  hosts: readonly string[],
  resolve: Resolve,
  opts: { signal?: AbortSignal; concurrency?: number; cap?: number; onProgress?: (done: number, total: number) => void } = {},
): Promise<ResolvedHost[]> {
  const list = hosts.slice(0, opts.cap ?? RESOLVE_CAP)
  let done = 0
  return mapPool(
    list,
    opts.concurrency ?? RESOLVE_CONCURRENCY,
    async (host): Promise<ResolvedHost> => {
      try {
        const a = await resolve(host, 'A')
        let addresses = a.records.map((r) => r.data)
        let cnames = a.cnames
        let rcode = a.status
        if (addresses.length === 0 && a.status === 0) {
          const aaaa = await resolve(host, 'AAAA')
          addresses = aaaa.records.map((r) => r.data)
          if (cnames.length === 0) cnames = aaaa.cnames
          rcode = aaaa.status
        }
        return { host, status: a.statusText, rcode, cnames, addresses, takeover: assessTakeover(cnames, rcode, addresses.length > 0) }
      } catch (e) {
        if (opts.signal?.aborted) throw e
        return { host, status: 'error', rcode: -1, cnames: [], addresses: [], error: e instanceof Error ? e.message : String(e), takeover: { verdict: 'none', severity: 'pass', reason: 'Lookup failed.' } }
      } finally {
        done++
        opts.onProgress?.(done, list.length)
      }
    },
    opts.signal,
  )
}

export function resolvedFindings(rows: readonly ResolvedHost[]): Finding[] {
  const f: Finding[] = []
  for (const r of rows) {
    const t = r.takeover
    if (t.verdict === 'possible-takeover' || t.verdict === 'dangling-cname') {
      f.push({
        severity: t.severity === 'pass' ? 'info' : t.severity,
        title: t.verdict === 'possible-takeover' ? `Possible subdomain takeover — verify manually: ${r.host}` : `Dangling CNAME: ${r.host}`,
        detail: `${t.reason} Chain: ${r.host} → ${r.cnames.join(' → ')}.`,
        fix: 'If the external resource no longer exists, delete the DNS record (or re-claim the resource) before someone else does.',
        ref: 'https://github.com/EdOverflow/can-i-take-over-xyz',
      })
    }
  }
  const nx = rows.filter((r) => r.rcode === 3 && r.cnames.length === 0).length
  if (nx > 0) f.push({ severity: 'info', title: `${nx} logged host name${nx > 1 ? 's' : ''} no longer resolve`, detail: 'Names from old certificates that are gone from DNS — normal churn.' })
  return f
}
