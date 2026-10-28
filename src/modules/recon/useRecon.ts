/**
 * Scan orchestration: every check runs concurrently with its own timeout and AbortController (linked to the scan's),
 * so one slow or failing source never blocks or breaks the others. Checks can be re-run individually.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchCrtsh, processCrtsh, ctFindings } from './crtsh'
import type { CtSummary } from './crtsh'
import type { DnsCheckData } from './dns'
import { runDnsCheck } from './dns'
import type { Resolve } from './doh'
import { createResolver } from './doh'
import type { EmailCheckData } from './email'
import { runEmailCheck } from './email'
import { errorMessage } from './net'
import { fetchViaProxy } from './proxy'
import type { RdapDomainResult, RdapIp } from './rdap'
import { fetchRdapDomain, fetchRdapIp, rdapDomainFindings } from './rdap'
import type { ReconTarget } from './target'
import { reverseName } from './target'
import type { CheckId, CheckStatus, Finding } from './types'
import type { WaybackResult } from './wayback'
import { fetchWayback } from './wayback'
import type { WebCheckData } from './website'
import { runWebCheck } from './website'

export interface CheckState<T = unknown> {
  status: CheckStatus
  findings: Finding[]
  data?: T
  error?: string
  ms?: number
  /** Short explanation shown instead of results (needs proxy, not applicable…). */
  note?: string
}

export interface IpCheckData {
  ip?: string
  ptr: string[]
  rdap?: RdapIp
  server?: string
  raw?: unknown
  addresses: string[]
}

export interface CtCheckData {
  domain: string
  summary: CtSummary
  unexpiredOnly: boolean
  url: string
}

export interface CheckDataMap {
  dns: DnsCheckData
  email: EmailCheckData
  ct: CtCheckData
  rdap: RdapDomainResult
  ip: IpCheckData
  wayback: WaybackResult
  web: WebCheckData
}

export type Checks = { [K in CheckId]: CheckState<CheckDataMap[K]> }

export const CHECK_ORDER: readonly CheckId[] = ['dns', 'email', 'ct', 'rdap', 'ip', 'wayback', 'web']

/** Per-check budget (the check settles as an error after this, even if a source never answers). */
export const CHECK_TIMEOUT_MS: Record<CheckId, number> = {
  dns: 30000,
  email: 60000,
  ct: 150000,
  rdap: 40000,
  ip: 40000,
  wayback: 60000,
  web: 60000,
}

const idle = (): Checks => ({
  dns: { status: 'idle', findings: [] },
  email: { status: 'idle', findings: [] },
  ct: { status: 'idle', findings: [] },
  rdap: { status: 'idle', findings: [] },
  ip: { status: 'idle', findings: [] },
  wayback: { status: 'idle', findings: [] },
  web: { status: 'idle', findings: [] },
})

interface Ctx {
  target: ReconTarget
  proxy?: string
  resolve: Resolve
  signal: AbortSignal
}

type Runner<K extends CheckId> = (ctx: Ctx) => Promise<{ data: CheckDataMap[K]; findings: Finding[] }>

function randomLabel(): string {
  const b = new Uint8Array(6)
  crypto.getRandomValues(b)
  return `scp-${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`
}

const RUNNERS: { [K in CheckId]: Runner<K> } = {
  dns: ({ target, resolve }) => runDnsCheck(target.host, resolve, randomLabel()),
  email: ({ target, resolve, proxy, signal }) =>
    runEmailCheck(target.host, target.registrable ?? target.host, resolve, {
      signal,
      fetchStsPolicy: proxy
        ? async (url) => {
            const env = await fetchViaProxy(proxy, url, { signal })
            if (env.status !== 200) throw new Error(`Policy file returned HTTP ${env.status}`)
            return env.body
          }
        : undefined,
    }),
  ct: async ({ target, signal }) => {
    const domain = target.registrable ?? target.host
    const r = await fetchCrtsh(domain, { signal })
    const summary = processCrtsh(r.entries, domain, Date.now())
    const findings = ctFindings(summary, domain)
    if (r.unexpiredOnly) findings.unshift({ severity: 'info', title: 'Only unexpired certificates retrieved', detail: 'The full crt.sh query failed (crt.sh is often overloaded for large domains); historical names are missing. Re-run later for the full history.' })
    return { data: { domain, summary, unexpiredOnly: r.unexpiredOnly, url: r.url }, findings }
  },
  rdap: async ({ target, signal }) => {
    const r = await fetchRdapDomain(target.host, target.registrable ?? target.host, { signal })
    if (r.kind === 'unavailable') return { data: r, findings: [{ severity: 'info', title: 'RDAP not available', detail: r.reason }] }
    return { data: r, findings: rdapDomainFindings(r.domain, Date.now()) }
  },
  ip: async ({ target, resolve, signal }) => {
    let addresses: string[] = []
    if (target.kind === 'ip') addresses = [target.host]
    else {
      const [a, aaaa] = await Promise.all([resolve(target.host, 'A').catch(() => undefined), resolve(target.host, 'AAAA').catch(() => undefined)])
      addresses = [...(a?.records ?? []), ...(aaaa?.records ?? [])].map((r) => r.data)
    }
    const ip = addresses[0]
    if (!ip) return { data: { ptr: [], addresses }, findings: [{ severity: 'info', title: 'No IP address to look up', detail: 'The name has no A/AAAA record.' }] }
    const rev = reverseName(ip)
    const [ptrR, rdapR] = await Promise.allSettled([rev ? resolve(rev, 'PTR') : Promise.reject(new Error('no PTR name')), fetchRdapIp(ip, { signal })])
    const ptr = ptrR.status === 'fulfilled' ? ptrR.value.records.map((r) => r.data.replace(/\.$/, '')) : []
    const f: Finding[] = []
    const data: IpCheckData = { ip, ptr, addresses }
    if (rdapR.status === 'fulfilled') {
      data.rdap = rdapR.value.ip
      data.server = rdapR.value.server
      data.raw = rdapR.value.raw
      const n = rdapR.value.ip
      f.push({ severity: 'info', title: `${ip} belongs to ${n.org ?? n.name ?? 'unknown network'}`, detail: [n.cidrs.join(', '), n.country, n.asns.join(', ')].filter(Boolean).join(' · ') || 'No network details.' })
    } else {
      f.push({ severity: 'info', title: 'IP RDAP lookup failed', detail: errorMessage(rdapR.reason) })
    }
    if (ptrR.status === 'fulfilled' && ptr.length === 0) f.push({ severity: 'info', title: 'No reverse DNS (PTR)', detail: `${ip} has no PTR record.` })
    return { data, findings: f }
  },
  wayback: async ({ target, signal }) => {
    const r = await fetchWayback(target.host, { signal })
    const f: Finding[] = []
    if (!r.latest && !r.first && r.errors.length === 0) f.push({ severity: 'info', title: 'Never archived', detail: 'The Wayback Machine has no capture of this site.' })
    if (r.first) f.push({ severity: 'info', title: `Archived since ${r.first.date.slice(0, 10)}`, detail: 'Old captures may expose removed pages, old JavaScript with endpoints or secrets, and former technologies.' })
    for (const e of r.errors) f.push({ severity: 'info', title: 'archive.org request failed', detail: e })
    return { data: r, findings: f }
  },
  web: ({ target, proxy, signal }) => {
    if (!proxy) throw new Error('needs-proxy')
    return runWebCheck(target.host, proxy, { signal })
  },
}

function applicable(target: ReconTarget, id: CheckId): boolean {
  if (target.kind === 'ip') return id === 'ip'
  return true
}

export function useRecon() {
  const [target, setTarget] = useState<ReconTarget | undefined>()
  const [checks, setChecks] = useState<Checks>(idle)
  const scanCtrl = useRef<AbortController | null>(null)
  const ctx = useRef<Ctx | null>(null)
  /** Run token per check: only the latest run of a check may write its state (restart, re-run, proxy change). */
  const runIds = useRef<Record<string, number>>({})
  const [startedAt, setStartedAt] = useState<Date | undefined>()

  useEffect(() => () => scanCtrl.current?.abort(), [])

  const update = useCallback(<K extends CheckId>(id: K, s: CheckState<CheckDataMap[K]>) => {
    setChecks((prev) => ({ ...prev, [id]: s }))
  }, [])

  const runOne = useCallback(
    async (id: CheckId) => {
      const c = ctx.current
      if (!c) return
      if (!applicable(c.target, id)) {
        runIds.current[id] = (runIds.current[id] ?? 0) + 1
        update(id, { status: 'skipped', findings: [], note: 'Not applicable to an IP address target.' })
        return
      }
      if (id === 'web' && !c.proxy) {
        runIds.current[id] = (runIds.current[id] ?? 0) + 1
        update('web', { status: 'needs-proxy', findings: [], note: 'needs-proxy' })
        return
      }
      const runId = (runIds.current[id] ?? 0) + 1
      runIds.current[id] = runId
      const current = () => runIds.current[id] === runId
      update(id, { status: 'running', findings: [] })
      const child = new AbortController()
      const onParent = () => child.abort()
      c.signal.addEventListener('abort', onParent, { once: true })
      let timedOut = false
      const timer = setTimeout(() => {
        timedOut = true
        child.abort()
      }, CHECK_TIMEOUT_MS[id])
      const t0 = performance.now()
      const aborted = new Promise<never>((_, reject) => child.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }))
      try {
        const r = await Promise.race([(RUNNERS[id] as Runner<CheckId>)({ ...c, signal: child.signal }), aborted])
        if (!current()) return // a newer scan / re-run replaced this one
        update(id, { status: 'done', findings: r.findings, data: r.data as never, ms: Math.round(performance.now() - t0) })
      } catch (e) {
        if (!current()) return
        const msg = timedOut ? `Timed out after ${CHECK_TIMEOUT_MS[id] / 1000} s` : c.signal.aborted ? 'Cancelled' : errorMessage(e)
        update(id, { status: 'error', findings: [], error: msg, ms: Math.round(performance.now() - t0) })
      } finally {
        clearTimeout(timer)
        c.signal.removeEventListener('abort', onParent)
      }
    },
    [update],
  )

  const start = useCallback(
    (t: ReconTarget, proxy?: string) => {
      scanCtrl.current?.abort()
      const ctrl = new AbortController()
      scanCtrl.current = ctrl
      ctx.current = { target: t, proxy, resolve: createResolver({ signal: ctrl.signal }), signal: ctrl.signal }
      setTarget(t)
      setStartedAt(new Date())
      setChecks(idle())
      for (const id of CHECK_ORDER) void runOne(id)
    },
    [runOne],
  )

  const cancel = useCallback(() => {
    scanCtrl.current?.abort()
  }, [])

  const rerun = useCallback(
    (id: CheckId) => {
      const c = ctx.current
      if (!c || c.signal.aborted) {
        if (!c) return
        // Scan was cancelled: give re-runs a fresh signal.
        const ctrl = new AbortController()
        scanCtrl.current = ctrl
        ctx.current = { ...c, signal: ctrl.signal, resolve: createResolver({ signal: ctrl.signal }) }
      }
      void runOne(id)
    },
    [runOne],
  )

  /** Update the proxy for subsequent re-runs (e.g. the user just configured one). */
  const setProxy = useCallback((proxy?: string) => {
    if (ctx.current) ctx.current = { ...ctx.current, proxy }
  }, [])

  const running = CHECK_ORDER.some((id) => checks[id].status === 'running')
  return { target, checks, start, cancel, rerun, running, startedAt, setProxy, resolver: () => ctx.current?.resolve, signal: () => ctx.current?.signal }
}
