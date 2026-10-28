/** Persisted settings and history (localStorage, 'scp:' prefix). */
import { validateProxyUrl } from './proxy'
import { normalizeTarget } from './target'

export const SETTINGS_KEY = 'scp:recon-settings'
export const HISTORY_KEY = 'scp:recon-history'
export const HISTORY_MAX = 10

export interface ReconSettings {
  proxyUrl: string
  saveHistory: boolean
}

export const DEFAULT_SETTINGS: ReconSettings = { proxyUrl: '', saveHistory: true }

/** Values come from localStorage (possibly edited or restored from a backup): never trust their shape. */
export function sanitizeSettings(x: unknown): ReconSettings {
  const o = (typeof x === 'object' && x !== null ? x : {}) as Record<string, unknown>
  const proxy = typeof o.proxyUrl === 'string' ? validateProxyUrl(o.proxyUrl) : undefined
  return { proxyUrl: proxy?.ok ? proxy.url : '', saveHistory: typeof o.saveHistory === 'boolean' ? o.saveHistory : true }
}

export interface HistoryEntry {
  target: string
  at: string
}

export function sanitizeHistory(x: unknown): HistoryEntry[] {
  if (!Array.isArray(x)) return []
  const out: HistoryEntry[] = []
  for (const e of x as Record<string, unknown>[]) {
    if (!e || typeof e.target !== 'string' || typeof e.at !== 'string') continue
    const n = normalizeTarget(e.target)
    if (n.ok && !out.some((o) => o.target === n.target.host)) out.push({ target: n.target.host, at: e.at })
    if (out.length >= HISTORY_MAX) break
  }
  return out
}

export function pushHistory(list: readonly HistoryEntry[], target: string, at: Date = new Date()): HistoryEntry[] {
  return [{ target, at: at.toISOString() }, ...list.filter((e) => e.target !== target)].slice(0, HISTORY_MAX)
}
