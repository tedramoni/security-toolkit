import { useMemo } from 'react'
import { useLocalStorage } from '../../lib/storage'
import { parseBaseline } from './report'
import { RULES_BY_ID } from './rules'
import type { Suppression } from './types'

/** Only rule toggles and suppressions are persisted — never scanned content. */
export const STORAGE_KEY = 'scp:skill-scanner'

export interface PersistedState {
  version: 1
  disabledRules: string[]
  suppressions: Suppression[]
}

export const EMPTY_STATE: PersistedState = { version: 1, disabledRules: [], suppressions: [] }

/** Defensive parse of whatever is in localStorage. */
export function sanitizeState(raw: unknown): PersistedState {
  if (typeof raw !== 'object' || raw === null) return EMPTY_STATE
  const r = raw as Record<string, unknown>
  const disabledRules = Array.isArray(r.disabledRules) ? r.disabledRules.filter((x): x is string => typeof x === 'string' && RULES_BY_ID.has(x)) : []
  let suppressions: Suppression[] = []
  try {
    suppressions = parseBaseline({ tool: 'ai-skill-scanner', suppressions: r.suppressions })
  } catch {
    suppressions = []
  }
  return { version: 1, disabledRules, suppressions }
}

export function useScannerState() {
  const [raw, setRaw] = useLocalStorage<unknown>(STORAGE_KEY, EMPTY_STATE)
  const state = useMemo(() => sanitizeState(raw), [raw])
  const update = (fn: (s: PersistedState) => PersistedState) => setRaw((prev: unknown) => fn(sanitizeState(prev)))
  return [state, update] as const
}
