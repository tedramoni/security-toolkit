import { useEffect, useState } from 'react'

/** All app data lives in localStorage under this prefix — nothing is ever sent to a server. */
export const STORAGE_PREFIX = 'scp:'

export const STORAGE_KEYS = {
  threatModels: `${STORAGE_PREFIX}threat-models`,
  reviews: `${STORAGE_PREFIX}reviews`,
  ciGenerator: `${STORAGE_PREFIX}ci-generator`,
} as const

export function readJSON<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key)
    return raw === null ? fallback : (JSON.parse(raw) as T)
  } catch {
    return fallback
  }
}

export function writeJSON(key: string, value: unknown): void {
  localStorage.setItem(key, JSON.stringify(value))
}

/** useState backed by localStorage. Syncs across tabs. */
export function useLocalStorage<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(() => readJSON(key, initial))

  useEffect(() => {
    writeJSON(key, value)
  }, [key, value])

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === key) setValue(readJSON(key, initial))
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
    // initial is intentionally excluded: it is only the fallback for the first read
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  return [value, setValue] as const
}

/** Snapshot of every app key, for the global backup. */
export function exportAll(): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i)
    if (key?.startsWith(STORAGE_PREFIX)) out[key] = readJSON(key, null)
  }
  return out
}

/** Restore a backup produced by exportAll. Ignores keys outside the app prefix. Returns the number of keys restored. */
export function importAll(data: unknown): number {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new Error('Backup must be a JSON object')
  }
  let count = 0
  for (const [key, value] of Object.entries(data)) {
    if (!key.startsWith(STORAGE_PREFIX)) continue
    writeJSON(key, value)
    count++
  }
  return count
}

export function newId(): string {
  return crypto.randomUUID()
}

