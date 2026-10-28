import type { Dependency, ParseResult, SkippedEntry } from '../types.ts'

interface V2Entry {
  name?: unknown
  version?: unknown
  resolved?: unknown
  dev?: unknown
  link?: unknown
  inBundle?: unknown
}

interface V1Entry {
  version?: unknown
  dev?: unknown
  bundled?: unknown
  dependencies?: Record<string, V1Entry>
}

const NM = 'node_modules/'

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** A package fetched from somewhere other than a registry tarball (git, local folder, tarball file). */
function isNonRegistry(resolved: unknown): boolean {
  if (typeof resolved !== 'string' || resolved === '') return false
  return !/^https?:\/\//i.test(resolved)
}

/** `npm:real-name@1.2.3` alias spec (used in v1 lockfiles and yarn). Returns null when not an alias. */
export function parseNpmAlias(spec: string): { name: string; version: string } | null {
  if (!spec.startsWith('npm:')) return null
  const rest = spec.slice(4)
  const at = rest.lastIndexOf('@')
  if (at <= 0) return null
  return { name: rest.slice(0, at), version: rest.slice(at + 1) }
}

const SEMVER_LIKE = /^\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]*)?$/

/**
 * Parse package-lock.json / npm-shrinkwrap.json (lockfileVersion 1, 2 and 3).
 * v2/v3 use the flat "packages" map, which is authoritative; v1 uses the nested "dependencies" tree.
 */
export function parsePackageLock(text: string): ParseResult {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (e) {
    throw new Error(`package-lock.json is not valid JSON: ${(e as Error).message}`)
  }
  if (!isObject(data)) throw new Error('package-lock.json must be a JSON object')

  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []

  if (isObject(data.packages)) {
    for (const [key, raw] of Object.entries(data.packages)) {
      if (key === '') continue // the root project itself
      if (!isObject(raw)) continue
      const entry = raw as V2Entry
      const idx = key.lastIndexOf(NM)
      if (idx === -1) {
        // workspace folder, e.g. "packages/api" — a local package, not something on the registry
        continue
      }
      if (entry.link === true) continue // symlink to a workspace; the target is listed separately
      const keyName = key.slice(idx + NM.length)
      const name = typeof entry.name === 'string' && entry.name ? entry.name : keyName
      if (typeof entry.version !== 'string' || !entry.version) {
        skipped.push({ entry: keyName, reason: 'no version in lockfile' })
        continue
      }
      if (isNonRegistry(entry.resolved)) {
        skipped.push({ entry: `${name}@${entry.version}`, reason: `not from the npm registry (${String(entry.resolved).slice(0, 60)})` })
        continue
      }
      deps.push({ name, version: entry.version, ecosystem: 'npm', dev: entry.dev === true })
    }
    return { deps, skipped }
  }

  if (isObject(data.dependencies)) {
    const walk = (tree: Record<string, V1Entry>) => {
      for (const [name, entry] of Object.entries(tree)) {
        if (!isObject(entry)) continue
        const version = typeof entry.version === 'string' ? entry.version : ''
        const alias = parseNpmAlias(version)
        if (alias) {
          deps.push({ name: alias.name, version: alias.version, ecosystem: 'npm', dev: entry.dev === true })
        } else if (SEMVER_LIKE.test(version)) {
          deps.push({ name, version, ecosystem: 'npm', dev: entry.dev === true })
        } else {
          skipped.push({ entry: `${name}@${version || '?'}`, reason: 'not a registry version (git, file or URL dependency)' })
        }
        if (isObject(entry.dependencies)) walk(entry.dependencies as Record<string, V1Entry>)
      }
    }
    walk(data.dependencies as Record<string, V1Entry>)
    return { deps, skipped }
  }

  throw new Error('No "packages" or "dependencies" found — is this really a package-lock.json?')
}
