/** OSV ecosystem identifiers used by this module (exact spelling expected by api.osv.dev). */
export type Ecosystem = 'npm' | 'PyPI' | 'Maven' | 'Go' | 'RubyGems' | 'Packagist' | 'crates.io'

export interface Dependency {
  name: string
  version: string
  ecosystem: Ecosystem
  /** True when the lockfile marks the package as development/test only. */
  dev?: boolean
}

export interface SkippedEntry {
  /** Package name or raw line that could not be used. */
  entry: string
  reason: string
}

export type LockfileFormat =
  | 'package-lock'
  | 'yarn-lock'
  | 'requirements'
  | 'pipfile-lock'
  | 'poetry-lock'
  | 'pom'
  | 'go-mod'
  | 'go-sum'
  | 'gemfile-lock'
  | 'composer-lock'
  | 'cargo-lock'

export interface ParseResult {
  deps: Dependency[]
  skipped: SkippedEntry[]
}

export function depKey(d: Pick<Dependency, 'ecosystem' | 'name' | 'version'>): string {
  return `${d.ecosystem}\u0000${d.name}\u0000${d.version}`
}

/**
 * Remove duplicate packages (same ecosystem/name/version). A package is only "dev" if every
 * occurrence is dev — if anything in production pulls it in, it ships.
 */
export function dedupeDeps(deps: Dependency[]): Dependency[] {
  const map = new Map<string, Dependency>()
  for (const d of deps) {
    const k = depKey(d)
    const prev = map.get(k)
    if (!prev) map.set(k, { ...d, dev: d.dev === true })
    else if (prev.dev && d.dev !== true) prev.dev = false
  }
  return [...map.values()]
}
