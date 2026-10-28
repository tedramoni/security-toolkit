import type { Dependency, ParseResult, SkippedEntry } from '../types.ts'
import { normalizePyName } from './pypi.ts'

/** composer.lock: "packages" (production) and "packages-dev" arrays. Ecosystem Packagist. */
export function parseComposerLock(text: string): ParseResult {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (e) {
    throw new Error(`composer.lock is not valid JSON: ${(e as Error).message}`)
  }
  if (typeof data !== 'object' || data === null) throw new Error('composer.lock must be a JSON object')
  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []
  for (const [section, dev] of [['packages', false], ['packages-dev', true]] as const) {
    const list = (data as Record<string, unknown>)[section]
    if (!Array.isArray(list)) continue
    for (const p of list as { name?: unknown; version?: unknown }[]) {
      if (typeof p?.name !== 'string' || typeof p.version !== 'string') continue
      if (p.version.startsWith('dev-') || p.version.endsWith('-dev')) {
        skipped.push({ entry: `${p.name} ${p.version}`, reason: 'development branch, not a released version' })
        continue
      }
      // Packagist tags are often "v5.4.1"; OSV records use "5.4.1"
      const version = p.version.replace(/^v(?=\d)/, '')
      deps.push({ name: p.name, version, ecosystem: 'Packagist', dev })
    }
  }
  return { deps, skipped }
}

/** Minimal reader for the `[[package]]` tables shared by Cargo.lock and poetry.lock. */
export function readTomlPackages(text: string): Record<string, string>[] {
  const out: Record<string, string>[] = []
  let current: Record<string, string> | null = null
  let last: Record<string, string> | null = null
  let prefix = ''
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line.startsWith('[')) {
      prefix = ''
      if (line === '[[package]]') {
        current = last = {}
        out.push(current)
      } else {
        // sub-tables of the last package, e.g. poetry's [package.source] (type = "git" / "directory")
        const sub = /^\[package\.([A-Za-z0-9_-]+)\]$/.exec(line)
        current = sub && last ? last : null
        if (sub) prefix = `${sub[1]}.`
      }
      continue
    }
    if (!current) continue
    const m = /^([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\[[^\]]*\]))\s*$/.exec(line)
    if (m) current[prefix + m[1]] = m[2] ?? m[3]
  }
  return out
}

/** Cargo.lock. Crates without a registry source are workspace members or path/git dependencies. */
export function parseCargoLock(text: string): ParseResult {
  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []
  for (const p of readTomlPackages(text)) {
    if (!p.name || !p.version) continue
    if (!p.source) continue // the workspace's own crates
    if (!p.source.startsWith('registry+')) {
      skipped.push({ entry: `${p.name} ${p.version}`, reason: 'git or path dependency, not from crates.io' })
      continue
    }
    deps.push({ name: p.name, version: p.version, ecosystem: 'crates.io' })
  }
  return { deps, skipped }
}

/** Is this package dev-only? Poetry < 1.5 uses category = "dev"; Poetry 2 lockfiles list groups = ["main", "dev"]. */
function poetryIsDev(p: Record<string, string>): boolean {
  if (p.category !== undefined) return p.category === 'dev'
  if (p.groups !== undefined) {
    const groups = [...p.groups.matchAll(/"([^"]*)"/g)].map((g) => g[1])
    return groups.length > 0 && !groups.includes('main')
  }
  return false
}

/** poetry.lock. Packages from git, local directories/files or URLs ([package.source]) are not on PyPI. */
export function parsePoetryLock(text: string): ParseResult {
  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []
  for (const p of readTomlPackages(text)) {
    if (!p.name || !p.version) continue
    const sourceType = p['source.type']
    if (sourceType && sourceType !== 'legacy') {
      // "legacy" = an alternative package index (a PyPI mirror); git/directory/file/url are not PyPI releases
      skipped.push({ entry: `${p.name} ${p.version}`, reason: `${sourceType} dependency, not a PyPI release` })
      continue
    }
    deps.push({ name: normalizePyName(p.name), version: p.version, ecosystem: 'PyPI', dev: poetryIsDev(p) })
  }
  return { deps, skipped }
}
