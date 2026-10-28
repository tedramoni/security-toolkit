import type { Dependency, ParseResult, SkippedEntry } from '../types.ts'

function unquote(s: string): string {
  // Berry quotes the whole multi-spec header, so after splitting on ", " a part may have only one quote.
  return s.trim().replace(/^"/, '').replace(/"$/, '')
}

/** Split "name@range" (name may be scoped: "@scope/name@range"). */
export function splitSpec(spec: string): { name: string; range: string } | null {
  const s = unquote(spec)
  const at = s.indexOf('@', s.startsWith('@') ? 1 : 0)
  if (at <= 0) return null
  return { name: s.slice(0, at), range: s.slice(at + 1) }
}

/** For "npm:real@^1" style alias ranges, return the real package name. */
function aliasTarget(range: string): string | null {
  if (!range.startsWith('npm:')) return null
  const inner = splitSpec(range.slice(4))
  return inner ? inner.name : null
}

/** git / GitHub / tarball URL / local path ranges. "npm:" aliases are registry packages. */
export function isNonRegistryRange(range: string): boolean {
  if (range.startsWith('npm:')) return false
  return /^(?:[a-z][a-z0-9+.-]*:|\.{0,2}\/|~\/)/i.test(range) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(range)
}

interface Block {
  header: string
  fields: Map<string, string>
}

function readBlocks(text: string): Block[] {
  const blocks: Block[] = []
  let current: Block | null = null
  for (const rawLine of text.split(/\r?\n/)) {
    if (rawLine.trim() === '' || rawLine.trimStart().startsWith('#')) continue
    const indent = rawLine.length - rawLine.trimStart().length
    const line = rawLine.trim()
    if (indent === 0) {
      current = line.endsWith(':') ? { header: line.slice(0, -1), fields: new Map() } : null
      if (current) blocks.push(current)
    } else if (indent === 2 && current) {
      // classic: `version "1.2.3"`   berry: `version: 1.2.3`
      const m = /^("?[\w-]+"?):?\s+(.*)$/.exec(line)
      if (m && !line.endsWith(':')) current.fields.set(unquote(m[1]), unquote(m[2]))
    }
  }
  return blocks
}

/** Parse yarn.lock — classic v1 and (best-effort) Yarn Berry v2+ lockfiles. Ecosystem npm. */
export function parseYarnLock(text: string): ParseResult {
  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []
  const blocks = readBlocks(text)
  if (blocks.length === 0) throw new Error('No entries found — is this a yarn.lock?')

  for (const block of blocks) {
    if (block.header === '__metadata') continue
    const firstSpec = block.header.split(/,\s*/)[0]
    const spec = splitSpec(firstSpec)
    const version = block.fields.get('version')
    if (!spec || !version) {
      skipped.push({ entry: unquote(firstSpec), reason: 'could not read package name or version' })
      continue
    }

    const resolution = block.fields.get('resolution')
    if (resolution !== undefined) {
      // Yarn Berry: resolution "name@npm:1.2.3" is authoritative
      const r = splitSpec(resolution)
      if (!r || !r.range.startsWith('npm:')) {
        skipped.push({ entry: resolution, reason: 'not from the npm registry (workspace, git, patch or link)' })
        continue
      }
      deps.push({ name: r.name, version: r.range.slice(4), ecosystem: 'npm' })
      continue
    }

    const resolved = block.fields.get('resolved')
    // GitHub shorthands ("user/repo#ref", "github:user/repo") resolve to https://codeload.github.com
    // tarballs, so the https check alone is not enough: also look at the requested range.
    if ((resolved !== undefined && !/^https?:\/\//i.test(resolved)) || isNonRegistryRange(spec.range)) {
      skipped.push({ entry: `${spec.name}@${version}`, reason: 'not from the npm registry (git, file or link)' })
      continue
    }
    const name = aliasTarget(spec.range) ?? spec.name
    deps.push({ name, version, ecosystem: 'npm' })
  }
  return { deps, skipped }
}
