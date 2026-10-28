import type { Dependency, ParseResult, SkippedEntry } from '../types.ts'

function stripComment(line: string): string {
  const i = line.indexOf('//')
  return (i === -1 ? line : line.slice(0, i)).trim()
}

/**
 * Parse go.mod "require" directives (single-line and block form), honouring "replace" directives.
 * Since Go 1.17 go.mod lists every module in the build (direct and // indirect), so this is the
 * best source of selected versions. Versions keep their leading "v", as OSV expects for Go.
 */
export function parseGoMod(text: string): ParseResult {
  const required: { path: string; version: string }[] = []
  const replaces = new Map<string, { path: string; version?: string }>()
  let block: 'require' | 'replace' | null = null

  const handle = (kind: 'require' | 'replace', body: string) => {
    // go.mod allows quoted module paths: require "golang.org/x/text" v0.3.0
    const words = (s: string) => s.trim().split(/\s+/).filter(Boolean).map((w) => w.replace(/^"(.*)"$/, '$1'))
    if (kind === 'require') {
      const [path, version] = words(body)
      if (path && version) required.push({ path, version })
    } else {
      // split instead of one big regex: linear time even on hostile pasted input
      const parts = body.split('=>')
      if (parts.length !== 2) return
      const [from, fromVersion, extraFrom] = words(parts[0])
      const [to, toVersion, extraTo] = words(parts[1])
      if (!from || !to || extraFrom !== undefined || extraTo !== undefined) return
      // "replace a v1.0.0 => b v1.2.0" replaces only that version; "replace a => b v1.2.0" every version
      const key = fromVersion ? `${from}@${fromVersion}` : from
      replaces.set(key, { path: to, version: toVersion })
    }
  }

  for (const raw of text.split(/\r?\n/)) {
    const line = stripComment(raw)
    if (!line) continue
    if (block) {
      if (line === ')') block = null
      else handle(block, line)
      continue
    }
    const m = /^(require|replace)\s*(\(|.+)$/.exec(line)
    if (!m) continue
    const kind = m[1] as 'require' | 'replace'
    if (m[2] === '(') block = kind
    else handle(kind, m[2].trim())
  }
  if (required.length === 0 && !/^module\s/m.test(text)) throw new Error('No module or require directives — is this a go.mod?')

  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []
  for (const { path, version } of required) {
    const rep = replaces.get(`${path}@${version}`) ?? replaces.get(path)
    if (rep) {
      if (!rep.version) {
        skipped.push({ entry: `${path}@${version}`, reason: `replaced by local path ${rep.path}` })
        continue
      }
      deps.push({ name: rep.path, version: rep.version, ecosystem: 'Go' })
      continue
    }
    deps.push({ name: path, version, ecosystem: 'Go' })
  }
  return { deps, skipped }
}

/** Compare two Go module versions (vMAJOR.MINOR.PATCH[-pre][+meta]). Good enough to pick the highest. */
export function compareGoVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([^+]*))?/.exec(v)
    return m ? { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? '' } : { nums: [0, 0, 0], pre: v }
  }
  const pa = parse(a)
  const pb = parse(b)
  for (let i = 0; i < 3; i++) if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] - pb.nums[i]
  if (pa.pre === pb.pre) return 0
  if (pa.pre === '') return 1 // a release sorts after its prereleases
  if (pb.pre === '') return -1
  return pa.pre < pb.pre ? -1 : 1
}

/**
 * Parse go.sum. It lists every module version Go *considered* (not only the selected one), so we
 * keep only lines for full module downloads (not "/go.mod" hashes) and the highest version per
 * module — Go's minimal version selection always picks the highest required version.
 */
export function parseGoSum(text: string): ParseResult {
  const best = new Map<string, string>()
  let lines = 0
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) continue
    const m = /^(\S+)\s+(v\S+?)(\/go\.mod)?\s+h1:\S+$/.exec(line)
    if (!m) continue
    lines++
    if (m[3]) continue
    const prev = best.get(m[1])
    if (!prev || compareGoVersions(m[2], prev) > 0) best.set(m[1], m[2])
  }
  if (lines === 0) throw new Error('No go.sum lines found')
  const deps: Dependency[] = [...best].map(([name, version]) => ({ name, version, ecosystem: 'Go' }))
  return {
    deps,
    skipped: [{ entry: 'go.sum', reason: 'go.sum may include versions not used in the build — upload go.mod for exact results' }],
  }
}
