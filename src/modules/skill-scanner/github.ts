import { isExecutablePath, isTextLikePath, baseName, executableMagic, looksBinary } from './classify'
import type { ScanFile } from './types'

/*
 * Fetch a public GitHub repository / folder / file from the browser.
 * api.github.com and raw.githubusercontent.com both send Access-Control-Allow-Origin: *.
 * Unauthenticated REST calls are limited to 60/hour per IP; raw.githubusercontent.com downloads
 * do not count against the REST limit. With a token, blobs are fetched through the API (5,000/hour).
 */

export interface GitHubTarget {
  owner: string
  repo: string
  /** Candidate [ref, path] splits (branch names may contain "/"). Empty when no ref given. */
  candidates: { ref: string; path: string }[]
  type: 'repo' | 'tree' | 'blob'
}

export type ParseResult = { ok: true; target: GitHubTarget } | { ok: false; error: string }

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/

export function parseGitHubUrl(input: string): ParseResult {
  let raw = input.trim()
  if (raw === '') return { ok: false, error: 'Enter a GitHub URL.' }
  if (!/^[a-z][a-z0-9+.-]{0,20}:\/\//i.test(raw)) raw = `https://${raw}`
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return { ok: false, error: 'Not a valid URL.' }
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { ok: false, error: 'Only https://github.com URLs are supported.' }
  const host = url.hostname.toLowerCase()
  if (host !== 'github.com' && host !== 'www.github.com') return { ok: false, error: `Only github.com URLs are supported (got ${host}).` }
  if (url.username || url.password) return { ok: false, error: 'URLs with embedded credentials are not accepted.' }
  if (url.port) return { ok: false, error: 'Unexpected port in URL.' }
  let segs: string[]
  try {
    segs = url.pathname.split('/').filter((s) => s !== '').map(decodeURIComponent)
  } catch {
    return { ok: false, error: 'Malformed URL encoding.' }
  }
  if (segs.length < 2) return { ok: false, error: 'URL must include an owner and a repository: https://github.com/<owner>/<repo>' }
  const owner = segs[0]
  const repo = segs[1].replace(/\.git$/i, '')
  if (!OWNER_RE.test(owner)) return { ok: false, error: `Invalid owner name "${owner}".` }
  if (!REPO_RE.test(repo) || repo === '.' || repo === '..') return { ok: false, error: `Invalid repository name "${repo}".` }
  if (segs.some((s) => s === '..' || s.includes('\0'))) return { ok: false, error: 'Path traversal in URL.' }
  if (segs.length === 2) return { ok: true, target: { owner, repo, candidates: [], type: 'repo' } }
  const kind = segs[2]
  if (kind !== 'tree' && kind !== 'blob') return { ok: false, error: `Unsupported GitHub URL (/${kind}/). Use a repository, /tree/<branch>/<path> or /blob/<branch>/<file> URL.` }
  const rest = segs.slice(3)
  if (rest.length === 0) return { ok: false, error: `Missing branch/tag after /${kind}/.` }
  const candidates: { ref: string; path: string }[] = []
  const maxRefSegs = kind === 'blob' ? rest.length - 1 : rest.length
  for (let k = 1; k <= Math.min(maxRefSegs, 5); k++) candidates.push({ ref: rest.slice(0, k).join('/'), path: rest.slice(k).join('/') })
  if (candidates.length === 0) return { ok: false, error: 'Blob URL must include a file path.' }
  return { ok: true, target: { owner, repo, candidates, type: kind } }
}

export interface FetchLimits {
  maxFiles: number
  maxFileBytes: number
  maxTotalBytes: number
  concurrency: number
}

export const DEFAULT_FETCH_LIMITS: FetchLimits = { maxFiles: 300, maxFileBytes: 1024 * 1024, maxTotalBytes: 20 * 1024 * 1024, concurrency: 6 }

export interface FetchResult {
  files: ScanFile[]
  warnings: string[]
  ref: string
  basePath: string
  /** Symlinks in the tree (reported like archive symlinks). */
  symlinks: string[]
  label: string
}

export class GitHubError extends Error {}

interface TreeEntry {
  path: string
  mode: string
  type: string
  sha: string
  size?: number
}

function rateLimitMessage(res: Response): string | undefined {
  const remaining = res.headers.get('x-ratelimit-remaining')
  const reset = Number(res.headers.get('x-ratelimit-reset'))
  if ((res.status === 403 || res.status === 429) && (remaining === '0' || res.status === 429)) {
    const when = Number.isFinite(reset) && reset > 0 ? new Date(reset * 1000).toLocaleTimeString() : 'later'
    return `GitHub API rate limit reached (60 requests/hour without a token). Try again after ${when}, or add a personal access token (kept in memory only).`
  }
  return undefined
}

async function api<T>(path: string, token: string | undefined, fetchImpl: typeof fetch, signal?: AbortSignal): Promise<{ status: number; data?: T }> {
  const headers: Record<string, string> = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }
  if (token) headers.Authorization = `Bearer ${token}`
  let res: Response
  try {
    res = await fetchImpl(`https://api.github.com${path}`, { headers, signal, credentials: 'omit', referrerPolicy: 'no-referrer' })
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e
    throw new GitHubError('Network error contacting api.github.com (offline, blocked by an extension/proxy, or CORS).')
  }
  const rl = rateLimitMessage(res)
  if (rl) throw new GitHubError(rl)
  if (res.status === 401) throw new GitHubError('GitHub rejected the token (401). Check that it is valid and not expired.')
  if (res.status === 404 || res.status === 422 || res.status === 409) return { status: res.status }
  if (!res.ok) throw new GitHubError(`GitHub API error ${res.status} for ${path}.`)
  return { status: res.status, data: (await res.json()) as T }
}

function encPath(p: string): string {
  return p.split('/').map(encodeURIComponent).join('/')
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/\s+/g, ''))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

export async function fetchGitHub(
  target: GitHubTarget,
  opts: { token?: string; signal?: AbortSignal; onProgress?: (msg: string) => void; limits?: FetchLimits; fetchImpl?: typeof fetch } = {},
): Promise<FetchResult> {
  const fetchImpl = opts.fetchImpl ?? fetch.bind(globalThis)
  const limits = opts.limits ?? DEFAULT_FETCH_LIMITS
  const token = opts.token?.trim() || undefined
  const { owner, repo } = target
  const repoPath = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`
  const warnings: string[] = []

  let candidates = target.candidates
  if (candidates.length === 0) {
    opts.onProgress?.('Looking up the default branch…')
    const r = await api<{ default_branch: string }>(repoPath, token, fetchImpl, opts.signal)
    if (!r.data) throw new GitHubError(`Repository ${owner}/${repo} not found. It may be private — add a token with read access.`)
    candidates = [{ ref: r.data.default_branch, path: '' }]
  }

  let tree: { tree: TreeEntry[]; truncated: boolean } | undefined
  let chosen = candidates[0]
  opts.onProgress?.('Listing files…')
  for (const c of candidates) {
    const r = await api<{ tree: TreeEntry[]; truncated: boolean }>(`${repoPath}/git/trees/${encodeURIComponent(c.ref)}?recursive=1`, token, fetchImpl, opts.signal)
    if (r.data) {
      tree = r.data
      chosen = c
      break
    }
  }
  if (!tree) throw new GitHubError(`Could not find branch/tag "${candidates[0].ref}" in ${owner}/${repo} (or the repository is private).`)
  if (tree.truncated) warnings.push('GitHub truncated the file listing (very large repository); some files were not scanned. Point the URL at the skill folder instead.')

  let basePath = chosen.path.replace(/\/+$/, '')
  let single: string | undefined
  if (target.type === 'blob') {
    if (baseName(basePath).toLowerCase() === 'skill.md') basePath = basePath.includes('/') ? basePath.slice(0, basePath.lastIndexOf('/')) : ''
    else single = basePath
  }
  const inScope = (p: string) => (single ? p === single : basePath === '' || p === basePath || p.startsWith(basePath + '/'))
  const entries = tree.tree.filter((e) => inScope(e.path))
  if (entries.length === 0) throw new GitHubError(`Nothing found at "${single ?? basePath}" on ${chosen.ref}.`)

  const files: ScanFile[] = []
  const symlinks: string[] = []
  const toFetch: TreeEntry[] = []
  let skippedBinary = 0
  let skippedLarge = 0
  for (const e of entries) {
    if (e.type !== 'blob') continue
    if (e.mode === '120000') {
      symlinks.push(e.path)
      continue
    }
    if (/(?:^|\/)(?:node_modules|\.git)\//.test(e.path)) continue
    if (isExecutablePath(e.path)) {
      files.push({ path: e.path, size: e.size ?? 0 })
      continue
    }
    if (!isTextLikePath(e.path)) {
      skippedBinary++
      continue
    }
    if ((e.size ?? 0) > limits.maxFileBytes) {
      skippedLarge++
      continue
    }
    toFetch.push(e)
  }
  if (skippedBinary) warnings.push(`${skippedBinary} non-text file(s) skipped (images, archives, fonts…).`)
  if (skippedLarge) warnings.push(`${skippedLarge} file(s) over ${limits.maxFileBytes / 1024} KB skipped.`)
  if (toFetch.length > limits.maxFiles) {
    warnings.push(`${toFetch.length} text files found; only the first ${limits.maxFiles} were fetched (SKILL.md and configs first).`)
    const prio = (p: string) => (/(?:^|\/)skill\.md$/i.test(p) ? 0 : /\.(?:md|json|jsonc)$/i.test(p) ? 1 : /\.(?:sh|py|js|ts|ps1|mjs|cjs)$/i.test(p) ? 2 : 3)
    toFetch.sort((a, b) => prio(a.path) - prio(b.path))
    toFetch.length = limits.maxFiles
  }

  let total = 0
  let done = 0
  let next = 0
  const ref = chosen.ref
  const worker = async () => {
    while (next < toFetch.length) {
      const e = toFetch[next++]
      if (total > limits.maxTotalBytes) return
      let bytes: Uint8Array
      if (token) {
        const r = await api<{ content: string; encoding: string }>(`${repoPath}/git/blobs/${e.sha}`, token, fetchImpl, opts.signal)
        if (!r.data || r.data.encoding !== 'base64') {
          warnings.push(`Could not fetch ${e.path}.`)
          continue
        }
        bytes = base64ToBytes(r.data.content)
      } else {
        let res: Response
        try {
          res = await fetchImpl(`https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encPath(ref)}/${encPath(e.path)}`, {
            signal: opts.signal,
            credentials: 'omit',
            referrerPolicy: 'no-referrer',
          })
        } catch (err) {
          if ((err as Error).name === 'AbortError') throw err
          warnings.push(`Network error fetching ${e.path}.`)
          continue
        }
        if (res.status === 429) throw new GitHubError('raw.githubusercontent.com rate limit reached. Wait a few minutes or add a token.')
        if (!res.ok) {
          warnings.push(`HTTP ${res.status} fetching ${e.path}.`)
          continue
        }
        bytes = new Uint8Array(await res.arrayBuffer())
      }
      total += bytes.length
      done++
      opts.onProgress?.(`Fetched ${done}/${toFetch.length} files…`)
      const magic = executableMagic(bytes)
      if (magic) files.push({ path: e.path, size: bytes.length, executable: magic })
      else if (looksBinary(bytes)) continue
      else files.push({ path: e.path, size: bytes.length, content: new TextDecoder('utf-8', { fatal: false }).decode(bytes) })
    }
  }
  await Promise.all(Array.from({ length: Math.min(limits.concurrency, toFetch.length) }, worker))
  if (total > limits.maxTotalBytes) warnings.push(`Stopped after ${(limits.maxTotalBytes / 1024 / 1024).toFixed(0)} MB of downloads.`)
  files.sort((a, b) => a.path.localeCompare(b.path))
  return { files, warnings, ref, basePath: single ?? basePath, symlinks, label: `${owner}/${repo}@${ref}${single || basePath ? `/${single ?? basePath}` : ''}` }
}
