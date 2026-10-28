import { describe, expect, it } from 'vitest'
import { fetchGitHub, GitHubError, parseGitHubUrl } from './github'

describe('parseGitHubUrl', () => {
  it('repository URLs', () => {
    const r = parseGitHubUrl('https://github.com/anthropics/skills')
    expect(r).toEqual({ ok: true, target: { owner: 'anthropics', repo: 'skills', candidates: [], type: 'repo' } })
    expect(parseGitHubUrl('github.com/o/r.git')).toMatchObject({ ok: true, target: { owner: 'o', repo: 'r' } })
    expect(parseGitHubUrl('https://www.github.com/o/r/')).toMatchObject({ ok: true })
  })

  it('tree URLs produce ref/path candidates (branch names may contain /)', () => {
    const r = parseGitHubUrl('https://github.com/o/r/tree/feature/x/skills/pdf')
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.target.type).toBe('tree')
    expect(r.target.candidates[0]).toEqual({ ref: 'feature', path: 'x/skills/pdf' })
    expect(r.target.candidates[1]).toEqual({ ref: 'feature/x', path: 'skills/pdf' })
  })

  it('blob URLs keep at least one path segment', () => {
    const r = parseGitHubUrl('https://github.com/o/r/blob/main/skills/pdf/SKILL.md')
    expect(r.ok && r.target.candidates).toEqual([
      { ref: 'main', path: 'skills/pdf/SKILL.md' },
      { ref: 'main/skills', path: 'pdf/SKILL.md' },
      { ref: 'main/skills/pdf', path: 'SKILL.md' },
    ])
    expect(parseGitHubUrl('https://github.com/o/r/blob/main').ok).toBe(false)
  })

  it('decodes percent-encoding', () => {
    const r = parseGitHubUrl('https://github.com/o/r/tree/main/my%20skill')
    expect(r.ok && r.target.candidates[0].path).toBe('my skill')
  })

  it.each([
    'https://gitlab.com/o/r',
    'https://github.com.evil.example/o/r',
    'https://raw.githubusercontent.com/o/r/main/x',
    'https://api.github.com/repos/o/r',
    'javascript:alert(1)',
    'file:///etc/passwd',
    'https://user:pass@github.com/o/r',
    'https://github.com:8443/o/r',
    'https://github.com/o',
    'https://github.com/o/r/issues/1',
    'https://github.com/o/r/tree/main/../../x',
    'https://github.com/-bad/r',
    'https://github.com/o/r/tree/',
    '',
  ])('rejects %s', (u) => expect(parseGitHubUrl(u).ok).toBe(false))
})

type Handler = (url: string, init?: RequestInit) => Response

function mockFetch(handler: Handler) {
  const calls: { url: string; init?: RequestInit }[] = []
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    calls.push({ url, init })
    return handler(url, init)
  }) as typeof fetch
  return { f, calls }
}

const json = (o: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', ...headers } })

const TREE = {
  truncated: false,
  tree: [
    { path: 'skills/pdf/SKILL.md', mode: '100644', type: 'blob', sha: 's1', size: 20 },
    { path: 'skills/pdf/run.sh', mode: '100644', type: 'blob', sha: 's2', size: 10 },
    { path: 'skills/pdf/logo.png', mode: '100644', type: 'blob', sha: 's3', size: 10 },
    { path: 'skills/pdf/bin/x.exe', mode: '100644', type: 'blob', sha: 's4', size: 99 },
    { path: 'skills/pdf/link', mode: '120000', type: 'blob', sha: 's5', size: 5 },
    { path: 'skills/other/SKILL.md', mode: '100644', type: 'blob', sha: 's6', size: 5 },
    { path: 'skills/pdf', mode: '040000', type: 'tree', sha: 't' },
  ],
}

describe('fetchGitHub', () => {
  it('lists the tree, filters to the folder and downloads text files from raw.githubusercontent.com', async () => {
    const { f, calls } = mockFetch((url) => {
      if (url === 'https://api.github.com/repos/o/r') return json({ default_branch: 'main' })
      if (url.startsWith('https://api.github.com/repos/o/r/git/trees/main')) return json(TREE)
      if (url === 'https://raw.githubusercontent.com/o/r/main/skills/pdf/SKILL.md') return new Response('---\nname: pdf\n---\n')
      if (url === 'https://raw.githubusercontent.com/o/r/main/skills/pdf/run.sh') return new Response('echo hi')
      return new Response('nope', { status: 404 })
    })
    const p = parseGitHubUrl('https://github.com/o/r/blob/main/skills/pdf/SKILL.md')
    if (!p.ok) throw new Error(p.error)
    const r = await fetchGitHub(p.target, { fetchImpl: f })
    expect(r.files.map((x) => x.path)).toEqual(['skills/pdf/bin/x.exe', 'skills/pdf/run.sh', 'skills/pdf/SKILL.md'])
    expect(r.files.find((x) => x.path.endsWith('.exe'))?.content).toBeUndefined()
    expect(r.symlinks).toEqual(['skills/pdf/link'])
    expect(r.warnings.join(' ')).toMatch(/non-text/)
    expect(calls.some((c) => c.url.includes('logo.png'))).toBe(false)
    expect(calls.every((c) => c.init?.credentials === 'omit')).toBe(true)
  })

  it('uses the blobs API with the token (never sent to raw.githubusercontent.com)', async () => {
    const { f, calls } = mockFetch((url) => {
      if (url.startsWith('https://api.github.com/repos/o/r/git/trees/main')) return json({ truncated: true, tree: TREE.tree.slice(0, 2) })
      if (url.endsWith('/git/blobs/s1')) return json({ encoding: 'base64', content: btoa('# Skill') })
      if (url.endsWith('/git/blobs/s2')) return json({ encoding: 'base64', content: btoa('echo hi') })
      return new Response('', { status: 404 })
    })
    const p = parseGitHubUrl('https://github.com/o/r/tree/main/skills/pdf')
    if (!p.ok) throw new Error(p.error)
    const r = await fetchGitHub(p.target, { fetchImpl: f, token: 'tkn' })
    expect(r.files).toHaveLength(2)
    expect(r.warnings.join(' ')).toMatch(/truncated/)
    expect(calls.every((c) => c.url.startsWith('https://api.github.com/'))).toBe(true)
    const headers = calls[0].init?.headers as Record<string, string> | undefined
    expect(headers?.Authorization).toBe('Bearer tkn')
  })

  it('tries longer refs when the first candidate does not exist', async () => {
    const { f } = mockFetch((url) => {
      if (url.includes('/git/trees/feature%2Fx')) return json({ truncated: false, tree: [{ path: 'a/SKILL.md', mode: '100644', type: 'blob', sha: 'z', size: 3 }] })
      if (url.includes('/git/trees/')) return json({ message: 'Not Found' }, 404)
      if (url === 'https://raw.githubusercontent.com/o/r/feature/x/a/SKILL.md') return new Response('# x')
      return new Response('', { status: 404 })
    })
    const p = parseGitHubUrl('https://github.com/o/r/tree/feature/x/a')
    if (!p.ok) throw new Error(p.error)
    const r = await fetchGitHub(p.target, { fetchImpl: f })
    expect(r.ref).toBe('feature/x')
    expect(r.files[0].content).toBe('# x')
  })

  it('reports rate limits clearly', async () => {
    const { f } = mockFetch(() => json({ message: 'API rate limit exceeded' }, 403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1700000000' }))
    const p = parseGitHubUrl('https://github.com/o/r')
    if (!p.ok) throw new Error(p.error)
    await expect(fetchGitHub(p.target, { fetchImpl: f })).rejects.toThrow(/rate limit/)
  })

  it('reports missing / private repositories', async () => {
    const { f } = mockFetch(() => json({ message: 'Not Found' }, 404))
    const p = parseGitHubUrl('https://github.com/o/private')
    if (!p.ok) throw new Error(p.error)
    await expect(fetchGitHub(p.target, { fetchImpl: f })).rejects.toThrow(GitHubError)
  })

  it('enforces the file cap', async () => {
    const tree = { truncated: false, tree: Array.from({ length: 10 }, (_, i) => ({ path: `f${i}.md`, mode: '100644', type: 'blob', sha: `s${i}`, size: 1 })) }
    const { f } = mockFetch((url) => (url.includes('/git/trees/') ? json(tree) : new Response('x')))
    const p = parseGitHubUrl('https://github.com/o/r/tree/main')
    if (!p.ok) throw new Error(p.error)
    const r = await fetchGitHub(p.target, { fetchImpl: f, limits: { maxFiles: 3, maxFileBytes: 1000, maxTotalBytes: 1e6, concurrency: 2 } })
    expect(r.files).toHaveLength(3)
    expect(r.warnings.join(' ')).toMatch(/only the first 3/)
  })
})
