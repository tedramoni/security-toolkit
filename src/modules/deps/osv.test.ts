import { describe, expect, it, vi } from 'vitest'
import type { FetchLike } from './osv.ts'
import { MAX_BATCH, chunk, fetchVulns, getVuln, isAbortError, queryBatch } from './osv.ts'
import type { Dependency } from './types.ts'
import { depKey } from './types.ts'

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })

const dep = (name: string, version = '1.0.0'): Dependency => ({ name, version, ecosystem: 'npm' })

interface Call {
  url: string
  body?: { queries: { package: { name: string }; version: string; page_token?: string }[] }
}

function recorder(handler: (call: Call, n: number) => Response | Promise<Response>) {
  const calls: Call[] = []
  const fetch: FetchLike = vi.fn(async (url: string, init?: RequestInit) => {
    const call: Call = { url, body: init?.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(call)
    return handler(call, calls.length)
  })
  return { fetch, calls }
}

describe('queryBatch', () => {
  it('sends package/version queries and maps results back in order', async () => {
    const { fetch, calls } = recorder(() =>
      json({ results: [{ vulns: [{ id: 'GHSA-1', modified: 'x' }] }, {}] }),
    )
    const r = await queryBatch([dep('a'), dep('b', '2.0.0')], { fetch, backoffMs: 0 })
    expect(calls[0].url).toBe('https://api.osv.dev/v1/querybatch')
    expect(calls[0].body).toEqual({
      queries: [
        { package: { name: 'a', ecosystem: 'npm' }, version: '1.0.0' },
        { package: { name: 'b', ecosystem: 'npm' }, version: '2.0.0' },
      ],
    })
    expect(r.idsByDep.get(depKey(dep('a')))).toEqual(['GHSA-1'])
    expect(r.idsByDep.get(depKey(dep('b', '2.0.0')))).toEqual([])
    expect(r.failed).toEqual([])
  })

  it('follows next_page_token only for the queries that have one', async () => {
    const { fetch, calls } = recorder((_c, n) =>
      n === 1
        ? json({ results: [{ vulns: [{ id: 'V1' }], next_page_token: 'tok-a' }, { vulns: [{ id: 'V9' }] }] })
        : json({ results: [{ vulns: [{ id: 'V2' }, { id: 'V1' }] }] }),
    )
    const r = await queryBatch([dep('a'), dep('b')], { fetch, backoffMs: 0 })
    expect(calls).toHaveLength(2)
    expect(calls[1].body?.queries).toEqual([{ package: { name: 'a', ecosystem: 'npm' }, version: '1.0.0', page_token: 'tok-a' }])
    expect(r.idsByDep.get(depKey(dep('a')))).toEqual(['V1', 'V2'])
    expect(r.idsByDep.get(depKey(dep('b')))).toEqual(['V9'])
  })

  it('reports packages whose later result pages failed as incomplete, keeping the ids already found', async () => {
    const { fetch } = recorder((_c, n) =>
      n === 1 ? json({ results: [{ vulns: [{ id: 'V1' }], next_page_token: 'tok-a' }, { vulns: [] }] }) : json({}, 400),
    )
    const r = await queryBatch([dep('a'), dep('b')], { fetch, backoffMs: 0, retries: 0 })
    expect(r.idsByDep.get(depKey(dep('a')))).toEqual(['V1'])
    expect(r.failed).toEqual([{ dep: dep('a'), error: expect.stringMatching(/HTTP 400.*incomplete/) }])
  })

  it(`chunks into batches of at most ${MAX_BATCH} and reports progress`, async () => {
    const deps = Array.from({ length: 2500 }, (_, i) => dep(`p${i}`))
    const { fetch, calls } = recorder((c) => json({ results: c.body!.queries.map(() => ({})) }))
    const progress: number[] = []
    await queryBatch(deps, { fetch, backoffMs: 0, onProgress: (d) => progress.push(d) })
    expect(calls.map((c) => c.body!.queries.length)).toEqual([1000, 1000, 500])
    expect(progress).toEqual([1000, 2000, 2500])
  })

  it('retries on 429 and 5xx, then succeeds', async () => {
    const { fetch, calls } = recorder((_c, n) =>
      n === 1 ? json({}, 429) : n === 2 ? json({}, 503) : json({ results: [{ vulns: [{ id: 'X' }] }] }),
    )
    const r = await queryBatch([dep('a')], { fetch, backoffMs: 0 })
    expect(calls).toHaveLength(3)
    expect(r.idsByDep.get(depKey(dep('a')))).toEqual(['X'])
  })

  it('retries network errors', async () => {
    let n = 0
    const fetch: FetchLike = async () => {
      if (++n === 1) throw new TypeError('Failed to fetch')
      return json({ results: [{}] })
    }
    const r = await queryBatch([dep('a')], { fetch, backoffMs: 0 })
    expect(r.failed).toEqual([])
  })

  it('does not retry 4xx client errors and reports the chunk as failed', async () => {
    const { fetch, calls } = recorder(() => json({ message: 'bad' }, 400))
    const r = await queryBatch([dep('a'), dep('b')], { fetch, backoffMs: 0 })
    expect(calls).toHaveLength(1)
    expect(r.failed.map((f) => f.dep.name)).toEqual(['a', 'b'])
    expect(r.failed[0].error).toMatch(/HTTP 400/)
  })

  it('gives up after the retry budget and keeps results of other chunks (partial results)', async () => {
    const deps = Array.from({ length: 1001 }, (_, i) => dep(`p${i}`))
    const { fetch } = recorder((c) => (c.body!.queries.length === 1000 ? json({ results: c.body!.queries.map(() => ({})) }) : json({}, 429)))
    const r = await queryBatch(deps, { fetch, backoffMs: 0, retries: 2 })
    expect(r.failed).toHaveLength(1)
    expect(r.failed[0].error).toMatch(/rate limit/)
    expect(r.idsByDep.size).toBe(1000)
  })

  it('rejects a response with the wrong number of results', async () => {
    const { fetch } = recorder(() => json({ results: [] }))
    const r = await queryBatch([dep('a')], { fetch, backoffMs: 0 })
    expect(r.failed[0].error).toMatch(/0 results for 1 queries/)
  })

  it('propagates aborts as AbortError', async () => {
    const ctrl = new AbortController()
    ctrl.abort()
    const { fetch } = recorder(() => json({ results: [{}] }))
    await expect(queryBatch([dep('a')], { fetch, signal: ctrl.signal })).rejects.toSatisfy(isAbortError)
  })

  it('passes the abort signal to fetch', async () => {
    const ctrl = new AbortController()
    const fetch: FetchLike = vi.fn(async (_u: string, init?: RequestInit) => {
      expect(init?.signal).toBe(ctrl.signal)
      return json({ results: [{}] })
    })
    await queryBatch([dep('a')], { fetch, signal: ctrl.signal })
    expect(fetch).toHaveBeenCalledOnce()
  })
})

describe('getVuln / fetchVulns', () => {
  it('fetches by id with URL encoding', async () => {
    const { fetch, calls } = recorder(() => json({ id: 'GHSA-x' }))
    await getVuln('GHSA-x/../y', { fetch })
    expect(calls[0].url).toBe('https://api.osv.dev/v1/vulns/GHSA-x%2F..%2Fy')
  })

  it('fetches unique ids with bounded concurrency and collects errors', async () => {
    let inFlight = 0
    let maxInFlight = 0
    const fetch: FetchLike = async (url: string) => {
      inFlight++
      maxInFlight = Math.max(maxInFlight, inFlight)
      await new Promise((r) => setTimeout(r, 2))
      inFlight--
      const id = decodeURIComponent(url.split('/').pop()!)
      return id === 'BAD' ? json({ message: 'not found' }, 404) : json({ id })
    }
    const ids = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'A', 'BAD']
    const progress: number[] = []
    const r = await fetchVulns(ids, { fetch, concurrency: 3, backoffMs: 0, onProgress: (d) => progress.push(d) })
    expect(maxInFlight).toBeLessThanOrEqual(3)
    expect(r.vulns.size).toBe(8)
    expect(r.errors).toEqual([{ id: 'BAD', error: 'OSV.dev returned HTTP 404' }])
    expect(progress.at(-1)).toBe(9)
  })

  it('handles an empty id list', async () => {
    const r = await fetchVulns([], { fetch: async () => json({}) })
    expect(r.vulns.size).toBe(0)
  })

  it('aborts', async () => {
    const ctrl = new AbortController()
    const fetch: FetchLike = async () => {
      ctrl.abort()
      throw new DOMException('aborted', 'AbortError')
    }
    await expect(fetchVulns(['A'], { fetch, signal: ctrl.signal })).rejects.toSatisfy(isAbortError)
  })
})

describe('chunk', () => {
  it('splits arrays', () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]])
    expect(chunk([], 3)).toEqual([])
  })
})
