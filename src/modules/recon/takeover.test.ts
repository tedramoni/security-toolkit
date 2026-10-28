import { describe, expect, it } from 'vitest'
import { resolveHosts, resolvedFindings } from './subdomains'
import { assessTakeover, findTakeoverService } from './takeover'
import { fakeResolver } from './test-helpers'

describe('takeover heuristics', () => {
  it('recognises services from the CNAME target', () => {
    expect(findTakeoverService('myapp.azurewebsites.net')?.service).toBe('Microsoft Azure')
    expect(findTakeoverService('bucket.s3.eu-west-1.amazonaws.com')?.service).toBe('AWS S3')
    expect(findTakeoverService('bucket.s3-website-us-east-1.amazonaws.com')?.service).toBe('AWS S3')
    expect(findTakeoverService('org.github.io')?.status).toBe('edge-case')
    expect(findTakeoverService('d111.cloudfront.net')).toBeUndefined() // "not vulnerable" upstream
    expect(findTakeoverService('notazurewebsites.net')).toBeUndefined()
    expect(findTakeoverService('my-elb.eu-west-1.elb.amazonaws.com')).toBeUndefined()
  })

  it('grades dangling CNAMEs', () => {
    expect(assessTakeover(['app.azurewebsites.net'], 3, false)).toMatchObject({ verdict: 'possible-takeover', severity: 'high', service: 'Microsoft Azure' })
    expect(assessTakeover(['b.s3.amazonaws.com'], 3, false)).toMatchObject({ verdict: 'possible-takeover', severity: 'medium' })
    expect(assessTakeover(['org.github.io'], 3, false)).toMatchObject({ verdict: 'possible-takeover', severity: 'low' })
    expect(assessTakeover(['old.vendor.example'], 3, false)).toMatchObject({ verdict: 'dangling-cname' })
    expect(assessTakeover(['app.azurewebsites.net'], 0, true)).toMatchObject({ verdict: 'review', severity: 'info' })
    expect(assessTakeover([], 3, false).verdict).toBe('none')
    expect(assessTakeover(['x.cloudfront.net'], 0, true).verdict).toBe('none')
  })
})

describe('resolveHosts', () => {
  it('resolves with bounded concurrency and a cap', async () => {
    let inFlight = 0
    let max = 0
    const base = fakeResolver({})
    const resolve = async (n: string, t: string) => {
      inFlight++
      max = Math.max(max, inFlight)
      await new Promise((r) => setTimeout(r, 1))
      inFlight--
      return base(n, t)
    }
    const hosts = Array.from({ length: 50 }, (_, i) => `h${i}.example.com`)
    const progress: number[] = []
    const rows = await resolveHosts(hosts, resolve, { concurrency: 4, cap: 20, onProgress: (d) => progress.push(d) })
    expect(rows).toHaveLength(20)
    expect(max).toBeLessThanOrEqual(4)
    expect(progress.at(-1)).toBe(20)
  })

  it('finds a dangling Azure CNAME', async () => {
    const resolve = fakeResolver({
      'old.example.com|A': { status: 3, cnames: ['old-app.azurewebsites.net'] },
      'www.example.com|A': { data: ['1.2.3.4'] },
      'v6.example.com|A': { data: [] },
      'v6.example.com|AAAA': ['2001:4860::1'],
    })
    const rows = await resolveHosts(['old.example.com', 'www.example.com', 'v6.example.com', 'gone.example.com'], resolve)
    expect(rows.map((r) => r.takeover.verdict)).toEqual(['possible-takeover', 'none', 'none', 'none'])
    expect(rows[2].addresses).toEqual(['2001:4860::1'])
    const f = resolvedFindings(rows)
    expect(f[0]).toMatchObject({ severity: 'high', title: 'Possible subdomain takeover — verify manually: old.example.com' })
    expect(f.some((x) => /no longer resolve/.test(x.title))).toBe(true)
  })
})
