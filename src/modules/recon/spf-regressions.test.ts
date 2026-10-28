/** Regression tests for SPF lookup accounting fixed during review (RFC 7208 §4.6.4, §6.1). */
import { describe, expect, it } from 'vitest'
import { analyzeSpf, parseSpf } from './email'
import { fakeResolver } from './test-helpers'

describe('SPF lookup accounting', () => {
  it('counts redirect only when there is no "all" mechanism', () => {
    expect(parseSpf('v=spf1 include:a.example redirect=b.example').lookupTerms).toBe(2)
    expect(parseSpf('v=spf1 include:a.example -all redirect=b.example').lookupTerms).toBe(1)
    expect(parseSpf('v=spf1 redirect=b.example').lookupTerms).toBe(1)
  })

  it('ip4 / ip6 / all / exp= cost no lookup; include, a, mx, ptr, exists do', () => {
    expect(parseSpf('v=spf1 ip4:192.0.2.1 ip6:2001:db8::1 exp=explain.example -all').lookupTerms).toBe(0)
    expect(parseSpf('v=spf1 include:x.example a mx ptr exists:%{i}.x.example -all').lookupTerms).toBe(5)
  })

  it('counts a void lookup only for NXDOMAIN / empty answers, not for a TXT without SPF', async () => {
    const resolve = fakeResolver({
      'example.com|TXT': ['v=spf1 include:gone.example include:nodata.example include:other-txt.example -all'],
      'gone.example|TXT': { status: 3 },
      'nodata.example|TXT': { status: 0, data: [] },
      'other-txt.example|TXT': ['google-site-verification=abc'],
    })
    const a = await analyzeSpf('example.com', resolve)
    expect(a.voidLookups).toBe(2)
    expect(a.totalLookups).toBe(3)
    // All three are still permerror includes (no SPF record found).
    expect(a.root.children.filter((c) => c.missing)).toHaveLength(3)
  })
})
