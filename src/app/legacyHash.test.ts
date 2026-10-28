import { describe, expect, it } from 'vitest'
import { legacyHashTarget } from './legacyHash'

const BASE = '/security-toolkit/'

describe('legacyHashTarget', () => {
  it('maps hash routes to path routes, keeping the query', () => {
    expect(legacyHashTarget('#/pki?tab=csr', BASE)).toBe('/security-toolkit/pki?tab=csr')
    expect(legacyHashTarget('#/data-lab?recipe=abc', BASE)).toBe('/security-toolkit/data-lab?recipe=abc')
    expect(legacyHashTarget('#/', BASE)).toBe('/security-toolkit/')
  })

  it('ignores non-route fragments', () => {
    expect(legacyHashTarget('', BASE)).toBeNull()
    expect(legacyHashTarget('#section', BASE)).toBeNull()
  })

  it('never produces an off-site URL', () => {
    expect(legacyHashTarget('#//evil.example/x', BASE)).toBe(BASE)
    expect(legacyHashTarget('#/\\evil.example', BASE)).toBe(BASE)
    expect(legacyHashTarget('#/javascript:alert(1)', BASE)).toBe(BASE)
  })
})
