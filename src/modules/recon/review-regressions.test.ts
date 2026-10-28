/** Regression tests for defects fixed during review (other than SPF, see spf-regressions.test.ts). */
import { describe, expect, it } from 'vitest'
import { pickSitemap } from './website'

describe('pickSitemap (privacy: never send the proxy to unrelated hosts)', () => {
  it('uses a robots.txt sitemap on the target, a parent or a sub-domain', () => {
    expect(pickSitemap(['https://www.example.com/sm.xml'], 'example.com')).toBe('https://www.example.com/sm.xml')
    expect(pickSitemap(['https://example.com/sm.xml'], 'www.example.com')).toBe('https://example.com/sm.xml')
  })
  it('ignores sitemaps on unrelated hosts, look-alikes and non-http(s) schemes', () => {
    expect(pickSitemap(['https://tracker.example.net/sm.xml', 'https://evilexample.com/x', 'ftp://example.com/sm.xml', 'not a url'], 'example.com')).toBe(
      'https://example.com/sitemap.xml',
    )
  })
})
