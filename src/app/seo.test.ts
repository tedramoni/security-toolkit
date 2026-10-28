import { describe, expect, it } from 'vitest'
import { MODULES } from './modules'
import { ALL_SEO, MAX_TITLE, PAGE_SEO, canonicalUrl, fullTitle, seoForPath } from './seo'
import { headTags, staticBody } from './seoHtml'

describe('SEO metadata', () => {
  it('covers exactly the registered modules', () => {
    expect(PAGE_SEO.map((p) => `/${p.path}`).sort()).toEqual(MODULES.map((m) => m.path).sort())
  })

  it('uses the same sidebar label and icon as the app, so the static page matches the app layout', () => {
    for (const m of MODULES) {
      const page = PAGE_SEO.find((p) => `/${p.path}` === m.path)!
      expect([page.icon, page.heading]).toEqual([m.icon, m.title])
    }
  })

  it('has unique titles and descriptions within search-result limits', () => {
    expect(new Set(ALL_SEO.map(fullTitle)).size).toBe(ALL_SEO.length)
    expect(new Set(ALL_SEO.map((p) => p.description)).size).toBe(ALL_SEO.length)
    for (const p of ALL_SEO) {
      expect(fullTitle(p).length, p.title).toBeLessThanOrEqual(MAX_TITLE)
      expect(p.description.length, p.path).toBeGreaterThanOrEqual(100)
      expect(p.description.length, p.path).toBeLessThanOrEqual(165)
    }
  })

  it('resolves pages from nested paths', () => {
    expect(seoForPath('/checklists/review/abc').path).toBe('checklists')
    expect(seoForPath('/').path).toBe('')
    expect(seoForPath('/unknown').path).toBe('')
    expect(canonicalUrl(seoForPath('/pki'))).toBe('https://tedramoni.github.io/security-toolkit/pki/')
  })

  it('escapes HTML and keeps JSON-LD from closing its script tag', () => {
    const page = { ...PAGE_SEO[0], title: 'A <b>"x"</b>', description: 'd </script><script>alert(1)</script>', features: ['</script>'] }
    const head = headTags(page)
    expect(head).not.toContain('<b>')
    expect(head.match(/<\/script>/g)?.length).toBe(head.match(/<script/g)?.length)
    expect(staticBody(page, '/b/')).not.toContain('<script')
  })

  it('marks the fallback page noindex without a canonical', () => {
    const head = headTags(ALL_SEO[0], { indexable: false })
    expect(head).toContain('noindex')
    expect(head).not.toContain('canonical')
  })
})
