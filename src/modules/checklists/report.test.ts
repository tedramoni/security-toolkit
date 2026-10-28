import { describe, expect, it } from 'vitest'
import { escapeHtmlText, mdInline, reviewToMarkdown, safeHttpUrl } from './report'
import { fixture, makeReview } from './testFixture'

describe('escaping helpers', () => {
  it('escapes HTML special characters', () => {
    expect(escapeHtmlText('<img src=x onerror=alert(1)> & co')).toBe('&lt;img src=x onerror=alert(1)&gt; &amp; co')
  })

  it('escapes markdown syntax and flattens newlines in inline text', () => {
    expect(mdInline('**bold** _x_ [l](u) `c` a|b\\')).toBe('\\*\\*bold\\*\\* \\_x\\_ \\[l\\](u) \\`c\\` a\\|b\\\\')
    expect(mdInline('line1\n  line2\r\nline3')).toBe('line1 line2 line3')
    expect(mdInline('PR #123')).toBe('PR #123')
  })

  it('accepts only http(s) URLs', () => {
    expect(safeHttpUrl('https://github.com/o/r/pull/1')).toBe('https://github.com/o/r/pull/1')
    expect(safeHttpUrl(' http://x.test/a b ')).toBe('http://x.test/a%20b')
    expect(safeHttpUrl('javascript:alert(1)')).toBeNull()
    expect(safeHttpUrl('data:text/html,hi')).toBeNull()
    expect(safeHttpUrl('not a url')).toBeNull()
    expect(safeHttpUrl('')).toBeNull()
  })
})

describe('reviewToMarkdown', () => {
  const review = makeReview({
    name: 'PR #123 — payment API',
    link: 'https://github.com/o/r/pull/123',
    results: {
      i1: { status: 'fail', note: 'No check on DELETE | see handler\nline 2' },
      i2: { status: 'na', note: 'no browser clients' },
      i3: { status: 'pass', note: '' },
      i4: { status: 'pass', note: 'pinned in #456' },
      removed: { status: 'fail', note: 'item no longer exists' },
    },
  })

  const md = reviewToMarkdown(review, fixture)

  it('includes title, link, checklist and progress', () => {
    expect(md).toContain('## Security review: PR #123 — payment API')
    expect(md).toContain('**Link:** <https://github.com/o/r/pull/123>')
    expect(md).toContain('**Checklist:** [Fixture](https://example.com/fx)')
    expect(md).toContain('**Progress:** 4/4 reviewed (100%) — **1 failed** · 2 passed · 1 N/A · 0 not reviewed')
  })

  it('lists failures first in a table with escaped notes and refs', () => {
    expect(md).toContain('| Category | Item | Note | Refs |')
    expect(md).toContain('| Access control | Check authorization on endpoints | No check on DELETE \\| see handler<br>line 2 | CWE-862 |')
    expect(md.indexOf('### Failed')).toBeLessThan(md.indexOf('### Not applicable'))
    expect(md.indexOf('### Not applicable')).toBeLessThan(md.indexOf('<details>'))
  })

  it('lists N/A items with notes and collapses passed items', () => {
    expect(md).toContain('- CORS allow-list — _no browser clients_')
    expect(md).toContain('<summary>Passed (2)</summary>')
    expect(md).toContain('- Pin actions to SHA — _pinned in #456_')
    expect(md.trim().endsWith('</sub>')).toBe(true)
  })

  it('ignores results for unknown items', () => {
    expect(md).not.toContain('item no longer exists')
  })

  it('can omit passed items', () => {
    expect(reviewToMarkdown(review, fixture, { includePassed: false })).not.toContain('<details>')
  })

  it('neutralises HTML and markdown injection in user text', () => {
    const evil = makeReview({
      name: '</details><script>alert(1)</script>',
      link: 'javascript:alert(1)',
      results: {
        i1: { status: 'fail', note: '<img src=x onerror=alert(1)>' },
        i2: { status: 'na', note: '</details>\n## fake heading' },
      },
    })
    const out = reviewToMarkdown(evil, fixture)
    expect(out).not.toContain('<script>')
    expect(out).not.toContain('<img')
    // Non-http links are shown as inert text, never as a link target.
    expect(out).toContain('**Ref:** javascript:alert(1)')
    expect(out).not.toMatch(/\]\(javascript:|<javascript:/)
    expect(out.match(/<\/details>/g)).toBeNull()
    expect(out).not.toMatch(/^## fake heading/m)
  })

  it('reports empty states and stack scope', () => {
    const out = reviewToMarkdown(makeReview({ stacks: ['infra'] }), fixture)
    expect(out).toContain('**Scope:** Infra / CI')
    expect(out).toContain('**Progress:** 0/3 reviewed (0%) — 0 failed')
    expect(out).toContain('_No failed items._')
    expect(out).not.toContain('<details>')
    expect(out).not.toContain('**Link:**')
  })
})
