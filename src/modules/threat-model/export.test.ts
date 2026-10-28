import { describe, expect, it } from 'vitest'
import { exampleModel } from './example.ts'
import { flowAttributes, mdCellSafe, mdInline, mermaidEscape, summarize, textualDfd, toMarkdown, toMermaid } from './export.ts'
import type { Threat, ThreatModel } from './model.ts'
import { createFlow, createModel, createNode } from './model.ts'
import { refreshThreats } from './stride.ts'

const NOW = '2026-03-04T10:00:00.000Z'
let n = 0
const ids = () => `t${++n}`

const threat = (over: Partial<Threat>): Threat => ({
  id: ids(),
  elementId: 'a',
  category: 'S',
  title: 'T',
  description: '',
  likelihood: 1,
  impact: 1,
  status: 'open',
  mitigation: '',
  generated: false,
  ...over,
})

function small(): ThreatModel {
  const m = createModel('m', 'Shop', NOW)
  m.elements = [createNode('a', 'external', 'User'), createNode('b', 'process', 'API'), createNode('c', 'datastore', 'DB')]
  m.elements.push(createFlow('f1', 'a', 'b', { protocol: 'HTTPS', dataClassification: 'confidential', crossesTrustBoundary: true }))
  m.elements.push(createFlow('f2', 'b', 'c', { protocol: '', name: 'queries' }))
  return m
}

describe('summarize', () => {
  it('counts by category, risk and status, excluding stale', () => {
    const m = small()
    m.threats = [
      threat({ category: 'S', likelihood: 3, impact: 3 }), // critical open
      threat({ category: 'T', likelihood: 2, impact: 3, status: 'mitigated' }), // high closed
      threat({ category: 'T', likelihood: 3, impact: 2 }), // high open
      threat({ category: 'I', likelihood: 1, impact: 1, status: 'accepted' }),
      threat({ category: 'D', likelihood: 3, impact: 3, stale: true, generated: true, ruleId: 'X' }),
    ]
    const s = summarize(m)
    expect(s.total).toBe(4)
    expect(s.stale).toBe(1)
    expect(s.open).toBe(2)
    expect(s.addressed).toBe(2)
    expect(s.byCategory.T).toEqual({ total: 2, open: 1 })
    expect(s.byCategory.D).toEqual({ total: 0, open: 0 })
    expect(s.byRisk.critical).toEqual({ total: 1, open: 1 })
    expect(s.byRisk.high).toEqual({ total: 2, open: 1 })
    expect(s.byStatus).toMatchObject({ open: 2, mitigated: 1, accepted: 1, transferred: 0 })
    expect(s.openHighCritical.map((t) => t.likelihood * t.impact)).toEqual([9, 6])
  })

  it('handles an empty model', () => {
    const s = summarize(createModel('x', 'x', NOW))
    expect(s.total).toBe(0)
    expect(s.openHighCritical).toEqual([])
  })
})

describe('textual DFD', () => {
  it('renders one line per flow with attributes', () => {
    expect(textualDfd(small())).toEqual([
      'User —[HTTPS, confidential, crosses trust boundary]→ API',
      'API —[protocol?, internal]→ DB (queries)',
    ])
  })

  it('flowAttributes omits boundary when not crossing', () => {
    expect(flowAttributes(createFlow('f', 'a', 'b', { protocol: 'gRPC', dataClassification: 'secret' }))).toBe('gRPC, secret')
  })

  it('shows ? for dangling endpoints', () => {
    const m = small()
    m.elements.push(createFlow('f3', 'ghost', 'b', { protocol: 'HTTP' }))
    expect(textualDfd(m)[2]).toBe('? —[HTTP, internal]→ API')
  })
})

describe('mermaidEscape', () => {
  it('leaves plain text alone', () => {
    expect(mermaidEscape('Orders API v2')).toBe('Orders API v2')
  })

  it('encodes characters that would break Mermaid syntax', () => {
    expect(mermaidEscape('say "hi"')).toBe('say #34;hi#34;')
    expect(mermaidEscape('a|b')).toBe('a#124;b')
    expect(mermaidEscape('[x](y){z}')).toBe('#91;x#93;#40;y#41;#123;z#125;')
    expect(mermaidEscape('<script>&')).toBe('#60;script#62;#38;')
    expect(mermaidEscape('a;b')).toBe('a#59;b')
    expect(mermaidEscape('`code`')).toBe('#96;code#96;')
    expect(mermaidEscape("it's")).toBe('it#39;s')
    expect(mermaidEscape('back\\slash')).toBe('back#92;slash')
  })

  it('escapes # exactly once (no double encoding of emitted entities)', () => {
    expect(mermaidEscape('C# & F#')).toBe('C#35; #38; F#35;')
    expect(mermaidEscape('#quot;')).toBe('#35;quot#59;')
  })

  it('collapses newlines and control characters', () => {
    expect(mermaidEscape('line1\nline2\r\n\tline3\u0000')).toBe('line1 line2 line3')
    expect(mermaidEscape('a b')).toBe('a b')
  })

  it('output never contains raw syntax characters', () => {
    const nasty = 'x"]-->y((evil))|"%%\n```\nend; click n1 "javascript:alert(1)"'
    const out = mermaidEscape(nasty)
    // once the entity codes are removed, no syntax character (nor a stray #) may remain
    expect(out.replace(/#\d+;/g, '')).not.toMatch(/["[\]()|{}<>`\n;#]/)
  })
})

describe('toMermaid', () => {
  it('uses generated ids, DFD shapes and dashed arrows for boundary crossings', () => {
    const out = toMermaid(small())
    expect(out.split('\n')).toEqual([
      'flowchart LR',
      '  n1["User"]',
      '  n2(("API"))',
      '  n3[("DB")]',
      '  n1 -.->|"HTTPS, confidential, crosses trust boundary"| n2',
      '  n2 -->|"queries: protocol?, internal"| n3',
      '  linkStyle 0 stroke:#f97316,stroke-width:2px',
    ])
  })

  it('escapes hostile names and never uses user ids', () => {
    const m = createModel('m', 'x', NOW)
    m.elements = [createNode('a"];click', 'process', 'Evil"] --> x'), createNode('b', 'datastore', 'Ok')]
    m.elements.push(createFlow('f', 'a"];click', 'b', { name: 'pipe|label', protocol: 'HTTP' }))
    const out = toMermaid(m)
    expect(out).toContain('n1(("Evil#34;#93; --#62; x"))')
    expect(out).toContain('|"pipe#124;label: HTTP, internal"|')
    expect(out).not.toContain('click')
    expect(out).not.toContain('linkStyle')
  })

  it('skips flows with missing endpoints and keeps linkStyle indexes aligned', () => {
    const m = small()
    m.elements.splice(3, 0, createFlow('bad', 'ghost', 'b', { crossesTrustBoundary: true }))
    const lines = toMermaid(m).split('\n')
    expect(lines.filter((l) => l.includes('->'))).toHaveLength(2)
    expect(lines.at(-1)).toBe('  linkStyle 0 stroke:#f97316,stroke-width:2px')
  })

  it('handles unnamed nodes', () => {
    const m = createModel('m', 'x', NOW)
    m.elements = [createNode('a', 'process', '')]
    expect(toMermaid(m)).toContain('n1(("#40;unnamed#41;"))')
  })
})

describe('mdInline', () => {
  it('escapes Markdown control characters', () => {
    expect(mdInline('*bold* _x_ `c` [l](u) <b> # | \\')).toBe('\\*bold\\* \\_x\\_ \\`c\\` \\[l\\](u) \\<b\\> \\# \\| \\\\')
    expect(mdInline('a\nb')).toBe('a b')
  })
})

describe('toMarkdown', () => {
  const m = refreshThreats(exampleModel('ex', NOW), ids).model
  const md = toMarkdown(m, NOW)

  it('contains all sections', () => {
    for (const h of ['# Threat model: Example: online shop', '## Assumptions', '## Summary', '### Open high and critical threats', '## System elements', '## Data flows', '### Diagram', '## Threats']) {
      expect(md).toContain(h)
    }
    expect(md).toContain('- **Report generated:** 2026-03-04')
  })

  it('embeds the mermaid diagram in a fenced block', () => {
    expect(md).toContain('```mermaid\nflowchart LR\n')
    expect(md.split('```').length).toBe(3) // exactly one fenced block
  })

  it('lists every element that has threats', () => {
    for (const el of m.elements.filter((e) => m.threats.some((t) => t.elementId === e.id))) {
      expect(md).toContain(`### ${mdInline(el.name || '')}`.trimEnd())
    }
  })

  it('escapes pipes and newlines from user content in tables', () => {
    const mm = small()
    mm.threats = [threat({ elementId: 'b', title: 'a|b', mitigation: 'line1\nline2', likelihood: 3, impact: 3 })]
    const out = toMarkdown(mm, NOW)
    expect(out).toContain('a\\|b')
    expect(out).toContain('line1<br>line2')
  })

  it('lists stale threats separately and excludes them from the main tables', () => {
    const mm = small()
    mm.threats = [threat({ elementId: 'b', title: 'Old one', stale: true, generated: true, ruleId: 'R' })]
    const out = toMarkdown(mm, NOW)
    expect(out).toContain('## Stale threats')
    expect(out).toContain('_No threats recorded._')
  })

  it('works for an empty model', () => {
    const out = toMarkdown(createModel('x', '', NOW), NOW)
    expect(out).toContain('# Threat model: Untitled')
    expect(out).toContain('_No elements._')
    expect(out).not.toContain('```mermaid')
  })

  it('escapes markdown in title, description and assumptions', () => {
    const mm = small()
    mm.name = '# <img src=x onerror=alert(1)>'
    mm.assumptions = ['*all* good']
    const out = toMarkdown(mm, NOW)
    expect(out).toContain('# Threat model: \\# \\<img src=x onerror=alert(1)\\>')
    expect(out).toContain('- \\*all\\* good')
  })
})

describe('review regressions: Markdown table cells', () => {
  it('mdCellSafe neutralises HTML, links and code spans with entities', () => {
    expect(mdCellSafe('<script>&[x](javascript:alert(1))`c`')).toBe('&#60;script&#62;&#38;&#91;x&#93;(javascript:alert(1))&#96;c&#96;')
  })

  it('toMarkdown never emits raw HTML from untrusted names, titles or mitigations in tables', () => {
    const m = small()
    m.elements[0] = { ...m.elements[0], name: '<img src=x onerror=alert(1)>' }
    m.threats = [threat({ elementId: 'a', title: '<b>t</b>', mitigation: '[click](javascript:alert(1))', likelihood: 3, impact: 3 })]
    const md = toMarkdown(m, NOW)
    // Inline text is backslash-escaped (\<img), table cells use entities: no unescaped tag may remain.
    expect(md).not.toMatch(/(^|[^\\])<img/)
    expect(md).not.toMatch(/(^|[^\\])<b>/)
    expect(md).not.toContain('[click]')
    expect(md).toContain('&#60;img src=x onerror=alert(1)&#62;')
  })

  it('mdInline flattens lone carriage returns too', () => {
    expect(mdInline('a\rb\r\nc\nd')).toBe('a b c d')
  })
})
