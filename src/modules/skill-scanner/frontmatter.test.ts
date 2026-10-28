import { describe, expect, it } from 'vitest'
import { fmString, parseFrontmatter, splitToolList } from './frontmatter'

describe('parseFrontmatter', () => {
  it('returns undefined without frontmatter', () => {
    expect(parseFrontmatter('# Title')).toBeUndefined()
    expect(parseFrontmatter('---\nname: x\nno closing')).toBeUndefined()
  })

  it('parses plain, quoted and commented scalars with line numbers', () => {
    const fm = parseFrontmatter(`---\nname: pdf-tools # comment\ndescription: "Say \\"hi\\"\\n"\nlicense: 'It''s MIT'\n---\nbody`)!
    expect(fm.data.name).toBe('pdf-tools')
    expect(fm.data.description).toBe('Say "hi"\n')
    expect(fm.data.license).toBe("It's MIT")
    expect(fm.lines).toEqual({ name: 2, description: 3, license: 4 })
    expect(fm.endLine).toBe(5)
  })

  it('accepts a BOM and a "..." terminator', () => {
    const fm = parseFrontmatter('\uFEFF---\nname: x\n...\n')!
    expect(fm.data.name).toBe('x')
  })

  it('parses literal and folded block scalars', () => {
    const fm = parseFrontmatter('---\nlit: |\n  line one\n  line two\nfold: >-\n  a\n  b\n\n  c\nnext: z\n---\n')!
    expect(fm.data.lit).toBe('line one\nline two')
    expect(fm.data.fold).toBe('a b\n\nc')
    expect(fm.data.next).toBe('z')
  })

  it('parses block lists, flow lists and nested maps', () => {
    const fm = parseFrontmatter('---\nallowed-tools:\n  - Read\n  - "Bash(git add *)"\npaths: [src/**, "docs/*.md"]\nmetadata:\n  author: me\n  version: "1.0"\n---\n')!
    expect(fm.data['allowed-tools']).toEqual(['Read', 'Bash(git add *)'])
    expect(fm.data.paths).toEqual(['src/**', 'docs/*.md'])
    expect(fm.data.metadata).toEqual({ author: 'me', version: '1.0' })
  })

  it('joins plain multi-line scalars', () => {
    const fm = parseFrontmatter('---\ndescription: first part\n  second part\n---\n')!
    expect(fm.data.description).toBe('first part second part')
  })

  it('records errors but keeps parsing', () => {
    const fm = parseFrontmatter('---\n!!weird\nname: ok\n---\n')!
    expect(fm.errors.length).toBe(1)
    expect(fm.data.name).toBe('ok')
  })

  it('fmString flattens values', () => {
    expect(fmString(['a', 'b'])).toBe('a b')
    expect(fmString({ k: 'v' })).toBe('k: v')
    expect(fmString(undefined)).toBeUndefined()
  })
})

describe('splitToolList', () => {
  it('splits on spaces/commas outside parentheses', () => {
    expect(splitToolList('Read, Bash(git add *) Bash(git commit *)')).toEqual(['Read', 'Bash(git add *)', 'Bash(git commit *)'])
    expect(splitToolList(['Read', 'Bash(npm run test *)'])).toEqual(['Read', 'Bash(npm run test *)'])
    expect(splitToolList(undefined)).toEqual([])
  })
})

describe('frontmatter prototype safety (regression)', () => {
  it('a "__proto__" key cannot inject inherited name/description', () => {
    const fm = parseFrontmatter('---\n__proto__:\n  name: injected\n  description: injected\n---\n')!
    expect(fm.data.name).toBeUndefined()
    expect(fm.data.description).toBeUndefined()
    expect(Object.getPrototypeOf(fm.data)).toBeNull()
    expect(({} as Record<string, unknown>).name).toBeUndefined()
  })
})
