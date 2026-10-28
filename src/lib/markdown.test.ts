import { describe, expect, it } from 'vitest'
import { mdCell, mdTable } from './markdown'

describe('markdown', () => {
  it('escapes pipes, backslashes and newlines in cells', () => {
    expect(mdCell('a|b\\c\nd')).toBe('a\\|b\\\\c<br>d')
  })

  it('builds a table', () => {
    expect(mdTable(['A', 'B'], [['1', '2']])).toBe('| A | B |\n| --- | --- |\n| 1 | 2 |')
  })
})
