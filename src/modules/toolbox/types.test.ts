import { describe, expect, it } from 'vitest'
import { mdText } from './types'

describe('mdText', () => {
  it('neutralises HTML and code spans, including a pasted backslash before a backtick', () => {
    expect(mdText('<img src=x onerror=alert(1)>')).toBe('&lt;img src=x onerror=alert(1)&gt;')
    expect(mdText('\\`code`')).toBe('\\&#96;code&#96;')
    expect(mdText('a & b')).toBe('a &amp; b')
  })
})
