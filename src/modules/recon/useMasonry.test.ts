import { describe, expect, it } from 'vitest'
import { MASONRY_ROW, masonrySpan } from './useMasonry'

describe('masonrySpan', () => {
  it('covers the tile height plus the gap, rounded up to whole rows', () => {
    expect(masonrySpan(100, 12)).toBe(Math.ceil(112 / MASONRY_ROW))
    expect(masonrySpan(101, 12, 4)).toBe(29)
    expect(masonrySpan(88, 12, 4)).toBe(25)
  })

  it('never returns less than one row, even for unmeasured or hidden tiles', () => {
    expect(masonrySpan(0, 12)).toBe(1)
    expect(masonrySpan(Number.NaN, 12)).toBe(1)
    expect(masonrySpan(-5, 12)).toBe(1)
  })
})
