import { useLayoutEffect, type RefObject } from 'react'

/** Grid row unit in px; tile heights are rounded up to a multiple of this. */
export const MASONRY_ROW = 4

/** Rows a tile of `height` px must span so the next tile starts `gap` px below it. */
export function masonrySpan(height: number, gap: number, row = MASONRY_ROW): number {
  if (!(height > 0)) return 1
  return Math.max(1, Math.ceil((height + gap) / row))
}

/**
 * Masonry packing for a CSS grid: the grid uses tiny auto rows (see .recon-masonry) and each direct child
 * spans as many rows as its measured height, so tiles of different heights pack without vertical gaps.
 * Re-measures when a tile resizes (expand toggles, data arriving, column width changes) and when tiles are
 * added or removed. Until the first measurement the grid keeps its normal layout, so nothing overlaps.
 */
export function useMasonry(ref: RefObject<HTMLElement | null>, gap: number) {
  useLayoutEffect(() => {
    const grid = ref.current
    if (!grid || typeof ResizeObserver === 'undefined') return

    const layout = (el: Element) => {
      if (!(el instanceof HTMLElement)) return
      el.style.gridRowEnd = `span ${masonrySpan(el.getBoundingClientRect().height, gap)}`
    }
    const resize = new ResizeObserver((entries) => {
      for (const e of entries) layout(e.target)
    })
    const watch = (el: Element) => {
      layout(el)
      resize.observe(el)
    }

    Array.from(grid.children).forEach(watch)
    grid.classList.add('recon-masonry')

    const mutations = new MutationObserver((records) => {
      for (const r of records) {
        r.addedNodes.forEach((n) => n instanceof Element && n.parentElement === grid && watch(n))
        r.removedNodes.forEach((n) => n instanceof Element && resize.unobserve(n))
      }
    })
    mutations.observe(grid, { childList: true })

    return () => {
      mutations.disconnect()
      resize.disconnect()
      grid.classList.remove('recon-masonry')
      for (const el of Array.from(grid.children)) if (el instanceof HTMLElement) el.style.gridRowEnd = ''
    }
  }, [ref, gap])
}

/** Grid gap between tiles in px; must match the .recon-grid gap in recon.css. */
export const MASONRY_GAP = 12

