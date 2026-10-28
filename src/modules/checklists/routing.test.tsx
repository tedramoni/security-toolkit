import { act, useEffect } from 'react'
import { createRoot } from 'react-dom/client'
import type { Root } from 'react-dom/client'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import ChecklistsModule from './index'

// Tell React this is a test environment that supports act().
;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

let container: HTMLDivElement
let root: Root
const seen = { path: '' }

function LocationProbe() {
  const { pathname } = useLocation()
  useEffect(() => {
    seen.path = pathname
  }, [pathname])
  return null
}

function render(path: string) {
  act(() => {
    root.render(
      <MemoryRouter initialEntries={[path]}>
        <LocationProbe />
        <Routes>
          <Route path="/checklists/*" element={<ChecklistsModule />} />
        </Routes>
      </MemoryRouter>,
    )
  })
}

beforeEach(() => {
  localStorage.clear()
  container = document.createElement('div')
  document.body.appendChild(container)
  root = createRoot(container)
})

afterEach(() => {
  act(() => root.unmount())
  container.remove()
})

describe('checklists module routing', () => {
  it('renders the home page at the module root', () => {
    render('/checklists')
    expect(container.querySelector('h1')?.textContent).toBe('Review Checklists')
    expect(seen.path).toBe('/checklists')
  })

  it('redirects unknown sub-paths to the module root so relative links keep working', () => {
    render('/checklists/some/unknown/path')
    expect(seen.path).toBe('/checklists')
    expect(container.querySelector('h1')?.textContent).toBe('Review Checklists')
  })

  it('shows a not-found page with a working back link for an unknown review id', () => {
    render('/checklists/review/does-not-exist')
    expect(container.querySelector('h1')?.textContent).toBe('Review not found')
    const back = container.querySelector('a')
    expect(back?.getAttribute('href')).toBe('/checklists')
  })

  it('category headings are real headings wrapping the toggle button (not headings inside buttons)', () => {
    localStorage.setItem(
      'scp:reviews',
      JSON.stringify([
        {
          schemaVersion: 1,
          id: 'r1',
          name: 'R',
          link: '',
          checklistId: 'pr-quick',
          checklistVersion: '1.0',
          stacks: [],
          results: {},
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
        },
      ]),
    )
    render('/checklists/review/r1')
    expect(container.querySelector('button h2, button h3')).toBeNull()
    const toggle = container.querySelector('h2 > button[aria-expanded]')
    expect(toggle).not.toBeNull()
  })
})
