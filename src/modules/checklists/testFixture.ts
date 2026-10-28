import type { Checklist, Review } from './types'

/** Small checklist used by the unit tests. */
export const fixture: Checklist = {
  id: 'fx',
  title: 'Fixture',
  version: '1',
  source: 'https://example.com/fx',
  description: 'test',
  categories: [
    {
      id: 'c1',
      title: 'Access control',
      description: 'd',
      items: [
        { id: 'i1', text: 'Check authorization on endpoints', detail: 'Deny by default.', refs: ['CWE-862'] },
        { id: 'i2', text: 'CORS allow-list', detail: 'No reflected origin.', stacks: ['web', 'api'] },
      ],
    },
    {
      id: 'c2',
      title: 'Infra',
      description: 'd',
      items: [
        { id: 'i3', text: 'Containers run as non-root', detail: 'USER directive.', stacks: ['infra'] },
        { id: 'i4', text: 'Pin actions to SHA', detail: 'Supply chain.', stacks: ['infra'] },
      ],
    },
  ],
}

export function makeReview(partial: Partial<Review> = {}): Review {
  return {
    schemaVersion: 1,
    id: 'r1',
    name: 'R',
    link: '',
    checklistId: 'fx',
    checklistVersion: '1',
    stacks: [],
    results: {},
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...partial,
  }
}
