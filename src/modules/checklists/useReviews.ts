import { useCallback, useMemo } from 'react'
import { STORAGE_KEYS, useLocalStorage } from '../../lib/storage'
import { futureVersionEntries, sanitizeReviews } from './review'
import type { Review } from './types'

export interface ReviewsStore {
  reviews: Review[]
  /** Functional update over the sanitized list. */
  update: (fn: (list: Review[]) => Review[]) => void
}

/** Saved reviews, validated on read so a corrupt or hand-edited localStorage entry cannot crash the UI. */
export function useReviews(): ReviewsStore {
  const [raw, setRaw] = useLocalStorage<unknown>(STORAGE_KEYS.reviews, [])
  const reviews = useMemo(() => sanitizeReviews(raw), [raw])
  const update = useCallback(
    (fn: (list: Review[]) => Review[]) =>
      setRaw((prev: unknown) => [...fn(sanitizeReviews(prev)), ...futureVersionEntries(prev)]),
    [setRaw],
  )
  return { reviews, update }
}
