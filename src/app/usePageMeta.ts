import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { canonicalUrl, fullTitle, seoForPath } from './seo.ts'

/** Keep <title>, meta description and canonical in sync with client-side navigation. */
export function usePageMeta() {
  const { pathname } = useLocation()
  useEffect(() => {
    const page = seoForPath(pathname)
    document.title = fullTitle(page)
    document.querySelector('meta[name="description"]')?.setAttribute('content', page.description)
    document.querySelector('link[rel="canonical"]')?.setAttribute('href', canonicalUrl(page))
  }, [pathname])
}
