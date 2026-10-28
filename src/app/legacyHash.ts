/**
 * Map an old hash-router URL fragment ("#/pki?tab=csr") to the equivalent path URL ("/security-toolkit/pki?tab=csr").
 * Returns null when the fragment is not a legacy route (e.g. a normal in-page anchor).
 */
export function legacyHashTarget(hash: string, base: string): string | null {
  if (!hash.startsWith('#/')) return null
  const route = hash.slice(2)
  // Only same-site relative routes: refuse anything that could become a protocol-relative or absolute URL.
  if (route.startsWith('/') || route.startsWith('\\') || /^[a-z][a-z0-9+.-]*:/i.test(route)) return base
  return `${base.endsWith('/') ? base : `${base}/`}${route}`
}
