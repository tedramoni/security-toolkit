/** Checks that need the target site itself — only run through the user's CORS proxy. */
import type { HeaderAnalysis } from '../toolbox/headers'
import { analyzeHeaders } from '../toolbox/headers'
import type { ProxyEnvelope, ProxyOptions } from './proxy'
import { envelopeToRawHeaders, fetchViaProxy, headerValues } from './proxy'
import type { SecurityTxt } from './securitytxt'
import { parseSecurityTxt, securityTxtFindings } from './securitytxt'
import type { Finding } from './types'

/* ---- robots.txt ---- */

export interface Robots {
  userAgents: string[]
  disallow: string[]
  allow: string[]
  sitemaps: string[]
  /** Disallowed paths whose names suggest sensitive areas. */
  interesting: string[]
}

const INTERESTING = ['admin', 'login', 'backup', 'private', 'internal', 'staging', 'test', 'dev', 'config', 'secret', '.git', '.env', 'api', 'debug', 'console', 'old', 'tmp', 'upload', 'cgi-bin', 'wp-admin', 'phpmyadmin', 'dashboard', 'manage']

export function parseRobots(text: string): Robots {
  const out: Robots = { userAgents: [], disallow: [], allow: [], sitemaps: [], interesting: [] }
  const seen = { ua: new Set<string>(), dis: new Set<string>(), allow: new Set<string>(), sm: new Set<string>() }
  for (const raw of text.slice(0, 512 * 1024).split(/\r?\n/)) {
    const hash = raw.indexOf('#')
    const line = (hash === -1 ? raw : raw.slice(0, hash)).trim()
    const i = line.indexOf(':')
    if (i <= 0) continue
    const k = line.slice(0, i).trim().toLowerCase()
    const v = line.slice(i + 1).trim()
    if (v === '') continue
    if (k === 'user-agent' && !seen.ua.has(v) && seen.ua.size < 200) {
      seen.ua.add(v)
      out.userAgents.push(v)
    } else if (k === 'disallow' && !seen.dis.has(v) && seen.dis.size < 1000) {
      seen.dis.add(v)
      out.disallow.push(v)
    } else if (k === 'allow' && !seen.allow.has(v) && seen.allow.size < 1000) {
      seen.allow.add(v)
      out.allow.push(v)
    } else if (k === 'sitemap' && !seen.sm.has(v) && seen.sm.size < 50) {
      seen.sm.add(v)
      out.sitemaps.push(v)
    }
  }
  out.interesting = out.disallow.filter((p) => {
    const lp = p.toLowerCase()
    return INTERESTING.some((w) => lp.includes(w))
  })
  return out
}

/* ---- sitemap ---- */

export function countSitemap(xml: string): { urls: number; isIndex: boolean } {
  const lower = xml.toLowerCase()
  let urls = 0
  let i = lower.indexOf('<loc>')
  while (i !== -1) {
    urls++
    i = lower.indexOf('<loc>', i + 5)
  }
  return { urls, isIndex: lower.includes('<sitemapindex') }
}

/**
 * Sitemap to fetch: the first one declared in robots.txt on the target's own host (or a parent / sub-domain of it),
 * else /sitemap.xml. A Sitemap: line pointing at an unrelated host is ignored so the proxy never contacts third parties
 * that the privacy notice does not list.
 */
export function pickSitemap(declared: readonly string[], host: string): string {
  for (const s of declared) {
    try {
      const u = new URL(s)
      const h = u.hostname.toLowerCase()
      if ((u.protocol === 'https:' || u.protocol === 'http:') && (h === host || h.endsWith('.' + host) || host.endsWith('.' + h))) return u.href
    } catch {
      /* not a URL */
    }
  }
  return `https://${host}/sitemap.xml`
}

/* ---- technology hints ---- */

export interface TechHint {
  name: string
  evidence: string
}

const HEADER_TECH: readonly [string, (v: string) => string | undefined][] = [
  ['server', (v) => v],
  ['x-powered-by', (v) => v],
  ['x-generator', (v) => v],
  ['x-aspnet-version', (v) => `ASP.NET ${v}`],
  ['x-aspnetmvc-version', (v) => `ASP.NET MVC ${v}`],
  ['cf-ray', () => 'Cloudflare'],
  ['x-vercel-id', () => 'Vercel'],
  ['x-nf-request-id', () => 'Netlify'],
  ['x-amz-cf-id', () => 'Amazon CloudFront'],
  ['x-github-request-id', () => 'GitHub Pages'],
  ['x-served-by', (v) => (/cache-/.test(v) ? 'Fastly' : undefined)],
  ['x-akamai-transformed', () => 'Akamai'],
  ['x-azure-ref', () => 'Azure Front Door'],
  ['x-shopify-stage', () => 'Shopify'],
  ['x-drupal-cache', () => 'Drupal'],
  ['x-litespeed-cache', () => 'LiteSpeed'],
  ['x-varnish', () => 'Varnish'],
]

const BODY_TECH: readonly [string, string][] = [
  ['/wp-content/', 'WordPress'],
  ['/wp-includes/', 'WordPress'],
  ['__NEXT_DATA__', 'Next.js'],
  ['/_next/static/', 'Next.js'],
  ['__NUXT__', 'Nuxt'],
  ['ng-version=', 'Angular'],
  ['data-reactroot', 'React'],
  ['drupal-settings-json', 'Drupal'],
  ['cdn.shopify.com', 'Shopify'],
  ['/media/jui/', 'Joomla'],
  ['static.wixstatic.com', 'Wix'],
  ['squarespace.com', 'Squarespace'],
  ['gatsby-', 'Gatsby'],
  ['/sites/default/files/', 'Drupal'],
  ['www.googletagmanager.com', 'Google Tag Manager'],
  ['google-analytics.com', 'Google Analytics'],
]

/** <meta name="generator" content="…"> without a backtracking regex over the whole document. */
export function metaGenerator(html: string): string | undefined {
  const lower = html.toLowerCase()
  let i = lower.indexOf('<meta')
  let guard = 0
  while (i !== -1 && guard++ < 500) {
    const end = lower.indexOf('>', i)
    if (end === -1) break
    const tag = html.slice(i, Math.min(end, i + 1000))
    if (/\bname\s*=\s*["']?generator\b/i.test(tag)) {
      const m = /\bcontent\s*=\s*"([^"]{0,200})"|\bcontent\s*=\s*'([^']{0,200})'/i.exec(tag)
      if (m) return (m[1] ?? m[2]).trim() || undefined
    }
    i = lower.indexOf('<meta', end)
  }
  return undefined
}

export function detectTech(env: ProxyEnvelope): TechHint[] {
  const out: TechHint[] = []
  const add = (name: string, evidence: string) => {
    if (!out.some((t) => t.name === name)) out.push({ name, evidence })
  }
  for (const [h, fn] of HEADER_TECH) {
    for (const v of headerValues(env, h)) {
      const name = fn(v)
      if (name) add(name.slice(0, 120), `${h} header`)
    }
  }
  const body = env.body.slice(0, 1024 * 1024)
  const gen = metaGenerator(body)
  if (gen) add(gen, 'meta generator')
  for (const [needle, name] of BODY_TECH) if (body.includes(needle)) add(name, `"${needle}" in HTML`)
  return out
}

/* ---- HSTS preload (hstspreload.org API, proxied: it sends no CORS header) ---- */

export interface PreloadStatus {
  status: string
  name?: string
}

export function parsePreloadStatus(json: unknown): PreloadStatus {
  const j = json as Record<string, unknown> | null
  if (!j || typeof j.status !== 'string') throw new Error('Unexpected hstspreload.org response')
  return { status: j.status, name: typeof j.name === 'string' ? j.name : undefined }
}

/* ---- orchestration ---- */

export interface WebCheckData {
  https?: ProxyEnvelope
  http?: ProxyEnvelope
  headers?: HeaderAnalysis
  redirects: { url: string; status: number; location?: string }[]
  httpsUpgrade?: boolean
  robots?: Robots
  robotsStatus?: number
  sitemap?: { url: string; urls: number; isIndex: boolean; truncated: boolean }
  securityTxt?: { url: string; parsed: SecurityTxt; legacy: boolean }
  preload?: PreloadStatus
  tech: TechHint[]
  errors: string[]
}

function ok200(e: PromiseSettledResult<ProxyEnvelope>): ProxyEnvelope | undefined {
  return e.status === 'fulfilled' && e.value.status === 200 ? e.value : undefined
}

/**
 * robots.txt and security.txt must be text/plain (RFC 9309 §2.3, RFC 9116 §3). Many sites (SPAs, CMS) answer unknown
 * paths with "200 text/html" soft-404 pages: parsing those would report e.g. "security.txt has no Contact field" for a
 * site that simply has no file.
 */
export function isText(env: ProxyEnvelope): boolean {
  const ct = (headerValues(env, 'content-type')[0] ?? '').trim().toLowerCase()
  if (ct === '') return !/^\s*</.test(env.body.slice(0, 512))
  return ct.startsWith('text/plain')
}

export async function runWebCheck(host: string, proxy: string, opts: ProxyOptions = {}): Promise<{ data: WebCheckData; findings: Finding[] }> {
  const get = (url: string) => fetchViaProxy(proxy, url, opts)
  const [https, http, robotsR, wellKnown, preloadR] = await Promise.allSettled([
    get(`https://${host}/`),
    get(`http://${host}/`),
    get(`https://${host}/robots.txt`),
    get(`https://${host}/.well-known/security.txt`),
    get(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(host)}`),
  ])
  const errors: string[] = []
  const reason = (r: PromiseSettledResult<unknown>) => (r.status === 'rejected' ? (r.reason instanceof Error ? r.reason.message : String(r.reason)) : '')
  if (https.status === 'rejected') {
    // If the main page cannot be fetched at all, the proxy itself is likely misconfigured: fail the check.
    if (http.status === 'rejected') throw new Error(reason(https))
    errors.push(`HTTPS: ${reason(https)}`)
  }
  const data: WebCheckData = { redirects: [], tech: [], errors }
  const f: Finding[] = []

  if (https.status === 'fulfilled') {
    const env = https.value
    data.https = env
    data.redirects = env.redirects
    data.headers = analyzeHeaders(envelopeToRawHeaders(env))
    data.tech = detectTech(env)
    f.push(...data.headers.findings.map((x) => ({ ...x, title: `Headers: ${x.title}` })))
    for (const c of data.headers.cookies) f.push(...c.findings)
    if (env.redirects.length > 3) f.push({ severity: 'low', title: `${env.redirects.length} redirects before the page`, detail: 'Long redirect chains slow page loads and each hop is another place to misconfigure.' })
    const finalHost = (() => {
      try {
        return new URL(env.finalUrl).hostname
      } catch {
        return host
      }
    })()
    if (finalHost !== host && !finalHost.endsWith('.' + host) && !host.endsWith('.' + finalHost)) {
      f.push({ severity: 'info', title: `Redirects to another domain (${finalHost})`, detail: 'Header results apply to the final page.' })
    }
    if (data.tech.length > 0) f.push({ severity: 'info', title: 'Technology hints', detail: data.tech.map((t) => `${t.name} (${t.evidence})`).join(', ') })
  }

  if (http.status === 'fulfilled') {
    data.http = http.value
    const first = http.value.redirects[0]
    const upgraded = first ? (first.location ?? '').startsWith('https://') || http.value.finalUrl.startsWith('https://') : http.value.finalUrl.startsWith('https://')
    data.httpsUpgrade = upgraded
    if (!upgraded && http.value.status < 400) {
      f.push({ severity: 'medium', title: 'HTTP is not redirected to HTTPS', detail: `http://${host}/ answers ${http.value.status} without redirecting to https://. Users following old links stay on plaintext.`, fix: 'Redirect all HTTP requests to HTTPS with a 301/308 and send HSTS.' })
    } else if (upgraded) {
      f.push({ severity: 'pass', title: 'HTTP redirects to HTTPS', detail: first ? `${first.status} → ${first.location ?? http.value.finalUrl}` : http.value.finalUrl })
    }
  } else {
    errors.push(`HTTP: ${reason(http)}`)
  }

  // robots.txt + sitemap
  const robotsEnv = ok200(robotsR)
  if (robotsR.status === 'fulfilled') data.robotsStatus = robotsR.value.status
  if (robotsEnv && isText(robotsEnv)) {
    data.robots = parseRobots(robotsEnv.body)
    if (data.robots.interesting.length > 0) {
      f.push({ severity: 'info', title: `robots.txt lists ${data.robots.interesting.length} potentially sensitive path(s)`, detail: `${data.robots.interesting.slice(0, 10).join(', ')}. robots.txt is public: it hides nothing and points attackers at these paths. Protect them with authentication instead.` })
    }
  } else if (robotsR.status === 'rejected') {
    errors.push(`robots.txt: ${reason(robotsR)}`)
  }
  const sitemapUrl = pickSitemap(data.robots?.sitemaps ?? [], host)
  try {
    const sm = await get(sitemapUrl)
    if (sm.status === 200) data.sitemap = { url: sitemapUrl, ...countSitemap(sm.body), truncated: sm.truncated }
  } catch (e) {
    errors.push(`sitemap: ${e instanceof Error ? e.message : String(e)}`)
  }

  // security.txt (well-known, then legacy root location)
  let st = ok200(wellKnown)
  let legacy = false
  let stUrl = `https://${host}/.well-known/security.txt`
  if (!st || !isText(st)) {
    try {
      const root = await get(`https://${host}/security.txt`)
      if (root.status === 200 && isText(root)) {
        st = root
        legacy = true
        stUrl = `https://${host}/security.txt`
      } else st = undefined
    } catch {
      st = undefined
    }
  }
  if (st) {
    const parsed = parseSecurityTxt(st.body)
    data.securityTxt = { url: stUrl, parsed, legacy }
    f.push(...securityTxtFindings(parsed, Date.now(), stUrl, legacy).map((x) => ({ ...x, title: x.title.startsWith('security.txt') ? x.title : `security.txt: ${x.title}` })))
  } else {
    f.push({ severity: 'low', title: 'No security.txt', detail: 'Researchers who find a vulnerability have no published way to reach you.', fix: `Publish https://${host}/.well-known/security.txt with Contact and Expires (RFC 9116).`, ref: 'https://securitytxt.org/' })
  }

  // HSTS preload
  if (preloadR.status === 'fulfilled' && preloadR.value.status === 200) {
    try {
      data.preload = parsePreloadStatus(JSON.parse(preloadR.value.body))
      const s = data.preload.status
      if (s === 'preloaded') f.push({ severity: 'pass', title: 'On the HSTS preload list', detail: 'Browsers never connect over plain HTTP, even on the first visit.' })
      else if (s === 'pending') f.push({ severity: 'info', title: 'HSTS preload submission pending', detail: 'Submitted to hstspreload.org; will ship with a future browser release.' })
      else f.push({ severity: 'info', title: `Not HSTS-preloaded (status: ${s})`, detail: 'The first visit can still be downgraded to HTTP. Preloading needs max-age ≥ 1 year, includeSubDomains and preload on the apex domain.', ref: 'https://hstspreload.org/' })
    } catch {
      errors.push('hstspreload.org: unexpected response')
    }
  } else {
    errors.push(`hstspreload.org: ${preloadR.status === 'rejected' ? reason(preloadR) : `HTTP ${preloadR.value.status}`}`)
  }

  if (errors.length > 0) f.push({ severity: 'info', title: 'Some proxied requests failed', detail: errors.slice(0, 6).join('; ') })
  return { data, findings: f }
}
