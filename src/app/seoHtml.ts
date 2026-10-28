/**
 * Build-time HTML for SEO: <head> tags and static page content shown before JavaScript runs
 * (and to crawlers / link-preview bots that do not execute JavaScript). Used by vite.config.ts.
 */
import { ALL_SEO, PAGE_SEO, REPO_URL, SITE_NAME, SITE_URL, canonicalUrl, fullTitle, type PageSeo } from './seo.ts'

export const OG_IMAGE = `${SITE_URL}og-image.png`

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** JSON for a <script type="application/ld+json"> block; "<" is escaped so the data cannot close the script. */
function jsonLd(data: unknown): string {
  return JSON.stringify(data).replace(/</g, '\\u003c')
}

function structuredData(page: PageSeo): unknown[] {
  const url = canonicalUrl(page)
  const app = {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: page.path ? `${page.heading} | ${SITE_NAME}` : SITE_NAME,
    url,
    description: page.description,
    applicationCategory: page.category,
    operatingSystem: 'Any (web browser)',
    browserRequirements: 'Requires JavaScript and a modern browser with WebCrypto.',
    isAccessibleForFree: true,
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
    featureList: page.features,
    image: OG_IMAGE,
    codeRepository: REPO_URL,
  }
  if (!page.path) {
    return [app, { '@context': 'https://schema.org', '@type': 'WebSite', name: SITE_NAME, url: SITE_URL }]
  }
  const breadcrumbs = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: SITE_NAME, item: SITE_URL },
      { '@type': 'ListItem', position: 2, name: page.heading, item: url },
    ],
  }
  return [app, breadcrumbs]
}

/** Tags injected into <head>. `indexable: false` is used for the 404 / SPA fallback page. */
export function headTags(page: PageSeo, { indexable = true } = {}): string {
  const title = fullTitle(page)
  const url = canonicalUrl(page)
  const tags = [
    `<title>${esc(title)}</title>`,
    `<meta name="description" content="${esc(page.description)}" />`,
    indexable ? `<link rel="canonical" href="${url}" />` : '<meta name="robots" content="noindex" />',
    `<meta property="og:type" content="website" />`,
    `<meta property="og:site_name" content="${SITE_NAME}" />`,
    `<meta property="og:title" content="${esc(title)}" />`,
    `<meta property="og:description" content="${esc(page.description)}" />`,
    `<meta property="og:url" content="${url}" />`,
    `<meta property="og:image" content="${OG_IMAGE}" />`,
    `<meta property="og:image:width" content="1200" />`,
    `<meta property="og:image:height" content="630" />`,
    `<meta property="og:image:alt" content="${SITE_NAME}: free browser-based security tools" />`,
    `<meta property="og:locale" content="en_US" />`,
    `<meta name="twitter:card" content="summary_large_image" />`,
    `<meta name="twitter:title" content="${esc(title)}" />`,
    `<meta name="twitter:description" content="${esc(page.description)}" />`,
    `<meta name="twitter:image" content="${OG_IMAGE}" />`,
  ]
  if (indexable) {
    for (const data of structuredData(page)) tags.push(`<script type="application/ld+json">${jsonLd(data)}</script>`)
  }
  return tags.map((t) => `    ${t}`).join('\n')
}

/**
 * Static content placed inside #root. React's createRoot replaces it on load, so users see the app;
 * crawlers and no-JS visitors get a real page with a heading, description and links to every tool.
 */
export function staticBody(page: PageSeo, base: string): string {
  const href = (p: PageSeo) => `${base}${p.path ? `${p.path}/` : ''}`
  // Same shell/sidebar markup as Layout.tsx, so swapping in the app causes almost no layout shift.
  const nav = ALL_SEO.map(
    (p) =>
      `<a href="${href(p)}"${p.path === page.path ? ' class="active" aria-current="page"' : ''}><span aria-hidden="true">${p.icon}</span> ${esc(p.path ? p.heading : 'Home')}</a>`,
  ).join('')
  const others = PAGE_SEO.filter((p) => p.path !== page.path)
  const links = others.map((p) => `<li><a href="${href(p)}">${esc(p.heading)}</a>: ${esc(p.description)}</li>`).join('')
  return [
    '<div class="shell">',
    `<aside class="sidebar"><a href="${base}" class="brand"><img src="${base}favicon.svg" alt="" width="26" height="26" />${SITE_NAME}</a>`,
    `<nav class="nav" aria-label="Modules">${nav}</nav>`,
    '<div class="sidebar-foot">🔒 Runs 100% in your browser. Your data never leaves this device.</div></aside>',
    '<main class="main seo-static">',
    `<header class="page-header"><h1>${esc(page.heading)}</h1><p>${esc(page.intro)}</p></header>`,
    `<ul>${page.features.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>`,
    '<noscript><p><strong>This tool needs JavaScript.</strong> Everything runs locally in your browser; nothing is uploaded.</p></noscript>',
    `<h2>${page.path ? 'More free security tools' : 'Tools'}</h2>`,
    `<ul>${links}</ul>`,
    `<p><a href="${REPO_URL}">Source code on GitHub</a> (open source).</p>`,
    '</main></div>',
  ].join('')
}

export function sitemapXml(lastmod: string): string {
  const urls = ALL_SEO.map(
    (p) => `  <url><loc>${canonicalUrl(p)}</loc><lastmod>${lastmod}</lastmod><priority>${p.path ? '0.8' : '1.0'}</priority></url>`,
  )
  return ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">', ...urls, '</urlset>', ''].join('\n')
}
