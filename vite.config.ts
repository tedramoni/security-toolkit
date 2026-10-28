/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'
import { HOME_SEO, PAGE_SEO } from './src/app/seo.ts'
import { headTags, sitemapXml, staticBody } from './src/app/seoHtml.ts'

// base must match the GitHub repository name for GitHub Pages
const BASE = '/security-toolkit/'
const HEAD_MARKER = '<!--seo-head-->'
const BODY_MARKER = '<!--seo-body-->'

/**
 * SEO for a static SPA on GitHub Pages:
 * - one <route>/index.html per tool with its own title, description, canonical, Open Graph, JSON-LD and static content;
 * - 404.html (noindex) as SPA fallback so deep links like /checklists/review/<id> still load the app;
 * - sitemap.xml.
 */
function seoPages(): Plugin {
  return {
    name: 'seo-pages',
    enforce: 'post',
    transformIndexHtml: {
      order: 'post',
      handler(html, ctx) {
        // Dev server: fill in the home page tags. The build keeps the markers for generateBundle.
        if (ctx.bundle) return html
        return html.replace(HEAD_MARKER, headTags(HOME_SEO)).replace(BODY_MARKER, staticBody(HOME_SEO, BASE))
      },
    },
    generateBundle(_options, bundle) {
      const index = bundle['index.html']
      if (!index || index.type !== 'asset') this.error('index.html not found in bundle')
      const template = String(index.source)
      if (!template.includes(HEAD_MARKER) || !template.includes(BODY_MARKER)) this.error('SEO markers missing from index.html')

      const render = (page = HOME_SEO, indexable = true) =>
        template.replace(HEAD_MARKER, headTags(page, { indexable })).replace(BODY_MARKER, indexable ? staticBody(page, BASE) : '')

      index.source = render()
      for (const page of PAGE_SEO) {
        this.emitFile({ type: 'asset', fileName: `${page.path}/index.html`, source: render(page) })
      }
      this.emitFile({ type: 'asset', fileName: '404.html', source: render(HOME_SEO, false) })
      this.emitFile({ type: 'asset', fileName: 'sitemap.xml', source: sitemapXml(new Date().toISOString().slice(0, 10)) })
    },
  }
}

export default defineConfig({
  base: BASE,
  plugins: [react(), seoPages()],
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
})
