import { expect, test } from '@playwright/test'

const SITE = 'https://tedramoni.github.io/security-toolkit/'
const PAGES = ['threat-model', 'toolbox', 'checklists', 'deps', 'data-lab', 'pki', 'skill-scanner', 'recon']

test('every tool has its own static, crawlable HTML (no JavaScript needed)', async ({ request }) => {
  const titles = new Set<string>()
  for (const path of ['', ...PAGES]) {
    const res = await request.get(path ? `${path}/` : '')
    expect(res.status()).toBe(200)
    const html = await res.text()
    const title = html.match(/<title>([^<]+)<\/title>/)?.[1]
    expect(title, path).toBeTruthy()
    titles.add(title!)
    expect(html).toContain(`<link rel="canonical" href="${SITE}${path ? `${path}/` : ''}" />`)
    expect(html).toMatch(/<meta name="description" content="[^"]{80,170}" \/>/)
    expect(html).toContain('<meta property="og:image" content="https://tedramoni.github.io/security-toolkit/og-image.png" />')
    expect(html).toContain('application/ld+json')
    expect(html).toMatch(/<div id="root"><div class="shell">.*<main class="main seo-static"><header class="page-header"><h1>[^<]+<\/h1>/)
  }
  expect(titles.size).toBe(PAGES.length + 1)
})

test('sitemap lists every page', async ({ request }) => {
  const xml = await (await request.get('sitemap.xml')).text()
  for (const path of ['', ...PAGES]) expect(xml).toContain(`<loc>${SITE}${path ? `${path}/` : ''}</loc>`)
})

test('static assets referenced by the head exist', async ({ request }) => {
  for (const f of ['og-image.png', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png', 'manifest.webmanifest', 'favicon.svg']) {
    expect((await request.get(f)).status(), f).toBe(200)
  }
})

test('title follows client-side navigation', async ({ page }) => {
  await page.goto('')
  await page.getByRole('navigation', { name: 'Modules' }).getByRole('link', { name: /PKI Tools/ }).click()
  await expect(page).toHaveURL(/\/security-toolkit\/pki\/$/)
  await expect(page).toHaveTitle(/PKI Tools/)
  await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', `${SITE}pki/`)
})

test('old hash links redirect to path URLs', async ({ page }) => {
  await page.goto('#/toolbox?tab=csp')
  await expect(page).toHaveURL(/\/security-toolkit\/toolbox\?tab=csp$/)
  await expect(page.getByRole('heading', { level: 1, name: 'Dev Toolbox' })).toBeVisible()
})

test('deep links into nested routes load the app', async ({ page }) => {
  await page.goto('checklists/review/does-not-exist')
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
})
