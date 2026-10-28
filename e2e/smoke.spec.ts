import { expect, test } from '@playwright/test'

const ROUTES = ['', '#/threat-model', '#/toolbox', '#/checklists', '#/deps', '#/data-lab', '#/pki', '#/skill-scanner']

for (const route of ROUTES) {
  test(`renders ${route || 'home'} without errors`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (e) => errors.push(e.message))
    page.on('console', (m) => {
      if (m.type() === 'error') errors.push(m.text())
    })

    await page.goto(route)
    await expect(page.locator('h1').first()).toBeVisible()
    await page.screenshot({ path: `test-results/screens/${route.replace('#/', '') || 'home'}.png`, fullPage: true })
    expect(errors).toEqual([])
  })
}
