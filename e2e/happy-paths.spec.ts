import { expect, test } from '@playwright/test'

test.beforeEach(async ({ page }) => {
  page.on('pageerror', (e) => {
    throw e
  })
})

test('toolbox: decodes and lints the sample JWT', async ({ page }) => {
  await page.goto('#/toolbox')
  await page.getByRole('button', { name: 'Load sample token' }).click()
  await expect(page.getByText('"alg"').first()).toBeVisible()
  await page.screenshot({ path: 'test-results/screens/flow-jwt.png', fullPage: true })
})

test('threat model: example generates STRIDE threats', async ({ page }) => {
  await page.goto('#/threat-model')
  await page.getByRole('button', { name: 'Load example' }).click()
  await page.getByRole('tab', { name: '4. Threats' }).click()
  await page.getByRole('button', { name: /^(Generate|Refresh generated) threats$/ }).click()
  await expect(page.getByRole('row', { name: /Attacker impersonates Customer/ })).toBeVisible()
  await page.screenshot({ path: 'test-results/screens/flow-threat-model.png', fullPage: true })
})

test('checklists: starts a PR review', async ({ page }) => {
  await page.goto('#/checklists')
  await page.getByRole('button', { name: 'Use this checklist' }).first().click()
  await page.getByRole('textbox', { name: 'Review name' }).fill('PR #42 — payment API')
  await page.getByRole('button', { name: 'Start review' }).click()
  await expect(page.getByRole('progressbar', { name: 'Review progress' })).toBeVisible()
  await page.screenshot({ path: 'test-results/screens/flow-checklist.png', fullPage: true })
})

test('deps: finds known vulnerabilities via OSV.dev', async ({ page }) => {
  await page.goto('#/deps')
  await page.getByRole('textbox').first().fill('requests==2.19.0\ndjango==3.2.0\n')
  await page.getByRole('button', { name: 'Add pasted content' }).click()
  await page.getByRole('button', { name: /Check 2 unique packages/ }).click()
  await expect(page.getByRole('link', { name: /^(GHSA|PYSEC|CVE)-/ }).first()).toBeVisible({ timeout: 30_000 })
  await page.screenshot({ path: 'test-results/screens/flow-deps.png', fullPage: true })
})
