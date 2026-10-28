import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'e2e',
  outputDir: 'test-results',
  use: { baseURL: 'http://localhost:4173/security-toolkit/' },
  webServer: {
    command: 'npm run preview -- --port 4173 --strictPort',
    url: 'http://localhost:4173/security-toolkit/',
    reuseExistingServer: !process.env.CI,
  },
})
