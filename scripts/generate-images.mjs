// Renders the social preview image and PNG app icons into public/.
// Run after changing the logo or tagline: node scripts/generate-images.mjs
import { readFileSync } from 'node:fs'
import { chromium } from 'playwright'

const logo = readFileSync(new URL('../public/favicon.svg', import.meta.url), 'utf8')
const out = (name) => new URL(`../public/${name}`, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')

const tools = ['Threat Modeling', 'JWT & CSP', 'OWASP Checklists', 'CVE Lookup', 'Data Lab', 'PKI Tools', 'AI Skill Scanner']

const ogHtml = `<!doctype html><html><body style="margin:0">
<div style="width:1200px;height:630px;box-sizing:border-box;padding:72px 80px;background:radial-gradient(circle at 85% 15%,#14532d 0,#0b1220 55%);
  font-family:'Segoe UI',Inter,system-ui,sans-serif;color:#e2e8f0;display:flex;flex-direction:column;justify-content:space-between">
  <div style="display:flex;align-items:center;gap:28px">
    <div style="width:112px;height:112px">${logo.replace('<svg ', '<svg width="112" height="112" ')}</div>
    <div style="font-size:76px;font-weight:800;letter-spacing:-1px">Security Toolkit</div>
  </div>
  <div style="font-size:40px;line-height:1.3;color:#cbd5e1;max-width:980px">Free AppSec tools that run <span style="color:#22c55e;font-weight:700">100% in your browser</span>. Nothing you paste is uploaded.</div>
  <div style="display:flex;flex-wrap:wrap;gap:14px">${tools
    .map((t) => `<span style="border:2px solid #22304d;background:#111a2e;border-radius:999px;padding:10px 22px;font-size:26px">${t}</span>`)
    .join('')}</div>
</div></body></html>`

const iconHtml = (size, pad) => `<!doctype html><html><body style="margin:0">
<div style="width:${size}px;height:${size}px;background:#0b1220;display:flex;align-items:center;justify-content:center">
  ${logo.replace('<svg ', `<svg width="${size - pad * 2}" height="${size - pad * 2}" `)}
</div></body></html>`

const browser = await chromium.launch()
const shots = [
  { file: 'og-image.png', html: ogHtml, w: 1200, h: 630 },
  { file: 'apple-touch-icon.png', html: iconHtml(180, 24), w: 180, h: 180 },
  { file: 'icon-192.png', html: iconHtml(192, 26), w: 192, h: 192 },
  { file: 'icon-512.png', html: iconHtml(512, 96), w: 512, h: 512 },
]
for (const s of shots) {
  const page = await browser.newPage({ viewport: { width: s.w, height: s.h } })
  await page.setContent(s.html)
  await page.screenshot({ path: out(s.file) })
  await page.close()
  console.log('wrote public/' + s.file)
}
await browser.close()
