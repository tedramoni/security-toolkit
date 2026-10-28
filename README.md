# Security Toolkit

A browser-only security toolbox for developers and AppSec teams: threat modeling, secure code review checklists, everyday dev security tools and dependency vulnerability checks. It is hosted on GitHub Pages and has **no backend**. Everything you type or paste stays in your browser (localStorage).

## Live demo

**[tedramoni.github.io/security-toolkit](https://tedramoni.github.io/security-toolkit/)**. It is redeployed automatically on every push to `main`.

## Modules

| Module | What it does |
| --- | --- |
| 🧭 **Threat Modeling** | STRIDE-per-element wizard: components, data flows, trust boundaries → generated threats with suggested mitigations, risk rating, Markdown/Mermaid export |
| 🧰 **Dev Toolbox** | JWT decoder & linter, CSP evaluator & builder, security headers / cookie checker, encoders & hashes, secrets scanner |
| ✅ **Review Checklists** | OWASP Top 10, API Security Top 10, ASVS subset and a quick PR checklist; save reviews and copy the result as a PR comment |
| 📦 **Dependencies & CI** | Check lockfiles (npm, yarn, pip, Maven, Go, Ruby, Composer, Cargo) against [OSV.dev](https://osv.dev); generate GitHub Actions security workflows (CodeQL, Dependabot, gitleaks, Semgrep, Trivy, Scorecard) |
| 🧪 **Data Lab** | Recipe workbench: chain encoding, crypto (AES, HMAC, PBKDF2), compression, hashing, IOC extraction and defanging operations; Magic auto-detection; shareable recipes |
| 🔐 **PKI Tools** | Certificate / chain / CSR / CRL decoder and linter, CSR and key generator, key matcher, format converter, OCSP helper, key ceremony planner, RFC 3647 CPS outline, all in-browser |
| 🤖 **AI Skill Scanner** | Static scanner for AI agent skills (`SKILL.md`), agent instruction files, MCP configs and Claude Code hooks: prompt injection, exfiltration, hidden Unicode / ASCII smuggling, dangerous commands; SARIF export. Rule categories inspired by [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) |
| 🛰️ **Website Recon** | Passive domain recon as a tile dashboard: DNS records, DNSSEC, CAA, SPF (with lookup counting), DMARC, DKIM, MTA-STS/TLS-RPT/BIMI, certificate-transparency subdomains with takeover hints, RDAP, IP ownership, Wayback history. Optional self-hosted CORS proxy (Cloudflare Worker template included) unlocks header, robots.txt and security.txt checks |

### Privacy

- All processing happens client-side. Nothing is sent anywhere, **except**:
  - the dependency checker, which sends package names and versions to the public OSV.dev API;
  - the AI Skill Scanner's optional GitHub import, which downloads the public repository you name from the GitHub API;
  - Website Recon, which sends the domain you scan to public DNS-over-HTTPS resolvers (Google, Cloudflare), crt.sh, rdap.org and archive.org, plus your own proxy if you configure one.
- Data is kept in `localStorage` under keys prefixed with `scp:`. Use **Export backup** on the home page to save it or move it to another browser.

## Development

```bash
npm install
npm run dev          # http://localhost:5173/security-toolkit/
npm test             # unit tests (Vitest)
npm run lint         # oxlint
npm run build        # type-check + production build to dist/
npx playwright install chromium   # once
npm run test:e2e     # smoke tests against the production build
```

Structure:

```
src/app/        shell: routing, layout, home, SEO metadata (seo.ts) and build-time HTML (seoHtml.ts)
src/lib/        shared helpers: storage, downloads, markdown
src/modules/    one folder per tool (lazy-loaded)
scripts/        generate-images.mjs renders the social preview image and app icons into public/
e2e/            Playwright smoke, flow and SEO tests
```

To add a tool, create `src/modules/<name>/index.tsx` with a default-exported component, register it in [src/app/modules.ts](src/app/modules.ts), and add its title, description and icon to [src/app/seo.ts](src/app/seo.ts). A unit test fails if the two lists disagree.

### SEO

Each tool has a real URL (`/security-toolkit/pki/`). At build time, a Vite plugin writes one static `index.html` per tool with these contents:

- its own title, description, canonical URL, Open Graph / Twitter tags and JSON-LD;
- crawlable content that the app replaces when it loads.

The plugin also writes `sitemap.xml` and a `404.html` fallback, so deep links keep working. Old `#/` links redirect to the new URLs.

## Deployment

The `Deploy to GitHub Pages` workflow builds and publishes on every push to `main`.

1. Push this repository to GitHub as `security-toolkit`. If you use a different name, update `base` in [vite.config.ts](vite.config.ts) and the URLs in [playwright.config.ts](playwright.config.ts).
2. In **Settings → Pages**, set **Source** to **GitHub Actions**.
3. The site is served at `https://<user>.github.io/security-toolkit/`.

CI runs lint, unit tests, build and Playwright smoke tests on every push and pull request. CodeQL and Dependabot are enabled for the repository itself.
