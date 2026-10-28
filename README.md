# Security Champion Toolkit

A browser-only toolbox for Security Champions: threat modeling, secure code review checklists, everyday dev security tools and dependency vulnerability checks. It is hosted on GitHub Pages and has **no backend**. Everything you type or paste stays in your browser (localStorage).

## Modules

| Module | What it does |
| --- | --- |
| 🧭 **Threat Modeling** | STRIDE-per-element wizard: components, data flows, trust boundaries → generated threats with suggested mitigations, risk rating, Markdown/Mermaid export |
| 🧰 **Dev Toolbox** | JWT decoder & linter, CSP evaluator & builder, security headers / cookie checker, encoders & hashes, secrets scanner |
| ✅ **Review Checklists** | OWASP Top 10, API Security Top 10, ASVS subset and a quick PR checklist; save reviews and copy the result as a PR comment |
| 📦 **Dependencies & CI** | Check lockfiles (npm, yarn, pip, Maven, Go, Ruby) against [OSV.dev](https://osv.dev); generate GitHub Actions security workflows (CodeQL, Dependabot, gitleaks, Semgrep, Trivy, Scorecard) |

### Privacy

- All processing happens client-side. Nothing is sent anywhere, **except** the dependency checker, which sends package names and versions to the public OSV.dev API.
- Data is kept in `localStorage` under keys prefixed with `scp:`. Use **Export backup** on the home page to save it or move it to another browser.

## Development

```bash
npm install
npm run dev          # http://localhost:5173/security-champion/
npm test             # unit tests (Vitest)
npm run lint         # oxlint
npm run build        # type-check + production build to dist/
npx playwright install chromium   # once
npm run test:e2e     # smoke tests against the production build
```

Structure:

```
src/app/        shell: routing (HashRouter), layout, home
src/lib/        shared helpers: storage, downloads, markdown
src/modules/    one folder per tool (lazy-loaded)
e2e/            Playwright smoke tests
```

To add a tool, create `src/modules/<name>/index.tsx` with a default-exported component and register it in [src/app/modules.ts](src/app/modules.ts).

## Deployment

The `Deploy to GitHub Pages` workflow builds and publishes on every push to `main`.

1. Push this repository to GitHub as `security-champion`. If you use a different name, update `base` in [vite.config.ts](vite.config.ts) and the URLs in [playwright.config.ts](playwright.config.ts).
2. In **Settings → Pages**, set **Source** to **GitHub Actions**.
3. The site is served at `https://<user>.github.io/security-champion/`.

CI runs lint, unit tests, build and Playwright smoke tests on every push and pull request. CodeQL and Dependabot are enabled for the repository itself.
