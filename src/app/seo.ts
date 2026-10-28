/**
 * SEO metadata for every public page. Pure data: imported by the app (runtime <title>/meta updates)
 * and by vite.config.ts (build-time static HTML per route, sitemap). Keep titles ≤ 60 chars and
 * descriptions ~140-160 chars.
 */

export const SITE_URL = 'https://tedramoni.github.io/security-toolkit/'
export const SITE_NAME = 'Security Toolkit'
export const REPO_URL = 'https://github.com/tedramoni/security-toolkit'

export interface PageSeo {
  /** Route path without leading slash; '' is the home page. Must match src/app/modules.ts. */
  path: string
  /** Sidebar icon; must match src/app/modules.ts (checked by seo.test.ts). */
  icon: string
  title: string
  description: string
  /** Visible heading + intro of the static (pre-JavaScript) page content. */
  heading: string
  intro: string
  /** Feature bullets rendered as crawlable text before the app loads. */
  features: string[]
  /** Schema.org applicationSubCategory. */
  category: string
}

export const HOME_SEO: PageSeo = {
  path: '',
  icon: '🏠',
  title: 'Security Toolkit: free browser-based AppSec tools',
  description:
    'Free, open-source security tools that run 100% in your browser: threat modeling, JWT & CSP checks, OWASP checklists, CVE lookups, PKI and data decoding.',
  heading: 'Security Toolkit',
  intro:
    'Everyday application security tools for developers, security champions and AppSec teams. Everything runs locally in your browser: nothing you paste is uploaded.',
  features: [
    'STRIDE threat modeling with Markdown and Mermaid export',
    'JWT decoder, CSP evaluator, security headers checker, secrets scanner',
    'OWASP Top 10, API Security Top 10 and ASVS review checklists',
    'Dependency vulnerability check against OSV.dev and GitHub Actions security workflows',
    'Data Lab: chain encoding, crypto, compression and hashing operations',
    'PKI tools: certificate, CSR and CRL decoder, CSR generator, key matcher',
    'AI Skill Scanner for agent skills, MCP configs and Claude Code hooks',
  ],
  category: 'SecurityApplication',
}

export const PAGE_SEO: PageSeo[] = [
  {
    path: 'threat-model',
    icon: '🧭',
    title: 'STRIDE Threat Modeling Tool (free, in-browser)',
    description:
      'Model components, data flows and trust boundaries, generate STRIDE threats with mitigations, rate risk and export a Markdown report with a Mermaid diagram.',
    heading: 'Threat Modeling',
    intro: 'A STRIDE-per-element threat modeling wizard for design reviews. Models are stored only in your browser.',
    features: [
      'Processes, data stores, external entities and data flows with trust boundaries',
      'Around 30 rules generate concrete threats with suggested mitigations',
      'Likelihood × impact risk rating, status, owner and ticket tracking',
      'Markdown report and Mermaid data-flow diagram export, JSON import/export',
    ],
    category: 'SecurityApplication',
  },
  {
    path: 'toolbox',
    icon: '🧰',
    title: 'JWT Decoder, CSP Evaluator & Security Headers Checker',
    description:
      'Decode and lint JWTs, evaluate Content-Security-Policy, grade HTTP security headers and cookies, encode/hash data and scan code for leaked secrets, all locally.',
    heading: 'Dev Toolbox',
    intro: 'Everyday security helpers for code and design reviews. Tokens, headers and code never leave your browser.',
    features: [
      'JWT decoder and linter: alg none, missing exp, weak claims, sensitive data',
      'CSP evaluator and builder: unsafe-inline, bypassable hosts, strict-dynamic',
      'Security headers and cookie checker with A+ to F grade',
      'Base64, URL, HTML, hex encoders and SHA hashes',
      'Secrets scanner for AWS, GitHub, Slack, Stripe keys and private keys',
    ],
    category: 'DeveloperApplication',
  },
  {
    path: 'checklists',
    icon: '✅',
    title: 'OWASP Top 10 & ASVS Secure Code Review Checklists',
    description:
      'Run secure code reviews with OWASP Top 10:2025, API Security Top 10 and ASVS 5.0 checklists, record pass/fail with notes and paste the summary into your PR.',
    heading: 'Review Checklists',
    intro: 'Structured security reviews for pull requests, features and services.',
    features: [
      'OWASP Top 10:2025, OWASP API Security Top 10 2023, ASVS 5.0 essentials',
      'Pull request quick review checklist',
      'Pass / fail / N/A with notes, filters by tech stack',
      'Copy the result as a PR comment, Markdown or JSON',
    ],
    category: 'SecurityApplication',
  },
  {
    path: 'deps',
    icon: '📦',
    title: 'Lockfile Vulnerability Scanner (OSV) & CI Security Generator',
    description:
      'Check package-lock, yarn.lock, requirements.txt, pom.xml, go.sum and more against OSV.dev, and generate GitHub Actions for CodeQL, Dependabot, gitleaks and Trivy.',
    heading: 'Dependencies & CI',
    intro: 'Find known vulnerabilities in your dependencies and harden your CI pipeline.',
    features: [
      'Parses npm, yarn, pip, Poetry, Maven, Go, Ruby, Composer and Cargo lockfiles',
      'OSV.dev lookup with CVSS severity and fixed versions, CSV/Markdown export',
      'GitHub Actions generator: CodeQL, Dependabot, dependency review, gitleaks, Semgrep, Trivy, Scorecard',
    ],
    category: 'SecurityApplication',
  },
  {
    path: 'data-lab',
    icon: '🧪',
    title: 'Data Lab: encode, decode, encrypt & hash in your browser',
    description:
      'Chain 100+ operations into recipes: Base64, hex, URL, AES-GCM, HMAC, PBKDF2, MD5/SHA, gzip, XOR brute force, IOC extraction and defanging, with Magic auto-detect.',
    heading: 'Data Lab',
    intro: 'A recipe workbench for decoding and transforming data during investigations and reviews.',
    features: [
      'Encodings: Base64, Base32, Base58, Base85, hex, URL, HTML entities, Punycode',
      'Crypto: AES-GCM/CBC/CTR, HMAC, PBKDF2, XOR and classical ciphers',
      'Hashing (MD5, SHA family, CRC32) and gzip/deflate compression',
      'IOC extraction, defang/refang, JSON/CSV, timestamps, hexdump, entropy',
      'Magic detects layered encodings; shareable recipe links',
    ],
    category: 'DeveloperApplication',
  },
  {
    path: 'pki',
    icon: '🔐',
    title: 'PKI Tools: Certificate, CSR & CRL Decoder, CSR Generator',
    description:
      'Decode and lint X.509 certificates, chains, CSRs and CRLs, generate CSRs and keys, match keys to certificates, convert PEM/DER/P7B/JWK. Nothing is uploaded.',
    heading: 'PKI Tools',
    intro: 'Certificate and key utilities powered by WebCrypto. Certificates and keys never leave your browser.',
    features: [
      'Certificate decoder and linter (CA/Browser Forum rules, RFC 5280)',
      'Chain builder and signature verifier, hostname check',
      'CSR decoder, CSR and key generator with the equivalent openssl command',
      'Key matcher, PEM/DER/PKCS#7/JWK converter, CRL checker, OCSP helper',
      'Key ceremony planner (M-of-N) and RFC 3647 CP/CPS outline builder',
    ],
    category: 'SecurityApplication',
  },
  {
    path: 'skill-scanner',
    icon: '🤖',
    title: 'AI Agent Skill & MCP Config Security Scanner',
    description:
      'Scan SKILL.md files, agent instructions, MCP server configs and Claude Code hooks for prompt injection, data exfiltration, hidden Unicode and dangerous commands.',
    heading: 'AI Skill Scanner',
    intro: 'Static security analysis for AI agent extensions before you install them.',
    features: [
      'Prompt injection, jailbreak and system-prompt leakage patterns',
      'Exfiltration, credential access, persistence and dangerous shell commands',
      'Hidden Unicode: ASCII smuggling (TAG characters), bidi overrides, zero-width',
      'MCP config and Claude Code settings checks (unpinned servers, wildcard permissions)',
      'Risk score with PASS/REVIEW/FAIL and SARIF, JSON, Markdown export',
    ],
    category: 'SecurityApplication',
  },
  {
    path: 'recon',
    icon: '🛰️',
    title: 'Website Recon: DNS, SPF/DMARC, Certificates & RDAP',
    description:
      'Passive recon for a domain: DNS records, SPF, DMARC, DKIM, CAA, DNSSEC, certificate transparency subdomains, RDAP registration, HSTS preload and archive history.',
    heading: 'Website Recon',
    intro: 'Passive reconnaissance of a domain using public, browser-accessible data sources.',
    features: [
      'DNS records over HTTPS: A, AAAA, MX, NS, TXT, CAA, SOA, DNSSEC',
      'Email security: SPF, DMARC, MTA-STS, TLS-RPT, BIMI and common DKIM selectors',
      'Subdomains and certificate history from Certificate Transparency logs',
      'RDAP domain registration and IP network ownership',
      'HSTS preload status, Wayback Machine history, security.txt checks',
    ],
    category: 'SecurityApplication',
  },
]

export const ALL_SEO: PageSeo[] = [HOME_SEO, ...PAGE_SEO]

export function seoForPath(pathname: string): PageSeo {
  const first = pathname.replace(/^\/+/, '').split('/')[0] ?? ''
  return PAGE_SEO.find((p) => p.path === first) ?? HOME_SEO
}

/**
 * Canonical URL. Each page is built as <path>/index.html, and GitHub Pages redirects /<path> to /<path>/,
 * so the trailing slash avoids a redirect hop.
 */
export function canonicalUrl(page: PageSeo): string {
  return page.path ? `${SITE_URL}${page.path}/` : SITE_URL
}

/** Search results truncate titles around 60 characters. */
export const MAX_TITLE = 65

/** Full <title>: page title + site name when it fits and is not already there. */
export function fullTitle(page: PageSeo): string {
  const branded = `${page.title} | ${SITE_NAME}`
  return page.title.includes(SITE_NAME) || branded.length > MAX_TITLE ? page.title : branded
}
