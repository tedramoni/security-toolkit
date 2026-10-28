import type { Finding, Severity } from './types'

/*
 * Content-Security-Policy parser & evaluator.
 * Sources:
 *  - MDN CSP reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy
 *  - Google strict CSP: https://web.dev/articles/strict-csp , https://csp.withgoogle.com/docs/strict-csp.html
 *  - Google CSP Evaluator bypass lists: https://github.com/google/csp-evaluator/tree/master/allowlist_bypasses
 *  - OWASP CSP cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
 */

const MDN = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy'
const STRICT_CSP = 'https://web.dev/articles/strict-csp'
const CSP_EVALUATOR = 'https://github.com/google/csp-evaluator/tree/master/allowlist_bypasses'

export interface CspDirective {
  name: string
  values: string[]
}

export interface ParsedCsp {
  directives: CspDirective[]
  /** Directive names that appeared more than once (only the first occurrence is enforced). */
  duplicates: string[]
  /** True when the input was labelled Content-Security-Policy-Report-Only. */
  reportOnly: boolean
  /** Additional comma-separated policies that were not evaluated. */
  extraPolicies: string[]
}

export function parseCsp(input: string): ParsedCsp {
  let text = input.trim()
  let reportOnly = false
  const m = /^content-security-policy(-report-only)?\s*:\s*/i.exec(text)
  if (m) {
    reportOnly = m[1] !== undefined
    text = text.slice(m[0].length)
  }
  // A comma separates multiple policies in a single header field.
  const [first, ...extraPolicies] = text.split(',')
  const directives: CspDirective[] = []
  const seen = new Set<string>()
  const duplicates: string[] = []
  for (const raw of (first ?? '').split(';')) {
    const tokens = raw.trim().split(/\s+/).filter(Boolean)
    if (tokens.length === 0) continue
    const name = tokens[0].toLowerCase()
    if (seen.has(name)) {
      duplicates.push(name)
      continue
    }
    seen.add(name)
    directives.push({ name, values: tokens.slice(1) })
  }
  return { directives, duplicates, reportOnly, extraPolicies: extraPolicies.map((p) => p.trim()).filter(Boolean) }
}

export function getDirective(csp: ParsedCsp, name: string): string[] | undefined {
  return csp.directives.find((d) => d.name === name)?.values
}

/* ---------- known directives ---------- */

const KNOWN_DIRECTIVES = new Set([
  'default-src', 'child-src', 'connect-src', 'fenced-frame-src', 'font-src', 'frame-src', 'img-src', 'manifest-src',
  'media-src', 'object-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem',
  'style-src-attr', 'worker-src', 'base-uri', 'sandbox', 'form-action', 'frame-ancestors', 'report-uri', 'report-to',
  'require-trusted-types-for', 'trusted-types', 'upgrade-insecure-requests', 'webrtc',
])

/** Deprecated or removed directives, with the advice to give. */
const DEPRECATED_DIRECTIVES: Record<string, string> = {
  'block-all-mixed-content': 'Deprecated: modern browsers block or auto-upgrade mixed content already. Use upgrade-insecure-requests if needed.',
  'plugin-types': 'Removed from CSP3 and browsers (plugins are gone). Use object-src \'none\'.',
  'prefetch-src': 'Removed from the spec and not supported by browsers; remove it.',
  'navigate-to': 'Removed from the spec and never shipped in browsers; remove it.',
  referrer: 'Obsolete CSP1.1 directive; use the Referrer-Policy header instead.',
  'reflected-xss': 'Obsolete; never widely supported. Remove it.',
  'disown-opener': 'Never shipped; use the Cross-Origin-Opener-Policy header instead.',
}

const KEYWORDS = ['self', 'none', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic', 'unsafe-hashes', 'report-sample', 'wasm-unsafe-eval', 'unsafe-allow-redirects', 'inline-speculation-rules']

/* ---------- bypassable hosts ---------- */

export interface BypassHost {
  /** Exact host, or "*.domain" meaning any subdomain of domain hosts attacker-controllable content. */
  host: string
  kind: 'JSONP endpoint' | 'AngularJS / script gadget library' | 'user-uploaded content'
}

/** Curated subset of Google CSP Evaluator's lists plus common user-content hosts. */
export const BYPASS_HOSTS: readonly BypassHost[] = [
  // JSONP (csp-evaluator allowlist_bypasses/jsonp.ts)
  ...[
    'www.google.com', 'accounts.google.com', 'www.googleapis.com', 'maps.googleapis.com', 'translate.googleapis.com',
    'www.googletagmanager.com', 'googletagmanager.com', 'www.google-analytics.com', 'ssl.google-analytics.com',
    'google-analytics.com', 'www.googleadservices.com', 'partner.googleadservices.com', 'pagead2.googlesyndication.com',
    'googleads.g.doubleclick.net', 'securepubads.g.doubleclick.net', 'www.youtube.com', 'graph.facebook.com',
    'api.facebook.com', 'www.facebook.com', 'syndication.twitter.com', 'cdn.syndication.twimg.com', 'publish.twitter.com',
    'api.vk.com', 'mc.yandex.ru', 'yandex.ru', 'vimeo.com', 'widgets.pinterest.com', 'api.instagram.com',
  ].map((host) => ({ host, kind: 'JSONP endpoint' as const })),
  // AngularJS & other script gadgets (csp-evaluator allowlist_bypasses/angular.ts)
  ...[
    'ajax.googleapis.com', 'www.gstatic.com', 'gstatic.com', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net',
    'oss.maxcdn.com', 'yastatic.net', 'yandex.st', 'cdn.shopify.com', 'cdn.bootcss.com', 'www.adobe.com',
  ].map((host) => ({ host, kind: 'AngularJS / script gadget library' as const })),
  // Anyone can upload files here (unpkg serves any published npm package)
  ...[
    'unpkg.com',
    '*.amazonaws.com', '*.cloudfront.net', 'storage.googleapis.com', 'firebasestorage.googleapis.com',
    '*.appspot.com', '*.blob.core.windows.net', '*.azureedge.net', 'raw.githubusercontent.com', '*.github.io',
    '*.herokuapp.com', 'dl.dropboxusercontent.com', '*.netlify.app', '*.vercel.app', '*.web.app', '*.firebaseapp.com',
  ].map((host) => ({ host, kind: 'user-uploaded content' as const })),
]

/** Extract the host part of a CSP host-source ("https://*.example.com:443/path" -> "*.example.com"). */
export function sourceHost(source: string): string | undefined {
  if (source.startsWith("'")) return undefined
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(\*|(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*)(?::(?:\d+|\*))?(?:\/.*)?$/i.exec(source)
  if (!m || /^[a-z][a-z0-9+.-]*:$/i.test(source)) return undefined
  return m[1].toLowerCase()
}

/** Find bypass-list entries reachable through a CSP source expression. */
export function matchBypassHosts(source: string): BypassHost[] {
  const host = sourceHost(source)
  if (!host || host === '*') return []
  const srcWild = host.startsWith('*.')
  const sb = srcWild ? host.slice(2) : host
  return BYPASS_HOSTS.filter(({ host: entry }) => {
    const entryWild = entry.startsWith('*.')
    const eb = entryWild ? entry.slice(2) : entry
    if (entryWild) {
      if (sb === eb) return srcWild
      // "*.com" covers "*.amazonaws.com"; "s3.amazonaws.com" is covered by "*.amazonaws.com".
      return sb.endsWith('.' + eb) || (srcWild && eb.endsWith('.' + sb))
    }
    return srcWild ? eb.endsWith('.' + sb) : sb === eb
  })
}

/* ---------- evaluator ---------- */

const isNonce = (v: string) => /^'nonce-[^']+'$/i.test(v)
const isHash = (v: string) => /^'sha(256|384|512)-[^']+'$/i.test(v)

export function evaluateCsp(csp: ParsedCsp): Finding[] {
  const f: Finding[] = []
  if (csp.directives.length === 0) {
    return [{ severity: 'high', title: 'Empty policy', detail: 'No directives were found, so nothing is restricted.', fix: 'Start from the strict policy in the builder below.', ref: STRICT_CSP }]
  }

  if (csp.reportOnly) {
    f.push({
      severity: 'info',
      title: 'Report-Only policy',
      detail: 'Content-Security-Policy-Report-Only only reports violations; it does not block anything.',
      fix: 'Once reports are clean, ship the same policy as Content-Security-Policy.',
      ref: MDN,
    })
  }
  if (csp.extraPolicies.length > 0) {
    f.push({
      severity: 'info',
      title: `${csp.extraPolicies.length} additional comma-separated polic${csp.extraPolicies.length > 1 ? 'ies' : 'y'} ignored here`,
      detail: 'A comma separates multiple policies; browsers enforce all of them (a resource must pass every policy). Only the first one is evaluated here — paste the others separately.',
    })
  }
  for (const d of csp.duplicates) {
    f.push({
      severity: 'low',
      title: `Duplicate directive "${d}"`,
      detail: 'Browsers enforce only the first occurrence and ignore the rest — the policy probably does not do what you think.',
      fix: `Merge the sources into a single ${d} directive.`,
    })
  }

  const defaultSrc = getDirective(csp, 'default-src')
  const scriptSrcDirective = getDirective(csp, 'script-src') ? 'script-src' : 'default-src'
  const scriptSrc = getDirective(csp, 'script-src') ?? defaultSrc

  if (!defaultSrc) {
    f.push({
      severity: scriptSrc ? 'low' : 'high',
      title: 'Missing default-src',
      detail: 'Fetch directives that are not set (img-src, connect-src, frame-src…) fall back to default-src. Without it, they allow everything — fine for an XSS-focused strict CSP, but injected markup can still load or exfiltrate data to any host.',
      fix: "Add default-src 'self' (or 'none') and open up specific directives as needed.",
      ref: MDN,
    })
  }

  // ---- script sources ----
  if (!scriptSrc) {
    f.push({
      severity: 'high',
      title: 'Scripts are not restricted',
      detail: 'Neither script-src nor default-src is set, so any script from anywhere (including inline) is allowed. CSP gives no XSS protection.',
      fix: "Add a strict script-src: 'nonce-{random}' 'strict-dynamic'.",
      ref: STRICT_CSP,
    })
  } else {
    const lower = scriptSrc.map((v) => v.toLowerCase())
    const hasNonce = scriptSrc.some(isNonce)
    const hasHash = scriptSrc.some(isHash)
    const strictDynamic = lower.includes("'strict-dynamic'")
    const hostsIgnored = strictDynamic && (hasNonce || hasHash)
    const downgrade = (s: Severity): Severity => (hostsIgnored ? 'info' : s)
    const ignoredNote = hostsIgnored ? " Because 'strict-dynamic' is used with a nonce/hash, CSP3 browsers ignore host and scheme sources here; this only matters for old browsers." : ''

    if (hostsIgnored) {
      f.push({
        severity: 'pass',
        title: `Strict ${scriptSrcDirective} (nonce/hash + 'strict-dynamic')`,
        detail: 'This is the recommended "strict CSP": only scripts carrying the nonce/hash (and scripts they load) run; allowlists are ignored by CSP3 browsers.',
        ref: STRICT_CSP,
      })
    } else if (strictDynamic) {
      f.push({
        severity: 'medium',
        title: "'strict-dynamic' without a nonce or hash",
        detail: "'strict-dynamic' disables host/'self' allowlists in CSP3 browsers, and without a nonce or hash nothing is trusted — no script will load at all.",
        fix: "Add 'nonce-{random}' (generated per response) to script-src and to every <script> tag.",
        ref: STRICT_CSP,
      })
    } else if (hasNonce || hasHash) {
      f.push({
        severity: 'low',
        title: "Nonce/hash used without 'strict-dynamic'",
        detail: 'Host allowlist entries in the same directive are still active, so the policy is only as strong as the weakest allowed host.',
        fix: "Add 'strict-dynamic' so scripts loaded by trusted scripts work and allowlists are ignored.",
        ref: STRICT_CSP,
      })
    }

    if (lower.includes("'unsafe-inline'")) {
      if (hasNonce || hasHash) {
        f.push({
          severity: 'info',
          title: "'unsafe-inline' is ignored (nonce/hash present)",
          detail: "Since CSP2, browsers ignore 'unsafe-inline' when a nonce or hash is present. It is only kept as a fallback for CSP1 browsers — this is the recommended backward-compatible pattern.",
          ref: STRICT_CSP,
        })
      } else {
        f.push({
          severity: 'high',
          title: `'unsafe-inline' in ${scriptSrcDirective}`,
          detail: 'Any injected <script> block or inline event handler (onerror=…) executes. CSP provides essentially no XSS protection.',
          fix: "Move inline scripts to files or tag them with a per-response nonce, then remove 'unsafe-inline' (or keep it only alongside a nonce for old browsers).",
          ref: STRICT_CSP,
        })
      }
    }
    if (lower.includes("'unsafe-eval'")) {
      f.push({
        severity: 'medium',
        title: `'unsafe-eval' in ${scriptSrcDirective}`,
        detail: 'Allows eval(), new Function(), setTimeout("string"). Turns DOM-based injections into code execution and enables script-gadget bypasses.',
        fix: "Remove eval-style code. If only WebAssembly needs it, use 'wasm-unsafe-eval' instead.",
        ref: MDN,
      })
    }
    if (lower.includes("'unsafe-hashes'")) {
      f.push({
        severity: 'low',
        title: "'unsafe-hashes' in script sources",
        detail: 'Allows inline event handlers matching a hash. Safer than unsafe-inline, but handlers are an injection-friendly pattern.',
        fix: 'Replace inline event handlers with addEventListener in a script file.',
      })
    }
    for (const v of scriptSrc) {
      const lv = v.toLowerCase()
      if (lv === '*' || /^(?:https?:\/\/)?\*(?::\*)?$/.test(lv)) {
        f.push({
          severity: downgrade('high'),
          title: `Wildcard source "${v}" in ${scriptSrcDirective}`,
          detail: 'Scripts can be loaded from any host, so an attacker can host their own script and inject a <script src>.' + ignoredNote,
          fix: "Use a nonce-based strict policy, or list exact hosts.",
          ref: STRICT_CSP,
        })
      } else if (['https:', 'http:', 'data:', 'blob:', 'filesystem:'].includes(lv)) {
        const sev: Severity = lv === 'blob:' || lv === 'filesystem:' ? 'medium' : 'high'
        f.push({
          severity: downgrade(sev),
          title: `Scheme-only source "${v}" in ${scriptSrcDirective}`,
          detail:
            (lv === 'data:'
              ? 'data: URIs let an attacker inline arbitrary script (<script src="data:,alert(1)">).'
              : lv === 'blob:' || lv === 'filesystem:'
                ? 'Allows scripts created from blobs; an attacker who can create a blob can run code.'
                : `Any host reachable over ${lv} can serve scripts — equivalent to a wildcard.`) + ignoredNote,
          fix: "Remove scheme-only sources from script-src (keep 'https:' only as a CSP2 fallback next to 'strict-dynamic').",
          ref: STRICT_CSP,
        })
      }
      const bypasses = matchBypassHosts(v)
      if (bypasses.length > 0 && !lv.startsWith("'")) {
        const kinds = [...new Set(bypasses.map((b) => b.kind))].join(', ')
        f.push({
          severity: downgrade('high'),
          title: `Bypassable host "${v}" in ${scriptSrcDirective}`,
          detail: `This host serves ${kinds} (e.g. ${bypasses.slice(0, 3).map((b) => b.host).join(', ')}). Attackers can load it to execute arbitrary JavaScript and bypass the allowlist.` + ignoredNote,
          fix: "Prefer a nonce-based policy with 'strict-dynamic'. Otherwise, self-host the library or allowlist a full path to the specific file.",
          ref: CSP_EVALUATOR,
        })
      }
    }
  }

  // ---- insecure / malformed sources in all directives ----
  for (const d of csp.directives) {
    for (const v of d.values) {
      const lv = v.toLowerCase()
      if (lv.startsWith('http://')) {
        f.push({
          severity: 'medium',
          title: `Plain HTTP source "${v}" in ${d.name}`,
          detail: 'Resources fetched over HTTP can be modified by anyone on the network path (MITM).',
          fix: 'Use https:// sources only, and add upgrade-insecure-requests.',
        })
      }
      if (KEYWORDS.includes(lv) || /^(nonce|sha256|sha384|sha512)-/.test(lv)) {
        f.push({
          severity: 'medium',
          title: `Unquoted keyword "${v}" in ${d.name}`,
          detail: `Keywords, nonces and hashes must be wrapped in single quotes. Unquoted, "${v}" is treated as a host name and the intended rule does not apply.`,
          fix: `Write '${v}' with single quotes.`,
        })
      }
    }
    if (d.values.length > 1 && d.values.some((v) => v.toLowerCase() === "'none'")) {
      f.push({
        severity: 'low',
        title: `'none' combined with other sources in ${d.name}`,
        detail: "'none' is ignored when other sources are listed, so the directive is not as restrictive as it looks.",
        fix: `Use either 'none' alone or a list of sources.`,
      })
    }
  }

  // ---- object-src ----
  const objectSrc = getDirective(csp, 'object-src') ?? defaultSrc
  if (!(objectSrc && objectSrc.length === 1 && objectSrc[0].toLowerCase() === "'none'")) {
    f.push({
      severity: 'medium',
      title: "object-src is not 'none'",
      detail: `${getDirective(csp, 'object-src') ? 'object-src allows plugin content' : "object-src is missing and default-src is not 'none'"}. <object>/<embed> can load content able to execute script, bypassing script-src in some cases.`,
      fix: "Add object-src 'none'.",
      ref: STRICT_CSP,
    })
  }

  // ---- base-uri (no fallback) ----
  const baseUri = getDirective(csp, 'base-uri')
  if (!baseUri) {
    f.push({
      severity: 'medium',
      title: 'Missing base-uri',
      detail: 'base-uri does not fall back to default-src. An injected <base href="https://evil"> redirects all relative script URLs — and defeats nonce-based policies for relative <script src>.',
      fix: "Add base-uri 'none' (or 'self' if the app uses <base>).",
      ref: STRICT_CSP,
    })
  } else if (baseUri.some((v) => v === '*' || /^https?:$/i.test(v))) {
    f.push({ severity: 'medium', title: 'base-uri allows any host', detail: 'An injected <base> tag can point to an attacker host.', fix: "Use base-uri 'none' or 'self'." })
  }

  // ---- frame-ancestors (no fallback; not supported in <meta>) ----
  const frameAncestors = getDirective(csp, 'frame-ancestors')
  if (!frameAncestors) {
    f.push({
      severity: 'medium',
      title: 'Missing frame-ancestors (clickjacking)',
      detail: 'Any site can embed this page in an iframe and trick users into clicking. frame-ancestors does not fall back to default-src and is ignored in <meta> policies.',
      fix: "Add frame-ancestors 'none' (or 'self'), or send X-Frame-Options: DENY.",
      ref: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
    })
  } else if (frameAncestors.some((v) => v === '*' || /^https?:$/i.test(v))) {
    f.push({ severity: 'medium', title: 'frame-ancestors allows any site', detail: 'The page can be framed by any origin — no clickjacking protection.', fix: "Use frame-ancestors 'none' or list the exact trusted origins." })
  }

  // ---- form-action ----
  if (!getDirective(csp, 'form-action')) {
    f.push({
      severity: 'low',
      title: 'Missing form-action',
      detail: 'form-action does not fall back to default-src. Injected forms (or hijacked existing ones) can submit data, including auto-filled passwords, to any origin.',
      fix: "Add form-action 'self' (plus any external form targets you really use).",
      ref: MDN,
    })
  }

  // ---- reporting ----
  const hasReportUri = !!getDirective(csp, 'report-uri')
  const hasReportTo = !!getDirective(csp, 'report-to')
  if (!hasReportUri && !hasReportTo) {
    f.push({
      severity: 'info',
      title: 'No violation reporting',
      detail: 'Without report-to / report-uri you will not learn about blocked attacks or policy breakage.',
      fix: 'Add report-to <group> (with a Reporting-Endpoints header) and report-uri <url> as a fallback.',
      ref: MDN,
    })
  } else if (hasReportUri && !hasReportTo) {
    f.push({
      severity: 'info',
      title: 'Only report-uri (deprecated)',
      detail: 'report-uri is deprecated in favour of report-to, but report-to is not yet supported everywhere.',
      fix: 'Send both: report-to <group> with a Reporting-Endpoints header, and keep report-uri as a fallback.',
      ref: MDN,
    })
  }

  // ---- deprecated / unknown directives ----
  for (const d of csp.directives) {
    if (Object.hasOwn(DEPRECATED_DIRECTIVES, d.name)) {
      f.push({ severity: 'low', title: `Deprecated directive "${d.name}"`, detail: DEPRECATED_DIRECTIVES[d.name], fix: `Remove ${d.name}.` })
    } else if (!KNOWN_DIRECTIVES.has(d.name)) {
      f.push({ severity: 'info', title: `Unknown directive "${d.name}"`, detail: 'Browsers ignore unknown directives. Check for a typo (e.g. "script-scr", "frame-ancestor").' })
    }
  }

  if (getDirective(csp, 'require-trusted-types-for')) {
    f.push({ severity: 'pass', title: 'Trusted Types enforced', detail: 'require-trusted-types-for blocks DOM XSS sinks (innerHTML…) from receiving plain strings.' })
  }

  return f
}

export function evaluateCspString(input: string): Finding[] {
  return evaluateCsp(parseCsp(input))
}

/* ---------- builder ---------- */

export interface CspBuilderOptions {
  mode: 'strict' | 'allowlist'
  /** Allowlist mode: extra hosts per directive (space/comma separated). */
  scriptHosts: string
  styleHosts: string
  imgHosts: string
  connectHosts: string
  fontHosts: string
  frameHosts: string
  frameAncestors: 'none' | 'self'
  formActionSelf: boolean
  upgradeInsecureRequests: boolean
  trustedTypes: boolean
  reportUri: string
  reportTo: string
}

export const DEFAULT_BUILDER_OPTIONS: CspBuilderOptions = {
  mode: 'strict',
  scriptHosts: '',
  styleHosts: '',
  imgHosts: '',
  connectHosts: '',
  fontHosts: '',
  frameHosts: '',
  frameAncestors: 'none',
  formActionSelf: true,
  upgradeInsecureRequests: true,
  trustedTypes: false,
  reportUri: '',
  reportTo: '',
}

export const NONCE_PLACEHOLDER = '{RANDOM_NONCE}'

function hostList(s: string): string[] {
  return s.split(/[\s,]+/).map((h) => h.trim()).filter((h) => h !== '' && !/[;'"]/.test(h))
}

export function buildCsp(o: CspBuilderOptions): string {
  const parts: string[] = []
  const add = (name: string, ...values: string[]) => parts.push([name, ...values].join(' '))
  if (o.mode === 'strict') {
    // Google's recommended strict CSP: nonce + strict-dynamic, with https:/'unsafe-inline' as fallbacks
    // that CSP3 / CSP2 browsers ignore.
    add('script-src', `'nonce-${NONCE_PLACEHOLDER}'`, "'strict-dynamic'", 'https:', "'unsafe-inline'")
    add('object-src', "'none'")
    add('base-uri', "'none'")
  } else {
    add('default-src', "'self'")
    add('script-src', "'self'", ...hostList(o.scriptHosts))
    add('style-src', "'self'", ...hostList(o.styleHosts))
    add('img-src', "'self'", 'data:', ...hostList(o.imgHosts))
    add('font-src', "'self'", ...hostList(o.fontHosts))
    add('connect-src', "'self'", ...hostList(o.connectHosts))
    const frames = hostList(o.frameHosts)
    add('frame-src', ...(frames.length > 0 ? frames : ["'none'"]))
    add('object-src', "'none'")
    add('base-uri', "'self'")
  }
  add('frame-ancestors', `'${o.frameAncestors}'`)
  if (o.formActionSelf) add('form-action', "'self'")
  if (o.upgradeInsecureRequests) add('upgrade-insecure-requests')
  if (o.trustedTypes) add('require-trusted-types-for', "'script'")
  if (o.reportTo.trim()) add('report-to', o.reportTo.trim().replace(/[;,\s]/g, ''))
  if (o.reportUri.trim()) add('report-uri', o.reportUri.trim().replace(/[;,\s]/g, ''))
  return parts.join('; ')
}

/** Random nonce (128 bits, base64) — for illustration; the server must generate a fresh one per response. */
export function sampleNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return btoa(String.fromCharCode(...bytes))
}
