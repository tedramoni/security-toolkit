/**
 * Address / hostname guard used in two places:
 *  - target normalisation (refuse to "recon" localhost, RFC 1918 ranges, cloud metadata…);
 *  - the optional CORS proxy (Cloudflare Worker template in proxy-worker.js.txt duplicates this logic in plain JS so the
 *    worker stays a single copy-pasteable file — keep both in sync; ssrf.test.ts checks the template's markers).
 *
 * Hostnames are expected in the form produced by the WHATWG URL parser (lower-case, punycode, IPv4 shorthand such as
 * "0x7f.1" or "2130706433" already canonicalised to dotted quad, IPv6 inside brackets).
 *
 * Limitation (documented in the UI): a public hostname can still resolve to a private address (DNS rebinding,
 * wildcard DNS services). Browsers and Workers cannot resolve DNS before fetch(), so only literal IPs and well-known
 * names are blocked here.
 */

/** Strict dotted-quad parser. Returns 4 octets or undefined. */
export function parseIPv4(s: string): number[] | undefined {
  const parts = s.split('.')
  if (parts.length !== 4) return undefined
  const out: number[] = []
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return undefined
    if (p.length > 1 && p[0] === '0') return undefined
    const n = Number(p)
    if (n > 255) return undefined
    out.push(n)
  }
  return out
}

/** IPv6 parser (with :: compression and an optional trailing dotted IPv4). Returns 8 16-bit words or undefined. */
export function parseIPv6(input: string): number[] | undefined {
  let s = input
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  const pct = s.indexOf('%')
  if (pct !== -1) s = s.slice(0, pct)
  if (s.length < 2 || s.length > 45 || !/^[0-9a-fA-F:.]+$/.test(s)) return undefined
  const dbl = s.indexOf('::')
  if (dbl !== -1 && s.indexOf('::', dbl + 1) !== -1) return undefined
  const parseSide = (side: string): number[] | undefined => {
    if (side === '') return []
    const groups = side.split(':')
    const words: number[] = []
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i]
      if (i === groups.length - 1 && g.includes('.')) {
        const v4 = parseIPv4(g)
        if (!v4) return undefined
        words.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3])
        continue
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return undefined
      words.push(parseInt(g, 16))
    }
    return words
  }
  if (dbl === -1) {
    const w = parseSide(s)
    return w && w.length === 8 ? w : undefined
  }
  const head = parseSide(s.slice(0, dbl))
  const tail = parseSide(s.slice(dbl + 2))
  if (!head || !tail || head.length + tail.length > 7) return undefined
  return [...head, ...new Array<number>(8 - head.length - tail.length).fill(0), ...tail]
}

/** Reason the IPv4 address is not a public unicast address, or undefined if it is public. */
export function blockedIPv4Reason(o: readonly number[]): string | undefined {
  const [a, b, c] = o
  if (a === 0) return '"this network" (0.0.0.0/8)'
  if (a === 10) return 'private network (10.0.0.0/8)'
  if (a === 100 && b >= 64 && b <= 127) return 'carrier-grade NAT (100.64.0.0/10)'
  if (a === 127) return 'loopback (127.0.0.0/8)'
  if (a === 169 && b === 254) return 'link-local / cloud metadata (169.254.0.0/16)'
  if (a === 172 && b >= 16 && b <= 31) return 'private network (172.16.0.0/12)'
  if (a === 192 && b === 0 && c === 0) return 'IETF protocol assignments (192.0.0.0/24)'
  if (a === 192 && b === 0 && c === 2) return 'documentation range (192.0.2.0/24)'
  if (a === 192 && b === 88 && c === 99) return '6to4 relay anycast (192.88.99.0/24)'
  if (a === 192 && b === 168) return 'private network (192.168.0.0/16)'
  if (a === 198 && (b === 18 || b === 19)) return 'benchmarking range (198.18.0.0/15)'
  if (a === 198 && b === 51 && c === 100) return 'documentation range (198.51.100.0/24)'
  if (a === 203 && b === 0 && c === 113) return 'documentation range (203.0.113.0/24)'
  if (a >= 224 && a <= 239) return 'multicast (224.0.0.0/4)'
  if (a >= 240) return 'reserved / broadcast (240.0.0.0/4)'
  return undefined
}

/** Reason the IPv6 address is not a public unicast address, or undefined if it is public. */
export function blockedIPv6Reason(w: readonly number[]): string | undefined {
  const embedded = (hi: number, lo: number) => blockedIPv4Reason([hi >> 8, hi & 0xff, lo >> 8, lo & 0xff])
  if (w.every((x) => x === 0)) return 'unspecified address (::)'
  if (w.slice(0, 7).every((x) => x === 0) && w[7] === 1) return 'loopback (::1)'
  // IPv4-mapped ::ffff:a.b.c.d and IPv4-compatible ::a.b.c.d (deprecated): judge the embedded IPv4.
  if (w.slice(0, 5).every((x) => x === 0) && (w[5] === 0xffff || w[5] === 0)) {
    return embedded(w[6], w[7]) ?? (w[5] === 0 ? 'deprecated IPv4-compatible address (::/96)' : undefined)
  }
  // IPv4-translated ::ffff:0:a.b.c.d (RFC 2765 / SIIT): judge the embedded IPv4.
  if (w.slice(0, 4).every((x) => x === 0) && w[4] === 0xffff && w[5] === 0) return embedded(w[6], w[7])
  // NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
  if (w[0] === 0x64 && w[1] === 0xff9b) return w[2] === 1 ? 'local-use NAT64 (64:ff9b:1::/48)' : embedded(w[6], w[7])
  if (w[0] === 0x100 && w[1] === 0 && w[2] === 0 && w[3] === 0) return 'discard-only prefix (100::/64)'
  if (w[0] === 0x2001 && w[1] === 0xdb8) return 'documentation range (2001:db8::/32)'
  if (w[0] === 0x2001 && w[1] === 0) return 'Teredo tunnel (2001::/32)'
  if (w[0] === 0x2002) return embedded(w[1], w[2]) ?? undefined
  if ((w[0] & 0xfe00) === 0xfc00) return 'unique local address (fc00::/7)'
  if ((w[0] & 0xffc0) === 0xfe80) return 'link-local (fe80::/10)'
  if ((w[0] & 0xffc0) === 0xfec0) return 'deprecated site-local (fec0::/10)'
  if ((w[0] & 0xff00) === 0xff00) return 'multicast (ff00::/8)'
  return undefined
}

/** Special-use / internal names (RFC 6761, RFC 8375, common corporate pseudo-TLDs, metadata endpoints). */
const BLOCKED_SUFFIXES = [
  'localhost',
  'local',
  'internal',
  'intranet',
  'corp',
  'lan',
  'home',
  'home.arpa',
  'test',
  'invalid',
  'example',
  'onion',
  'arpa',
  // Public wildcard DNS services that map names to arbitrary (often private) IPs.
  'nip.io',
  'sslip.io',
  'xip.io',
  'localtest.me',
  'lvh.me',
]

const BLOCKED_NAMES = ['metadata', 'instance-data', 'metadata.google.internal', 'metadata.azure.internal']

export type HostKind = 'ipv4' | 'ipv6' | 'name'

export interface HostCheck {
  kind: HostKind
  /** Present when the host must not be contacted / scanned. */
  blocked?: string
}

/** Classify a URL hostname and say whether it must be blocked. */
export function checkHost(hostname: string): HostCheck {
  const h = hostname.toLowerCase().replace(/\.$/, '')
  if (h.startsWith('[') || h.includes(':')) {
    const w = parseIPv6(h)
    if (!w) return { kind: 'ipv6', blocked: 'invalid IPv6 address' }
    const r = blockedIPv6Reason(w)
    return r ? { kind: 'ipv6', blocked: r } : { kind: 'ipv6' }
  }
  const v4 = parseIPv4(h)
  if (v4) {
    const r = blockedIPv4Reason(v4)
    return r ? { kind: 'ipv4', blocked: r } : { kind: 'ipv4' }
  }
  // Something that looks numeric but is not a canonical dotted quad (the URL parser canonicalises valid forms).
  if (/^[0-9.]+$/.test(h) || /^0x[0-9a-f]+$/.test(h)) return { kind: 'name', blocked: 'non-canonical numeric host' }
  if (h === '') return { kind: 'name', blocked: 'empty host' }
  if (!h.includes('.')) return { kind: 'name', blocked: 'single-label (intranet) host name' }
  if (BLOCKED_NAMES.includes(h)) return { kind: 'name', blocked: 'cloud metadata endpoint' }
  for (const s of BLOCKED_SUFFIXES) {
    if (h === s || h.endsWith('.' + s)) return { kind: 'name', blocked: `special-use / internal name (.${s})` }
  }
  return { kind: 'name' }
}

const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443'])

export type ProxyTargetCheck = { ok: true; url: URL } | { ok: false; reason: string }

/**
 * Validate a URL the proxy is asked to fetch (also applied to every redirect hop): http/https only, no credentials,
 * standard web ports only, public host.
 */
export function checkProxyTarget(raw: string): ProxyTargetCheck {
  if (raw.length > 2048) return { ok: false, reason: 'URL too long' }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return { ok: false, reason: 'invalid URL' }
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { ok: false, reason: 'only http and https URLs are allowed' }
  if (url.username || url.password) return { ok: false, reason: 'credentials in URL are not allowed' }
  if (!ALLOWED_PORTS.has(url.port)) return { ok: false, reason: `port ${url.port} is not allowed` }
  const c = checkHost(url.hostname)
  if (c.blocked) return { ok: false, reason: `blocked host: ${c.blocked}` }
  return { ok: true, url }
}
