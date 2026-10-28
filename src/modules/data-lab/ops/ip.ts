/* IPv4 / IPv6 CIDR calculations (BigInt for IPv6). */
import { OpError } from '../engine/types'
import { isIPv6 } from './extract'

export function parseIPv4(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s)
  if (!m) return null
  const parts = m.slice(1).map(Number)
  if (parts.some((p, i) => p > 255 || (m[i + 1].length > 1 && m[i + 1][0] === '0'))) return null
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
}

export function formatIPv4(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.')
}

export function parseIPv6(s: string): bigint | null {
  if (!isIPv6(s)) return null
  let text = s
  const lastColon = s.lastIndexOf(':')
  const tail = s.slice(lastColon + 1)
  if (tail.includes('.')) {
    const v4 = parseIPv4(tail)
    if (v4 === null) return null
    text = s.slice(0, lastColon + 1) + ((v4 >>> 16).toString(16) + ':' + (v4 & 0xffff).toString(16))
  }
  let groups: string[]
  if (text.includes('::')) {
    const [l, r] = text.split('::')
    const left = l ? l.split(':') : []
    const right = r ? r.split(':') : []
    groups = [...left, ...new Array<string>(8 - left.length - right.length).fill('0'), ...right]
  } else groups = text.split(':')
  let v = 0n
  for (const g of groups) v = (v << 16n) | BigInt(parseInt(g, 16))
  return v
}

/** RFC 5952 canonical text form. */
export function formatIPv6(v: bigint): string {
  const groups: number[] = []
  for (let i = 7; i >= 0; i--) groups.push(Number((v >> BigInt(i * 16)) & 0xffffn))
  // longest run of ≥2 zero groups is compressed (first one wins on ties)
  let bestStart = -1
  let bestLen = 0
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++
      continue
    }
    let j = i
    while (j < 8 && groups[j] === 0) j++
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i
      bestLen = j - i
    }
    i = j
  }
  const hex = groups.map((g) => g.toString(16))
  if (bestStart < 0) return hex.join(':')
  return hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLen).join(':')
}

const V4_RANGES: [string, number, string][] = [
  ['0.0.0.0', 8, '"This network" (RFC 791)'],
  ['10.0.0.0', 8, 'Private (RFC 1918)'],
  ['100.64.0.0', 10, 'Carrier-grade NAT shared space (RFC 6598)'],
  ['127.0.0.0', 8, 'Loopback (RFC 1122)'],
  ['169.254.0.0', 16, 'Link-local (RFC 3927)'],
  ['172.16.0.0', 12, 'Private (RFC 1918)'],
  ['192.0.0.0', 24, 'IETF protocol assignments (RFC 6890)'],
  ['192.0.2.0', 24, 'Documentation TEST-NET-1 (RFC 5737)'],
  ['192.88.99.0', 24, 'Deprecated 6to4 relay anycast (RFC 7526)'],
  ['192.168.0.0', 16, 'Private (RFC 1918)'],
  ['198.18.0.0', 15, 'Benchmarking (RFC 2544)'],
  ['198.51.100.0', 24, 'Documentation TEST-NET-2 (RFC 5737)'],
  ['203.0.113.0', 24, 'Documentation TEST-NET-3 (RFC 5737)'],
  ['224.0.0.0', 4, 'Multicast (RFC 5771)'],
  ['255.255.255.255', 32, 'Limited broadcast (RFC 919)'],
  ['240.0.0.0', 4, 'Reserved for future use (RFC 1112)'],
]

const V6_RANGES: [string, number, string][] = [
  ['::1', 128, 'Loopback'],
  ['::', 128, 'Unspecified address'],
  ['::ffff:0:0', 96, 'IPv4-mapped address'],
  ['64:ff9b::', 96, 'IPv4/IPv6 translation (RFC 6052)'],
  ['2001:db8::', 32, 'Documentation (RFC 3849)'],
  ['2001::', 32, 'Teredo (RFC 4380)'],
  ['2002::', 16, '6to4 (RFC 3056)'],
  ['fc00::', 7, 'Unique local address (RFC 4193)'],
  ['fe80::', 10, 'Link-local unicast'],
  ['ff00::', 8, 'Multicast'],
  ['2000::', 3, 'Global unicast'],
]

function v4Mask(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
}

export function classifyIPv4(ip: number): string {
  for (const [base, p, label] of V4_RANGES) {
    const m = v4Mask(p)
    if (((ip & m) >>> 0) === ((parseIPv4(base) as number) & m) >>> 0) return label
  }
  return 'Public (globally routable unicast)'
}

export function classifyIPv6(ip: bigint): string {
  for (const [base, p, label] of V6_RANGES) {
    const mask = p === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - p)) - 1n)
    if ((ip & mask) === ((parseIPv6(base) as bigint) & mask)) return label
  }
  return 'Reserved / other'
}

export function cidrInfo(input: string): string {
  const s = input.trim()
  const [addr, prefixText] = s.split('/')
  const v4 = parseIPv4(addr)
  if (v4 !== null) {
    const prefix = prefixText === undefined ? 32 : Number(prefixText)
    if (!/^\d{1,2}$/.test(prefixText ?? '32') || prefix > 32) throw new OpError(`Invalid IPv4 prefix length in '${s}'`)
    const mask = v4Mask(prefix)
    const network = (v4 & mask) >>> 0
    const broadcast = (network | (~mask >>> 0)) >>> 0
    const total = 2 ** (32 - prefix)
    let first = network
    let last = broadcast
    let usable = total
    if (prefix <= 30) {
      first = network + 1
      last = broadcast - 1
      usable = total - 2
    }
    const lines = [
      `Address:          ${formatIPv4(v4)}`,
      `CIDR:             ${formatIPv4(network)}/${prefix}`,
      `Netmask:          ${formatIPv4(mask)}`,
      `Wildcard mask:    ${formatIPv4(~mask >>> 0)}`,
      `Network:          ${formatIPv4(network)}`,
      prefix <= 30 ? `Broadcast:        ${formatIPv4(broadcast)}` : `Broadcast:        n/a (/${prefix})`,
      `Host range:       ${formatIPv4(first)} – ${formatIPv4(last)}`,
      `Total addresses:  ${total.toLocaleString('en-US')}`,
      `Usable hosts:     ${usable.toLocaleString('en-US')}${prefix === 31 ? ' (point-to-point link, RFC 3021)' : ''}`,
      `Type:             ${classifyIPv4(network)}`,
    ]
    if (network !== v4) lines.splice(1, 0, `Note:             host bits set — the network is ${formatIPv4(network)}/${prefix}`)
    return lines.join('\n')
  }
  const v6 = parseIPv6(addr)
  if (v6 !== null) {
    const prefix = prefixText === undefined ? 128 : Number(prefixText)
    if (!/^\d{1,3}$/.test(prefixText ?? '128') || prefix > 128) throw new OpError(`Invalid IPv6 prefix length in '${s}'`)
    const all = (1n << 128n) - 1n
    const hostMask = (1n << BigInt(128 - prefix)) - 1n
    const network = v6 & (all ^ hostMask)
    const last = network | hostMask
    const total = 1n << BigInt(128 - prefix)
    return [
      `Address:          ${formatIPv6(v6)}`,
      `CIDR:             ${formatIPv6(network)}/${prefix}`,
      `Network:          ${formatIPv6(network)}`,
      `Range:            ${formatIPv6(network)} – ${formatIPv6(last)}`,
      `Total addresses:  ${total.toLocaleString('en-US')}${prefix <= 64 ? ` (2^${128 - prefix})` : ''}`,
      `Type:             ${classifyIPv6(network)}`,
    ].join('\n')
  }
  throw new OpError(`'${s.slice(0, 60)}' is not an IPv4/IPv6 address or CIDR block`)
}
