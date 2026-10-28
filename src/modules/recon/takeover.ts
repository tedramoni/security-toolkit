/**
 * Subdomain-takeover heuristics for CNAMEs discovered via certificate transparency.
 *
 * Service list derived from the community "can-i-take-over-xyz" project (EdOverflow,
 * https://github.com/EdOverflow/can-i-take-over-xyz, fingerprints.json reviewed 2026-10). Only entries with a
 * CNAME pattern are used; their published status is kept:
 *  - "vulnerable"  + nxdomain fingerprint → a dangling CNAME (target NXDOMAIN) is the takeover signal itself;
 *  - "vulnerable"  without nxdomain fingerprint → the real fingerprint is an HTTP error page we cannot fetch from the
 *    browser, so a dangling CNAME is a strong hint, a live one is not;
 *  - "edge case"   → takeover depends on account/verification details;
 * Services listed as "not vulnerable" (CloudFront, ELB, Fastly, Firebase, GitLab, Netlify…) are not flagged.
 *
 * Everything here is a lead to verify manually — never proof.
 */

export type TakeoverStatus = 'vulnerable' | 'edge-case'

export interface TakeoverService {
  service: string
  /** Lower-case domain suffixes matched against the CNAME chain. */
  suffixes: readonly string[]
  status: TakeoverStatus
  /** The published fingerprint is NXDOMAIN on the CNAME target. */
  nxdomain: boolean
}

export const TAKEOVER_SERVICES: readonly TakeoverService[] = [
  { service: 'AWS Elastic Beanstalk', suffixes: ['elasticbeanstalk.com'], status: 'vulnerable', nxdomain: true },
  { service: 'AWS S3', suffixes: ['s3.amazonaws.com', 's3-website.amazonaws.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Agile CRM', suffixes: ['agilecrm.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Airee.ru', suffixes: ['airee.ru'], status: 'vulnerable', nxdomain: false },
  { service: 'Anima', suffixes: ['animaapp.io'], status: 'vulnerable', nxdomain: false },
  { service: 'Bitbucket', suffixes: ['bitbucket.io'], status: 'vulnerable', nxdomain: false },
  { service: 'Discourse', suffixes: ['trydiscourse.com'], status: 'vulnerable', nxdomain: true },
  { service: 'Gemfury', suffixes: ['furyns.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Ghost', suffixes: ['ghost.io'], status: 'vulnerable', nxdomain: false },
  { service: 'HatenaBlog', suffixes: ['hatenablog.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Help Juice', suffixes: ['helpjuice.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Help Scout', suffixes: ['helpscoutdocs.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Helprace', suffixes: ['helprace.com'], status: 'vulnerable', nxdomain: false },
  { service: 'JetBrains YouTrack', suffixes: ['youtrack.cloud'], status: 'vulnerable', nxdomain: false },
  { service: 'LaunchRock', suffixes: ['launchrock.com'], status: 'vulnerable', nxdomain: false },
  {
    service: 'Microsoft Azure',
    suffixes: [
      'cloudapp.net',
      'cloudapp.azure.com',
      'azurewebsites.net',
      'blob.core.windows.net',
      'azure-api.net',
      'azurehdinsight.net',
      'azureedge.net',
      'azurecontainer.io',
      'database.windows.net',
      'azuredatalakestore.net',
      'search.windows.net',
      'azurecr.io',
      'redis.cache.windows.net',
      'servicebus.windows.net',
      'visualstudio.com',
      // Not in the fingerprint file, but listed in Microsoft's own "prevent dangling DNS entries" guidance.
      'trafficmanager.net',
    ],
    status: 'vulnerable',
    nxdomain: true,
  },
  { service: 'Ngrok', suffixes: ['ngrok.io'], status: 'vulnerable', nxdomain: false },
  { service: 'Readme.io', suffixes: ['readme.io'], status: 'vulnerable', nxdomain: false },
  { service: 'Strikingly', suffixes: ['s.strikinglydns.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Surge.sh', suffixes: ['surge.sh'], status: 'vulnerable', nxdomain: false },
  { service: 'SurveySparrow', suffixes: ['surveysparrow.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Uberflip', suffixes: ['read.uberflip.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Uptimerobot', suffixes: ['stats.uptimerobot.com'], status: 'vulnerable', nxdomain: false },
  { service: 'WordPress.com', suffixes: ['wordpress.com'], status: 'vulnerable', nxdomain: false },
  { service: 'Worksites', suffixes: ['worksites.net'], status: 'vulnerable', nxdomain: false },
  // "Edge case" entries (no CNAME pattern published; well-known hosting suffixes added here).
  { service: 'GitHub Pages', suffixes: ['github.io'], status: 'edge-case', nxdomain: false },
  { service: 'Heroku', suffixes: ['herokuapp.com', 'herokudns.com', 'herokussl.com'], status: 'edge-case', nxdomain: false },
  { service: 'Shopify', suffixes: ['myshopify.com'], status: 'edge-case', nxdomain: false },
  { service: 'Tumblr', suffixes: ['domains.tumblr.com'], status: 'edge-case', nxdomain: false },
  { service: 'Webflow', suffixes: ['proxy.webflow.com', 'proxy-ssl.webflow.com'], status: 'edge-case', nxdomain: false },
  { service: 'Wix', suffixes: ['wixdns.net'], status: 'edge-case', nxdomain: false },
]

function matchesSuffix(host: string, suffix: string): boolean {
  return host === suffix || host.endsWith('.' + suffix)
}

/** S3 regional endpoints: bucket.s3.eu-west-1.amazonaws.com, bucket.s3-website-us-east-1.amazonaws.com, … */
function isS3(host: string): boolean {
  if (!host.endsWith('.amazonaws.com')) return false
  return host.split('.').some((l) => l === 's3' || l.startsWith('s3-website') || l.startsWith('s3-'))
}

export function findTakeoverService(host: string): TakeoverService | undefined {
  const h = host.toLowerCase().replace(/\.$/, '')
  if (isS3(h)) return TAKEOVER_SERVICES.find((s) => s.service === 'AWS S3')
  return TAKEOVER_SERVICES.find((s) => s.suffixes.some((x) => matchesSuffix(h, x)))
}

export type TakeoverVerdict = 'possible-takeover' | 'dangling-cname' | 'review' | 'none'

export interface TakeoverAssessment {
  verdict: TakeoverVerdict
  severity: 'high' | 'medium' | 'low' | 'info' | 'pass'
  service?: string
  reason: string
}

/**
 * @param cnames CNAME chain returned by the resolver for the subdomain (in order)
 * @param rcode  final DNS status of the A lookup (3 = NXDOMAIN)
 * @param hasAddress the chain ends in at least one A/AAAA record
 */
export function assessTakeover(cnames: readonly string[], rcode: number, hasAddress: boolean): TakeoverAssessment {
  if (cnames.length === 0) return { verdict: 'none', severity: 'pass', reason: 'No CNAME.' }
  const svc = cnames.map(findTakeoverService).find((x) => x !== undefined)
  const dangling = rcode === 3 || (rcode === 0 && !hasAddress)
  const target = cnames[cnames.length - 1]
  if (svc && dangling) {
    if (svc.status === 'vulnerable') {
      return {
        verdict: 'possible-takeover',
        severity: svc.nxdomain ? 'high' : 'medium',
        service: svc.service,
        reason: `CNAME to ${svc.service} (${target}) does not resolve${rcode === 3 ? ' (NXDOMAIN)' : ''}. Possible subdomain takeover — verify manually.`,
      }
    }
    return { verdict: 'possible-takeover', severity: 'low', service: svc.service, reason: `CNAME to ${svc.service} (${target}) does not resolve. Takeover is an edge case for this service — verify manually.` }
  }
  if (dangling) {
    return { verdict: 'dangling-cname', severity: 'low', reason: `Dangling CNAME: ${target} does not resolve. Remove the record if the service is gone.` }
  }
  if (svc && svc.status === 'vulnerable') {
    return { verdict: 'review', severity: 'info', service: svc.service, reason: `Points to ${svc.service}; resolves today. If the resource is ever deleted, the subdomain becomes claimable.` }
  }
  return { verdict: 'none', severity: 'pass', service: svc?.service, reason: 'CNAME resolves.' }
}
